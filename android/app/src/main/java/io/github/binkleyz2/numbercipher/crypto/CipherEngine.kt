package io.github.binkleyz2.numbercipher.crypto

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.GeneralSecurityException
import java.security.SecureRandom
import java.text.Normalizer
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** A user-facing error; [message] is safe to show in the UI. */
class CipherException(message: String) : Exception(message)

/** Thrown when the user cancels; not an error. */
class CancelledException : Exception("Cancelled")

/** Progress of a running encrypt/decrypt. [fraction] is 0..1; [secondsLeft] is null until known. */
data class WorkProgress(val fraction: Float, val secondsLeft: Int?, val rounds: Int)

/**
 * Number Cipher code format — identical to the Mac and Windows apps.
 *
 * Version 2 (written here):
 *   bytes  = version(1)=2 | rounds(4, big-endian) | salt(16) | nonce(12) | ciphertext(n) | tag(16)
 *   key    = PBKDF2-HMAC-SHA256(NFC(passphrase) as UTF-8, salt, rounds) -> 32 bytes
 *   cipher = AES-256-GCM, with version|rounds|salt as authenticated data
 * Version 1 (still decrypted): version(1)=1 | salt(16) | nonce | ct | tag, fixed 2,000,000 rounds.
 * Both: plaintext padded with 0x00 to a multiple of 16 bytes; each byte -> two letters
 * from "ABCDEFGHJKLMNPQR" (no I or O).
 *
 * How Android meets the ~10 s target on any phone: instead of predicting a round count from
 * a benchmark (fragile on phones that hop between big and little cores, or slow down when
 * warm), encryption keeps iterating until the worker thread has spent 10 s of CPU time, then
 * stops and records exactly how many rounds it did. Stopping early is valid because a
 * one-block PBKDF2 key for N rounds is simply the running result after N steps. Counting CPU
 * time (not wall time) means a pause in the background can't produce a weaker code.
 */
class CipherEngine(
    private val kdf: Pbkdf2 = Pbkdf2.best(),
    /** Monotonic CPU-time clock of the calling thread, in nanoseconds. */
    private val workClock: () -> Long = { System.nanoTime() },
) {
    companion object {
        const val CURRENT_VERSION: Int = 2
        const val V1_ROUNDS = 2_000_000
        const val TARGET_SECONDS = 10.0
        const val MIN_ROUNDS = 2_000_000
        /** Upper bound accepted when decrypting, so a corrupted or hostile code can't hang the app. */
        const val MAX_ROUNDS = 1_000_000_000
        const val SALT_LENGTH = 16
        const val NONCE_LENGTH = 12
        const val TAG_LENGTH = 16
        const val PAD_BLOCK = 16
        const val ALPHABET = "ABCDEFGHJKLMNPQR"
        private const val ALLOWED = "0123456789 ,.-\n\t"
        private const val CHUNK = 32_768

        const val MSG_ONLY_NUMBERS = "Only digits, spaces, commas, periods, dashes and line breaks are allowed."
        const val MSG_NO_DIGITS = "Enter at least one number."
        const val MSG_NO_PASSPHRASE = "Enter a passphrase."
        const val MSG_MALFORMED = "That doesn't look like a Number Cipher code (check for typos or missing letters)."
        const val MSG_FIRST_LETTER = "The first letter of a code is always A. Check the start of the code for a typo."
        const val MSG_NEWER = "This code was made by a newer version of Number Cipher. Update this app to decrypt it."
        const val MSG_WRONG = "Wrong passphrase, or the code was altered."

        private val random = SecureRandom()

        /** Rough passphrase strength in bits, matching the Mac and Windows meters. */
        fun strengthBits(passphrase: String): Double {
            if (passphrase.isEmpty()) return 0.0
            var pool = 0
            if (passphrase.any { it.isLowerCase() }) pool += 26
            if (passphrase.any { it.isUpperCase() }) pool += 26
            if (passphrase.any { it.isDigit() }) pool += 10
            if (passphrase.any { !it.isLetterOrDigit() }) pool += 33
            return passphrase.length * (Math.log(maxOf(pool, 2).toDouble()) / Math.log(2.0))
        }

        fun toLetters(data: ByteArray): String = buildString(data.size * 2) {
            for (b in data) {
                val v = b.toInt() and 0xFF
                append(ALPHABET[v shr 4]); append(ALPHABET[v and 0x0F])
            }
        }

        fun fromLetters(code: String): ByteArray {
            val letters = code.uppercase().filter { !it.isWhitespace() && it != '-' }
            if (letters.isEmpty() || letters.length % 2 != 0) throw CipherException(MSG_MALFORMED)
            return ByteArray(letters.length / 2) { i ->
                val hi = ALPHABET.indexOf(letters[2 * i])
                val lo = ALPHABET.indexOf(letters[2 * i + 1])
                if (hi < 0 || lo < 0) throw CipherException(MSG_MALFORMED)
                (hi shl 4 or lo).toByte()
            }
        }

        fun group(s: String, size: Int = 5): String = s.chunked(size).joinToString(" ")

        /** Reads the header: (header length, rounds). */
        fun readHeader(bytes: ByteArray): Pair<Int, Int> {
            if (bytes.isEmpty()) throw CipherException(MSG_MALFORMED)
            return when (val v = bytes[0].toInt() and 0xFF) {
                1 -> (1 + SALT_LENGTH) to V1_ROUNDS
                2 -> {
                    if (bytes.size < 5 + SALT_LENGTH) throw CipherException(MSG_MALFORMED)
                    val r = ByteBuffer.wrap(bytes, 1, 4).int.toLong() and 0xFFFF_FFFFL
                    if (r < 100_000 || r > MAX_ROUNDS) throw CipherException(MSG_MALFORMED)
                    (5 + SALT_LENGTH) to r.toInt()
                }
                0 -> throw CipherException(MSG_MALFORMED)
                in 3..15 -> throw CipherException(MSG_NEWER)   // future versions all start with "A"
                else -> throw CipherException(MSG_FIRST_LETTER) // any other first letter is a typo
            }
        }

        /** Rounds stored in a code, or null if it can't be read. */
        fun roundsIn(code: String): Int? = try { readHeader(fromLetters(code)).second } catch (_: CipherException) { null }

        private fun passwordBytes(passphrase: String) =
            Normalizer.normalize(passphrase, Normalizer.Form.NFC).toByteArray(Charsets.UTF_8)
    }

    /**
     * Encrypts [numbers]. Normally runs until ~10 s of CPU work; [fixedRounds] forces an
     * exact count (tests). [onProgress] is called on the worker thread.
     */
    fun encrypt(
        numbers: String,
        passphrase: String,
        fixedRounds: Int? = null,
        isCancelled: () -> Boolean = { false },
        onProgress: (WorkProgress) -> Unit = {},
    ): String {
        val cleaned = numbers.replace("\r\n", "\n").replace('\r', '\n').trim()
        if (cleaned.any { it !in ALLOWED }) throw CipherException(MSG_ONLY_NUMBERS)
        if (cleaned.none { it in '0'..'9' }) throw CipherException(MSG_NO_DIGITS)
        if (passphrase.isEmpty()) throw CipherException(MSG_NO_PASSPHRASE)

        val text = cleaned.toByteArray(Charsets.UTF_8)
        val plain = text.copyOf((text.size / PAD_BLOCK + 1) * PAD_BLOCK)
        text.fill(0)
        val salt = ByteArray(SALT_LENGTH).also(random::nextBytes)
        val pw = passwordBytes(passphrase)
        val key = ByteArray(32)
        try {
            val targetNs = (TARGET_SECONDS * 1e9).toLong()
            val start = workClock()
            val cb = object : ChunkCallback {
                override fun onChunk(done: Int): Int {
                    if (isCancelled()) return ChunkCallback.CANCEL
                    if (fixedRounds != null) {
                        onProgress(WorkProgress(done.toFloat() / fixedRounds, null, done))
                        return ChunkCallback.CONTINUE
                    }
                    val elapsed = workClock() - start
                    val timeFraction = elapsed.toDouble() / targetNs
                    val minFraction = done.toDouble() / MIN_ROUNDS
                    // On a very slow device the minimum round count, not the clock, sets the pace.
                    val fraction = if (timeFraction >= 1 && minFraction < 1) minFraction else minOf(timeFraction, 1.0)
                    val left = if (timeFraction < 1) Math.ceil((targetNs - elapsed) / 1e9).toInt()
                               else if (minFraction < 1) Math.ceil(elapsed / 1e9 * (1 / minFraction - 1)).toInt()
                               else 0
                    onProgress(WorkProgress(fraction.toFloat(), left, done))
                    return if (elapsed >= targetNs && done >= MIN_ROUNDS) ChunkCallback.STOP else ChunkCallback.CONTINUE
                }
            }
            val maxRounds = fixedRounds ?: (MAX_ROUNDS / 2)
            val rounds = kdf.derive(pw, salt, maxRounds, CHUNK, key, cb)
            if (rounds == 0) throw CancelledException()

            val header = ByteBuffer.allocate(5 + SALT_LENGTH).put(CURRENT_VERSION.toByte()).putInt(rounds).put(salt).array()
            val nonce = ByteArray(NONCE_LENGTH).also(random::nextBytes)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_LENGTH * 8, nonce))
            cipher.updateAAD(header)
            val sealed = cipher.doFinal(plain) // ciphertext || tag
            return group(toLetters(header + nonce + sealed))
        } finally {
            key.fill(0); pw.fill(0); plain.fill(0)
        }
    }

    /** Decrypts [code]. [onProgress] is called on the worker thread with exact progress. */
    fun decrypt(
        code: String,
        passphrase: String,
        isCancelled: () -> Boolean = { false },
        onProgress: (WorkProgress) -> Unit = {},
    ): String {
        if (passphrase.isEmpty()) throw CipherException(MSG_NO_PASSPHRASE)
        val bytes = fromLetters(code)
        val (headerLength, rounds) = readHeader(bytes)
        if (bytes.size < headerLength + NONCE_LENGTH + TAG_LENGTH) throw CipherException(MSG_MALFORMED)

        val header = bytes.copyOfRange(0, headerLength)
        val salt = bytes.copyOfRange(headerLength - SALT_LENGTH, headerLength)
        val nonce = bytes.copyOfRange(headerLength, headerLength + NONCE_LENGTH)
        val sealed = bytes.copyOfRange(headerLength + NONCE_LENGTH, bytes.size)

        val pw = passwordBytes(passphrase)
        val key = ByteArray(32)
        var plain: ByteArray? = null
        try {
            val start = workClock()
            val cb = object : ChunkCallback {
                override fun onChunk(done: Int): Int {
                    if (isCancelled()) return ChunkCallback.CANCEL
                    val elapsed = (workClock() - start) / 1e9
                    val left = if (done > 0 && elapsed > 0.2) Math.ceil(elapsed * (rounds - done) / done).toInt() else null
                    onProgress(WorkProgress(done.toFloat() / rounds, left, done))
                    return ChunkCallback.CONTINUE
                }
            }
            if (kdf.derive(pw, salt, rounds, CHUNK, key, cb) == 0) throw CancelledException()

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_LENGTH * 8, nonce))
            cipher.updateAAD(header)
            plain = try { cipher.doFinal(sealed) } catch (_: GeneralSecurityException) { throw CipherException(MSG_WRONG) }
            var end = plain.size
            while (end > 0 && plain[end - 1] == 0.toByte()) end--
            val decoder = Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
            return try { decoder.decode(ByteBuffer.wrap(plain, 0, end)).toString() } catch (_: CharacterCodingException) { throw CipherException(MSG_WRONG) }
        } finally {
            key.fill(0); pw.fill(0); plain?.fill(0)
        }
    }
}
