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
 * Both: plaintext is UTF-8 text padded with 0x00 to the next multiple of 16 bytes.
 *
 * Written as words (1.5+): the bytes are read as a bit string, most significant bit first, split
 * into 11-bit numbers (the last padded with 0 bits), each picking a word from the BIP39 English list
 * ([WordList]). Every v2 code is 49 + 16k bytes, so the byte count is the largest
 * n <= 11*words/8 with n % 16 == 1, and ceil(8n/11) must equal the word count.
 * Written as letters (1.0–1.4, still read): each byte -> two letters from "ABCDEFGHJKLMNPQR".
 * A code containing any letter outside that set is read as words.
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
        const val MAX_TEXT_BYTES = 20_000
        const val WORDS_PER_LINE = 6
        private const val CHUNK = 32_768

        const val MSG_NO_TEXT = "Enter some text to encrypt."
        const val MSG_NULL_CHAR = "The text contains a null character, which can't be encrypted."
        const val MSG_TOO_LONG = "That's too much text (the limit is 20,000 bytes, about 20,000 English characters)."
        const val MSG_WORD_COUNT = "A word seems to be missing or extra. Check the code against the original."
        const val MSG_FIRST_WORD = "The first word of the code looks wrong. Check it for a typo."
        const val MSG_LAST_WORD = "The last word of the code looks wrong. Check it for a typo."
        fun msgUnknownWord(word: String, position: Int) =
            "\u201C$word\u201D (word $position) isn't one of the code words. Check its spelling."
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

        private val wordIndex: Map<String, Int> by lazy { WordList.words.withIndex().associate { it.value to it.index } }
        private val prefixIndex: Map<String, Int> by lazy { WordList.words.withIndex().associate { it.value.take(4) to it.index } }

        /** True if [code] has any letter outside the old letter-code alphabet, so it must be words. */
        fun isWordCode(code: String): Boolean =
            code.any { (it in 'a'..'z' || it in 'A'..'Z') && it.uppercaseChar() !in ALPHABET }

        /** Reads a word code or an old letter code. */
        fun decode(code: String): ByteArray = if (isWordCode(code)) fromWords(code) else fromLetters(code)

        fun toWords(data: ByteArray): String {
            val words = ArrayList<String>((data.size * 8 + 10) / 11)
            var acc = 0; var bits = 0
            for (b in data) {
                acc = acc shl 8 or (b.toInt() and 0xFF); bits += 8
                if (bits >= 11) { bits -= 11; words.add(WordList.words[acc ushr bits and 0x7FF]) }
                acc = acc and ((1 shl bits) - 1)
            }
            if (bits > 0) words.add(WordList.words[acc shl (11 - bits) and 0x7FF])
            return words.chunked(WORDS_PER_LINE).joinToString("\n") { it.joinToString(" ").uppercase() }
        }

        fun fromWords(code: String): ByteArray {
            // Words are runs of ASCII letters; anything else (spaces, line breaks, numbering, punctuation) separates them.
            val tokens = Regex("[A-Za-z]+").findAll(code).map { it.value }.toList()
            val indices = tokens.mapIndexed { i, t ->
                val w = t.lowercase()
                wordIndex[w] ?: (if (w.length >= 4) prefixIndex[w.take(4)] else null)
                    ?: throw CipherException(msgUnknownWord(t.uppercase(), i + 1))
            }
            val count = indices.size
            var n = count * 11 / 8
            n -= (n - 1).mod(16)
            if (n < 49 + PAD_BLOCK || (n * 8 + 10) / 11 != count) throw CipherException(MSG_WORD_COUNT)

            val out = ByteArray(n)
            var o = 0
            var acc = 0; var bits = 0
            for (v in indices) {
                acc = acc shl 11 or v; bits += 11
                while (bits >= 8 && o < n) { bits -= 8; out[o++] = (acc ushr bits).toByte() }
                acc = acc and ((1 shl bits) - 1)
            }
            if (acc != 0) throw CipherException(MSG_LAST_WORD)
            return out
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

        /** Reads the header: (header length, rounds). [words]: the code was written as words. */
        fun readHeader(bytes: ByteArray, words: Boolean = false): Pair<Int, Int> {
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
                else -> throw CipherException(if (words) MSG_FIRST_WORD else MSG_FIRST_LETTER) // any other first letter/word is a typo
            }
        }

        /** Rounds stored in a code, or null if it can't be read. */
        fun roundsIn(code: String): Int? = try { readHeader(decode(code), isWordCode(code)).second } catch (_: CipherException) { null }

        private fun passwordBytes(passphrase: String) =
            Normalizer.normalize(passphrase, Normalizer.Form.NFC).toByteArray(Charsets.UTF_8)
    }

    /**
     * Encrypts [text]. Normally runs until ~10 s of CPU work; [fixedRounds] forces an
     * exact count (tests). [onProgress] is called on the worker thread.
     */
    fun encrypt(
        text: String,
        passphrase: String,
        fixedRounds: Int? = null,
        isCancelled: () -> Boolean = { false },
        onProgress: (WorkProgress) -> Unit = {},
    ): String {
        val cleaned = text.replace("\r\n", "\n").replace('\r', '\n').trim()
        if (cleaned.isEmpty()) throw CipherException(MSG_NO_TEXT)
        if ('\u0000' in cleaned) throw CipherException(MSG_NULL_CHAR)
        val utf8 = cleaned.toByteArray(Charsets.UTF_8)
        if (utf8.size > MAX_TEXT_BYTES) { utf8.fill(0); throw CipherException(MSG_TOO_LONG) }
        if (passphrase.isEmpty()) { utf8.fill(0); throw CipherException(MSG_NO_PASSPHRASE) }

        val plain = utf8.copyOf((utf8.size / PAD_BLOCK + 1) * PAD_BLOCK)
        utf8.fill(0)
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
            return toWords(header + nonce + sealed)
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
        val words = isWordCode(code)
        val bytes = if (words) fromWords(code) else fromLetters(code)
        val (headerLength, rounds) = readHeader(bytes, words)
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
