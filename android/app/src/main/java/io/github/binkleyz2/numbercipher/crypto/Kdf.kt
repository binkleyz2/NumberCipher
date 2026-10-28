package io.github.binkleyz2.numbercipher.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Called after each chunk of PBKDF2 iterations with the total done so far. Return
 * [CONTINUE], [STOP] (keep the key for `done` iterations) or [CANCEL].
 *
 * The native code calls [onChunk] by name, so this interface and its implementations
 * are kept un-renamed by R8 (see proguard-rules.pro).
 */
interface ChunkCallback {
    fun onChunk(done: Int): Int

    companion object {
        const val CONTINUE = 1
        const val STOP = 0
        const val CANCEL = -1
    }
}

/** PBKDF2-HMAC-SHA256 with a 32-byte key, run in chunks with a progress/stop callback. */
interface Pbkdf2 {
    /** Human-readable implementation name, shown in the device speed panel. */
    val name: String

    /**
     * Runs up to [maxRounds] iterations. Returns the iteration count the key in [out]
     * corresponds to, or 0 if cancelled.
     */
    fun derive(password: ByteArray, salt: ByteArray, maxRounds: Int, chunk: Int, out: ByteArray, callback: ChunkCallback): Int

    companion object {
        /** The native implementation when the library loads (always, in the app), else the JVM one. */
        fun best(): Pbkdf2 = if (NativeKdf.available) NativeKdf else JvmPbkdf2
    }
}

/** C implementation using the CPU's SHA-256 instructions when present (see src/main/cpp). */
object NativeKdf : Pbkdf2 {
    val available: Boolean = try {
        System.loadLibrary("numbercipher")
        true
    } catch (_: Throwable) {
        false
    }

    override val name: String get() = if (available) nativeBackendName() else "unavailable"

    override fun derive(password: ByteArray, salt: ByteArray, maxRounds: Int, chunk: Int, out: ByteArray, callback: ChunkCallback): Int =
        nativeDerive(password, salt, maxRounds, chunk, out, callback)

    @JvmStatic private external fun nativeDerive(
        password: ByteArray, salt: ByteArray, maxRounds: Int, chunk: Int, out: ByteArray, callback: ChunkCallback,
    ): Int

    @JvmStatic private external fun nativeBackendName(): String
}

/** Pure JVM fallback (and the reference the unit tests run on a desktop JVM). */
object JvmPbkdf2 : Pbkdf2 {
    override val name = "Java (no native code)"

    override fun derive(password: ByteArray, salt: ByteArray, maxRounds: Int, chunk: Int, out: ByteArray, callback: ChunkCallback): Int {
        require(maxRounds >= 1)
        // javax.crypto rejects empty HMAC keys; an all-zero 64-byte key is the same HMAC key.
        val key = if (password.isEmpty()) ByteArray(64) else password
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }
        mac.update(salt)
        mac.update(byteArrayOf(0, 0, 0, 1))
        var u = mac.doFinal()
        val t = u.copyOf()
        var done = 1
        var status = ChunkCallback.CONTINUE
        while (done < maxRounds) {
            val n = minOf(chunk - done % chunk, maxRounds - done)
            repeat(n) {
                u = mac.doFinal(u)
                for (i in t.indices) t[i] = (t[i].toInt() xor u[i].toInt()).toByte()
            }
            done += n
            status = callback.onChunk(done)
            if (status <= ChunkCallback.STOP) break
        }
        u.fill(0)
        if (status == ChunkCallback.CANCEL) {
            out.fill(0)
            t.fill(0)
            return 0
        }
        t.copyInto(out)
        t.fill(0)
        return done
    }
}
