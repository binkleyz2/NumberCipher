package io.github.binkleyz2.numbercipher

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.binkleyz2.numbercipher.crypto.ChunkCallback
import io.github.binkleyz2.numbercipher.crypto.CipherEngine
import io.github.binkleyz2.numbercipher.crypto.DeviceProfile
import io.github.binkleyz2.numbercipher.crypto.JvmPbkdf2
import io.github.binkleyz2.numbercipher.crypto.NativeKdf
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Runs on a real device or emulator: the native code must match the Java reference exactly. */
@RunWith(AndroidJUnit4::class)
class NativeKdfTest {
    private val go = object : ChunkCallback { override fun onChunk(done: Int) = ChunkCallback.CONTINUE }

    @Test fun nativeLibraryLoads() = assertTrue(NativeKdf.available)

    @Test fun nativeMatchesJava() {
        val salt = ByteArray(16) { it.toByte() }
        for (pw in listOf("a", "correct horse battery", "é-passé", "x".repeat(64), "y".repeat(65), "z".repeat(200))) {
            for (rounds in listOf(1, 2, 1000, 70_001)) {
                val a = ByteArray(32); val b = ByteArray(32)
                assertEquals(rounds, NativeKdf.derive(pw.toByteArray(), salt, rounds, 32_768, a, go))
                JvmPbkdf2.derive(pw.toByteArray(), salt, rounds, 32_768, b, go)
                assertArrayEquals("pw=$pw rounds=$rounds", b, a)
            }
        }
    }

    @Test fun nativeEngineDecryptsMacCode() =
        assertEquals("4111 2222 3333 4444\n555-0199", CipherEngine(NativeKdf).decrypt(CipherEngineTestCodes.V2, "maple orbit tundra swivel"))

    @Test fun deviceProfileMeasures() {
        val p = DeviceProfile.measure(InstrumentationRegistry.getInstrumentation().targetContext, NativeKdf)
        Log.i("NumberCipher", "Profile: $p")
        assertTrue(p.roundsPerSecond > 10_000)
    }
}

object CipherEngineTestCodes {
    const val V2 = "ACAAA EKDQA DBGEF LEMLQ DKHGL GKKPB AMQKD EBAAC LAMBL DQBRP LQLPN GHRNL CJNPN CQNHE DFKJL " +
        "GHNNK KHMMR CGMJL CMFNB KKBDH KEAQB JLBDE FEFPA DRPQP KMELF JEGCM KRJHR CNPNJ NJDDH PQHRK RNNEF RLJCD EM"
}
