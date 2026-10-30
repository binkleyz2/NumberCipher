package io.github.binkleyz2.numbercipher

import io.github.binkleyz2.numbercipher.crypto.ChunkCallback
import io.github.binkleyz2.numbercipher.crypto.CipherEngine
import io.github.binkleyz2.numbercipher.crypto.CipherException
import io.github.binkleyz2.numbercipher.crypto.CancelledException
import io.github.binkleyz2.numbercipher.crypto.JvmPbkdf2
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.security.MessageDigest
import io.github.binkleyz2.numbercipher.crypto.WordList
import java.util.concurrent.atomic.AtomicLong

/** Format and compatibility tests, run on a desktop JVM with the pure-Java PBKDF2. */
class CipherEngineTest {
    private val engine = CipherEngine(JvmPbkdf2)

    companion object {
        const val PASS1 = "correct horse battery"
        // Version 1 code made by the original Mac-format implementation.
        const val V1 = "ABPJB MHPDB GPLNN GFDDR QMLMQ PFBGK LRFRK PAAQK BHCMH BQJCE AFAPG MJNQJ QRLAM AHJRJ " +
            "CMMLG BFDKK GDEAM NJABM CDPKQ NCMEA PPBAG BABFR CQEQL KERHD RAQNE RMQDN JEPDE HCELC FDRRH LELPP KLBC"
        const val PASS2 = "maple orbit tundra swivel"
        // Version 2 code (300,000 rounds) made by recover.py, the Mac app's format.
        const val V2 = "ACAAA EKDQA DBGEF LEMLQ DKHGL GKKPB AMQKD EBAAC LAMBL DQBRP LQLPN GHRNL CJNPN CQNHE DFKJL " +
            "GHNNK KHMMR CGMJL CMFNB KKBDH KEAQB JLBDE FEFPA DRPQP KMELF JEGCM KRJHR CNPNJ NJDDH PQHRK RNNEF RLJCD EM"
        // Word code (300,000 rounds) made by recover.py, passphrase PASS2.
        val WORDS = """
            ACOUSTIC ABILITY CEILING SCATTER SUBJECT PITCH
            ELEMENT LIVE DAY VIEW BONE POPULAR
            MENTION GALAXY SIX PHYSICAL GHOST GLUE
            ENGAGE SOLID VALID BULLET TIP ASTHMA
            CAPITAL MORNING FEVER IRON BASIC TRACK
            FANCY CREEK BALL AWAY ABANDON CRACK
            NEWS HELMET CLIFF CAGE DEPOSIT COLLECT
            QUESTION FLAG REFORM POST USED SIBLING
            PRIVATE DRIP MATH ORANGE CART ENTRY
            DANCE DIET MARKET SHOCK BONE POLAR
            RESULT BORDER REFLECT JAR SPORT TILT
            COURSE EVOLVE COOK KID DRIFT YOUNG
            OUTSIDE FATAL SING IMPULSE GLIMPSE RIDE
            AWAKE FEATURE UNLOCK RESEMBLE SCALE
        """.trimIndent()
        const val WORDS_TEXT = "Meet at the caf\u00E9, 7:30 pm.\nBring the 4111 key \uD83D\uDD11"
        const val TEXT = "Any text: \u00FCn\u00EFc\u00F8d\u00E9 \uD83C\uDF89"
    }

    private fun assertError(contains: String, block: () -> Unit) {
        try {
            block(); fail("expected error containing '$contains'")
        } catch (e: CipherException) {
            assertTrue("'${e.message}' should contain '$contains'", e.message!!.contains(contains))
        }
    }

    @Test fun wordListIsOfficialBip39() {
        val hash = MessageDigest.getInstance("SHA-256").digest((WordList.words.joinToString("\n") + "\n").toByteArray())
            .joinToString("") { "%02x".format(it) }
        assertEquals(2048, WordList.words.size)
        assertEquals("2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda", hash)
    }

    @Test fun decryptsRecoverPyWordCode() = assertEquals(WORDS_TEXT, engine.decrypt(WORDS, PASS2))

    @Test fun decryptsMacVersion1Code() = assertEquals("4111 2222 3333 4444", engine.decrypt(V1, PASS1))

    @Test fun decryptsMacVersion2Code() = assertEquals("4111 2222 3333 4444\n555-0199", engine.decrypt(V2, PASS2))

    @Test fun roundTripNormalizesLineBreaks() {
        val c = engine.encrypt("$TEXT\r\nline two", PASS1, fixedRounds = 200_000)
        assertEquals("$TEXT\nline two", engine.decrypt(c, PASS1))
        assertTrue(c.split(Regex("\\s+")).all { it == it.uppercase() && it.lowercase() in WordList.words })
        assertEquals(200_000, CipherEngine.roundsIn(c))
    }

    private fun words(c: String) = c.split(Regex("\\s+")).toMutableList()

    @Test fun correctsMisspellingAfterFourthLetter() {
        val w = words(engine.encrypt(TEXT, PASS1, fixedRounds = 200_000))
        w[3] = w[3].take(4) + "QX"
        assertEquals(TEXT, engine.decrypt(w.joinToString(" "), PASS1))
    }

    @Test fun acceptsNumberingAndCommas() {
        val w = words(engine.encrypt(TEXT, PASS1, fixedRounds = 200_000))
        assertEquals(TEXT, engine.decrypt(w.mapIndexed { i, x -> "${i + 1}. ${x.lowercase()}" }.joinToString(", "), PASS1))
    }

    @Test fun missingWord() {
        val w = words(engine.encrypt(TEXT, PASS1, fixedRounds = 200_000)); w.removeAt(10)
        assertError("missing or extra") { engine.decrypt(w.joinToString(" "), PASS1) }
    }

    @Test fun unknownWord() {
        val w = words(engine.encrypt(TEXT, PASS1, fixedRounds = 200_000)); w[6] = "ZZZZQ"
        assertError("\u201CZZZZQ\u201D (word 7)") { engine.decrypt(w.joinToString(" "), PASS1) }
    }

    @Test fun alteredWord() {
        val w = words(WORDS); w[20] = if (w[20] == "APPLE") "ZOO" else "APPLE"
        assertError("Wrong passphrase") { engine.decrypt(w.joinToString(" "), PASS2) }
    }

    @Test fun firstWordTypo() = assertError("first word") { engine.decrypt("ZOO " + words(WORDS).drop(1).joinToString(" "), PASS2) }
    @Test fun futureVersionWords() = assertError("newer version") { engine.decrypt("ADAPT " + words(WORDS).drop(1).joinToString(" "), PASS2) }
    @Test fun roundsInWordCode() = assertEquals(300_000, CipherEngine.roundsIn(WORDS))

    @Test fun everyEncryptionIsUnique() =
        assertNotEquals(engine.encrypt("123", PASS1, fixedRounds = 200_000), engine.encrypt("123", PASS1, fixedRounds = 200_000))

    @Test fun acceptsLowercaseAndDashes() {
        assertEquals("4111 2222 3333 4444\n555-0199", engine.decrypt(V2.lowercase().replace(' ', '-'), PASS2))
        val c = engine.encrypt("42", PASS1, fixedRounds = 200_000)
        assertEquals("42", engine.decrypt(c.lowercase().replace(' ', '-').replace('\n', '-'), PASS1))
    }

    @Test fun unicodePassphraseIsNormalized() {
        // "é" typed as one character (NFC) or as e + accent (NFD) must give the same key.
        val c = engine.encrypt("1", "café", fixedRounds = 200_000)
        assertEquals("1", engine.decrypt(c, "café"))
    }

    @Test fun rejectsWrongPassphrase() = assertError("Wrong passphrase") { engine.decrypt(V2, "wrong") }

    @Test fun rejectsAlteredLetter() {
        val t = V2.toCharArray(); t[60] = if (t[60] == 'A') 'B' else 'A'
        assertError("Wrong passphrase") { engine.decrypt(String(t), PASS2) }
    }

    @Test fun firstLetterTypo() = assertError("always A") { engine.decrypt("B" + V2.substring(1), PASS2) }
    @Test fun futureVersion() = assertError("newer version") { engine.decrypt("AD" + V2.substring(2), PASS2) }
    @Test fun shortLetterCode() = assertError("doesn't look like") { engine.decrypt("ABCDE", PASS2) }
    @Test fun noText() = assertError("Enter some text") { engine.encrypt(" \r\n ", PASS1) }
    @Test fun tooMuchText() = assertError("too much text") { engine.encrypt("x".repeat(20_001), PASS1) }

    @Test fun cancelStopsWork() {
        try {
            engine.encrypt("1", PASS1, fixedRounds = 5_000_000, isCancelled = { true }); fail()
        } catch (_: CancelledException) { }
    }

    /** Time-targeted encryption: stops once the (fake) clock passes 10 s and the minimum is met. */
    @Test fun stopsAtTenSecondsOfWork() {
        val fakeNs = AtomicLong(0)
        val fastKdf = object : io.github.binkleyz2.numbercipher.crypto.Pbkdf2 {
            override val name = "test"
            override fun derive(password: ByteArray, salt: ByteArray, maxRounds: Int, chunk: Int, out: ByteArray, callback: ChunkCallback): Int {
                // Pretend each chunk takes 10 ms, so 10 s = 1,000 chunks.
                var done = 0
                while (done < maxRounds) {
                    done += chunk
                    fakeNs.addAndGet(10_000_000)
                    if (callback.onChunk(done) <= ChunkCallback.STOP) break
                }
                out.fill(1)
                return done
            }
        }
        val e = CipherEngine(fastKdf) { fakeNs.get() }
        val code = e.encrypt("5", PASS1)
        assertEquals(1_000 * 32_768, CipherEngine.roundsIn(code))
    }

    /** Writes a code for the CI step that checks recover.py (the Mac format) can decrypt it. */
    @Test fun writesInteropCode() {
        val dir = File("build/interop").apply { mkdirs() }
        File(dir, "android_code.txt").writeText(engine.encrypt("Android \u2192 recover.py \u00E9 6011", PASS2, fixedRounds = 300_000))
    }
}
