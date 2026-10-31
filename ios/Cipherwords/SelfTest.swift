import Foundation
import CryptoKit

/// Launch check used by the build pipeline: `xcrun simctl launch --console-pty <device> <bundle id> -selftest`.
/// Runs the engine on the simulator, prints PASS/FAIL lines and a code for recover.py to check, then exits.
enum SelfTest {
    static func runAndExit() -> Never {
        var failures = 0
        func check(_ name: String, _ ok: Bool) {
            print("\(ok ? "PASS" : "FAIL")  \(name)")
            if !ok { failures += 1 }
        }

        let pass1 = "correct horse battery", pass2 = "maple orbit tundra swivel"
        // Letter code (format v2) made by recover.py.
        let v2 = "ACAAA EKDQA DBGEF LEMLQ DKHGL GKKPB AMQKD EBAAC LAMBL DQBRP LQLPN GHRNL CJNPN CQNHE DFKJL " +
                 "GHNNK KHMMR CGMJL CMFNB KKBDH KEAQB JLBDE FEFPA DRPQP KMELF JEGCM KRJHR CNPNJ NJDDH PQHRK RNNEF RLJCD EM"
        // Word code made by recover.py (300,000 rounds).
        let words = """
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
"""
        let wordsText = "Meet at the caf\u{E9}, 7:30 pm.\nBring the 4111 key \u{1F511}"

        let joined = WordList.words.joined(separator: "\n") + "\n"
        let hash = SHA256.hash(data: Data(joined.utf8)).map { String(format: "%02x", $0) }.joined()
        check("word list is the official BIP39 list",
              WordList.words.count == 2048 && hash == "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda")
        check("decrypts letter code", (try? CipherEngine.decrypt(v2, passphrase: pass2)) == "4111 2222 3333 4444\n555-0199")
        check("decrypts recover.py word code", (try? CipherEngine.decrypt(words, passphrase: pass2)) == wordsText)

        let text = "iPhone \u{00FC}n\u{00EF}c\u{00F8}d\u{00E9} \u{1F389}\r\nline two"
        let code = (try? CipherEngine.encrypt(text, passphrase: pass1, rounds: 200_000)) ?? ""
        check("round trip", (try? CipherEngine.decrypt(code, passphrase: pass1)) == "iPhone \u{00FC}n\u{00EF}c\u{00F8}d\u{00E9} \u{1F389}\nline two")
        check("wrong passphrase rejected", {
            do { _ = try CipherEngine.decrypt(code, passphrase: "wrong"); return false }
            catch let e as CipherError { return e == .authenticationFailed } catch { return false }
        }())

        let start = Date()
        let rounds = CipherEngine.calibratedRounds
        print("INFO  calibrated \(rounds) rounds (\(String(format: "%.2f", Date().timeIntervalSince(start))) s to measure)")
        check("calibrated rounds within bounds", rounds >= CipherEngine.minRounds && rounds <= CipherEngine.maxRounds / 2)

        // A code for the pipeline to decrypt with recover.py.
        if let interop = try? CipherEngine.encrypt("iOS \u{2192} recover.py \u{00E9} 4111", passphrase: pass2, rounds: 300_000) {
            print("BEGIN CODE\n\(interop)\nEND CODE")
        }

        print(failures == 0 ? "SELFTEST PASS" : "SELFTEST FAIL (\(failures))")
        fflush(stdout)
        exit(failures == 0 ? 0 : 1)
    }
}
