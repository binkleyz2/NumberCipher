// Compatibility self-test for the Mac engine. CI compiles it together with the engine:
//   swiftc -O Sources/NumberCipher/CipherEngine.swift Sources/NumberCipher/WordList.swift Tests/MacSelfTest/main.swift -o selftest
//   ./selftest                  run the tests (exit 1 on failure)
//   ./selftest encrypt <text>   (passphrase from NC_PASS, 300,000 rounds) -> prints a word code
import Foundation
import CryptoKit

let args = CommandLine.arguments
if args.count == 3 && args[1] == "encrypt" {
    print(try CipherEngine.encrypt(args[2], passphrase: ProcessInfo.processInfo.environment["NC_PASS"] ?? "", rounds: 300_000))
    exit(0)
}

var failures = 0
func check(_ name: String, _ ok: Bool) { print("\(ok ? "PASS" : "FAIL")  \(name)"); if !ok { failures += 1 } }
func throwsError(_ expected: CipherError, _ f: () throws -> Any) -> Bool {
    do { _ = try f(); return false } catch let e as CipherError { return e == expected } catch { return false }
}

let pass1 = "correct horse battery", pass2 = "maple orbit tundra swivel"
let v1 = "ABPJB MHPDB GPLNN GFDDR QMLMQ PFBGK LRFRK PAAQK BHCMH BQJCE AFAPG MJNQJ QRLAM AHJRJ " +
         "CMMLG BFDKK GDEAM NJABM CDPKQ NCMEA PPBAG BABFR CQEQL KERHD RAQNE RMQDN JEPDE HCELC FDRRH LELPP KLBC"
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
check("word list is the official BIP39 list", WordList.words.count == 2048 && hash == "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda")

check("decrypts v1 letter code", (try? CipherEngine.decrypt(v1, passphrase: pass1)) == "4111 2222 3333 4444")
check("decrypts v2 letter code", (try? CipherEngine.decrypt(v2, passphrase: pass2)) == "4111 2222 3333 4444\n555-0199")
check("decrypts recover.py word code", (try? CipherEngine.decrypt(words, passphrase: pass2)) == wordsText)

let text = "Any text: \u{00FC}n\u{00EF}c\u{00F8}d\u{00E9} \u{1F389}\r\nline two"
let c = try CipherEngine.encrypt(text, passphrase: pass1, rounds: 200_000)
check("word round trip (line breaks normalized)", (try? CipherEngine.decrypt(c, passphrase: pass1)) == "Any text: \u{00FC}n\u{00EF}c\u{00F8}d\u{00E9} \u{1F389}\nline two")
let w = c.split(whereSeparator: \.isWhitespace).map(String.init)
check("output is upper-case list words", w.allSatisfy { WordList.words.contains($0.lowercased()) })
check("lowercase, commas and numbering accepted",
      (try? CipherEngine.decrypt(w.enumerated().map { "\($0 + 1). \($1.lowercased())" }.joined(separator: ", "), passphrase: pass1)) != nil)
var typo = w; typo[3] = String(typo[3].prefix(4)) + "QX"
check("misspelling after the 4th letter is corrected", (try? CipherEngine.decrypt(typo.joined(separator: " "), passphrase: pass1)) != nil)
check("same input gives a different code each time",
      (try CipherEngine.encrypt("123", passphrase: pass1, rounds: 200_000)) != (try CipherEngine.encrypt("123", passphrase: pass1, rounds: 200_000)))
check("wrong passphrase rejected", throwsError(.authenticationFailed) { try CipherEngine.decrypt(c, passphrase: "wrong") })
var missing = w; missing.remove(at: 10)
check("missing word reported", throwsError(.wordCount) { try CipherEngine.decrypt(missing.joined(separator: " "), passphrase: pass1) })
var unknown = w; unknown[6] = "ZZZZQ"
check("unknown word reported", throwsError(.unknownWord("ZZZZQ", 7)) { try CipherEngine.decrypt(unknown.joined(separator: " "), passphrase: pass1) })
var swapped = w; swapped[20] = swapped[20] == "APPLE" ? "ZOO" : "APPLE"
check("altered word rejected", throwsError(.authenticationFailed) { try CipherEngine.decrypt(swapped.joined(separator: " "), passphrase: pass1) })
check("bad first word reported", throwsError(.badFirstWord) { try CipherEngine.decrypt((["ZOO"] + w.dropFirst()).joined(separator: " "), passphrase: pass1) })
check("future version reported", throwsError(.unsupportedVersion) { try CipherEngine.decrypt((["ADAPT"] + w.dropFirst()).joined(separator: " "), passphrase: pass1) })
check("first letter typo (letter code)", throwsError(.badFirstLetter) { try CipherEngine.decrypt("B" + v2.dropFirst(), passphrase: pass2) })
check("empty text rejected", throwsError(.emptyText) { try CipherEngine.encrypt(" \n ", passphrase: pass1) })
check("estimate reads word codes", CipherEngine.estimatedSeconds(forCode: words) != nil)

print(failures == 0 ? "ALL PASSED" : "\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
