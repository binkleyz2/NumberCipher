import Foundation
import CryptoKit
import CommonCrypto
import Security

/// Number Cipher code format
///
/// Version 2 (written by this app):
///   bytes  = version(1)=2 | rounds(4, big-endian) | salt(16) | nonce(12) | ciphertext(n) | tag(16)
///   key    = PBKDF2-HMAC-SHA256(passphrase, salt, rounds) -> 32 bytes
///            rounds is calibrated so key derivation takes ~10 seconds on the encrypting Mac
///   cipher = AES-256-GCM, with version|rounds|salt as authenticated data
///
/// Version 1 (still decrypted): version(1)=1 | salt(16) | nonce | ct | tag, fixed 2,000,000 rounds.
///
/// Both: plaintext padded with 0x00 to a multiple of 16 bytes; each byte -> two letters
/// from "ABCDEFGHJKLMNPQR" (no I or O).
enum CipherError: LocalizedError {
    case invalidNumbers, noDigits, emptyPassphrase, malformedCode, unsupportedVersion, authenticationFailed, internalError

    var errorDescription: String? {
        switch self {
        case .invalidNumbers:       return "Only digits, spaces, commas, periods, dashes and line breaks are allowed."
        case .noDigits:             return "Enter at least one number."
        case .emptyPassphrase:      return "Enter a passphrase."
        case .malformedCode:        return "That doesn't look like a Number Cipher code (check for typos or missing letters)."
        case .unsupportedVersion:   return "This code was made by a newer version of Number Cipher."
        case .authenticationFailed: return "Wrong passphrase, or the code was altered."
        case .internalError:        return "Something went wrong inside the encryption engine."
        }
    }
}

enum CipherEngine {
    static let currentVersion: UInt8 = 2
    static let v1Rounds: UInt32 = 2_000_000
    static let targetSeconds: Double = 10
    static let minRounds: UInt32 = 2_000_000
    /// Upper bound accepted when decrypting, so a corrupted or hostile code can't hang the app for hours.
    static let maxRounds: UInt32 = 1_000_000_000
    static let saltLength = 16
    static let padBlock = 16
    static let alphabet: [Character] = Array("ABCDEFGHJKLMNPQR")
    private static let allowed = Set("0123456789 ,.-\n\t")

    /// Rounds that take ~10 s on this Mac. Measured once, on first use, then reused.
    static let calibratedRounds: UInt32 = calibrate()

    // MARK: Public API

    static func encrypt(_ numbers: String, passphrase: String) throws -> String {
        let cleaned = numbers.trimmingCharacters(in: .whitespacesAndNewlines)
        guard cleaned.allSatisfy({ allowed.contains($0) }) else { throw CipherError.invalidNumbers }
        guard cleaned.contains(where: \.isNumber) else { throw CipherError.noDigits }
        guard !passphrase.isEmpty else { throw CipherError.emptyPassphrase }

        var plain = Array(cleaned.utf8)
        let padded = ((plain.count / padBlock) + 1) * padBlock
        plain += [UInt8](repeating: 0, count: padded - plain.count)
        defer { wipe(&plain) }

        let rounds = calibratedRounds
        let salt = try randomBytes(saltLength)
        var header = Data([currentVersion])
        header.append(contentsOf: [UInt8(rounds >> 24), UInt8(rounds >> 16 & 0xFF), UInt8(rounds >> 8 & 0xFF), UInt8(rounds & 0xFF)])
        header.append(salt)

        let key = try deriveKey(passphrase: passphrase, salt: salt, rounds: rounds)
        let sealed = try AES.GCM.seal(Data(plain), using: key, nonce: AES.GCM.Nonce(), authenticating: header)
        guard let combined = sealed.combined else { throw CipherError.internalError }
        return group(toLetters(header + combined))
    }

    static func decrypt(_ code: String, passphrase: String) throws -> String {
        guard !passphrase.isEmpty else { throw CipherError.emptyPassphrase }
        let bytes = [UInt8](try fromLetters(code))
        guard let version = bytes.first else { throw CipherError.malformedCode }

        let headerLength: Int
        let rounds: UInt32
        switch version {
        case 1:
            headerLength = 1 + saltLength
            rounds = v1Rounds
        case 2:
            headerLength = 1 + 4 + saltLength
            guard bytes.count >= headerLength else { throw CipherError.malformedCode }
            rounds = bytes[1..<5].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
            guard rounds >= 100_000, rounds <= maxRounds else { throw CipherError.malformedCode }
        default:
            throw CipherError.unsupportedVersion
        }
        guard bytes.count >= headerLength + 12 + 16 else { throw CipherError.malformedCode }

        let header = Data(bytes[0..<headerLength])
        let salt = Data(bytes[(headerLength - saltLength)..<headerLength])
        let key = try deriveKey(passphrase: passphrase, salt: salt, rounds: rounds)

        do {
            let box = try AES.GCM.SealedBox(combined: Data(bytes[headerLength...]))
            var plain = Array(try AES.GCM.open(box, using: key, authenticating: header))
            defer { wipe(&plain) }
            while plain.last == 0 { plain.removeLast() }
            guard let text = String(bytes: plain, encoding: .utf8) else { throw CipherError.authenticationFailed }
            return text
        } catch {
            throw CipherError.authenticationFailed
        }
    }

    /// Rough time a decrypt of `code` will take on this Mac, for the UI. Nil if unreadable.
    static func estimatedSeconds(forCode code: String) -> Double? {
        guard let bytes = try? [UInt8](fromLetters(code)), let v = bytes.first else { return nil }
        let rounds: UInt32
        if v == 1 { rounds = v1Rounds }
        else if v == 2, bytes.count >= 5 { rounds = bytes[1..<5].reduce(UInt32(0)) { $0 << 8 | UInt32($1) } }
        else { return nil }
        return Double(rounds) / Double(calibratedRounds) * targetSeconds
    }

    // MARK: Key derivation

    private static func deriveKey(passphrase: String, salt: Data, rounds: UInt32) throws -> SymmetricKey {
        var pw = Array(passphrase.precomposedStringWithCanonicalMapping.utf8)
        var out = [UInt8](repeating: 0, count: 32)
        defer { wipe(&pw); wipe(&out) }
        guard pbkdf2(&pw, salt: [UInt8](salt), rounds: rounds, into: &out) else { throw CipherError.internalError }
        return SymmetricKey(data: out)
    }

    private static func pbkdf2(_ pw: inout [UInt8], salt: [UInt8], rounds: UInt32, into out: inout [UInt8]) -> Bool {
        let outCount = out.count
        let status: Int32 = pw.withUnsafeBufferPointer { pwBuf in
            pwBuf.withMemoryRebound(to: CChar.self) { pwChars in
                salt.withUnsafeBufferPointer { saltBuf in
                    out.withUnsafeMutableBufferPointer { outBuf in
                        CCKeyDerivationPBKDF(
                            CCPBKDFAlgorithm(kCCPBKDF2),
                            pwChars.baseAddress, pwChars.count,
                            saltBuf.baseAddress, saltBuf.count,
                            CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                            rounds,
                            outBuf.baseAddress, outCount)
                    }
                }
            }
        }
        return status == kCCSuccess
    }

    /// Times a short PBKDF2 run and scales it to `targetSeconds`.
    private static func calibrate() -> UInt32 {
        var pw = Array("calibration-passphrase".utf8)
        let salt = [UInt8](repeating: 7, count: saltLength)
        var out = [UInt8](repeating: 0, count: 32)
        let probe: UInt32 = 1_000_000
        _ = pbkdf2(&pw, salt: salt, rounds: 50_000, into: &out)   // warm up
        let start = DispatchTime.now().uptimeNanoseconds
        guard pbkdf2(&pw, salt: salt, rounds: probe, into: &out) else { return minRounds }
        let elapsed = Double(DispatchTime.now().uptimeNanoseconds - start) / 1e9
        guard elapsed > 0 else { return minRounds }
        let estimate = Double(probe) / elapsed * targetSeconds
        let rounded = (estimate / 100_000).rounded() * 100_000
        return UInt32(min(max(rounded, Double(minRounds)), Double(maxRounds) / 2))
    }

    // MARK: Letter encoding

    static func toLetters(_ data: Data) -> String {
        var s = String()
        s.reserveCapacity(data.count * 2)
        for b in data {
            s.append(alphabet[Int(b >> 4)])
            s.append(alphabet[Int(b & 0x0F)])
        }
        return s
    }

    static func fromLetters(_ code: String) throws -> Data {
        var lookup = [Character: UInt8]()
        for (i, c) in alphabet.enumerated() { lookup[c] = UInt8(i) }
        let letters = code.uppercased().filter { !$0.isWhitespace && $0 != "-" }
        guard !letters.isEmpty, letters.count % 2 == 0 else { throw CipherError.malformedCode }

        var out = Data(capacity: letters.count / 2)
        var hi: UInt8? = nil
        for c in letters {
            guard let v = lookup[c] else { throw CipherError.malformedCode }
            if let h = hi { out.append(h << 4 | v); hi = nil } else { hi = v }
        }
        return out
    }

    static func group(_ s: String, size: Int = 5) -> String {
        var result = String()
        for (i, c) in s.enumerated() {
            if i > 0 && i % size == 0 { result.append(" ") }
            result.append(c)
        }
        return result
    }

    // MARK: Helpers

    private static func randomBytes(_ n: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: n)
        guard SecRandomCopyBytes(kSecRandomDefault, n, &bytes) == errSecSuccess else { throw CipherError.internalError }
        return Data(bytes)
    }

    private static func wipe(_ buf: inout [UInt8]) {
        buf.withUnsafeMutableBytes { p in
            if let base = p.baseAddress { memset_s(base, p.count, 0, p.count) }
        }
    }
}
