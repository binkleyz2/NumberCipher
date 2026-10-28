import Foundation
import CryptoKit
import CommonCrypto
import Security

/// Number Cipher format, version 1
///
///   bytes  = version(1) | salt(16) | nonce(12) | ciphertext(n) | tag(16)
///   key    = PBKDF2-HMAC-SHA256(passphrase, salt, 2,000,000 rounds) -> 32 bytes
///   cipher = AES-256-GCM, with version|salt as authenticated data
///   text   = plaintext padded with 0x00 to a multiple of 16 bytes (hides exact length)
///   letters= each byte -> two letters from "ABCDEFGHJKLMNPQR" (no I or O)
///
/// AES-GCM runs on the Apple Silicon AES hardware via CryptoKit. The 2M-round KDF
/// takes well under a second on an M4 but makes every password guess expensive.
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
    static let version: UInt8 = 1
    static let rounds: UInt32 = 2_000_000
    static let saltLength = 16
    static let padBlock = 16
    static let alphabet: [Character] = Array("ABCDEFGHJKLMNPQR")
    private static let allowed = Set("0123456789 ,.-\n\t")

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

        let salt = try randomBytes(saltLength)
        let header = Data([version]) + salt
        let key = try deriveKey(passphrase: passphrase, salt: salt)

        let sealed = try AES.GCM.seal(Data(plain), using: key, nonce: AES.GCM.Nonce(), authenticating: header)
        guard let combined = sealed.combined else { throw CipherError.internalError }
        return group(toLetters(header + combined))
    }

    static func decrypt(_ code: String, passphrase: String) throws -> String {
        guard !passphrase.isEmpty else { throw CipherError.emptyPassphrase }
        let bytes = try fromLetters(code)
        guard bytes.count >= 1 + saltLength + 12 + 16 else { throw CipherError.malformedCode }
        guard bytes[bytes.startIndex] == version else { throw CipherError.unsupportedVersion }

        let header = bytes.prefix(1 + saltLength)
        let salt = header.dropFirst()
        let key = try deriveKey(passphrase: passphrase, salt: Data(salt))

        do {
            let box = try AES.GCM.SealedBox(combined: bytes.dropFirst(1 + saltLength))
            var plain = Array(try AES.GCM.open(box, using: key, authenticating: header))
            defer { wipe(&plain) }
            while plain.last == 0 { plain.removeLast() }
            guard let text = String(bytes: plain, encoding: .utf8) else { throw CipherError.authenticationFailed }
            return text
        } catch is CipherError {
            throw CipherError.authenticationFailed
        } catch {
            throw CipherError.authenticationFailed
        }
    }

    // MARK: Key derivation

    private static func deriveKey(passphrase: String, salt: Data) throws -> SymmetricKey {
        var pw = Array(passphrase.precomposedStringWithCanonicalMapping.utf8)
        var out = [UInt8](repeating: 0, count: 32)
        defer { wipe(&pw); wipe(&out) }

        let status: Int32 = pw.withUnsafeBufferPointer { pwBuf in
            salt.withUnsafeBytes { saltBuf in
                pwBuf.withMemoryRebound(to: CChar.self) { pwChars in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        pwChars.baseAddress, pwChars.count,
                        saltBuf.bindMemory(to: UInt8.self).baseAddress, saltBuf.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        rounds,
                        &out, out.count)
                }
            }
        }
        guard status == kCCSuccess else { throw CipherError.internalError }
        return SymmetricKey(data: out)
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
