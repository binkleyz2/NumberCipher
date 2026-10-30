using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace NumberCipher.Core;

/// <summary>A user-facing error; Message is safe to show in the UI.</summary>
public sealed class CipherException(string message) : Exception(message);

/// <summary>
/// Cipherwords code format — identical to the Mac app, so codes move freely between them.
///
/// Version 2 (written here):
///   bytes  = version(1)=2 | rounds(4, big-endian) | salt(16) | nonce(12) | ciphertext(n) | tag(16)
///   key    = PBKDF2-HMAC-SHA256(NFC(passphrase) as UTF-8, salt, rounds) -> 32 bytes
///            rounds is calibrated so key derivation takes ~10 seconds on the encrypting computer
///   cipher = AES-256-GCM, with version|rounds|salt as authenticated data
///
/// Version 1 (still decrypted): version(1)=1 | salt(16) | nonce | ct | tag, fixed 2,000,000 rounds.
///
/// Both: plaintext is UTF-8 text padded with 0x00 to the next multiple of 16 bytes.
///
/// Written as words (1.5+): the bytes are read as a bit string, most significant bit first, split
/// into 11-bit numbers (the last padded with 0 bits), each picking a word from the BIP39 English list
/// (WordList.cs). Every v2 code is 49 + 16k bytes, so the byte count is the largest
/// n &lt;= 11*words/8 with n % 16 == 1, and ceil(8n/11) must equal the word count.
/// Written as letters (1.0–1.4, still read): each byte -> two letters from "ABCDEFGHJKLMNPQR".
/// A code containing any letter outside that set is read as words.
///
/// PBKDF2 and AES-GCM run through Windows CNG, which uses the CPU's AES and SHA instructions.
/// </summary>
public static class CipherEngine
{
    public const byte CurrentVersion = 2;
    public const int V1Rounds = 2_000_000;
    public const double TargetSeconds = 10;
    public const int MinRounds = 2_000_000;
    /// <summary>Upper bound accepted when decrypting, so a corrupted or hostile code can't hang the app for hours.</summary>
    public const int MaxRounds = 1_000_000_000;
    public const int SaltLength = 16;
    public const int NonceLength = 12;
    public const int TagLength = 16;
    public const int PadBlock = 16;
    public const string Alphabet = "ABCDEFGHJKLMNPQR";
    public const int MaxTextBytes = 20_000;
    public const int WordsPerLine = 6;

    private static readonly Dictionary<string, int> wordIndex =
        WordList.Words.Select((w, i) => (w, i)).ToDictionary(p => p.w, p => p.i);
    private static readonly Dictionary<string, int> prefixIndex =
        WordList.Words.Select((w, i) => (w, i)).ToDictionary(p => p.w[..Math.Min(4, p.w.Length)], p => p.i);

    private static readonly Lazy<int> calibrated = new(Calibrate, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>Rounds that take ~10 s on this computer. Measured once, on first use, then reused.</summary>
    public static int CalibratedRounds => calibrated.Value;

    // ---- Public API -------------------------------------------------------------------------

    /// <param name="rounds">Override the calibrated round count (used by tests).</param>
    public static string Encrypt(string text, string passphrase, int? rounds = null)
    {
        string cleaned = text.Replace("\r\n", "\n").Replace('\r', '\n').Trim();
        if (cleaned.Length == 0)
            throw new CipherException("Enter some text to encrypt.");
        if (cleaned.Contains('\0'))
            throw new CipherException("The text contains a null character, which can't be encrypted.");
        if (Encoding.UTF8.GetByteCount(cleaned) > MaxTextBytes)
            throw new CipherException("That's too much text (the limit is 20,000 bytes, about 20,000 English characters).");
        if (passphrase.Length == 0)
            throw new CipherException("Enter a passphrase.");

        int r = rounds ?? CalibratedRounds;
        byte[] utf8 = new UTF8Encoding(false, throwOnInvalidBytes: true).GetBytes(cleaned);
        byte[] plain = new byte[(utf8.Length / PadBlock + 1) * PadBlock];
        utf8.CopyTo(plain, 0);
        CryptographicOperations.ZeroMemory(utf8);

        byte[] salt = RandomNumberGenerator.GetBytes(SaltLength);
        byte[] header = new byte[1 + 4 + SaltLength];
        header[0] = CurrentVersion;
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(1, 4), (uint)r);
        salt.CopyTo(header, 5);

        byte[] key = DeriveKey(passphrase, salt, r);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceLength);
        byte[] output = new byte[header.Length + NonceLength + plain.Length + TagLength];
        try
        {
            using var aes = new AesGcm(key, TagLength);
            aes.Encrypt(nonce, plain,
                output.AsSpan(header.Length + NonceLength, plain.Length),
                output.AsSpan(output.Length - TagLength, TagLength),
                header);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plain);
        }
        header.CopyTo(output, 0);
        nonce.CopyTo(output, header.Length);
        return ToWords(output);
    }

    public static string Decrypt(string code, string passphrase)
    {
        if (passphrase.Length == 0)
            throw new CipherException("Enter a passphrase.");
        bool words = IsWordCode(code);
        byte[] bytes = words ? FromWords(code) : FromLetters(code);
        (int headerLength, int rounds) = ReadHeader(bytes, words);
        if (bytes.Length < headerLength + NonceLength + TagLength) throw Malformed();

        ReadOnlySpan<byte> all = bytes;
        ReadOnlySpan<byte> header = all[..headerLength];
        byte[] salt = all[(headerLength - SaltLength)..headerLength].ToArray();
        ReadOnlySpan<byte> nonce = all.Slice(headerLength, NonceLength);
        ReadOnlySpan<byte> tag = all[^TagLength..];
        ReadOnlySpan<byte> cipher = all[(headerLength + NonceLength)..^TagLength];

        byte[] key = DeriveKey(passphrase, salt, rounds);
        byte[] plain = new byte[cipher.Length];
        try
        {
            using var aes = new AesGcm(key, TagLength);
            aes.Decrypt(nonce, cipher, tag, plain, header);
            int end = plain.Length;
            while (end > 0 && plain[end - 1] == 0) end--;
            return new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(plain, 0, end);
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException)
        {
            throw new CipherException("Wrong passphrase, or the code was altered.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    /// <summary>Rough time a decrypt of <paramref name="code"/> will take here, for the UI. Null if unreadable.</summary>
    public static double? EstimatedSeconds(string code)
    {
        try
        {
            bool words = IsWordCode(code);
            (_, int rounds) = ReadHeader(words ? FromWords(code) : FromLetters(code), words);
            return (double)rounds / CalibratedRounds * TargetSeconds;
        }
        catch (CipherException) { return null; }
    }

    /// <summary>Rough passphrase strength in bits, matching the Mac app's meter.</summary>
    public static double StrengthBits(string passphrase)
    {
        if (passphrase.Length == 0) return 0;
        int pool = 0;
        if (passphrase.Any(char.IsLower)) pool += 26;
        if (passphrase.Any(char.IsUpper)) pool += 26;
        if (passphrase.Any(char.IsDigit)) pool += 10;
        if (passphrase.Any(c => !char.IsLetterOrDigit(c))) pool += 33;
        return passphrase.Length * Math.Log2(Math.Max(pool, 2));
    }

    // ---- Format helpers ---------------------------------------------------------------------

    private static (int headerLength, int rounds) ReadHeader(byte[] bytes, bool words)
    {
        if (bytes.Length == 0) throw Malformed();
        switch (bytes[0])
        {
            case 1:
                return (1 + SaltLength, V1Rounds);
            case 2:
                if (bytes.Length < 5 + SaltLength) throw Malformed();
                uint r = BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(1, 4));
                if (r < 100_000 || r > MaxRounds) throw Malformed();
                return (5 + SaltLength, (int)r);
            case 0:
                throw Malformed();
            case < 16:
                // Future format versions all start with "A" (byte < 16).
                throw new CipherException("This code was made by a newer version of Cipherwords. Update this app to decrypt it.");
            default:
                // A first letter other than "A" (or a first word outside ACOUSTIC..ADDRESS) can't be any version: it's a typo.
                throw new CipherException(words
                    ? "The first word of the code looks wrong. Check it for a typo."
                    : "The first letter of a code is always A. Check the start of the code for a typo.");
        }
    }

    private static CipherException Malformed() =>
        new("That doesn't look like a Cipherwords code (check for typos or missing letters).");

    private static byte[] DeriveKey(string passphrase, byte[] salt, int rounds)
    {
        byte[] pw = Encoding.UTF8.GetBytes(passphrase.Normalize(NormalizationForm.FormC));
        try
        {
            return Rfc2898DeriveBytes.Pbkdf2(pw, salt, rounds, HashAlgorithmName.SHA256, 32);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pw);
        }
    }

    /// <summary>Times a short PBKDF2 run and scales it to <see cref="TargetSeconds"/>.</summary>
    private static int Calibrate()
    {
        byte[] pw = Encoding.UTF8.GetBytes("calibration-passphrase");
        byte[] salt = new byte[SaltLength];
        Array.Fill(salt, (byte)7);
        const int probe = 1_000_000;
        Rfc2898DeriveBytes.Pbkdf2(pw, salt, 50_000, HashAlgorithmName.SHA256, 32); // warm up
        var sw = Stopwatch.StartNew();
        Rfc2898DeriveBytes.Pbkdf2(pw, salt, probe, HashAlgorithmName.SHA256, 32);
        double elapsed = sw.Elapsed.TotalSeconds;
        if (elapsed <= 0) return MinRounds;
        double estimate = probe / elapsed * TargetSeconds;
        double rounded = Math.Round(estimate / 100_000) * 100_000;
        return (int)Math.Clamp(rounded, MinRounds, MaxRounds / 2);
    }

    // ---- Words ------------------------------------------------------------------------------

    /// <summary>True if <paramref name="code"/> has any letter outside the old letter-code alphabet, so it must be words.</summary>
    public static bool IsWordCode(string code) =>
        code.Any(c => char.IsAsciiLetter(c) && !Alphabet.Contains(char.ToUpperInvariant(c)));

    public static string ToWords(ReadOnlySpan<byte> data)
    {
        var words = new List<string>((data.Length * 8 + 10) / 11);
        uint acc = 0; int bits = 0;
        foreach (byte b in data)
        {
            acc = acc << 8 | b; bits += 8;
            if (bits >= 11) { bits -= 11; words.Add(WordList.Words[(int)(acc >> bits & 0x7FF)]); }
            acc &= (1u << bits) - 1;
        }
        if (bits > 0) words.Add(WordList.Words[(int)(acc << (11 - bits) & 0x7FF)]);
        return string.Join("\n", words.Chunk(WordsPerLine).Select(line => string.Join(' ', line).ToUpperInvariant()));
    }

    public static byte[] FromWords(string code)
    {
        // Words are runs of ASCII letters; anything else (spaces, line breaks, numbering, punctuation) separates them.
        var indices = new List<int>();
        var sb = new StringBuilder();
        void Flush()
        {
            if (sb.Length == 0) return;
            string w = sb.ToString().ToLowerInvariant();
            sb.Clear();
            if (wordIndex.TryGetValue(w, out int v) || (w.Length >= 4 && prefixIndex.TryGetValue(w[..4], out v)))
                indices.Add(v);
            else
                throw new CipherException($"\u201C{w.ToUpperInvariant()}\u201D (word {indices.Count + 1}) isn't one of the code words. Check its spelling.");
        }
        foreach (char c in code)
        {
            if (char.IsAsciiLetter(c)) sb.Append(c); else Flush();
        }
        Flush();

        int count = indices.Count;
        int n = count * 11 / 8;
        n -= (n - 1) % 16;
        if (n < 49 + PadBlock || (n * 8 + 10) / 11 != count)
            throw new CipherException("A word seems to be missing or extra. Check the code against the original.");

        byte[] output = new byte[n];
        int o = 0;
        uint acc = 0; int bits = 0;
        foreach (int v in indices)
        {
            acc = acc << 11 | (uint)v; bits += 11;
            while (bits >= 8 && o < n) { bits -= 8; output[o++] = (byte)(acc >> bits); }
            acc &= (1u << bits) - 1;
        }
        if (acc != 0) throw new CipherException("The last word of the code looks wrong. Check it for a typo.");
        return output;
    }

    // ---- Letters (codes made by versions 1.0–1.4) ---------------------------------------------

    public static string ToLetters(ReadOnlySpan<byte> data)
    {
        var sb = new StringBuilder(data.Length * 2);
        foreach (byte b in data)
        {
            sb.Append(Alphabet[b >> 4]);
            sb.Append(Alphabet[b & 0x0F]);
        }
        return sb.ToString();
    }

    public static byte[] FromLetters(string code)
    {
        var letters = code.ToUpperInvariant().Where(c => !char.IsWhiteSpace(c) && c != '-').ToArray();
        if (letters.Length == 0 || letters.Length % 2 != 0) throw Malformed();
        byte[] output = new byte[letters.Length / 2];
        for (int i = 0; i < letters.Length; i += 2)
        {
            int hi = Alphabet.IndexOf(letters[i]);
            int lo = Alphabet.IndexOf(letters[i + 1]);
            if (hi < 0 || lo < 0) throw Malformed();
            output[i / 2] = (byte)(hi << 4 | lo);
        }
        return output;
    }

    public static string Group(string s, int size = 5)
    {
        var sb = new StringBuilder(s.Length + s.Length / size);
        for (int i = 0; i < s.Length; i++)
        {
            if (i > 0 && i % size == 0) sb.Append(' ');
            sb.Append(s[i]);
        }
        return sb.ToString();
    }
}
