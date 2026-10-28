// Checks that the Windows engine reads and writes exactly the same codes as the Mac app
// and recover.py. Usage:
//   InteropTest                       run self-tests (prints PASS/FAIL, exit 1 on failure)
//   InteropTest encrypt <rounds> <numbers>   (passphrase from NC_PASS) -> prints code
//   InteropTest decrypt <code>               (passphrase from NC_PASS) -> prints numbers
using NumberCipher.Core;

if (args.Length > 0)
{
    string pw = Environment.GetEnvironmentVariable("NC_PASS") ?? "";
    Console.WriteLine(args[0] == "encrypt"
        ? CipherEngine.Encrypt(args[2], pw, int.Parse(args[1]))
        : CipherEngine.Decrypt(args[1], pw));
    return 0;
}

int failures = 0;
void Check(string name, bool ok) { Console.WriteLine($"{(ok ? "PASS" : "FAIL")}  {name}"); if (!ok) failures++; }

const string pass = "correct horse battery";
// A version-1 code produced by the original Mac-format implementation.
const string v1 = "ABPJB MHPDB GPLNN GFDDR QMLMQ PFBGK LRFRK PAAQK BHCMH BQJCE AFAPG MJNQJ QRLAM AHJRJ " +
                  "CMMLG BFDKK GDEAM NJABM CDPKQ NCMEA PPBAG BABFR CQEQL KERHD RAQNE RMQDN JEPDE HCELC FDRRH LELPP KLBC";
Check("decrypts v1 code", CipherEngine.Decrypt(v1, pass) == "4111 2222 3333 4444");

string c = CipherEngine.Encrypt("4111 2222\r\n3333 4444", pass, 200_000);
Check("v2 round trip (Windows line breaks normalized)", CipherEngine.Decrypt(c, pass) == "4111 2222\n3333 4444");
Check("code is letters A-R without I/O", c.Replace(" ", "").All(ch => CipherEngine.Alphabet.Contains(ch)));
Check("same input gives a different code each time", CipherEngine.Encrypt("123", pass, 200_000) != CipherEngine.Encrypt("123", pass, 200_000));
Check("lowercase and dashes accepted", CipherEngine.Decrypt(c.ToLowerInvariant().Replace(' ', '-'), pass) == "4111 2222\n3333 4444");

bool Throws(Action a, string contains) { try { a(); return false; } catch (CipherException e) { return e.Message.Contains(contains); } }
Check("wrong passphrase rejected", Throws(() => CipherEngine.Decrypt(c, "wrong"), "Wrong passphrase"));
char[] t = c.ToCharArray(); int k = 60; t[k] = t[k] == 'A' ? 'B' : 'A';
Check("altered letter rejected", Throws(() => CipherEngine.Decrypt(new string(t), pass), "Wrong passphrase"));
Check("letters outside alphabet rejected", Throws(() => CipherEngine.Decrypt("ABCXZ", pass), "doesn't look like"));
Check("non-number input rejected", Throws(() => CipherEngine.Encrypt("12a", pass), "Only digits"));
Check("changed first letter reported as typo", Throws(() => CipherEngine.Decrypt("B" + c[1..], pass), "always A"));
Check("future version (AD...) reported as newer", Throws(() => CipherEngine.Decrypt("AD" + c[2..], pass), "newer version"));

var sw = System.Diagnostics.Stopwatch.StartNew();
int rounds = CipherEngine.CalibratedRounds;
Console.WriteLine($"INFO  calibrated {rounds:N0} rounds on this machine ({sw.Elapsed.TotalSeconds:F2}s to measure)");
Check("calibrated rounds within bounds", rounds >= CipherEngine.MinRounds && rounds <= CipherEngine.MaxRounds / 2);

Console.WriteLine(failures == 0 ? "ALL PASSED" : $"{failures} FAILED");
return failures == 0 ? 0 : 1;
