// Checks that the Windows engine reads and writes exactly the same codes as the Mac app
// and recover.py. Usage:
//   InteropTest                            run self-tests (prints PASS/FAIL, exit 1 on failure)
//   InteropTest encrypt <rounds> <text>    (passphrase from NC_PASS) -> prints a word code
//   InteropTest decrypt <code>             (passphrase from NC_PASS) -> prints the text
using System.Security.Cryptography;
using System.Text;
using NumberCipher.Core;

if (args.Length > 0)
{
    string pw = Environment.GetEnvironmentVariable("NC_PASS") ?? "";
    Console.OutputEncoding = new UTF8Encoding(false);
    Console.WriteLine(args[0] == "encrypt"
        ? CipherEngine.Encrypt(args[2], pw, int.Parse(args[1]))
        : CipherEngine.Decrypt(args[1], pw));
    return 0;
}

int failures = 0;
void Check(string name, bool ok) { Console.WriteLine($"{(ok ? "PASS" : "FAIL")}  {name}"); if (!ok) failures++; }
bool Throws(Action a, string contains) { try { a(); return false; } catch (CipherException e) { return e.Message.Contains(contains); } }

const string pass = "correct horse battery";
const string pass2 = "maple orbit tundra swivel";
// A version-1 letter code produced by the original Mac-format implementation.
const string v1 = "ABPJB MHPDB GPLNN GFDDR QMLMQ PFBGK LRFRK PAAQK BHCMH BQJCE AFAPG MJNQJ QRLAM AHJRJ " +
                  "CMMLG BFDKK GDEAM NJABM CDPKQ NCMEA PPBAG BABFR CQEQL KERHD RAQNE RMQDN JEPDE HCELC FDRRH LELPP KLBC";
// A version-2 letter code made by recover.py.
const string v2 = "ACAAA EKDQA DBGEF LEMLQ DKHGL GKKPB AMQKD EBAAC LAMBL DQBRP LQLPN GHRNL CJNPN CQNHE DFKJL " +
                  "GHNNK KHMMR CGMJL CMFNB KKBDH KEAQB JLBDE FEFPA DRPQP KMELF JEGCM KRJHR CNPNJ NJDDH PQHRK RNNEF RLJCD EM";
// A word code made by recover.py (300,000 rounds).
const string words = """
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
    """;
const string wordsText = "Meet at the caf\u00E9, 7:30 pm.\nBring the 4111 key \U0001F511";

string listHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", WordList.Words) + "\n")));
Check("word list is the official BIP39 list", WordList.Words.Length == 2048 && listHash == "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda");

Check("decrypts v1 letter code", CipherEngine.Decrypt(v1, pass) == "4111 2222 3333 4444");
Check("decrypts v2 letter code", CipherEngine.Decrypt(v2, pass2) == "4111 2222 3333 4444\n555-0199");
Check("decrypts recover.py word code", CipherEngine.Decrypt(words, pass2) == wordsText);

string c = CipherEngine.Encrypt("Any text: \u00FCn\u00EFc\u00F8d\u00E9 \U0001F389\r\nline two", pass, 200_000);
Check("word round trip (Windows line breaks normalized)", CipherEngine.Decrypt(c, pass) == "Any text: \u00FCn\u00EFc\u00F8d\u00E9 \U0001F389\nline two");
string[] w = c.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
Check("output is upper-case list words", w.All(x => x == x.ToUpperInvariant() && WordList.Words.Contains(x.ToLowerInvariant())));
Check("same input gives a different code each time", CipherEngine.Encrypt("123", pass, 200_000) != CipherEngine.Encrypt("123", pass, 200_000));
Check("lowercase, commas and numbering accepted",
      CipherEngine.Decrypt(string.Join(", ", w.Select((x, i) => $"{i + 1}. {x.ToLowerInvariant()}")), pass).StartsWith("Any text"));
string[] typo = (string[])w.Clone(); typo[3] = typo[3][..4] + "QX";
Check("misspelling after the 4th letter is corrected", CipherEngine.Decrypt(string.Join(' ', typo), pass).StartsWith("Any text"));

Check("wrong passphrase rejected", Throws(() => CipherEngine.Decrypt(c, "wrong"), "Wrong passphrase"));
Check("missing word reported", Throws(() => CipherEngine.Decrypt(string.Join(' ', w.Where((_, i) => i != 10)), pass), "missing or extra"));
string[] unknown = (string[])w.Clone(); unknown[6] = "ZZZZQ";
Check("unknown word reported", Throws(() => CipherEngine.Decrypt(string.Join(' ', unknown), pass), "\u201CZZZZQ\u201D (word 7)"));
string[] swapped = (string[])w.Clone(); swapped[20] = swapped[20] == "APPLE" ? "ZOO" : "APPLE";
Check("altered word rejected", Throws(() => CipherEngine.Decrypt(string.Join(' ', swapped), pass), "Wrong passphrase"));
Check("bad first word reported", Throws(() => CipherEngine.Decrypt("ZOO " + string.Join(' ', w[1..]), pass), "first word"));
Check("future version reported", Throws(() => CipherEngine.Decrypt("ADAPT " + string.Join(' ', w[1..]), pass), "newer version"));
char[] t = v2.ToCharArray(); int k = 60; t[k] = t[k] == 'A' ? 'B' : 'A';
Check("altered letter rejected", Throws(() => CipherEngine.Decrypt(new string(t), pass2), "Wrong passphrase"));
Check("first letter typo (letter code)", Throws(() => CipherEngine.Decrypt("B" + v2[1..], pass2), "always A"));
Check("empty text rejected", Throws(() => CipherEngine.Encrypt(" \r\n ", pass), "Enter some text"));
Check("too much text rejected", Throws(() => CipherEngine.Encrypt(new string('x', 20_001), pass), "too much text"));
Check("estimate reads word codes", CipherEngine.EstimatedSeconds(words) is not null);

var sw = System.Diagnostics.Stopwatch.StartNew();
int rounds = CipherEngine.CalibratedRounds;
Console.WriteLine($"INFO  calibrated {rounds:N0} rounds on this machine ({sw.Elapsed.TotalSeconds:F2}s to measure)");
Check("calibrated rounds within bounds", rounds >= CipherEngine.MinRounds && rounds <= CipherEngine.MaxRounds / 2);

Console.WriteLine(failures == 0 ? "ALL PASSED" : $"{failures} FAILED");
return failures == 0 ? 0 : 1;
