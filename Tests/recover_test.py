"""Tests for recover.py, the reference implementation of the code format.
Run from the repo folder:  python3 Tests/recover_test.py"""
import os, random, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import recover as r
from cryptography.exceptions import InvalidTag

PASS1, PASS2 = "correct horse battery", "maple orbit tundra swivel"
V1 = ("ABPJB MHPDB GPLNN GFDDR QMLMQ PFBGK LRFRK PAAQK BHCMH BQJCE AFAPG MJNQJ QRLAM AHJRJ "
      "CMMLG BFDKK GDEAM NJABM CDPKQ NCMEA PPBAG BABFR CQEQL KERHD RAQNE RMQDN JEPDE HCELC FDRRH LELPP KLBC")
V2 = ("ACAAA EKDQA DBGEF LEMLQ DKHGL GKKPB AMQKD EBAAC LAMBL DQBRP LQLPN GHRNL CJNPN CQNHE DFKJL "
      "GHNNK KHMMR CGMJL CMFNB KKBDH KEAQB JLBDE FEFPA DRPQP KMELF JEGCM KRJHR CNPNJ NJDDH PQHRK RNNEF RLJCD EM")
TEXT = "Any text: ünïcødé \U0001F389"
failures = 0


def check(name, ok):
    global failures
    print(("PASS  " if ok else "FAIL  ") + name)
    failures += not ok


def error(f):
    try:
        f()
        return "no error"
    except InvalidTag:
        return "Wrong passphrase"
    except ValueError as e:
        return str(e)


check("decrypts v1 letter code", r.decrypt(V1, PASS1) == "4111 2222 3333 4444")
check("decrypts v2 letter code", r.decrypt(V2, PASS2) == "4111 2222 3333 4444\n555-0199")
check("every 49+16k byte length round-trips through words",
      all(r.from_words(r.to_words(b)) == b for b in (bytes([2]) + os.urandom(48 + 16 * k) for k in range(1, 400))))
ok_len = lambda c: (lambda n: n >= 65 and (n * 8 + 10) // 11 == c)(c * 11 // 8 - (c * 11 // 8 - 1) % 16)
check("valid word counts are never adjacent (a missing/extra word is always caught)",
      all(not ok_len(c - 1) and not ok_len(c + 1) for c in range(1, 20000) if ok_len(c)))
check("word codes are never read as letter codes",
      all(r.is_word_code(r.to_words(bytes([2]) + os.urandom(48 + 16 * random.randint(1, 60)))) for _ in range(2000)))
check("letter codes are not read as word codes", not r.is_word_code(V1) and not r.is_word_code(V2))

c = r.encrypt(TEXT + "\r\nline two", PASS1, 200_000)
w = c.split()
check("round trip (line breaks normalized)", r.decrypt(c, PASS1) == TEXT + "\nline two")
check("short text is 48 words", len(r.encrypt("hello", PASS1, 200_000).split()) == 48)
check("lowercase, commas and numbering accepted",
      r.decrypt(", ".join(f"{i}. {x.lower()}" for i, x in enumerate(w, 1)), PASS1) == TEXT + "\nline two")
typo = list(w); typo[3] = typo[3][:4] + "QX"
check("misspelling after the 4th letter corrected", r.decrypt(" ".join(typo), PASS1) == TEXT + "\nline two")
check("missing word", "missing or extra" in error(lambda: r.decrypt(" ".join(w[:10] + w[11:]), PASS1)))
check("extra word", "missing or extra" in error(lambda: r.decrypt(" ".join(w[:10] + ["APPLE"] + w[10:]), PASS1)))
check("unknown word", "“ZZZZQ” (word 7)" in error(lambda: r.decrypt(" ".join(w[:6] + ["ZZZZQ"] + w[7:]), PASS1)))
swap = list(w); swap[20] = "ZOO" if swap[20] == "APPLE" else "APPLE"
check("altered word", error(lambda: r.decrypt(" ".join(swap), PASS1)) == "Wrong passphrase")
check("wrong passphrase", error(lambda: r.decrypt(c, "nope")) == "Wrong passphrase")
check("bad first word", "first word" in error(lambda: r.decrypt(" ".join(["ZOO"] + w[1:]), PASS1)))
check("future version", "newer version" in error(lambda: r.decrypt(" ".join(["ADAPT"] + w[1:]), PASS1)))
last = r.WORD_INDEX[w[-1].lower()]
bad_last = r.WORDS[last ^ 1].upper()
check("bad last word", "last word" in error(lambda: r.decrypt(" ".join(w[:-1] + [bad_last]), PASS1)))
check("empty text", "Enter some text" in error(lambda: r.encrypt(" \n ", PASS1, 200_000)))
check("null character", "null character" in error(lambda: r.encrypt("a\0b", PASS1, 200_000)))
check("too much text", "too much text" in error(lambda: r.encrypt("x" * 20_001, PASS1, 200_000)))

print("ALL PASSED" if not failures else f"{failures} FAILED")
sys.exit(1 if failures else 0)
