#!/usr/bin/env python3
"""Compares test_pbkdf2 output with Python's hashlib (the same PBKDF2 recover.py uses).
   python3 check.py <test_pbkdf2 output file>"""
import hashlib, sys

PWS = ["", "a", "correct horse battery", "é-passé",
       "0123456789012345678901234567890123456789012345678901234567890123",
       "01234567890123456789012345678901234567890123456789012345678901234",
       "a much longer passphrase that is well over one sixty-four byte block in length, for sure"]
SALT = bytes(range(1, 17))

ok = bad = 0
for line in open(sys.argv[1]):
    p = line.split()
    if p[0] == "case":
        i, r, got, h = int(p[1]), int(p[2]), int(p[3]), p[4]
        want = hashlib.pbkdf2_hmac("sha256", PWS[i].encode(), SALT, r, 32).hex()
        good = got == r and h == want
    elif p[0] == "stop":
        got, h = int(p[1]), p[2]
        good = got == 300000 and h == hashlib.pbkdf2_hmac("sha256", b"stop", SALT, 300000, 32).hex()
    elif p[0] == "cancel":
        good = p[1] == "0" and p[2] == "zeroed=1"
    else:
        print(line.rstrip())
        continue
    ok += good
    bad += not good
    if not good:
        print("MISMATCH", line.rstrip())
print(f"{ok} matched hashlib, {bad} mismatched")
sys.exit(1 if bad else 0)
