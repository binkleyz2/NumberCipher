#!/usr/bin/env python3
"""Independent decoder/encoder for Number Cipher codes (formats v1 and v2).

Lets you recover your numbers on any computer even without the Mac app.
Requires:  pip3 install cryptography

  python3 recover.py decrypt "ABCDE FGHJK ..."
  python3 recover.py encrypt "4111 2222 3333"

Format v2: version(1)=2 | rounds(4, big-endian) | salt(16) | nonce(12) | ciphertext | tag(16)
Format v1: version(1)=1 | salt(16) | nonce(12) | ciphertext | tag(16), fixed 2,000,000 rounds
Key = PBKDF2-HMAC-SHA256(passphrase, salt, rounds); cipher = AES-256-GCM with the header as AAD.
"""
import getpass, hashlib, os, struct, sys, time, unicodedata
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

V1_ROUNDS, SALT, PAD = 2_000_000, 16, 16
MIN_ROUNDS, MAX_ROUNDS, TARGET_SECONDS = 2_000_000, 1_000_000_000, 10
ALPHA = "ABCDEFGHJKLMNPQR"
ALLOWED = set("0123456789 ,.-\n\t")


def key(pw: str, salt: bytes, rounds: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", unicodedata.normalize("NFC", pw).encode(), salt, rounds, 32)


def calibrate() -> int:
    probe = 1_000_000
    t = time.perf_counter()
    key("calibration-passphrase", bytes([7]) * SALT, probe)
    est = probe / (time.perf_counter() - t) * TARGET_SECONDS
    return int(min(max(round(est / 100_000) * 100_000, MIN_ROUNDS), MAX_ROUNDS // 2))


def to_letters(b: bytes) -> str:
    s = "".join(ALPHA[x >> 4] + ALPHA[x & 15] for x in b)
    return " ".join(s[i:i + 5] for i in range(0, len(s), 5))


def from_letters(code: str) -> bytes:
    s = "".join(c for c in code.upper() if not c.isspace() and c != "-")
    if not s or len(s) % 2 or any(c not in ALPHA for c in s):
        raise ValueError("That doesn't look like a Number Cipher code.")
    return bytes(ALPHA.index(s[i]) << 4 | ALPHA.index(s[i + 1]) for i in range(0, len(s), 2))


def encrypt(numbers: str, pw: str, rounds: int | None = None) -> str:
    numbers = numbers.strip()
    if not set(numbers) <= ALLOWED or not any(c.isdigit() for c in numbers):
        raise ValueError("Only digits, spaces, commas, periods, dashes and line breaks are allowed.")
    rounds = rounds or calibrate()
    plain = numbers.encode()
    plain += b"\0" * ((len(plain) // PAD + 1) * PAD - len(plain))
    salt = os.urandom(SALT)
    header = bytes([2]) + struct.pack(">I", rounds) + salt
    nonce = os.urandom(12)
    return to_letters(header + nonce + AESGCM(key(pw, salt, rounds)).encrypt(nonce, plain, header))


def decrypt(code: str, pw: str) -> str:
    b = from_letters(code)
    if b[0] == 1:
        hlen, rounds = 1 + SALT, V1_ROUNDS
    elif b[0] == 2:
        hlen = 5 + SALT
        if len(b) < hlen:
            raise ValueError("That doesn't look like a Number Cipher code.")
        rounds = struct.unpack(">I", b[1:5])[0]
        if not 100_000 <= rounds <= MAX_ROUNDS:
            raise ValueError("That doesn't look like a Number Cipher code.")
    else:
        raise ValueError("Unsupported code version.")
    header, salt = b[:hlen], b[hlen - SALT:hlen]
    nonce, ct = b[hlen:hlen + 12], b[hlen + 12:]
    return AESGCM(key(pw, salt, rounds)).decrypt(nonce, ct, header).rstrip(b"\0").decode()


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("encrypt", "decrypt"):
        sys.exit(__doc__)
    pw = getpass.getpass("Passphrase: ")
    print("Working (about 10 seconds)…", file=sys.stderr)
    try:
        print((encrypt if sys.argv[1] == "encrypt" else decrypt)(sys.argv[2], pw))
    except InvalidTag:
        sys.exit("Wrong passphrase, or the code was altered.")
    except ValueError as e:
        sys.exit(str(e))
