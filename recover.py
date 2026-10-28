#!/usr/bin/env python3
"""Independent decoder/encoder for Number Cipher codes (format v1).

Lets you recover your numbers on any computer even without the Mac app.
Requires:  pip3 install cryptography

  python3 recover.py decrypt "ABCDE FGHJK ..."
  python3 recover.py encrypt "4111 2222 3333"
"""
import getpass, hashlib, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

VERSION, ROUNDS, SALT, PAD = 1, 2_000_000, 16, 16
ALPHA = "ABCDEFGHJKLMNPQR"
ALLOWED = set("0123456789 ,.-\n\t")


def key(pw: str, salt: bytes) -> bytes:
    import unicodedata
    return hashlib.pbkdf2_hmac("sha256", unicodedata.normalize("NFC", pw).encode(), salt, ROUNDS, 32)


def to_letters(b: bytes) -> str:
    s = "".join(ALPHA[x >> 4] + ALPHA[x & 15] for x in b)
    return " ".join(s[i:i + 5] for i in range(0, len(s), 5))


def from_letters(code: str) -> bytes:
    s = "".join(c for c in code.upper() if not c.isspace() and c != "-")
    if not s or len(s) % 2:
        raise ValueError("malformed code")
    return bytes(ALPHA.index(s[i]) << 4 | ALPHA.index(s[i + 1]) for i in range(0, len(s), 2))


def encrypt(numbers: str, pw: str) -> str:
    numbers = numbers.strip()
    if not set(numbers) <= ALLOWED or not any(c.isdigit() for c in numbers):
        raise ValueError("numbers only")
    plain = numbers.encode()
    plain += b"\0" * ((len(plain) // PAD + 1) * PAD - len(plain))
    salt = os.urandom(SALT)
    header = bytes([VERSION]) + salt
    nonce = os.urandom(12)
    return to_letters(header + nonce + AESGCM(key(pw, salt)).encrypt(nonce, plain, header))


def decrypt(code: str, pw: str) -> str:
    b = from_letters(code)
    if b[0] != VERSION:
        raise ValueError("unsupported version")
    header, nonce, ct = b[:1 + SALT], b[1 + SALT:1 + SALT + 12], b[1 + SALT + 12:]
    return AESGCM(key(pw, header[1:])).decrypt(nonce, ct, header).rstrip(b"\0").decode()


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("encrypt", "decrypt"):
        sys.exit(__doc__)
    pw = getpass.getpass("Passphrase: ")
    try:
        print((encrypt if sys.argv[1] == "encrypt" else decrypt)(sys.argv[2], pw))
    except InvalidTag:
        sys.exit("Wrong passphrase, or the code was altered.")
