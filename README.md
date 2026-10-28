# Number Cipher

A native macOS app (Apple Silicon, macOS 14+) that turns number sequences into a letter-only code, and back.

## Build

Requires Xcode or the Xcode Command Line Tools (`xcode-select --install`).

```bash
cd NumberCipher
chmod +x build.sh
./build.sh
open "build/Number Cipher.app"
```

## Use

- **Encrypt:** type numbers (digits, spaces, commas, periods, dashes, line breaks), enter a passphrase twice, press ⌘↩. Copy the letter code.
- **Decrypt:** paste the letter code, enter the passphrase, press ⌘↩. Spaces and case in the code don't matter.
- Copied results are hidden from clipboard managers and cleared from the clipboard after 60 seconds.

## Why it's hard to crack

| Layer | What it does |
|---|---|
| AES-256-GCM (CryptoKit) | Industry-standard encryption, run on the Apple Silicon AES hardware. Any altered letter is detected. |
| PBKDF2-SHA256, tuned to ~10 seconds | On first use the app measures your Mac and picks a round count (tens of millions on an M4) so deriving the key takes ~10 s. The count is stored in the code, so any Mac can decrypt it. Every passphrase guess costs an attacker that same work. |
| Random 16-byte salt + nonce | Encrypting the same numbers twice gives completely different codes, so patterns leak nothing. |
| Padding to 16-byte blocks | The code length doesn't reveal exactly how many digits you encrypted. |
| Letters A–R without I and O | Unambiguous when written down or read aloud. |

**The passphrase is the only real weak point.** Use 4+ random words or 14+ mixed characters. There is no recovery if you forget it.

## Recovery without the app

`recover.py` is an independent implementation of the same format:

```bash
pip3 install cryptography
python3 recover.py decrypt "ABPJB MHPDB ..."
```

Codes made by version 1.0 (fixed 2,000,000 rounds) still decrypt in both the app and `recover.py`.

Keep a copy of it with your backups so your codes never depend on this one app.

## Releases

Download the prebuilt app from the repo's **Releases** page. To publish a new release, change the number in `VERSION` and push to `main`; GitHub builds the app on an Apple Silicon Mac and attaches it automatically.
