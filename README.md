# Number Cipher

Native apps for **Mac** (Apple Silicon, macOS 14+) and **Windows** (10/11, x64 and ARM64) that turn number sequences into a letter-only code, and back. Both use the same code format and strength, so a code made on one decrypts on the other.

Prebuilt downloads for both are on the repo's **Releases** page.

## Build — Mac

Requires Xcode or the Xcode Command Line Tools (`xcode-select --install`).

```bash
cd NumberCipher
chmod +x build.sh
./build.sh
open "build/Number Cipher.app"
```

## Build — Windows

Requires the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0). From the repo folder:

```powershell
dotnet publish windows/NumberCipher.Windows -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -o out
out\NumberCipher.exe
```

Use `-r win-arm64` for Windows on ARM. `dotnet run --project windows/InteropTest` runs the compatibility tests.

| Folder | Contents |
|---|---|
| `windows/NumberCipher.Core` | The cipher engine (same format as the Mac app) |
| `windows/NumberCipher.Windows` | The Windows app window |
| `windows/InteropTest` | Tests that codes cross between Windows, Mac and `recover.py` |

## Use

- **Encrypt:** type numbers (digits, spaces, commas, periods, dashes, line breaks), enter a passphrase twice, press ⌘↩ (Ctrl+Enter on Windows). Copy the letter code.
- **Decrypt:** paste the letter code, enter the passphrase, press ⌘↩ (Ctrl+Enter). Spaces and case in the code don't matter.
- Copied results are hidden from clipboard managers (and from Windows clipboard history and cloud sync) and cleared from the clipboard after 60 seconds.

## Why it's hard to crack

| Layer | What it does |
|---|---|
| AES-256-GCM (CryptoKit on Mac, CNG on Windows) | Industry-standard encryption, run on the CPU's built-in AES hardware. Any altered letter is detected. |
| PBKDF2-SHA256, tuned to ~10 seconds | On first use the app measures your computer and picks a round count (tens of millions on an M4) so deriving the key takes ~10 s. The count is stored in the code, so any Mac or PC can decrypt it. Every passphrase guess costs an attacker that same work. |
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

To publish a new release, change the number in `VERSION` and push to `main`. GitHub builds the Mac app on an Apple Silicon Mac and the Windows app on a Windows machine (after running the compatibility tests), then publishes them together.
