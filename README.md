# Number Cipher

Native apps for **Mac** (Apple Silicon, macOS 14+), **Windows** (10/11, x64 and ARM64) and **Android** (8.0+ phones, tablets, foldables and Chromebooks) that turn number sequences into a letter-only code, and back. All three use the same code format and strength, so a code made on one decrypts on the others.

Prebuilt downloads are on the repo's **Releases** page.

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

## Build — Android

GitHub builds and tests the APK automatically (`.github/workflows/android.yml`). To build it yourself, open the `android/` folder in Android Studio, or with JDK 17, the Android SDK and Gradle 8.11:

```bash
cd android
./gradlew :app:assembleRelease     # or `gradle` if the wrapper isn't present yet
```

| Folder | Contents |
|---|---|
| `android/app/src/main/cpp` | Native PBKDF2-SHA256: ARMv8 SHA-256 instructions, x86 SHA extensions, or portable C, chosen at runtime |
| `android/app/src/main/java/.../crypto` | Cipher engine (same format as the other apps) and device speed analysis |
| `android/app/src/test`, `androidTest` | Compatibility tests (desktop JVM) and native-code tests (device/emulator) |
| `android/nativetest` | Checks the native code against Python's `hashlib` |

**How Android keeps the ~10 second target on any device.** Phones vary enormously in speed, switch work between fast and slow cores, and slow down when warm, so predicting a round count from a quick benchmark is unreliable. Instead, the Android app keeps iterating until the worker thread has done 10 seconds of CPU work, then records exactly how many rounds it completed. (A one-block PBKDF2 key for N rounds is just the running result after N steps, so stopping at any point gives a valid key.) Counting CPU time rather than wall-clock time means pausing the app can't produce a weaker code. Very slow devices never go below the 2,000,000-round minimum.

Key stretching is a single chain of SHA-256 steps, so it runs on one CPU core: more cores, the GPU and the NPU can't speed it up. What matters is the fastest core and whether it has SHA-256 instructions (nearly all 64-bit ARM phones do). The app's **ⓘ** panel shows the chip, core speeds, which SHA-256 path is in use, and measured rounds per second.

Because each code stores its round count, a code made on a fast device takes proportionally longer to decrypt on a slow one. The app shows the expected time, a live countdown and a Cancel button.

## Use

- **Encrypt:** type numbers (digits, spaces, commas, periods, dashes, line breaks), enter a passphrase twice, press ⌘↩ (Ctrl+Enter on Windows). Copy the letter code.
- **Decrypt:** paste the letter code, enter the passphrase, press ⌘↩ (Ctrl+Enter). Spaces and case in the code don't matter.
- Copied results are hidden from clipboard managers (and from Windows clipboard history and cloud sync, and Android's clipboard preview) and cleared from the clipboard after 60 seconds.
- Android only: **Paste** and **Share** buttons (Share sends only the letter code, never the numbers), and the app blocks screenshots and hides its contents in the recent-apps view.

## Why it's hard to crack

| Layer | What it does |
|---|---|
| AES-256-GCM (CryptoKit on Mac, CNG on Windows, BoringSSL on Android) | Industry-standard encryption, run on the CPU's built-in AES hardware. Any altered letter is detected. |
| PBKDF2-SHA256, tuned to ~10 seconds | The Mac and Windows apps measure the computer and pick a round count (tens of millions on an M4) so deriving the key takes ~10 s; Android counts 10 s of actual work (see above). The count is stored in the code, so any device can decrypt it. Every passphrase guess costs an attacker that same work. |
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

To publish a new release, change the number in `VERSION` and push to `main`. GitHub builds the Mac app on an Apple Silicon Mac, the Windows app on a Windows machine and the Android APK on Linux (after running the compatibility tests), then publishes them together.

The Android APK is signed with the key in the `ANDROID_KEYSTORE_B64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS` and `ANDROID_KEY_PASSWORD` repository secrets. Android only installs an update over an existing app signed with the same key, so keep a backup of that keystore.

## License

Copyright (C) 2026 Zachary Elwyn

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the [LICENSE](LICENSE) file for details.
