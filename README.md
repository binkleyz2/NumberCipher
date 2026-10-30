# Cipherwords

Native apps for **Mac** (Apple Silicon, macOS 14+), **Windows** (10/11, x64 and ARM64) and **Android** (8.0+ phones, tablets, foldables and Chromebooks) that turn any text (numbers, notes, passwords, addresses, any language or emoji) into a code made of ordinary English words, and back. All three use the same code format and strength, so a code made on one decrypts on the others. (Cipherwords was called Number Cipher before version 1.5; its codes still decrypt.)

```
ACOUSTIC ABILITY CEILING SCATTER SUBJECT PITCH
ELEMENT LIVE DAY VIEW BONE POPULAR
...
```

Prebuilt downloads are on the repo's **Releases** page.

## Build — Mac

Requires Xcode or the Xcode Command Line Tools (`xcode-select --install`).

```bash
cd NumberCipher
chmod +x build.sh
./build.sh
open "build/Cipherwords.app"
```

## Build — Windows

Requires the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0). From the repo folder:

```powershell
dotnet publish windows/NumberCipher.Windows -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -o out
out\Cipherwords.exe
```

Use `-r win-arm64` for Windows on ARM. `dotnet run --project windows/InteropTest` runs the compatibility tests.

| Folder | Contents |
|---|---|
| `windows/NumberCipher.Core` | The cipher engine (same format as the Mac app) |
| `windows/NumberCipher.Windows` | The Windows app window |
| `windows/InteropTest` | Tests that codes cross between Windows, Mac and `recover.py` |

The folders, project files and Android package still use the original internal name, `NumberCipher`. Changing the Android package name would make Android treat the app as a different one, so it couldn't update the installed app.

Mac and `recover.py` tests are in `Tests/`. The **Checks** workflow runs every platform's tests on each pull request.

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

- **Encrypt:** type or paste any text (up to 20,000 bytes, about 20,000 English characters), enter a passphrase twice, press ⌘↩ (Ctrl+Enter on Windows). Copy the word code.
- **Decrypt:** paste the word code, enter the passphrase, press ⌘↩ (Ctrl+Enter). Capitalization, line breaks, commas and numbering (`1. ACOUSTIC 2. ABILITY`) in the code don't matter, and only the first four letters of each word count, so a misspelling after that is corrected automatically. If a word is missing, extra or not on the list, the app tells you which. The passphrase is case-sensitive: it must match exactly.
- **Older letter codes** (`ACAAA EKDQA ...`, made by versions 1.0–1.4) still decrypt; just paste them in.
- **Length:** a short message is 48 words; each further 16 bytes of text adds about 12 words.
- Copied results are hidden from clipboard managers (and from Windows clipboard history and cloud sync, and Android's clipboard preview) and cleared from the clipboard after 60 seconds.
- Android only: **Paste** and **Share** buttons (Share sends only the code, never the decrypted text), and the app blocks screenshots and hides its contents in the recent-apps view.

## Why it's hard to crack

| Layer | What it does |
|---|---|
| AES-256-GCM (CryptoKit on Mac, CNG on Windows, BoringSSL on Android) | Industry-standard encryption, run on the CPU's built-in AES hardware. Any altered word or letter is detected. |
| PBKDF2-SHA256, tuned to ~10 seconds | The Mac and Windows apps measure the computer and pick a round count (tens of millions on an M4) so deriving the key takes ~10 s; Android counts 10 s of actual work (see above). The count is stored in the code, so any device can decrypt it. Every passphrase guess costs an attacker that same work. |
| Random 16-byte salt + nonce | Encrypting the same numbers twice gives completely different codes, so patterns leak nothing. |
| Padding to 16-byte blocks | The code length doesn't reveal exactly how long your text is. |
| Words from the BIP39 list | 2,048 common, distinct English words (the list used for cryptocurrency recovery phrases), each carrying 11 bits. Easy to write down or read aloud, and no two words share their first four letters. The words are just a way of writing the encrypted bytes: they add no strength and remove none. |

**The passphrase is the only real weak point.** Use 4+ random words or 14+ mixed characters. There is no recovery if you forget it.

## Recovery without the app

`recover.py` is an independent implementation of the same format:

```bash
pip3 install cryptography
python3 recover.py decrypt "ACOUSTIC ABILITY CEILING ..."
python3 recover.py decrypt -          # paste a long code, then Ctrl+D
```

It contains the word list and a full description of the format, and also reads older letter codes, including those from version 1.0 (fixed 2,000,000 rounds).

Keep a copy of it with your backups so your codes never depend on this one app.

## Releases

To publish a new release, change the number in `VERSION` and push to `main`. GitHub builds the Mac app on an Apple Silicon Mac, the Windows app on a Windows machine and the Android APK on Linux (after running the compatibility tests), then publishes them together.

The Android APK is signed with the key in the `ANDROID_KEYSTORE_B64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS` and `ANDROID_KEY_PASSWORD` repository secrets. Android only installs an update over an existing app signed with the same key, so keep a backup of that keystore.

## License

Copyright (C) 2026 Zachary Elwyn

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the [LICENSE](LICENSE) file for details.
