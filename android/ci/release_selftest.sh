#!/bin/bash
# Installs the release APK on the running emulator and runs the built-in self-test, which
# decrypts a Mac-format code and round-trips a new one through the minified release build.
set -u
PKG=io.github.binkleyz2.numbercipher
APK=${1:-android/app/build/outputs/apk/release/app-release.apk}
adb uninstall $PKG >/dev/null 2>&1 || true
adb install "$APK" || exit 1
adb logcat -c
adb shell am start -W -n $PKG/.MainActivity --ez nc_selftest true
for i in $(seq 1 60); do
  line=$(adb logcat -d -s NumberCipher:I | grep SELFTEST | tail -1)
  if [ -n "$line" ]; then
    echo "$line"
    case "$line" in *PASS*) exit 0;; *) adb logcat -d -s NumberCipher:* AndroidRuntime:E | tail -40; exit 1;; esac
  fi
  sleep 2
done
echo "No self-test result"; adb logcat -d | grep -iE "numbercipher|fatal|androidruntime" | tail -40; exit 1
