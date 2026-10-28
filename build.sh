#!/bin/bash
# Builds "Number Cipher.app" natively for Apple Silicon (M4 or newer preferred).
set -euo pipefail
cd "$(dirname "$0")"

if [[ "$(uname -m)" != "arm64" ]]; then
  echo "This build targets Apple Silicon (arm64). Run it on an M-series Mac." >&2
  exit 1
fi

swift build -c release --arch arm64
BIN="$(swift build -c release --arch arm64 --show-bin-path)/NumberCipher"
APP="build/Number Cipher.app"
VERSION="$(tr -d '[:space:]' < VERSION)"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/NumberCipher"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Number Cipher</string>
  <key>CFBundleDisplayName</key><string>Number Cipher</string>
  <key>CFBundleIdentifier</key><string>local.numbercipher</string>
  <key>CFBundleExecutable</key><string>NumberCipher</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSArchitecturePriority</key><array><string>arm64</string></array>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSPrincipalClass</key><string>NSApplication</string>
</dict>
</plist>
PLIST

# Ad-hoc sign with hardened runtime so Gatekeeper will run it locally.
codesign --force --options runtime --sign - "$APP"

echo
echo "Built version ${VERSION}: $(pwd)/$APP"
echo "Drag it to /Applications, or run:  open \"$APP\""
