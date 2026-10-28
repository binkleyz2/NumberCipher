#!/bin/bash
# Runs on the emulator: native-library tests, then the release APK self-test.
# Failures are reported as GitHub annotations (::error::) so they show up without logs.
set -u
annotate() {  # title, file
  local body
  body=$(sed -e 's/%/%25/g' "$2" | head -c 6000 | awk 'BEGIN{ORS="%0A"} {print}')
  echo "::error title=$1::$body"
}
LOG=${RUNNER_TEMP:-/tmp}/connected.log
rc=0
gradle -p android :app:connectedDebugAndroidTest --stacktrace > "$LOG" 2>&1 || rc=$?
tail -30 "$LOG"
if [ $rc -ne 0 ]; then
  F=${RUNNER_TEMP:-/tmp}/failures.txt
  : > "$F"
  for x in $(find android/app/build/outputs/androidTest-results -name '*.xml' 2>/dev/null); do
    python3 - "$x" >> "$F" <<'PY'
import sys, xml.etree.ElementTree as ET
for tc in ET.parse(sys.argv[1]).iter('testcase'):
    for f in list(tc.iter('failure')) + list(tc.iter('error')):
        print(f"{tc.get('classname')}.{tc.get('name')}: {(f.get('message') or '')[:300]}")
        print("\n".join((f.text or '').splitlines()[:12]))
PY
  done
  grep -E "What went wrong|FAILED|Exception|error:" -A4 "$LOG" | head -60 >> "$F"
  annotate "connected tests" "$F"
fi
adb logcat -d -s NumberCipher:I | tail -5
S=${RUNNER_TEMP:-/tmp}/selftest.log
./android/ci/release_selftest.sh > "$S" 2>&1; src=$?
cat "$S"
[ $src -eq 0 ] || annotate "release self-test" "$S"
[ $rc -eq 0 ] && [ $src -eq 0 ]
