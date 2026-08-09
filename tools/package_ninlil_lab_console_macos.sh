#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${1:-"$ROOT/dist"}
APP="$OUT/Ninlil LAB Console.app"
CONTENTS="$APP/Contents"

if [ "$(uname -s)" != Darwin ]; then
    echo "This packager creates a macOS .app and must run on macOS." >&2
    exit 1
fi

if [ -e "$APP" ]; then
    echo "Refusing to replace existing app: $APP" >&2
    exit 1
fi
mkdir -p "$CONTENTS/MacOS" "$CONTENTS/Resources"
install -m 0755 "$ROOT/tools/ninlil_lab_console.py" "$CONTENTS/Resources/ninlil_lab_console.py"
install -m 0644 "$ROOT/tools/ninlil_lab_backend.py" "$CONTENTS/Resources/ninlil_lab_backend.py"
install -m 0644 "$ROOT/tools/ninlil_lab_ui.html" "$CONTENTS/Resources/ninlil_lab_ui.html"

cat >"$CONTENTS/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>Ninlil LAB Console</string>
  <key>CFBundleDisplayName</key><string>Ninlil LAB Console</string>
  <key>CFBundleIdentifier</key><string>org.ninlil.lab-console</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleExecutable</key><string>ninlil-lab-console</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
</dict></plist>
PLIST

cat >"$CONTENTS/MacOS/ninlil-lab-console" <<'LAUNCHER'
#!/bin/sh
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
for PYTHON in /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
    if [ -x "$PYTHON" ]; then
        exec "$PYTHON" "$HERE/Resources/ninlil_lab_console.py"
    fi
done
/usr/bin/osascript -e 'display alert "Ninlil LAB Console" message "Python 3 was not found on this Mac." as critical'
exit 1
LAUNCHER
chmod 0755 "$CONTENTS/MacOS/ninlil-lab-console"
echo "Created: $APP"
