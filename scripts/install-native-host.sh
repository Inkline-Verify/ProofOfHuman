#!/bin/sh
# Registers the Inkline helper as a Chrome native-messaging host
# (com.inkline.presence) so the extension can reach it.
#
# Usage:
#   scripts/install-native-host.sh [EXTENSION_ID]
#
# The extension ID is taken from, in order: the argument, $INKLINE_EXTENSION_ID,
# or auto-detection from Chrome's profile preferences when exactly one Inkline
# extension is installed. Find it manually at chrome://extensions (Developer
# mode -> ID under the extension name).
#
# Which helper gets registered, in order: $INKLINE_HELPER_APP (a path to an
# installed InklinePresenceHelper.app), ~/Applications/InklinePresenceHelper.app,
# or the local dist/ build (built if missing).
set -eu

HOST_NAME="com.inkline.presence"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHROME_SUPPORT="$HOME/Library/Application Support/Google/Chrome"
HOST_DIR="$CHROME_SUPPORT/NativeMessagingHosts"

# --- extension ID -----------------------------------------------------------
detect_extension_id() {
  # Scans every Chrome profile's Preferences for installed extensions whose
  # manifest name starts with "Inkline". Prints the ID only if exactly one.
  python3 - "$CHROME_SUPPORT" <<'PY'
import glob, json, os, sys
root = sys.argv[1]
found = set()
for prefs in glob.glob(os.path.join(root, "*", "Preferences")) + glob.glob(os.path.join(root, "*", "Secure Preferences")):
    try:
        data = json.load(open(prefs, encoding="utf-8"))
    except Exception:
        continue
    for ext_id, entry in (data.get("extensions", {}).get("settings", {}) or {}).items():
        name = (entry.get("manifest") or {}).get("name", "")
        if not name and entry.get("path"):
            # Unpacked extensions store only their path; read the manifest there.
            try:
                name = json.load(open(os.path.join(entry["path"], "manifest.json"), encoding="utf-8")).get("name", "")
            except Exception:
                name = ""
        if name.startswith("Inkline"):
            found.add(ext_id)
if len(found) == 1:
    print(found.pop())
elif len(found) > 1:
    print("multiple:" + ",".join(sorted(found)), file=sys.stderr)
PY
}

EXT_ID="${1:-${INKLINE_EXTENSION_ID:-}}"
if [ -z "$EXT_ID" ]; then
  EXT_ID="$(detect_extension_id 2>/dev/null || true)"
fi
if [ -z "$EXT_ID" ]; then
  echo "could not determine the Inkline extension ID." >&2
  echo "Load the extension first (chrome://extensions -> Load unpacked -> extension/)," >&2
  echo "then run: $0 <EXTENSION_ID>" >&2
  exit 1
fi
case "$EXT_ID" in
  *[!a-p]*|"") echo "invalid extension ID: $EXT_ID (expected 32 chars a-p)" >&2; exit 1;;
esac
[ ${#EXT_ID} -eq 32 ] || { echo "invalid extension ID length: $EXT_ID" >&2; exit 1; }

# --- helper -----------------------------------------------------------------
if [ -n "${INKLINE_HELPER_APP:-}" ]; then
  APP="$INKLINE_HELPER_APP"
elif [ -x "$HOME/Applications/InklinePresenceHelper.app/Contents/MacOS/InklinePresenceHelper" ]; then
  APP="$HOME/Applications/InklinePresenceHelper.app"
else
  APP="$ROOT/dist/InklinePresenceHelper.app"
  # Rebuild only when there is no bundle yet or a signing identity was given;
  # otherwise keep the existing (possibly Developer ID-signed) bundle intact.
  if [ ! -x "$APP/Contents/MacOS/InklinePresenceHelper" ] || [ -n "${CODESIGN_IDENTITY:-}" ]; then
    "$ROOT/scripts/build-app.sh"
  fi
fi
HELPER="$APP/Contents/MacOS/InklinePresenceHelper"
if [ ! -x "$HELPER" ]; then
  echo "helper binary not found at: $HELPER" >&2
  exit 1
fi

# --- manifest ---------------------------------------------------------------
mkdir -p "$HOST_DIR"
# Retire the pre-rename host manifest so Chrome has exactly one Inkline host.
rm -f "$HOST_DIR/com.inkline.helper.json"
cat > "$HOST_DIR/$HOST_NAME.json" <<MANIFEST
{
  "name": "$HOST_NAME",
  "description": "Inkline presence helper",
  "path": "$HELPER",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://$EXT_ID/"]
}
MANIFEST

echo "installed: $HOST_DIR/$HOST_NAME.json"
echo "extension: $EXT_ID"
echo "helper:    $HELPER"
echo
echo "For other Chromium channels, copy the manifest into their"
echo "NativeMessagingHosts directory (e.g. .../Google/Chrome Beta/...)."
