#!/bin/sh
# Inkline installer for macOS (Touch ID Mac + Chrome).
#
#   sh install.sh                      # download release VERSION, install, enroll
#   sh install.sh <EXTENSION_ID>       # same, with an explicit extension ID
#   sh install.sh --local path.zip     # install from a local zip (must match SHA)
#
# What it does:
#   1. downloads InklinePresenceHelper.zip from the GitHub release,
#   2. verifies its SHA-256 against the value embedded below,
#   3. unzips to ~/Applications/InklinePresenceHelper.app (the app is
#      notarized and stapled, so no quarantine handling is needed),
#   4. checks Gatekeeper accepts it (spctl) and aborts otherwise,
#   5. registers the Chrome native-messaging host for your extension ID,
#   6. enrolls this Mac with the notary (creates the Secure Enclave key).
set -eu

VERSION="${INKLINE_VERSION:-0.2.1}"
REPO="Inkline-Verify/ProofOfHuman"
NOTARY_URL="${INKLINE_NOTARY_URL:-https://inkline-notary-production.up.railway.app}"
# SHA-256 of dist/InklinePresenceHelper.zip for VERSION. Update on every
# release:  shasum -a 256 dist/InklinePresenceHelper.zip
HELPER_SHA256="1de53ab85cfbf2a0d148a7a3330f6c4eb5559808a4a23496311597100a616d12"

ZIP_URL="https://github.com/$REPO/releases/download/v$VERSION/InklinePresenceHelper.zip"
RAW_URL="https://raw.githubusercontent.com/$REPO/v$VERSION"
APP_DIR="$HOME/Applications"
APP="$APP_DIR/InklinePresenceHelper.app"
HELPER="$APP/Contents/MacOS/InklinePresenceHelper"

LOCAL_ZIP=""
EXT_ID=""
while [ $# -gt 0 ]; do
  case "$1" in
    --local) LOCAL_ZIP="$2"; shift 2;;
    -h|--help) sed -n '2,20p' "$0"; exit 0;;
    *) EXT_ID="$1"; shift;;
  esac
done

die() { echo "error: $*" >&2; exit 1; }
[ "$(uname -s)" = Darwin ] || die "Inkline runs on macOS only"
command -v python3 >/dev/null || die "python3 is required"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# 1. fetch
if [ -n "$LOCAL_ZIP" ]; then
  cp "$LOCAL_ZIP" "$WORK/helper.zip"
  echo "using local zip: $LOCAL_ZIP"
else
  echo "downloading $ZIP_URL"
  curl -fsSL --retry 3 -o "$WORK/helper.zip" "$ZIP_URL" || die "download failed"
fi

# 2. verify
ACTUAL="$(shasum -a 256 "$WORK/helper.zip" | awk '{print $1}')"
[ "$HELPER_SHA256" != "__HELPER_SHA256__" ] || die "installer has no embedded SHA-256; refusing to install"
[ "$ACTUAL" = "$HELPER_SHA256" ] || die "SHA-256 mismatch
  expected $HELPER_SHA256
  actual   $ACTUAL"
echo "sha256 OK"

# 3. install
mkdir -p "$APP_DIR"
rm -rf "$APP"
ditto -x -k "$WORK/helper.zip" "$APP_DIR"
[ -x "$HELPER" ] || die "unexpected zip layout: $HELPER missing"

# 4. gatekeeper
if ! spctl -a -vv "$APP" 2>"$WORK/spctl.txt"; then
  cat "$WORK/spctl.txt" >&2
  rm -rf "$APP"
  die "Gatekeeper rejected the app; not installing"
fi
grep -q "Notarized Developer ID" "$WORK/spctl.txt" || { rm -rf "$APP"; die "app is not notarized"; }
echo "gatekeeper: accepted (Notarized Developer ID)"
echo "installed:  $APP"

# 5. native host
# Look next to this script first (repo checkout or release download), then fetch.
NH="$(dirname "$0")/scripts/install-native-host.sh"
[ -f "$NH" ] || NH="$(dirname "$0")/install-native-host.sh"
if [ ! -f "$NH" ]; then
  NH="$WORK/install-native-host.sh"
  curl -fsSL -o "$NH" "$RAW_URL/scripts/install-native-host.sh" \
    || die "cannot fetch install-native-host.sh (private repo or offline?) — download it from the release and place it next to install.sh"
fi
if [ -z "$EXT_ID" ] && [ -t 0 ]; then
  printf "Chrome extension ID (leave empty to auto-detect): "
  read -r EXT_ID || true
fi
INKLINE_HELPER_APP="$APP" sh "$NH" $EXT_ID

# 6. enroll
echo
if "$HELPER" status 2>/dev/null | grep -q '"enrolled":true'; then
  echo "already enrolled; keeping the existing presence key"
  "$HELPER" status 2>/dev/null
else
  echo "enrolling with $NOTARY_URL ..."
  "$HELPER" enroll --notary "$NOTARY_URL" 2>/dev/null || die "enrollment failed (see message above)"
fi

cat <<EOF

Inkline is installed.

Next steps:
  1. Load the extension, if you have not already:
       chrome://extensions -> Developer mode -> Load unpacked -> the extension/ folder
       (or install it from the Chrome Web Store once published)
  2. Reload any open Gmail tabs.
  3. Send yourself a message and approve it with Touch ID.

To remove Inkline later: sh uninstall.sh
EOF
