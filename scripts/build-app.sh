#!/bin/sh
# Packages the helper as a macOS app bundle — the ONLY supported way to run it.
# Native messaging and Secure Enclave keychain access need a bundle, never a
# bare binary:
#   dist/InklinePresenceHelper.app/Contents/MacOS/InklinePresenceHelper
#   (+ dist/InklinePresenceHelper.zip when signing is real)
#
# Usage:
#   scripts/build-app.sh                      # ad-hoc signed: builds, but cannot enroll
#   CODESIGN_IDENTITY="Developer ID Application: You (TEAMID)" \
#   PROVISIONING_PROFILE=path/to/InklinePresenceHelper_DevID.provisionprofile \
#     scripts/build-app.sh
#   NOTARY_PROFILE=<notarytool-keychain-profile> ...  # also notarize + staple
#
# The Secure Enclave presence key can only be persisted by a bundle signed
# with a real identity plus the keychain entitlements in
# helper/InklinePresenceHelper.entitlements (TEAMID is taken from the
# identity) and an embedded Developer ID provisioning profile that grants
# them. Ad-hoc builds fail enrollment with errSecMissingEntitlement (-34018).
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="$ROOT/dist/InklinePresenceHelper.app"
BIN="$ROOT/helper/.build/release/InklinePresenceHelper"
IDENTITY="${CODESIGN_IDENTITY:--}"
PROFILE="${PROVISIONING_PROFILE:-}"
ENTITLEMENTS_TEMPLATE="$ROOT/helper/InklinePresenceHelper.entitlements"

echo "building helper (release)..."
(cd "$ROOT/helper" && swift build -c release >/dev/null)

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/InklinePresenceHelper"

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.inkline.presence-helper</string>
    <key>CFBundleName</key>
    <string>InklinePresenceHelper</string>
    <key>CFBundleDisplayName</key>
    <string>Inkline Presence Helper</string>
    <key>CFBundleExecutable</key>
    <string>InklinePresenceHelper</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>0.1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
PLIST

if [ "$IDENTITY" = "-" ]; then
  echo "signing ad-hoc (no entitlements; enrollment will not work)"
  codesign --force --options runtime --sign "$IDENTITY" "$APP"
else
  TEAM_ID="$(printf '%s' "$IDENTITY" | sed -n 's/.*(\([A-Z0-9]*\))$/\1/p')"
  if [ -z "$TEAM_ID" ]; then
    echo "cannot read TEAMID from CODESIGN_IDENTITY (expected '... (TEAMID)')" >&2
    exit 1
  fi
  if [ -n "$PROFILE" ]; then
    cp "$PROFILE" "$APP/Contents/embedded.provisionprofile"
  else
    echo "warning: PROVISIONING_PROFILE not set; keychain entitlements may be refused at runtime" >&2
  fi
  ENTITLEMENTS="$ROOT/dist/InklinePresenceHelper.entitlements"
  sed "s/TEAMID/$TEAM_ID/g" "$ENTITLEMENTS_TEMPLATE" > "$ENTITLEMENTS"
  echo "signing with: $IDENTITY  (team $TEAM_ID, entitlements + embedded profile)"
  codesign --force --options runtime --entitlements "$ENTITLEMENTS" --sign "$IDENTITY" "$APP"
fi
codesign --verify --deep --strict "$APP"
echo "built: $APP"

if [ -n "${NOTARY_PROFILE:-}" ] && [ "$IDENTITY" != "-" ]; then
  echo "notarizing..."
  ZIP="$ROOT/dist/InklinePresenceHelper.zip"
  ditto -c -k --keepParent "$APP" "$ZIP"
  xcrun notarytool submit "$ZIP" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$APP"
  ditto -c -k --keepParent "$APP" "$ZIP"
  echo "notarized and stapled: $ZIP"
else
  echo "skipped notarization (set CODESIGN_IDENTITY and NOTARY_PROFILE to enable)"
fi

echo
echo "register with Chrome:  scripts/install-native-host.sh"
