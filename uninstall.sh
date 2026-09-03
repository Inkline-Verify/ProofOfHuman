#!/bin/sh
# Removes Inkline from this Mac: the helper app, the Chrome native-messaging
# host manifest, the Secure Enclave presence key, and the helper's local
# state. The notary's registry entry is left in place (it holds only a public
# key; without the enclave key it can never sign again).
set -eu

APP="$HOME/Applications/InklinePresenceHelper.app"
HELPER="$APP/Contents/MacOS/InklinePresenceHelper"
STATE="$HOME/Library/Application Support/Inkline"

# Destroy the Secure Enclave key while the helper is still around to do it.
if [ -x "$HELPER" ]; then
  "$HELPER" reset >/dev/null 2>&1 && echo "presence key destroyed" || echo "note: could not reset presence key (already gone?)"
fi

rm -rf "$APP" && echo "removed: $APP"

for dir in "$HOME/Library/Application Support/Google/Chrome"* "$HOME/Library/Application Support/Chromium" "$HOME/Library/Application Support/BraveSoftware/Brave-Browser"; do
  for f in "$dir/NativeMessagingHosts/com.inkline.presence.json" "$dir/NativeMessagingHosts/com.inkline.helper.json"; do
    [ -f "$f" ] && rm -f "$f" && echo "removed: $f"
  done
done

rm -rf "$STATE" && echo "removed: $STATE"

echo
echo "Inkline is uninstalled. Remove the extension at chrome://extensions if you wish."
echo "(Your enrollment record stays in the notary registry; it cannot be used without this Mac's key.)"
