#!/bin/sh
# One-command setup for a Mac with Touch ID.
#
#   scripts/setup.sh                # uses DEFAULT_NOTARY below
#   scripts/setup.sh <notary-url>   # or point at a specific notary
#
# Builds the helper, connects it to Chrome, and enrolls this Mac with the
# notary. After this, load the extension/ folder via chrome://extensions
# (Developer mode -> Load unpacked) and send an email in Gmail.
set -eu

# Hosted notary (Railway). Override with INKLINE_NOTARY_URL or an argument.
DEFAULT_NOTARY="https://inkline-notary-production.up.railway.app"

NOTARY_URL="${1:-${INKLINE_NOTARY_URL:-$DEFAULT_NOTARY}}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

"$ROOT/scripts/install-native-host.sh"

echo
echo "enrolling this Mac with the notary at $NOTARY_URL ..."
"$ROOT/dist/InklinePresenceHelper.app/Contents/MacOS/InklinePresenceHelper" enroll --notary "$NOTARY_URL"

echo
echo "Setup complete. Last step:"
echo "  1. Open chrome://extensions"
echo "  2. Turn on Developer mode (top right)"
echo "  3. Click 'Load unpacked' and select: $ROOT/extension"
echo
echo "Then send yourself a Gmail message and approve it with your fingerprint."
