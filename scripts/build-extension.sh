#!/bin/sh
# Packages the Chrome extension for distribution as dist/extension.zip.
# Ships only what the extension needs: manifest.json, the scripts, icons, and
# config.js (which must already carry the production URLs). Nothing else from
# extension/ or the repo is included.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/extension"
OUT="$ROOT/dist/extension.zip"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Refuse to package a config that still points at localhost.
if grep -qE "^\s*[A-Z_]+: '[^']*(localhost|127\.0\.0\.1)" "$SRC/config.js"; then
  echo "extension/config.js still contains a localhost URL; set production URLs first" >&2
  exit 1
fi

mkdir -p "$STAGE/extension" "$ROOT/dist"
for f in manifest.json background.js content.js config.js stamp-style.js options.html options.js onboarding.html onboarding.js; do
  cp "$SRC/$f" "$STAGE/extension/$f"
done
mkdir -p "$STAGE/extension/icons" "$STAGE/extension/stamps/sm"
cp "$SRC"/icons/icon*.png "$STAGE/extension/icons/"
cp "$SRC"/stamps/*.png "$STAGE/extension/stamps/"
cp "$SRC"/stamps/sm/*.png "$STAGE/extension/stamps/sm/"

rm -f "$OUT"
(cd "$STAGE" && zip -q -X -r "$OUT" extension -x '*.DS_Store')
echo "built: $OUT"
unzip -l "$OUT" | awk 'NR>3 && $4 != "" {print "  " $4}' | grep -v '/$'
