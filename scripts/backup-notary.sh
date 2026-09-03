#!/bin/sh
# Backs up the hosted notary's state file (/data/notary.json on the Railway
# volume). That file is the single trust root: it holds the notary's private
# signing key and the enrollment registry. Losing it invalidates every
# receipt ever issued; leaking it lets anyone forge receipts.
#
# Run once after deploying and again after any enrollment or notary change.
# Backups go OUTSIDE the repository (default ~/InklineBackups), mode 0600.
#
# Usage:
#   scripts/backup-notary.sh                # -> ~/InklineBackups/notary-YYYY-MM-DD.json
#   BACKUP_DIR=/Volumes/Secure scripts/backup-notary.sh
#
# Requires: railway CLI, logged in, run from the linked project directory.
# (`railway run` executes locally, so it cannot read the volume; this uses
# the service filesystem API instead.)
set -eu

BACKUP_DIR="${BACKUP_DIR:-$HOME/InklineBackups}"
OUT="$BACKUP_DIR/notary-$(date +%F).json"

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
umask 077
railway service files download /data/notary.json "$OUT.tmp" >/dev/null

# Refuse to keep anything that is not the notary state (e.g. an error page).
if ! node -e 'const j=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")); if(!j.notaryKey||!j.registry) process.exit(1)' "$OUT.tmp"; then
  rm -f "$OUT.tmp"
  echo "backup failed: output was not a notary state file" >&2
  exit 1
fi
mv "$OUT.tmp" "$OUT"
chmod 600 "$OUT"

echo "backed up: $OUT"
node -e 'const j=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")); console.log("  notary pub  "+j.notaryKey.pub); console.log("  enrollments "+Object.keys(j.registry).length)' "$OUT"
