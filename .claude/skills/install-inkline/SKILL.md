---
name: install-inkline
description: Install Inkline (proof-of-human email stamps) on this Mac — download the notarized helper, connect it to Chrome, enroll with the notary, load the extension, and verify with a test email. Use when the user asks to install, set up, or fix Inkline.
---

# Install Inkline on this Mac

Inkline stamps Gmail messages with a Touch ID approval: helper app (signs in
the Secure Enclave) + Chrome extension + hosted notary. Set it up end to end
and verify it works. Mail is never blocked by Inkline: when something is
broken, emails simply send WITHOUT a stamp and the reason appears as
`[inkline] ...` lines in the Gmail tab's DevTools console.

## Requirements (check first)

- macOS 13+ on a Mac with Touch ID and a fingerprint enrolled
- Chrome (or Chromium) with Gmail
- Do NOT build the helper from source: an ad-hoc build cannot create Secure
  Enclave keys (fails with errSecMissingEntitlement, -34018). Always use the
  notarized release build via install.sh.

## Steps

1. Run the installer from the repo root (it downloads the notarized helper
   from the GitHub release, verifies its SHA-256, checks Gatekeeper,
   registers the Chrome native-messaging host, and enrolls this Mac):

       sh install.sh

   Enrollment creates a fingerprint-locked key; if macOS prompts for
   Touch ID, tell the user to press it.
2. Load the extension: have the user open chrome://extensions, enable
   Developer mode (top right), click "Load unpacked", and select the
   `extension/` folder of this repo. You cannot do this step for them —
   Chrome requires a human file-picker interaction.
3. The extension opens its onboarding page automatically (or open
   chrome-extension://<extension-id>/onboarding.html). It live-checks:
   helper installed, enrolled, stamp picked, first stamped send. Wait for
   the first two to show [ ok ].
4. Have the user reload any open Gmail tab, send themselves a message, and
   approve it in the Inkline window with Touch ID. The received email ends
   with a "Verified with Inkline" footer linking to the receipt.
5. Open the receipt link and confirm the verify page shows all checks green.

## Troubleshooting

- **No approval window on Send** → the Gmail tab predates the extension
  load: reload the extension at chrome://extensions AND reload the Gmail
  tab, in that order. Then check the `[inkline]` console lines.
- `native_host_unavailable` → rerun `sh install.sh`; confirm
  `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.inkline.presence.json`
  exists and its `path` points at
  `~/Applications/InklinePresenceHelper.app/Contents/MacOS/InklinePresenceHelper`.
- `not_enrolled` → run the helper binary directly:
  `~/Applications/InklinePresenceHelper.app/Contents/MacOS/InklinePresenceHelper enroll`
- `declined` → the user cancelled Touch ID; just send again.
- `timeout` → the approval window sat unanswered ~2 minutes; send again.
- Helper "Killed: 9" → someone built from source; delete that build and use
  the release app via install.sh (see Requirements).
- SHA-256 mismatch from install.sh → the local install.sh is stale or the
  download was tampered with; re-download install.sh from the latest GitHub
  release and retry. Never bypass the check.

## Never do

- Never disable Gatekeeper, bypass the SHA-256 check, or ad-hoc-sign the app.
- Never edit the helper, notary URLs, or enrollment state to "make it pass" —
  a green check must mean the real flow works.
