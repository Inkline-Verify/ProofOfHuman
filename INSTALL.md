# Install

## Requirements

- macOS 27 or later on a Mac with Touch ID (fingerprint enrolled). App
  Attest, which every stamp requires, is unavailable on earlier macOS.
- Google Chrome and Gmail. Other Chromium browsers can work, but the
  installer only registers the helper with Google Chrome; copy
  `com.inkline.presence.json` into the other browser's
  `NativeMessagingHosts` folder yourself.
- For building the helper yourself instead of downloading: Xcode command line
  tools plus an Apple Development certificate *and provisioning profile* for
  `com.inkline.presence-helper` (see `scripts/build-app.sh`)

## Quick install

1. Download `extension.zip` from the
   [latest release](https://github.com/Inkline-Verify/ProofOfHuman/releases),
   unzip it somewhere permanent, then `chrome://extensions` → Developer mode →
   **Load unpacked** → select the unzipped `extension` folder. A setup page
   opens and checks everything live.
2. In Terminal, run:
   ```sh
   curl -fsSL https://raw.githubusercontent.com/Inkline-Verify/ProofOfHuman/main/install.sh -o install.sh && sh install.sh
   ```
   It downloads the notarized helper from the GitHub release, verifies its
   SHA-256, installs it, connects it to Chrome, and enrolls this Mac.
3. Send yourself a Gmail message and approve it with Touch ID. The stamp
   links to your receipt at https://verify.inklineverify.com — anyone can
   check it there.

## Setup with an AI agent

With Claude Code, open this repo and type `/install-inkline`: the repo ships
a skill that walks you through loading the extension, runs `install.sh`, and
troubleshoots. With another agent (Cursor, ...), ask it to follow
`.claude/skills/install-inkline/SKILL.md`.

Use the release helper that `install.sh` downloads. A helper built from
source with `scripts/setup.sh` cannot create Secure Enclave keys unless it is
signed with Inkline's provisioning profile (it fails with
errSecMissingEntitlement, -34018), and no agent can get around Apple's code
signing.

## Troubleshooting

Inkline never blocks mail. If the helper is missing, blocked, or not
enrolled, emails send normally **without a stamp** and the reason is logged
to the DevTools console of the Gmail tab (`[inkline] ...`).
