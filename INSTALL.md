# Install

## Requirements

- macOS 13+ on a Mac with Touch ID (fingerprint enrolled)
- Chrome or a Chromium browser, Gmail
- For building the helper yourself instead of downloading: Xcode command line
  tools plus an Apple Development certificate *and provisioning profile* for
  `com.inkline.presence-helper` (see `scripts/build-app.sh`)

## Quick install

1. In Terminal, run:
   ```sh
   curl -fsSL https://raw.githubusercontent.com/Inkline-Verify/ProofOfHuman/main/install.sh -o install.sh && sh install.sh
   ```
   It downloads the notarized helper from the GitHub release, verifies its
   SHA-256, installs it, connects it to Chrome, and enrolls this Mac.
2. Download `extension.zip` from the
   [latest release](https://github.com/Inkline-Verify/ProofOfHuman/releases),
   unzip it somewhere permanent, then `chrome://extensions` → Developer mode →
   **Load unpacked** → select the unzipped `extension` folder. A setup page
   opens and checks everything live.
3. Send yourself a Gmail message and approve it with Touch ID. The stamp
   links to your receipt at https://verify.inklineverify.com — anyone can
   check it there.

## Setup with an AI agent

Open this repo in an AI coding agent (Claude Code, Cursor, ...) and paste:

> Set up Inkline on this Mac: run scripts/setup.sh with the default hosted
> notary, tell me when to press Touch ID, and walk me through loading the
> extension folder at chrome://extensions. If the helper is killed by macOS
> or enrollment fails with errSecMissingEntitlement (-34018), stop and tell
> me to download the signed helper from the GitHub Releases page instead of
> building locally.

The agent runs the build, registers the native host, and enrolls you. The one
thing no agent can do is bypass Apple's code signing — Secure Enclave keys
require a properly signed helper, which is why the Release build exists.

## Troubleshooting

Inkline never blocks mail. If the helper is missing, blocked, or not
enrolled, emails send normally **without a stamp** and the reason is logged
to the DevTools console of the Gmail tab (`[inkline] ...`).
