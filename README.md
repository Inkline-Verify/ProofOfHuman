# Inkline

**[inklineverify.com](https://www.inklineverify.com)** · **[verify a receipt](https://verify.inklineverify.com/verifier/)**

**Proof of human.** When you hit Send in Gmail, Inkline shows you the exact
message and asks for Touch ID. The email goes out with a small footer linking
to a receipt — cryptographic evidence that a person saw exactly these words
and approved them. Anyone can verify a receipt offline, in their browser,
without an account.

Mail is **never blocked**: if anything in the chain fails, the email sends
without a stamp and the reason is logged to the console.

## How it works

When you press Send in Gmail:

1. The Chrome extension intercepts the click, extracts the message, and
   hands it to the helper over native messaging. The extension is
   deliberately untrusted plumbing: it only carries text and cannot forge
   a receipt.
2. The helper, a native Swift app, canonicalizes the email itself and shows
   it in a confirmation window. One touch of the Touch ID sensor signs the
   content with a Secure Enclave key that never leaves the chip and only
   signs after a live fingerprint match. It has no code path that signs a
   hash it was merely handed.
3. The notary, a small Node server with zero dependencies, checks the
   signature and a fresh single-use nonce, then co-signs and issues the
   receipt. It never sees the email, only a content hash.
4. The extension appends a small footer to the outgoing email linking to
   the receipt. A recipient opens the verify page, pastes the message, and
   the receipt is checked entirely in their browser. Verification never
   contacts the notary.

Repository layout:

- extension/ — the Chrome extension, Manifest V3
- helper/ — the Swift helper app, the trust anchor
- notary/ — the Node notary server
- verifier/ — the static verify page, live at verify.inklineverify.com
- shared/ and canonical/ — the canonicalization spec, shared codecs, and
  golden test vectors that keep the JS and Swift implementations
  byte-for-byte identical

## What a receipt proves — honestly

A valid receipt proves the enrolled key signed exactly this content after a
Touch ID check, witnessed by the notary. A receipt does not prove who
composed the words, only that a person approved them.

**What ships today (v0.2.0, macOS 27+):** the tier is *enclave-attested* and
mandatory. Apple's App Attest certifies at enrollment that the signing key
was created inside a genuine Secure Enclave in the signed helper, and every
stamp carries a fresh per-send attestation that the notary verifies before
co-signing; the notary refuses enrollment and co-signatures without it.
Receipts issued by earlier releases keep verifying — the verify page shows
them as issued before hardware attestation became part of every stamp.

The hosted notary and approval API run from a separate service repository;
`notary/` here is the reference implementation of the receipt protocol.

## Verify receipts in your own code

```sh
npm install inkline-verify
```
`packages/inkline-verify` publishes the same `shared/` modules the notary
and the public verify page use: `verify(receipt)` for approval receipts,
`verify(receipt, { email })` for stamps. Offline, no dependencies.

## Install

See [INSTALL.md](INSTALL.md). Short version: download the signed helper from
Releases, run `./install.sh`, load `extension/` at `chrome://extensions`.

## Develop & test

```sh
npm test                 # notary + shared crypto (golden vectors)
cd helper && swift test  # Swift canonicalization against the same vectors
node notary/src/main.js  # local notary on :8787
```

## License

MIT — see [LICENSE](LICENSE).
