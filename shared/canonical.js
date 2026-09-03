// Inkline canonical email v1.
//
// Email infrastructure rewrites messages in transit (line endings, MIME
// encodings, whitespace, HTML wrapping). The signed content hash is therefore
// computed over a canonical form that survives those transformations, and a
// recipient recomputes it from the message they received.
//
// canonText, applied to every field:
//   1. Unicode NFC
//   2. lowercase
//   3. Unicode NFC again (lowercasing can denormalize)
//   4. collapse every run of whitespace (the exact set below) to one space
//   5. trim leading/trailing spaces
//
// The whitespace set is fixed by this spec (it mirrors ECMAScript \s) so that
// every implementation matches scalar-for-scalar. See
// helper/Sources/InklineCore/Canonical.swift for the Swift twin.

import { cjson } from './cjson.js';
import { b64uEncode, sha256, utf8 } from './b64.js';

const WS_RUN = new RegExp(
  '[' +
    '\\t\\n\\u000b\\f\\r \\u00a0\\u1680' +
    '\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff' +
    ']+',
  'gu'
);

export function canonText(s) {
  if (typeof s !== 'string') throw new Error('canonText: expected string');
  return s
    .normalize('NFC')
    .toLowerCase()
    .normalize('NFC')
    .replace(WS_RUN, ' ')
    .replace(/^ | $/g, '');
}

export function canonicalEmail({ from, to = [], cc = [], subject = '', body = '' }) {
  if (typeof from !== 'string' || from.length === 0) {
    throw new Error('canonicalEmail: from is required');
  }
  if (!Array.isArray(to) || !Array.isArray(cc)) {
    throw new Error('canonicalEmail: to/cc must be arrays');
  }
  return {
    v: 1,
    from: canonText(from),
    to: to.map(canonText),
    cc: cc.map(canonText),
    subject: canonText(subject),
    body: canonText(body),
  };
}

export async function emailContentHash(email) {
  return b64uEncode(await sha256(utf8(cjson(canonicalEmail(email)))));
}
