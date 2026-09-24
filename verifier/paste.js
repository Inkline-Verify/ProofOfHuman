// Turns what a recipient has (the Verify link, and the message as they see
// it in their mail client) back into the fields the extension signed.
//
// Pure functions, no DOM: shared by verify.js and the tests.

// Format characters (zero-width spaces and the like) that mail clients and
// clipboards carry around. The extension strips them before signing.
export const INVISIBLE_RE = /[­؜᠎​‌‎‏⁠-⁤⁪-⁯﻿]/g;

// The footer line the extension appends after signing. Plain-text views
// wrap it in '*' and put the link on its own line; both are dropped.
const FOOTER_RE = /^\s*\S*\s*(proof of human|human verified|signed by a human|sent by a human|approved with touch id)\s*[·|-]\s*verified with inkline\s*\*?\s*$/i;
const RECEIPT_URL_RE = /^\s*<?\s*https?:\/\/[^\s>]*inkline[^\s>]*#[^\s>]+>?\*?\s*$/i;

// Where the quoted history starts in a reply. Gmail: "On <date> <name>
// <addr> wrote:" (possibly wrapped over two or three lines), then lines
// prefixed with ">". Outlook/Apple Mail: a separator line.
const QUOTE_START_RE = /^\s*on\s.+/i;
const WROTE_RE = /wrote:\s*$/i;
const SEPARATOR_RE = /^\s*(-+\s*original message\s*-+|_{5,}|-{5,})\s*$/i;

// The Verify link fragment is "<receipt>" or
// "<receipt>&from=…&to=…&cc=…&subject=…" (URL-encoded, lists comma-separated).
// The receipt is base64url, so the first "&" separates it from the headers.
export function parseFragment(fragment) {
  const raw = (fragment || '').replace(/^#/, '');
  if (!raw) return { receipt: '' };
  const amp = raw.indexOf('&');
  if (amp < 0) return { receipt: raw };
  const out = { receipt: raw.slice(0, amp) };
  const params = new URLSearchParams(raw.slice(amp + 1));
  for (const key of ['from', 'to', 'cc', 'subject']) {
    if (params.has(key)) out[key] = params.get(key);
  }
  return out;
}

// Returns { body, trimmedQuote } — the pasted text with the footer, the
// receipt link and any quoted earlier messages removed.
export function cleanPastedBody(text) {
  const lines = (text || '').replace(INVISIBLE_RE, '').split('\n');
  let cut = lines.length;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith('>') || SEPARATOR_RE.test(line)) { cut = i; break; }
    if (QUOTE_START_RE.test(line)) {
      // Gmail wraps long attribution lines; look ahead up to two lines.
      const joined = [line, lines[i + 1], lines[i + 2]].filter((l) => l !== undefined);
      let acc = '';
      let found = false;
      for (const part of joined) {
        acc += (acc ? ' ' : '') + part.trim();
        if (WROTE_RE.test(acc)) { found = true; break; }
      }
      if (found) { cut = i; break; }
    }
  }
  const kept = lines
    .slice(0, cut)
    .filter((line) => !FOOTER_RE.test(line) && !RECEIPT_URL_RE.test(line));
  return { body: kept.join('\n'), trimmedQuote: cut < lines.length };
}
