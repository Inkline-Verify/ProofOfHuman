// Base64url (RFC 4648 §5, no padding) and small byte helpers.
// Runs unchanged in browsers and Node >= 20 (WebCrypto via globalThis.crypto).

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const REVERSE = new Map([...ALPHABET].map((c, i) => [c, i]));

export function b64uEncode(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = i + 1 < bytes.length ? bytes[i + 1] : undefined;
    const c = i + 2 < bytes.length ? bytes[i + 2] : undefined;
    out += ALPHABET[a >> 2];
    out += ALPHABET[((a & 3) << 4) | (b === undefined ? 0 : b >> 4)];
    if (b !== undefined) out += ALPHABET[((b & 15) << 2) | (c === undefined ? 0 : c >> 6)];
    if (c !== undefined) out += ALPHABET[c & 63];
  }
  return out;
}

export function b64uDecode(str) {
  if (typeof str !== 'string' || str.length % 4 === 1) {
    throw new Error('b64u: invalid length');
  }
  const out = new Uint8Array(Math.floor((str.length * 3) / 4));
  let acc = 0;
  let bits = 0;
  let n = 0;
  for (const ch of str) {
    const v = REVERSE.get(ch);
    if (v === undefined) throw new Error('b64u: invalid character');
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[n++] = (acc >> bits) & 0xff;
    }
  }
  return out.subarray(0, n);
}

export function utf8(str) {
  return new TextEncoder().encode(str);
}

export function utf8Decode(bytes) {
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

export function concatBytes(...arrays) {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export async function sha256(bytes) {
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes));
}
