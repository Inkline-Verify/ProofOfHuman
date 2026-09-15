// Minimal CBOR (RFC 8949) codec — exactly what App Attest objects need.
// Decode supports: unsigned/negative integers, byte strings, text strings,
// definite-length arrays and maps (text keys), tags (unwrapped), booleans,
// null, and floats. Indefinite lengths are rejected.
// Encode exists for the test fixtures that fabricate attestation objects.

export function cborDecode(bytes) {
  const [value, offset] = readItem(bytes, 0);
  if (offset !== bytes.length) throw new Error('cbor: trailing bytes');
  return value;
}

function readItem(b, o) {
  if (o >= b.length) throw new Error('cbor: truncated');
  const initial = b[o];
  const major = initial >> 5;
  const info = initial & 0x1f;
  let arg;
  let off = o + 1;
  if (info < 24) {
    arg = info;
  } else if (info === 24) {
    arg = b[off];
    off += 1;
  } else if (info === 25) {
    arg = (b[off] << 8) | b[off + 1];
    off += 2;
  } else if (info === 26) {
    arg = b[off] * 0x1000000 + ((b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]);
    off += 4;
  } else if (info === 27) {
    arg = 0;
    for (let i = 0; i < 8; i++) arg = arg * 256 + b[off + i];
    if (!Number.isSafeInteger(arg)) throw new Error('cbor: 64-bit value too large');
    off += 8;
  } else {
    throw new Error('cbor: indefinite/reserved length unsupported');
  }
  if (off > b.length) throw new Error('cbor: truncated');

  switch (major) {
    case 0:
      return [arg, off];
    case 1:
      return [-1 - arg, off];
    case 2: {
      if (off + arg > b.length) throw new Error('cbor: truncated byte string');
      return [b.slice(off, off + arg), off + arg];
    }
    case 3: {
      if (off + arg > b.length) throw new Error('cbor: truncated text string');
      const text = new TextDecoder('utf-8', { fatal: true }).decode(b.subarray(off, off + arg));
      return [text, off + arg];
    }
    case 4: {
      const out = [];
      let p = off;
      for (let i = 0; i < arg; i++) {
        const [v, next] = readItem(b, p);
        out.push(v);
        p = next;
      }
      return [out, p];
    }
    case 5: {
      const out = {};
      let p = off;
      for (let i = 0; i < arg; i++) {
        const [k, afterKey] = readItem(b, p);
        if (typeof k !== 'string') throw new Error('cbor: non-text map key unsupported');
        const [v, next] = readItem(b, afterKey);
        out[k] = v;
        p = next;
      }
      return [out, p];
    }
    case 6: {
      // Tag: unwrap and return the tagged value.
      return readItem(b, off);
    }
    case 7: {
      if (info === 20) return [false, off];
      if (info === 21) return [true, off];
      if (info === 22) return [null, off];
      if (info === 25 || info === 26 || info === 27) {
        const size = info === 25 ? 2 : info === 26 ? 4 : 8;
        const view = new DataView(b.buffer, b.byteOffset + o + 1, size);
        const value = info === 25 ? halfToFloat(view.getUint16(0)) : info === 26 ? view.getFloat32(0) : view.getFloat64(0);
        return [value, o + 1 + size];
      }
      throw new Error('cbor: unsupported simple value');
    }
    default:
      throw new Error('cbor: unreachable');
  }
}

function halfToFloat(h) {
  const sign = (h & 0x8000) ? -1 : 1;
  const exp = (h >> 10) & 0x1f;
  const frac = h & 0x3ff;
  if (exp === 0) return sign * frac * 2 ** -24;
  if (exp === 31) return frac ? NaN : sign * Infinity;
  return sign * (1024 + frac) * 2 ** (exp - 25);
}

export function cborEncode(value) {
  const chunks = [];
  writeItem(value, chunks);
  const total = chunks.reduce((s, c) => s + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

function writeHead(major, arg, chunks) {
  if (arg < 24) {
    chunks.push(Uint8Array.of((major << 5) | arg));
  } else if (arg < 0x100) {
    chunks.push(Uint8Array.of((major << 5) | 24, arg));
  } else if (arg < 0x10000) {
    chunks.push(Uint8Array.of((major << 5) | 25, arg >> 8, arg & 0xff));
  } else if (arg < 0x100000000) {
    chunks.push(
      Uint8Array.of((major << 5) | 26, (arg >>> 24) & 0xff, (arg >>> 16) & 0xff, (arg >>> 8) & 0xff, arg & 0xff)
    );
  } else {
    throw new Error('cbor: value too large to encode');
  }
}

function writeItem(v, chunks) {
  if (v === null) {
    chunks.push(Uint8Array.of(0xf6));
  } else if (typeof v === 'boolean') {
    chunks.push(Uint8Array.of(v ? 0xf5 : 0xf4));
  } else if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) throw new Error('cbor: only integers encodable');
    if (v >= 0) writeHead(0, v, chunks);
    else writeHead(1, -1 - v, chunks);
  } else if (typeof v === 'string') {
    const bytes = new TextEncoder().encode(v);
    writeHead(3, bytes.length, chunks);
    chunks.push(bytes);
  } else if (v instanceof Uint8Array) {
    writeHead(2, v.length, chunks);
    chunks.push(v);
  } else if (Array.isArray(v)) {
    writeHead(4, v.length, chunks);
    for (const item of v) writeItem(item, chunks);
  } else if (typeof v === 'object') {
    const keys = Object.keys(v);
    writeHead(5, keys.length, chunks);
    for (const k of keys) {
      writeItem(k, chunks);
      writeItem(v[k], chunks);
    }
  } else {
    throw new Error('cbor: unsupported type');
  }
}
