// Canonical JSON v1. Every signature in Inkline is computed over bytes
// produced by this serializer, so it must be byte-identical across
// implementations (see helper/Sources/InklineCore/CJSON.swift).
//
// Rules:
//   - objects: keys sorted by UTF-16 code units, no whitespace
//   - strings: JSON.stringify escaping (", \, \b \t \n \f \r, other
//     control chars as \u00xx lowercase; non-ASCII emitted verbatim)
//   - numbers: safe integers only
//   - allowed values: object, array, string, integer, boolean, null

export function cjson(value) {
  return ser(value);
}

function ser(v) {
  if (v === null) return 'null';
  const t = typeof v;
  if (t === 'boolean') return v ? 'true' : 'false';
  if (t === 'number') {
    if (!Number.isSafeInteger(v)) throw new Error('cjson: numbers must be safe integers');
    return String(v);
  }
  if (t === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(ser).join(',') + ']';
  if (t === 'object') {
    const keys = Object.keys(v).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + ser(v[k])).join(',') + '}';
  }
  throw new Error('cjson: unsupported type ' + t);
}
