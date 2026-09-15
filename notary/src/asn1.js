// Minimal DER reader — enough to locate the App Attest nonce extension
// (OID 1.2.840.113635.100.8.2) inside a credential certificate and to walk
// its value down to the 32-byte nonce octet string.

// DER encoding of the OID content bytes for 1.2.840.113635.100.8.2.
const APP_ATTEST_NONCE_OID = Uint8Array.of(
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x02
);

export function derReadTlv(bytes, offset) {
  if (offset + 2 > bytes.length) throw new Error('der: truncated');
  const tag = bytes[offset];
  let len = bytes[offset + 1];
  let headerLen = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error('der: unsupported length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + bytes[offset + 2 + i];
    headerLen = 2 + n;
  }
  const contentStart = offset + headerLen;
  const contentEnd = contentStart + len;
  if (contentEnd > bytes.length) throw new Error('der: truncated content');
  return { tag, contentStart, contentEnd, next: contentEnd };
}

function indexOfBytes(haystack, needle, from = 0) {
  outer: for (let i = from; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

// Recursively search a DER blob for the first primitive OCTET STRING whose
// content is exactly 32 bytes.
function findOctetString32(bytes, start, end) {
  let o = start;
  while (o < end) {
    const tlv = derReadTlv(bytes, o);
    if (tlv.tag === 0x04 && tlv.contentEnd - tlv.contentStart === 32) {
      return bytes.slice(tlv.contentStart, tlv.contentEnd);
    }
    if (tlv.tag & 0x20) {
      // constructed: descend
      const inner = findOctetString32(bytes, tlv.contentStart, tlv.contentEnd);
      if (inner) return inner;
    }
    o = tlv.next;
  }
  return null;
}

// Extract the expected-nonce bytes from a credential certificate (raw DER).
// The extension value is: OCTET STRING { SEQUENCE { [1] { OCTET STRING nonce } } }.
export function extractAppAttestNonce(certDer) {
  // Locate the extension by its OID TLV (06 09 <oid bytes>).
  const oidTlv = new Uint8Array(2 + APP_ATTEST_NONCE_OID.length);
  oidTlv[0] = 0x06;
  oidTlv[1] = APP_ATTEST_NONCE_OID.length;
  oidTlv.set(APP_ATTEST_NONCE_OID, 2);

  let from = 0;
  while (true) {
    const at = indexOfBytes(certDer, oidTlv, from);
    if (at === -1) return null;
    let o = at + oidTlv.length;
    try {
      let tlv = derReadTlv(certDer, o);
      if (tlv.tag === 0x01) {
        // optional BOOLEAN critical flag
        tlv = derReadTlv(certDer, tlv.next);
      }
      if (tlv.tag === 0x04) {
        const nonce = findOctetString32(certDer, tlv.contentStart, tlv.contentEnd);
        if (nonce) return nonce;
      }
    } catch {
      // fall through and keep searching: the OID byte pattern can in theory
      // appear inside an unrelated value
    }
    from = at + 1;
  }
}
