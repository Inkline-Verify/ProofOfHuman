// Synthetic App Attest material for tests.
//
// Real attestations can only be produced by Apple hardware inside a signed
// app, so the test suite fabricates structurally identical objects — same
// CBOR layout, same authenticator data, same nonce-in-certificate extension —
// chained to a locally generated fixture CA. The verifier under test accepts
// an injectable root, so the full verification path (chain, nonce, keyId,
// counters) is exercised for real; only Apple's root is substituted.

import { execFileSync } from 'node:child_process';
import { createHash, createSign, randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { cborEncode } from '../../src/cbor.js';

const OID_APP_ATTEST_NONCE = '1.2.840.113635.100.8.2';

function openssl(args, cwd) {
  return execFileSync('openssl', args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
}

function sha256(buf) {
  return createHash('sha256').update(buf).digest();
}

function genP256Key(dir, name) {
  openssl(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', `${name}.key`], dir);
  return readFileSync(join(dir, `${name}.key`), 'utf8');
}

function rawPubFromKeyFile(dir, name) {
  const spki = openssl(['ec', '-in', `${name}.key`, '-pubout', '-outform', 'DER'], dir);
  const point = spki.subarray(spki.length - 65);
  if (point[0] !== 0x04) throw new Error('fixture: unexpected SPKI layout');
  return Buffer.from(point);
}

// Creates a fixture PKI: root CA and an intermediate "attestation CA".
export function makeTestPki() {
  const dir = mkdtempSync(join(tmpdir(), 'inkline-pki-'));
  genP256Key(dir, 'root');
  openssl(
    ['req', '-x509', '-new', '-key', 'root.key', '-subj', '/CN=Fixture App Attest Root CA',
     '-days', '30', '-sha256', '-out', 'root.pem'],
    dir
  );
  genP256Key(dir, 'int');
  openssl(['req', '-new', '-key', 'int.key', '-subj', '/CN=Fixture App Attest CA 1', '-out', 'int.csr'], dir);
  writeFileSync(join(dir, 'ca-ext.cnf'), '[v3_ca]\nbasicConstraints=critical,CA:TRUE\n');
  openssl(
    ['x509', '-req', '-in', 'int.csr', '-CA', 'root.pem', '-CAkey', 'root.key',
     '-CAcreateserial', '-days', '30', '-sha256',
     '-extfile', 'ca-ext.cnf', '-extensions', 'v3_ca', '-out', 'int.pem'],
    dir
  );
  return {
    dir,
    rootPem: readFileSync(join(dir, 'root.pem'), 'utf8'),
  };
}

function buildAttestAuthData({ appId, keyId, aaguid }) {
  const rpIdHash = sha256(Buffer.from(appId, 'utf8'));
  const flags = Buffer.of(0x40); // attested credential data present
  const counter = Buffer.alloc(4); // 0
  const aaguidBytes = Buffer.alloc(16);
  aaguidBytes.set(Buffer.from(aaguid, 'utf8'));
  const credIdLen = Buffer.of(0, 32);
  return Buffer.concat([rpIdHash, flags, counter, aaguidBytes, credIdLen, keyId]);
}

// Fabricates a complete attestation object for the given client data hash.
export function makeAttestation({ pki, appId, clientDataHash, aaguid = 'appattestdevelop' }) {
  const dir = pki.dir;
  const name = 'cred-' + randomUUID().slice(0, 8);
  const credKeyPem = genP256Key(dir, name);
  const pubRaw = rawPubFromKeyFile(dir, name);
  const keyId = sha256(pubRaw);

  const authData = buildAttestAuthData({ appId, keyId, aaguid });
  const nonce = sha256(Buffer.concat([authData, clientDataHash]));

  // Credential certificate carrying the nonce extension:
  // SEQUENCE { [1] { OCTET STRING nonce } }
  const extDer = '3024a1220420' + nonce.toString('hex');
  writeFileSync(
    join(dir, `${name}-ext.cnf`),
    `[cred]\nbasicConstraints=CA:FALSE\n${OID_APP_ATTEST_NONCE}=DER:${extDer}\n`
  );
  openssl(['req', '-new', '-key', `${name}.key`, '-subj', '/CN=Fixture Credential', '-out', `${name}.csr`], dir);
  openssl(
    ['x509', '-req', '-in', `${name}.csr`, '-CA', 'int.pem', '-CAkey', 'int.key',
     '-CAcreateserial', '-days', '30', '-sha256',
     '-extfile', `${name}-ext.cnf`, '-extensions', 'cred', '-out', `${name}.pem`],
    dir
  );
  const credDer = openssl(['x509', '-in', `${name}.pem`, '-outform', 'DER'], dir);
  const intDer = openssl(['x509', '-in', 'int.pem', '-outform', 'DER'], dir);

  const attestation = cborEncode({
    fmt: 'apple-appattest',
    attStmt: {
      x5c: [new Uint8Array(credDer), new Uint8Array(intDer)],
      receipt: new Uint8Array(0),
    },
    authData: new Uint8Array(authData),
  });

  return { attestation, keyId: new Uint8Array(keyId), credKeyPem, pubRaw: new Uint8Array(pubRaw) };
}

// Fabricates an assertion by the credential key over the given client data.
export function makeAssertion({ credKeyPem, appId, clientData, counter }) {
  const rpIdHash = sha256(Buffer.from(appId, 'utf8'));
  const authData = Buffer.concat([
    rpIdHash,
    Buffer.of(0x40),
    (() => {
      const b = Buffer.alloc(4);
      b.writeUInt32BE(counter);
      return b;
    })(),
  ]);
  const clientDataHash = sha256(Buffer.from(clientData));
  const signature = createSign('sha256')
    .update(Buffer.concat([authData, clientDataHash]))
    .sign(credKeyPem);
  return cborEncode({
    signature: new Uint8Array(signature),
    authenticatorData: new Uint8Array(authData),
  });
}
