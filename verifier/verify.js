// Offline receipt verification. Uses the same shared modules as the notary,
// so a receipt that verifies here verifies everywhere. Serve this directory
// alongside shared/ (e.g. `npx serve` from the repository root).

import { verifyReceipt } from '../shared/receipt.js';

const $ = (id) => document.getElementById(id);

const CHECK_LABELS = {
  decode: 'Receipt decodes',
  payload: 'Payload is well-formed',
  contentHash: 'Email matches the signed content hash',
  kid: 'Presence key matches its fingerprint',
  presenceSig: 'Touch ID–signed presence signature verifies',
  notaryKid: 'Receipt was issued by the trusted notary',
  notarySig: 'Notary co-signature verifies',
};

function splitAddresses(value) {
  return value
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

// The Verify link in an email footer carries the receipt in the URL fragment
// (which never reaches any server). Pre-fill it, and pre-fill the deploy's
// default notary key.
function prefill() {
  const fragment = window.location.hash.slice(1);
  if (fragment) $('receipt').value = fragment;

  const config = window.INKLINE_VERIFIER_CONFIG ?? {};
  if (config.NOTARY_PUB && !$('notaryPub').value) {
    $('notaryPub').value = config.NOTARY_PUB;
    if (config.NOTARY_NAME) {
      $('notaryPub').title = 'Default notary: ' + config.NOTARY_NAME;
    }
  }
}
prefill();
window.addEventListener('hashchange', prefill);

// Arriving without a receipt in the link means the user must paste one.
const advanced = document.getElementById('advanced');
if (advanced && !$('receipt').value) advanced.open = true;

$('verify').addEventListener('click', async () => {
  const result = $('result');
  result.textContent = 'Verifying…';

  // The received email contains the Inkline footer, but the footer was
  // injected AFTER signing, so it is not part of the signed content. Drop
  // any footer line so pasting the message exactly as received verifies.
  // Mail clients and clipboards can carry invisible format characters
  // (zero-width spaces and the like). The extension strips them before
  // signing, so strip them from pasted input too.
  const INVISIBLE_RE = /[\u00ad\u061c\u180e\u200b\u200c\u200e\u200f\u2060-\u2064\u206a-\u206f\ufeff]/g;
  const body = $('body').value
    .replace(INVISIBLE_RE, '')
    .split('\n')
    .filter((line) => !/^\s*\S*\s*(proof of human|human verified|signed by a human|sent by a human|approved with touch id)\s*[·|-]\s*verified with inkline\s*$/i.test(line.trim()))
    .join('\n');

  const email = {
    from: $('from').value,
    to: splitAddresses($('to').value),
    cc: splitAddresses($('cc').value),
    subject: $('subject').value.replace(INVISIBLE_RE, ''),
    body,
  };

  let outcome;
  try {
    outcome = await verifyReceipt({
      receipt: $('receipt').value.trim(),
      email,
      notaryPub: $('notaryPub').value.trim(),
    });
  } catch (err) {
    outcome = { ok: false, checks: {}, error: String(err && err.message ? err.message : err) };
  }

  const verdict = document.createElement('div');
  verdict.className = 'verdict ' + (outcome.ok ? 'ok' : 'bad');
  verdict.textContent = outcome.ok
    ? 'Verified: a person approved exactly this content with Touch ID.'
    : 'NOT verified' + (outcome.error ? ' — ' + outcome.error : '');
  if (outcome.ok) {
    const tier = document.createElement('div');
    tier.className = 'tier';
    tier.textContent = 'Trust tier: not hardware-attested. This receipt cannot yet prove the key lives in a Secure Enclave or that Touch ID was used; that proof arrives with App Attest on macOS 27. Read it as a good-faith signal.';
    verdict.appendChild(tier);
    const scope = document.createElement('div');
    scope.className = 'tier';
    scope.textContent = 'Covers the message text, subject, and addresses. Images and attachments are not signed.';
    verdict.appendChild(scope);
  }

  const list = document.createElement('ul');
  list.className = 'checks';
  for (const [key, label] of Object.entries(CHECK_LABELS)) {
    const li = document.createElement('li');
    li.className = outcome.checks[key] ? 'pass' : 'fail';
    li.textContent = label;
    list.appendChild(li);
  }

  const panel = document.createElement('div');
  panel.className = 'panel ' + (outcome.ok ? 'ok' : 'bad');
  panel.append(verdict, list);

  if (outcome.ok && outcome.payload) {
    const when = document.createElement('p');
    when.className = 'tier';
    const date = new Date(outcome.payload.iat * 1000);
    when.textContent = `Approved at ${date.toLocaleString()} by presence key ${outcome.payload.kid.slice(0, 12)}…`;
    panel.appendChild(when);
  }

  if (outcome.ok) {
    const cta = document.createElement('p');
    cta.className = 'cta';
    cta.append('Want your emails to carry this proof? ');
    const link = document.createElement('a');
    link.href = 'https://www.inklineverify.com/docs';
    link.target = '_blank';
    link.rel = 'noreferrer';
    link.textContent = 'Get Inkline';
    cta.append(link, ' — free, open source, two-minute install.');
    panel.appendChild(cta);
  }

  result.replaceChildren(panel);
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
});
