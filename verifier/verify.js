// Offline receipt verification. Uses the same shared modules as the notary,
// so a receipt that verifies here verifies everywhere. Serve this directory
// alongside shared/ (e.g. `npx serve` from the repository root).

import { verifyReceipt } from '../shared/receipt.js';
import { parseFragment, cleanPastedBody, INVISIBLE_RE } from './paste.js';

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
  // Since extension 0.2.1 the link also carries the signed headers, so the
  // recipient only pastes the message text. Older links carry the receipt
  // alone and the fields stay editable either way.
  const link = parseFragment(window.location.hash);
  if (link.receipt) $('receipt').value = link.receipt;
  for (const key of ['from', 'to', 'cc', 'subject']) {
    if (link[key] !== undefined) $(key).value = link[key];
  }

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

  // The footer and the quoted earlier messages were never signed (the
  // footer is injected after signing; Gmail collapses the quote out of the
  // compose box). Drop both so pasting the message as received verifies.
  const { body, trimmedQuote } = cleanPastedBody($('body').value);

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
    tier.textContent = outcome.tier === 'enclave-attested'
      ? 'Trust tier: hardware-attested. Apple\u2019s App Attest certified that the signing key was generated inside a genuine Secure Enclave in the signed Inkline helper, and this receipt carried a fresh per-send attestation.'
      : 'Verified: signed with Touch ID on the sender\u2019s enrolled Mac and witnessed by the notary. Issued before hardware attestation became part of every stamp \u2014 today\u2019s stamps also carry Apple\u2019s certification of the signing key.';
    verdict.appendChild(tier);
    const scope = document.createElement('div');
    scope.className = 'tier';
    scope.textContent = 'Covers the message text, subject, and addresses. Images and attachments are not signed.'
      + (trimmedQuote ? ' Quoted earlier messages were left out: only the new text was signed.' : '');
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
