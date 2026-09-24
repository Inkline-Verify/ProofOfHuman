import test from 'node:test';
import assert from 'node:assert/strict';
import { parseFragment, cleanPastedBody } from './paste.js';

test('fragment with only a receipt', () => {
  assert.deepEqual(parseFragment('#eyJhYmMifQ'), { receipt: 'eyJhYmMifQ' });
  assert.deepEqual(parseFragment(''), { receipt: '' });
});

test('fragment with headers', () => {
  const q = new URLSearchParams({ from: 'a@x.io', to: 'b@x.io,c@x.io', cc: '', subject: 'Re: O-1A | Next Steps' });
  const f = parseFragment('#eyJhYmMifQ&' + q.toString());
  assert.equal(f.receipt, 'eyJhYmMifQ');
  assert.equal(f.from, 'a@x.io');
  assert.equal(f.to, 'b@x.io,c@x.io');
  assert.equal(f.cc, '');
  assert.equal(f.subject, 'Re: O-1A | Next Steps');
});

const NEW = "Thanks so much!\n\nGreat to meet you Alee. Let me know once you've filled out the agent\ninformation so I can move on the the recommender section.\n\nBest,\nGeorgina";

test('html view: footer line and quoted thread dropped', () => {
  const pasted = NEW + '\n\nSigned by a human · Verified with Inkline\n\nOn Wed, Sep 23, 2026 at 5:58 PM Adrian Garcia <adrian@globalcitizens.ai> wrote:\nHi Georgina,\n\nThank you for confirming.';
  const r = cleanPastedBody(pasted);
  assert.equal(r.body.trim(), NEW);
  assert.equal(r.trimmedQuote, true);
});

test('plain-text view: starred footer, receipt link line, wrapped attribution, > quotes', () => {
  const pasted = NEW + '\n\n*Signed by a human · Verified with Inkline\n<https://verify.inklineverify.com/verifier/#eyJub3RhcnkiOnsi>*\n\nOn Wed, Sep 23, 2026 at 5:58 PM Adrian Garcia <adrian@globalcitizens.ai>\nwrote:\n\n> Hi Georgina,\n>\n> Thank you.';
  const r = cleanPastedBody(pasted);
  assert.equal(r.body.trim(), NEW);
  assert.equal(r.trimmedQuote, true);
});

test('attribution wrapped over three lines', () => {
  const pasted = 'Let me know!\n\nOn Mon, Sep 21, 2026 at 5:57 AM Georgina Alcaraz <\ngigialcaraz38@gmail.com> wrote:\n\n>> hi';
  assert.equal(cleanPastedBody(pasted).body.trim(), 'Let me know!');
});

test('a sentence starting with "On" but not an attribution is kept', () => {
  const pasted = 'On Monday I will send the list.\n\nBest,\nG';
  const r = cleanPastedBody(pasted);
  assert.equal(r.body, pasted);
  assert.equal(r.trimmedQuote, false);
});

test('outlook separator and invisible characters', () => {
  const pasted = 'Hi​ there\n\n-----Original Message-----\nFrom: x';
  assert.equal(cleanPastedBody(pasted).body.trim(), 'Hi there');
});

test('no quote: body untouched apart from footer', () => {
  const r = cleanPastedBody('Hello\n\nProof of human · Verified with Inkline');
  assert.equal(r.body.trim(), 'Hello');
  assert.equal(r.trimmedQuote, false);
});
