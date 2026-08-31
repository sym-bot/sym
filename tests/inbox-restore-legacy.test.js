#!/usr/bin/env node
'use strict';
/**
 * Legacy inbox entries restore with minted seq/id instead of being lost or unfetchable.
 *
 * _loadInbox() trusted persisted messages verbatim. Two legacy shapes exist on real disks
 * (seq and id were introduced together at v0.10.0; the durable feed crossed that boundary,
 * and codex-mac crossed plugin 0.8.0→0.9.2 in one evening):
 *   A. entries with NEITHER seq nor id — `m.seq > cursor` is false forever, so they NEVER
 *      surface: silent loss wearing a working inbox.
 *   B. entries with seq but NO id — they surface rendered as "[undefined]" and no fetch call
 *      can ever retrieve them. This is the exact symptom codex-mac reported on 2026-08-31:
 *      "truncated in sym_receive without an identifier, so sym_fetch could not retrieve them".
 * Redelivery of a legacy no-seq entry that MIGHT already have been drained is the chosen
 * failure: surfacing twice is recoverable, silent loss is not.
 */
require('./_isolate-home');
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { SymNode } = require('../lib/node');

const NAME = 'legacy-inbox-node';
const mk = () => new SymNode({ name: NAME, autoStart: false, silent: true });

test('shape B: a persisted entry with seq but no id restores fetchable, not [undefined]', () => {
  const n0 = mk();
  fs.mkdirSync(path.dirname(n0._inboxFile), { recursive: true });
  fs.writeFileSync(n0._inboxFile, JSON.stringify({
    seq: 2, cursor: 0,
    messages: [
      { seq: 1, from: 'codex-mac', content: 'x'.repeat(3500), receivedAt: Date.now(), directed: true },
      { seq: 2, id: 'in0002', from: 'codex-mac', content: 'has id', receivedAt: Date.now() },
    ],
  }));
  const n = mk();
  const { messages } = n.inbox({ peek: true });
  assert.equal(messages.length, 2, 'both entries surface');
  for (const m of messages) {
    assert.match(String(m.id), /^in\d{4}$/, `every surfaced entry carries a mintable id, got ${m.id}`);
    assert.ok(n.inboxGet(m.id), `inboxGet(${m.id}) returns the entry`);
  }
  assert.equal(n.inboxGet(messages[0].id).content.length, 3500, 'the 3.5KB directed body is retrievable in full');
});

test('shape A: a persisted entry with neither seq nor id surfaces once instead of vanishing', () => {
  const n0 = mk();
  fs.mkdirSync(path.dirname(n0._inboxFile), { recursive: true });
  fs.writeFileSync(n0._inboxFile, JSON.stringify({
    seq: 5, cursor: 5,
    messages: [ { from: 'codex-mac', content: 'pre-seq era entry', receivedAt: Date.now() } ],
  }));
  const n = mk();
  const { messages } = n.inbox({ peek: true });
  assert.equal(messages.length, 1, 'the no-seq entry surfaces (redelivery beats silent loss)');
  assert.match(String(messages[0].id), /^in\d{4}$/);
  assert.ok(messages[0].seq > 5, 'minted seq lands above the persisted cursor so it is drainable');
});

test('minting does not collide with the next live push', () => {
  const n0 = mk();
  fs.mkdirSync(path.dirname(n0._inboxFile), { recursive: true });
  fs.writeFileSync(n0._inboxFile, JSON.stringify({
    seq: 3, cursor: 0,
    messages: [ { seq: 3, from: 'p', content: 'no id', receivedAt: Date.now() } ],
  }));
  const n = mk();
  n._pushInbox({ source: 'peer', content: 'fresh', cmb: { categories: { focus: { text: 'fresh' } }, metadata: { key: 'k1' } } });
  const ids = n.inbox({ peek: true }).messages.map((m) => m.id);
  assert.equal(new Set(ids).size, ids.length, `ids must be unique, got ${ids.join(',')}`);
});
