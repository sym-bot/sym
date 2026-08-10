'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * Duplex presence for intermittent harnesses — the daemon's delivery spool for
 * hosted agents (CTO design 2026-08-10, dev seat build).
 *
 * The failure: codex-mac sent a directed CMB; the reply was REFUSED at the
 * sender with "Peer not connected". Hosted agents are keyed by socketId in the
 * daemon, so when a harness socket closes the agent stops existing as an
 * addressable entity — a sender cannot even form the intent to reach it.
 *
 * The four cases below are the CTO's stated verification, kept verbatim in
 * intent. The fifth is mine: it pins the claim the whole design rests on — that
 * this is an EXTENSION of the node inbox rather than a second mailbox.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { nodeDir } = require('../lib/config');
const spool = require('../lib/hosted-spool');

let n = 0;
function makeAgent(base, { withIdentity = true, nodeId = null } = {}) {
  const name = `${base}-${Date.now()}-${n++}`;
  const dir = nodeDir(name);
  fs.mkdirSync(dir, { recursive: true });
  const id = nodeId || `019f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
  if (withIdentity) {
    fs.writeFileSync(path.join(dir, 'identity.json'),
      JSON.stringify({ nodeId: id, name, publicKey: 'pk', privateKey: 'sk' }));
  }
  return { name, nodeId: id, dir };
}

function envelope(focus, opts = {}) {
  return {
    from: opts.from || 'sender-node',
    fromName: opts.fromName || 'sender',
    to: opts.to || null,
    cmb: opts.cmb || { categories: { focus: { text: focus } } },
    encrypted: !!opts.encrypted,
    key: opts.key || `cmb-${focus.replace(/\W/g, '')}`,
  };
}

describe('hosted-agent delivery spool (duplex presence)', () => {
  it('accepts for a detached-but-known agent, and delivers it once on attach', async () => {
    const a = makeAgent('detached');
    assert.strictEqual(spool.verifyIdentity(a.name, a.nodeId).ok, true);

    spool.appendSpool(a.nodeId, envelope('sent while the harness was down'));

    const first = spool.drainSpool(a.nodeId);
    assert.strictEqual(first.drained, 1, 'attach drains the backlog');
    assert.strictEqual(first.messages[0].cmb.categories.focus.text, 'sent while the harness was down');

    // Second attach on a different socket must NOT re-deliver: the cursor, not
    // the socket write, is what marks a message handed over.
    const second = spool.drainSpool(a.nodeId);
    assert.strictEqual(second.drained, 0, 'a second attach does not double-deliver');
  });

  it('refuses a name with no identity on disk — a typo must not create state', async () => {
    const ghost = makeAgent('ghost', { withIdentity: false });
    const v = spool.verifyIdentity(ghost.name, ghost.nodeId);
    assert.strictEqual(v.ok, false);
    assert.match(v.reason, /no local identity/);
    assert.strictEqual(fs.existsSync(spool.spoolPath(ghost.nodeId)), false,
      'refusing must leave NO spool file behind');
  });

  it('refuses a claimed nodeId that does not match the identity on disk', async () => {
    // The CTO's original gate was "a name with an identity.json", which measured
    // 961 of 962 node directories — existence alone gates nothing. The nodeId
    // must match, because names are claimed and nodeIds are recorded.
    const a = makeAgent('impostor');
    const v = spool.verifyIdentity(a.name, '019fffff-dead-7000-8000-ffffffffffff');
    assert.strictEqual(v.ok, false);
    assert.match(v.reason, /does not match/);
  });

  it('stays bounded, and NEVER discards unread mail quietly', async () => {
    const a = makeAgent('bounded');
    const evictions = [];
    for (let i = 0; i < 8; i++) {
      const r = spool.appendSpool(a.nodeId, envelope(`msg ${i}`), { maxCount: 3 });
      evictions.push(...r.evicted);
    }
    const st = spool.spoolStatus(a.nodeId);
    assert.ok(st.held <= 3, 'the ring holds the cap');
    assert.ok(evictions.length > 0, 'unread mail destroyed to make room must be reported');
    assert.ok(evictions.every((m) => m.directed), 'the evicted records are surfaced whole, not counted');

    // A byte cap as well as a count cap: the count cap alone is the wrong
    // instrument when one big-text CMB outweighs a hundred small ones.
    const b = makeAgent('bytes');
    const big = 'x'.repeat(4096);
    for (let i = 0; i < 6; i++) spool.appendSpool(b.nodeId, envelope(big + i), { maxBytes: 8192 });
    assert.ok(spool.spoolStatus(b.nodeId).bytes <= 8192 * 2, 'the byte cap bounds the file');
  });

  it('never evicts BELOW the cursor — read mail is free, unread mail is loss', async () => {
    const a = makeAgent('cursor');
    for (let i = 0; i < 3; i++) spool.appendSpool(a.nodeId, envelope(`read ${i}`), { maxCount: 10 });
    assert.strictEqual(spool.drainSpool(a.nodeId).drained, 3, 'precondition: three are read');

    const r = spool.appendSpool(a.nodeId, envelope('the one that overflows'), { maxCount: 3 });
    assert.strictEqual(r.evicted.length, 0,
      'evicting an already-read message is recycling, not loss — it must not cry wolf');
  });

  it("does NOT write into the node's admitted inbox — spool and inbox are different objects", () => {
    // This asserts the OPPOSITE of my first cut, which wrote the spool into
    // <nodeDir>/inbox.json to get "one mailbox". codex-mac drew the boundary and
    // it is a correctness one, not a tidiness one: inbox.json is the ADMITTED feed
    // a running node writes after its OWN verify + SVAF. If the daemon could
    // append there, a custodian would be writing into a node's admitted memory and
    // receiver-autonomous admission would be bypassed by whoever holds the socket.
    const a = makeAgent('boundary');
    spool.appendSpool(a.nodeId, envelope('held for a detached identity'));

    assert.strictEqual(
      fs.existsSync(path.join(nodeDir(a.name), 'inbox.json')), false,
      "spooling must NOT create or touch the node's inbox.json",
    );
    assert.ok(fs.existsSync(spool.spoolPath(a.nodeId)), 'the envelope lives in its own store');
    assert.ok(!spool.spoolPath(a.nodeId).includes(nodeDir(a.name)),
      'and that store is not inside the node directory');
  });

  it('holds the envelope AS RECEIVED, needing no plaintext to be custodian', () => {
    // The daemon must be able to hold directed mail it cannot read. Where the
    // sender E2E-encrypted, ciphertext is what gets spooled and what comes back.
    const a = makeAgent('sealed');
    const sealed = { sealed: 'BASE64CIPHERTEXT', alg: 'x25519-xsalsa20' };
    spool.appendSpool(a.nodeId, envelope('unused', { cmb: sealed, encrypted: true }));

    const out = spool.drainSpool(a.nodeId);
    assert.strictEqual(out.drained, 1);
    assert.strictEqual(out.messages[0].encrypted, true, 'the envelope records that it is sealed');
    assert.deepStrictEqual(out.messages[0].cmb, sealed, 'and hands back exactly what arrived');
    assert.strictEqual(out.messages[0].cmb.categories, undefined,
      'the daemon never needed plaintext categories to do its job');
  });
});
