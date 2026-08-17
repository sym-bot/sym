'use strict';

/**
 * The driver half of the two-stock-nodes gate — runs INSIDE the empty-directory install, so every
 * `require` below resolves against the packed artifact and nothing else. Kept separate from the
 * orchestrator for exactly that reason: a driver that lived in the repo tree would resolve sym's
 * checkout and quietly prove the wrong thing.
 *
 * HOME is redirected before the first require of sym, because lib/config computes the node-data
 * root from process.env.HOME at module-load time. Get this order wrong and the gate writes into
 * the developer's real mesh store — which is both a mess and a false pass, since a pre-existing
 * store could satisfy the survives-a-restart clause on its own.
 */

const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-stock-home-'));
process.env.HOME = sandbox;

const { SymNode } = require('@sym-bot/sym');
const { NullDiscovery } = require('@sym-bot/sym/lib/discovery.js');
const symPkg = require('@sym-bot/sym/package.json');

/** In-process duplex pair. The transport is mocked; everything above it is the real path. */
function bidirectionalPair() {
  const a = {};
  const b = {};
  const mk = (self, peer) => ({
    on: (ev, fn) => { self[ev] = fn; },
    send: (frame) => setImmediate(() => { if (peer.message) peer.message(frame); }),
    close: () => { if (self.close) self.close(); },
  });
  return [mk(a, b), mk(b, a)];
}

const waitFor = async (pred, timeoutMs = 15000) => {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (pred()) return true;
    await new Promise((r) => setTimeout(r, 50));
  }
  return false;
};

const FOCUS = 'two stock sym nodes prove the open runtime is self-sufficient';

(async () => {
  console.log(`  driving @sym-bot/sym ${symPkg.version} from ${path.dirname(require.resolve('@sym-bot/sym'))}`);

  const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const aName = `stock-a-${stamp}`;
  const bName = `stock-b-${stamp}`;

  const nodeA = new SymNode({ name: aName, silent: true, discovery: new NullDiscovery() });
  const nodeB = new SymNode({ name: bName, silent: true, discovery: new NullDiscovery() });
  await nodeA.start();
  await nodeB.start();

  const [tA, tB] = bidirectionalPair();
  tA.on('message', (frame) => nodeA._frameHandler.handle(nodeB.nodeId, bName, frame));
  tB.on('message', (frame) => nodeB._frameHandler.handle(nodeA.nodeId, aName, frame));
  nodeA._addPeer(nodeA._createPeer(tA, nodeB.nodeId, bName, true, 'bonjour'));
  nodeB._addPeer(nodeB._createPeer(tB, nodeA.nodeId, aName, false, 'bonjour'));
  await new Promise((r) => setTimeout(r, 400)); // let the handshake round-trip settle

  const received = [];
  nodeB.on('memory-received', (evt) => received.push(evt));

  // CREATE + SIGN — remember() mints the record and signs it with A's identity key.
  const sent = nodeA.remember({
    focus: FOCUS,
    issue: 'a released runtime can resolve, start, and still fail to exchange a single block',
    intent: 'exercise create → sign → wire → verify → evaluate → admit → store, then restart',
    motivation: 'the artifact users receive is not the artifact the repo tests',
    commitment: 'this gate blocks the release when any clause fails',
    perspective: 'node A, the sender',
    mood: { text: 'procedural', valence: 0, arousal: 0 },
  }, { to: nodeB.nodeId });
  assert.ok(sent && sent.key, 'CREATE: remember() must return a local entry with a CMB key');
  console.log(`  A created + signed ${sent.key}`);

  // EXCHANGE + VERIFY + EVALUATE — a memory-received event means the frame reached B's handler,
  // B verified the author's signature against the roster key, and SVAF ran on the record.
  const arrived = await waitFor(() => received.length > 0);
  assert.ok(arrived, 'EXCHANGE: B must receive and process A\'s record (no memory-received event)');
  const evt = received[0];
  console.log(`  B evaluated it → decision "${evt.decision}"`);

  // VERIFY — B checked A's signature against the roster key before any of this counted. The flag
  // is receiver-local bookkeeping, which is exactly why it is the right thing to assert: it is
  // what B concluded, not what A claimed.
  assert.strictEqual(evt.entry && evt.entry._cmbVerified, true,
    'VERIFY: B must mark the record signature-verified before admitting it');

  // ADMIT — the gate demands admission, not merely evaluation. A node that receives everything and
  // admits nothing is the exact silent failure this milestone exists to rule out.
  assert.notStrictEqual(evt.decision, 'rejected', 'ADMIT: B evaluated the record but refused it');
  const stored = evt.entry;
  assert.ok(stored, 'ADMIT: the admitted record must be handed back as a stored entry');

  // The durable, signed record of the verdict is the Admission Attestation on the remix — the
  // heuristic gate (the ratified production default) carries no `svaf` block on the entry, so
  // asserting one here would have gated on the neural path nobody runs.
  const admission = stored.cmb && stored.cmb.admission;
  assert.ok(admission, 'ADMIT: an admitted remix must carry its signed Admission Attestation');
  assert.strictEqual(admission.of, sent.key,
    `ADMIT: the attestation must bind A's record ${sent.key}, got ${admission.of}`);
  assert.strictEqual(admission.verdict, evt.decision,
    'ADMIT: the persisted verdict must be the verdict that was reached');
  assert.ok(stored.cmb.provenance && typeof stored.cmb.provenance.totalDrift === 'number',
    'ADMIT: the remix must record the drift it was admitted at');

  // LINEAGE, AS v2 DEFINES IT. Heuristic fusion keeps the incoming category text verbatim and v2
  // addresses by content alone, so an admitted block lands on the INCOMING BLOCK'S ADDRESS: it IS
  // that block, and descent holds by identity rather than by an edge (writing parents:[k] on a
  // block whose own address is k would be a self-edge no reachability walk can leave). Both shapes
  // are legitimate, so the gate asserts the property that must hold either way — the stored record
  // is reachable back to what A sent.
  const parents = (stored.cmb.metadata && stored.cmb.metadata.lineage && stored.cmb.metadata.lineage.parents) || [];
  const collapsed = stored.key === sent.key && stored.cmb.collapsed === true;
  assert.ok(collapsed || parents.includes(sent.key),
    `LINEAGE: stored remix must either collapse onto A's block ${sent.key} or parent it — ` +
    `got key ${stored.key}, parents [${parents.join(', ')}]`);
  console.log(`  B admitted + stored it (${collapsed ? 'collapsed onto A\'s block, descent by identity' : `parents [${parents.join(', ')}]`})`);

  // RESTART — stop B entirely and construct a fresh node on the same name/data dir. This is the
  // clause an in-memory store passes accidentally, so it is checked against a NEW process object,
  // not a re-read of the old one.
  await nodeB.stop();
  const nodeB2 = new SymNode({ name: bName, silent: true, discovery: new NullDiscovery() });
  await nodeB2.start();

  const recalled = nodeB2.recall(FOCUS) || [];
  const survivor = recalled.find((e) => {
    const p = (e.cmb && e.cmb.metadata && e.cmb.metadata.lineage && e.cmb.metadata.lineage.parents) || [];
    return e.key === sent.key || p.includes(sent.key);
  });
  assert.ok(survivor,
    `RESTART: after restarting B, the admitted record descending from ${sent.key} was not recallable ` +
    `(recall returned ${recalled.length} entr${recalled.length === 1 ? 'y' : 'ies'})`);
  assert.ok(survivor.cmb && survivor.cmb.admission && survivor.cmb.admission.of === sent.key,
    'RESTART: the survivor must still carry the signed attestation of its admission — a record that ' +
    'survives without its verdict cannot be audited later');
  console.log(`  after restart B recalled it, lineage intact`);

  await nodeA.stop();
  await nodeB2.stop();
  fs.rmSync(sandbox, { recursive: true, force: true });
  process.exit(0);
})().catch((err) => {
  console.error(`  ${err.message}`);
  console.error(`  node data kept at ${sandbox}`);
  process.exit(1);
});
