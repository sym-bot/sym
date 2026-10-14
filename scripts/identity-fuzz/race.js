'use strict';
/**
 * node scripts/identity-fuzz/race.js <kind> [rounds] [starters]: real processes start one agent at the same moment.
 * kind: legacy | pinned-mix | husk | husk-content | split | new | chaos (some SIGKILLed at a random moment) |
 * mixed (half of them 0.14.2) | only-0.14.2. After each round a clean start of this tree must load the original agent
 * (for new: the one agent all loaded) with its whole store, with exactly one identity of the name on disk.
 */
const fs = require('fs'); const path = require('path'); const cp = require('child_process');
const { LIB, waitForLoad, makeIdentity, put, legacy, newRoot, envFor, op } = require('./common');
const [kind, roundsText = '10', nText = '6'] = process.argv.slice(2);
const ROUNDS = Number(roundsText); const N = Number(nText); const NF = 200;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function startAll(specs, env) {
  const at = Date.now() + 500;
  return specs.map(({ lib, spec }) => {
    const code = `const t=${at}; while (Date.now() < t) {} require(${JSON.stringify(path.join(__dirname, 'op.js'))});`;
    const p = cp.spawn(process.execPath, ['-e', `process.argv.splice(1, 0, 'op'); ${code}`, lib, JSON.stringify(spec)], { env });
    let so = ''; p.stdout.on('data', (d) => { so += d; });
    return { p, done: new Promise((res) => p.on('close', (c, sig) => { const l = so.trim().split('\n').filter((x) => x.startsWith('{')).pop(); try { res(sig ? { killed: true } : JSON.parse(l)); } catch { res({ ok: false, err: 'CRASH' }); } })) };
  });
}
(async () => {
  const tally = {};
  for (let r = 0; r < ROUNDS; r++) {
    waitForLoad();
    const root = newRoot(`race-${kind}`); const nodes = path.join(root, 'state', 'nodes');
    const split = kind === 'split';
    const env = envFor(root, split ? { SYM_IDENTITY_DIR: path.join(root, 'idvol') } : {});
    const id = makeIdentity('agent');
    if (kind !== 'new') legacy(path.join(nodes, 'agent'), id, NF);
    if (split) { fs.rmSync(path.join(nodes, 'agent', 'identity.json')); put(path.join(root, 'idvol', 'agent', 'identity.json'), JSON.stringify(id)); }
    if (kind === 'husk' || kind === 'chaos') put(path.join(nodes, 'by-id', id.nodeId, 'lock.pid'), '2147483646\n');
    if (kind === 'husk-content') put(path.join(nodes, 'by-id', id.nodeId, 'cmbs', 'from-0142.json'), '{}');
    const specs = Array.from({ length: N }, (_, i) => {
      const pinned = (kind === 'pinned-mix' || kind === 'chaos') && i % 2;
      const lib = kind === 'only-0.14.2' || (kind === 'mixed' && i % 2) ? LIB.base : LIB.mine;
      return { lib, spec: pinned ? { op: 'load', name: 'agent', nodeId: id.nodeId, create: false } : { op: 'load', name: 'agent' } };
    });
    const procs = startAll(specs, env);
    if (kind === 'chaos') { await sleep(500 + Math.floor(Math.random() * 120)); for (const x of procs) if (Math.random() < 0.6) x.p.kill('SIGKILL'); }
    const res = await Promise.all(procs.map((x) => x.done));
    const after = op(LIB.mine, { op: 'load', name: 'agent' }, env);
    const ids = new Set(res.filter((x) => x.ok).map((x) => x.nodeId));
    const want = kind === 'new' ? [...ids][0] : id.nodeId;
    const roots = [path.join(nodes, 'by-id'), split ? path.join(root, 'idvol', 'by-id') : null].filter(Boolean);
    const named = new Set();
    for (const d of roots) { let es = []; try { es = fs.readdirSync(d); } catch { /* */ } for (const e of es) { if (e.startsWith('.')) continue; try { const j = JSON.parse(fs.readFileSync(path.join(d, e, 'identity.json'), 'utf8')); if (j.name === 'agent' && j.privateKey) named.add(e); } catch { /* */ } } }
    let store = NF; if (kind !== 'new') { try { store = fs.readdirSync(path.join(nodes, 'by-id', id.nodeId, 'cmbs')).filter((f) => /^c\d+\.json$/.test(f)).length; } catch { store = -1; } }
    const startersOk = res.every((x) => x.killed || !x.ok || x.nodeId === want);
    const good = after.ok && after.nodeId === want && (kind === 'new' || after.key === id.privateKey) && store === NF && named.size === 1 && startersOk;
    const verdict = good ? 'good' : 'BAD';
    tally[verdict] = (tally[verdict] || 0) + 1;
    const outs = res.map((x) => (x.killed ? 'killed' : x.ok ? (x.nodeId === want ? 'same' : 'NEW') : x.err));
    if (!good) console.log(`r${r}: starters=[${outs.join(',')}] after=${after.ok ? (after.nodeId === want ? 'same' : 'NEW') : `${after.err}: ${after.msg}`} identities named agent=${named.size} store=${store}`);
    fs.rmSync(root, { recursive: true, force: true });
  }
  console.log(`${kind}: ${ROUNDS} rounds of ${N} starters`, JSON.stringify(tally));
})();
