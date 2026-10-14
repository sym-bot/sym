'use strict';
/**
 * node scripts/identity-fuzz/kill.js <scenario>: kill -9 at every mutating fs step (before it and after it) of one
 * operation of this tree, then check what follows. Migration scenarios: this tree's next start by name and pinned (the
 * same agent, its whole store, every copy of its key 0600), a 0.14.2 rollback, a 0.13 rollback, and this tree then
 * 0.14.2. Export: never a startable source beside a complete bundle; resume or abort; the move completes on another
 * host. Import: the retry completes, and the agent loads by pin, by name, and under 0.14.2.
 *
 * Scenarios: legacy legacy-pinned legacy-husk legacy-husk-content split mint mint-split xvol-byid xvol-identity
 * (the xvol ones need SYM_FUZZ_FAR on another volume) export export-split import import-split.
 */
const fs = require('fs'); const path = require('path'); const cp = require('child_process');
const { LIB, FAR, waitForLoad, makeIdentity, put, legacy, newRoot, envFor, op } = require('./common');
const scenario = process.argv[2];
const NF = 12;
const SC = {
  legacy: (root) => { const id = makeIdentity('agent'); legacy(path.join(root, 'state/nodes/agent'), id, NF); return { id, spec: { op: 'load', name: 'agent' } }; },
  'legacy-pinned': (root) => { const id = makeIdentity('agent'); legacy(path.join(root, 'state/nodes/agent'), id, NF); return { id, spec: { op: 'load', name: 'agent', nodeId: id.nodeId, create: false } }; },
  'legacy-husk': (root) => { const id = makeIdentity('agent'); legacy(path.join(root, 'state/nodes/agent'), id, NF); put(path.join(root, 'state/nodes/by-id', id.nodeId, 'lock.pid'), '2147483646\n'); return { id, spec: { op: 'load', name: 'agent' } }; },
  'legacy-husk-content': (root) => {
    const id = makeIdentity('agent'); legacy(path.join(root, 'state/nodes/agent'), id, NF);
    put(path.join(root, 'state/nodes/by-id', id.nodeId, 'cmbs', 'c0.json'), '{"husk":1}'); put(path.join(root, 'state/nodes/by-id', id.nodeId, 'extra.json'), '{}');
    return { id, spec: { op: 'load', name: 'agent' } };
  },
  split: (root) => {
    const id = makeIdentity('agent'); legacy(path.join(root, 'state/nodes/agent'), id, NF); fs.rmSync(path.join(root, 'state/nodes/agent/identity.json'));
    put(path.join(root, 'idvol/agent/identity.json'), JSON.stringify(id)); return { id, env: { SYM_IDENTITY_DIR: path.join(root, 'idvol') }, spec: { op: 'load', name: 'agent' } };
  },
  'xvol-byid': (root) => {
    const id = makeIdentity('agent'); legacy(path.join(root, 'state/nodes/agent'), id, NF);
    const far = fs.mkdtempSync(path.join(FAR, 'kf-')); fs.symlinkSync(far, path.join(root, 'state/nodes/by-id')); return { id, far, spec: { op: 'load', name: 'agent' } };
  },
  'xvol-identity': (root) => {
    const id = makeIdentity('agent'); legacy(path.join(root, 'state/nodes/agent'), id, NF); fs.rmSync(path.join(root, 'state/nodes/agent/identity.json'));
    put(path.join(root, 'idvol/agent/identity.json'), JSON.stringify(id));
    const far = fs.mkdtempSync(path.join(FAR, 'kf-')); fs.symlinkSync(far, path.join(root, 'idvol/by-id'));
    return { id, far, env: { SYM_IDENTITY_DIR: path.join(root, 'idvol') }, spec: { op: 'load', name: 'agent' } };
  },
  mint: () => ({ id: null, spec: { op: 'load', name: 'agent' } }),
  'mint-split': (root) => ({ id: null, env: { SYM_IDENTITY_DIR: path.join(root, 'idvol') }, spec: { op: 'load', name: 'agent' } }),
};
if (/^xvol/.test(scenario) && !FAR) { console.error('set SYM_FUZZ_FAR to a directory on another volume'); process.exit(2); }
const tally = {}; const bump = (k) => { tally[k] = (tally[k] || 0) + 1; };
const same = (r, id) => Boolean(r && r.ok && id && r.nodeId === id.nodeId && r.key === id.privateKey);
const looseKeys = (dirs, key) => {
  const bad = [];
  const walk = (d) => { let es = []; try { es = fs.readdirSync(d); } catch { return; } for (const e of es) { const p = path.join(d, e); const st = fs.lstatSync(p); if (st.isDirectory()) walk(p); else if (st.isFile() && /^(identity|e2e-keypair)\.json$/.test(e) && fs.readFileSync(p, 'utf8').includes(key) && (st.mode & 0o077)) bad.push(p); } };
  dirs.filter(Boolean).forEach(walk); return bad;
};

function migration() {
  const fresh = () => { const root = newRoot(scenario); const sc = SC[scenario](root); return { root, sc, env: envFor(root, sc.env) }; };
  const done = (f) => { fs.rmSync(f.root, { recursive: true, force: true }); if (f.sc.far) fs.rmSync(f.sc.far, { recursive: true, force: true }); };
  const f0 = fresh(); const n0 = op(LIB.mine, f0.sc.spec, f0.env, 0); done(f0);
  if (!n0.ok) { console.log('the operation fails without a kill:', JSON.stringify(n0)); process.exit(1); }
  for (let k = 1; k <= n0.steps; k++) {
    for (const when of ['before', 'after']) {
      waitForLoad();
      const res = {};
      for (const check of ['next', 'pinned', '0.14.2', '0.13', 'next>0.14.2']) {
        const f = fresh();
        if (!op(LIB.mine, f.sc.spec, f.env, k, when).killed) { res.kill = 'not-reached'; done(f); break; }
        const load = (lib, extra = {}) => op(lib, { op: 'load', name: 'agent', ...extra }, f.env);
        const id = f.sc.id;
        if (check === 'next') {
          const a = load(LIB.mine); const b = load(LIB.mine);
          const ok = id ? same(a, id) && same(b, id) : a.ok && b.ok && a.nodeId === b.nodeId;
          let note = '';
          if (ok && id) { let n = 0; try { n = fs.readdirSync(path.join(f.root, 'state/nodes/by-id', id.nodeId, 'cmbs')).length; } catch { /* */ } if (n !== NF) note += ` STORE ${n}/${NF}`; }
          if (ok) { const loose = looseKeys([f.root, f.sc.far], a.key); if (loose.length) note += ` LOOSE-KEY ${loose.map((p) => path.relative(f.root, p)).join(',')}`; }
          res[check] = (ok ? 'same' : (a.ok ? 'NEW' : a.err)) + note;
        } else if (check === 'pinned') {
          const ref = id || (() => { const m = load(LIB.mine); return { nodeId: m.nodeId, privateKey: m.key }; })();
          res[check] = same(load(LIB.mine, { nodeId: ref.nodeId, create: false }), ref) ? 'same' : 'DIFF';
        } else if (check === 'next>0.14.2') {
          const m = load(LIB.mine); const r = load(LIB.base);
          const ref = id || { nodeId: m.nodeId, privateKey: m.key };
          res[check] = same(m, ref) && same(r, ref) ? 'same' : `next=${same(m, ref) ? 'same' : m.err || 'NEW'} 0.14.2=${same(r, ref) ? 'same' : r.err || 'NEW'}`;
        } else {
          const r = load(check === '0.14.2' ? LIB.base : LIB.v013);
          const m = load(LIB.mine); // and this tree afterwards
          const ref = id || (m.ok ? { nodeId: m.nodeId, privateKey: m.key } : null);
          res[check] = (same(r, ref) ? 'same' : (r.ok ? 'NEW' : r.err)) + (id && !same(m, id) ? ` then next=${m.ok ? 'NEW' : m.err}` : '');
        }
        done(f);
      }
      for (const [a, b] of Object.entries(res)) bump(`${a}:${String(b).split(' ')[0]}`);
      if (Object.values(res).some((v) => v !== 'same')) console.log(`k=${k} ${when}: ${Object.entries(res).map(([a, b]) => `${a}=${b}`).join(' ')}`);
    }
  }
  console.log(`${scenario}: ${n0.steps} steps, ${2 * n0.steps} crash points`, JSON.stringify(tally));
}

function relocation(what, split) {
  const host = (tag) => { const root = newRoot(tag); return { root, env: envFor(root, split ? { SYM_IDENTITY_DIR: path.join(root, 'idvol') } : {}) }; };
  const setup = () => {
    const A = host('xa'); const B = host('xb');
    const hk = op(LIB.mine, { op: 'hostkey' }, B.env);
    const made = op(LIB.mine, { op: 'load', name: 'agent' }, A.env);
    const dir = path.join(A.root, 'state/nodes/by-id', made.nodeId, 'cmbs');
    for (let i = 0; i < 5; i++) put(path.join(dir, `m${i}.json`), '{}');
    const pub = JSON.parse(fs.readFileSync(path.join(split ? path.join(A.root, 'idvol') : path.join(A.root, 'state/nodes'), 'by-id', made.nodeId, 'identity.json'), 'utf8')).publicKey;
    const out = path.join(A.root, 'agent.bundle');
    return { A, B, hk, id: { nodeId: made.nodeId, privateKey: made.key, publicKey: pub }, out, exportSpec: { op: 'export', name: 'agent', out, toHostKey: hk.publicKey } };
  };
  const done = (x) => { fs.rmSync(x.A.root, { recursive: true, force: true }); fs.rmSync(x.B.root, { recursive: true, force: true }); };
  const grep = (root, key) => cp.spawnSync('grep', ['-rl', key, root], { encoding: 'utf8' }).stdout.trim().split('\n').filter((f) => f && !/\.bundle(\.\d+\.tmp)?$/.test(f));
  const s0 = setup();
  const importSpec = (x) => ({ op: 'import', from: x.out, hostPrivateKey: x.hk.privateKey, expect: { nodeId: x.id.nodeId, key: x.id.publicKey } });
  let N;
  if (what === 'export') N = op(LIB.mine, s0.exportSpec, s0.A.env, 0).steps;
  else { op(LIB.mine, s0.exportSpec, s0.A.env); N = op(LIB.mine, importSpec(s0), s0.B.env, 0).steps; }
  done(s0);
  for (let k = 1; k <= N; k++) {
    for (const when of ['before', 'after']) {
      waitForLoad();
      const x = setup(); const line = [];
      let good;
      if (what === 'export') {
        if (!op(LIB.mine, x.exportSpec, x.A.env, k, when).killed) { bump('not-reached'); done(x); continue; }
        const mine = op(LIB.mine, { op: 'load', name: 'agent' }, x.A.env);
        const base = op(LIB.base, { op: 'load', name: 'agent', nodeId: x.id.nodeId, create: false }, x.A.env);
        const complete = fs.existsSync(x.out);
        const unsafe = complete && ((mine.ok && mine.key) || (base.ok && base.key));
        line.push(unsafe ? 'UNSAFE' : 'safe', `complete=${complete}`, `start=${mine.ok ? 'starts' : mine.err}`, `0.14.2=${base.ok ? (base.key ? 'starts' : 'keyless') : base.err}`);
        const ab = op(LIB.mine, { op: 'abort', name: 'agent' }, x.A.env);
        const aborted = ab.ok && ab.aborted;
        if (aborted) {
          const again = op(LIB.mine, { op: 'load', name: 'agent' }, x.A.env);
          good = !unsafe && same(again, x.id) && !fs.existsSync(x.out);
          line.push(`abort=${same(again, x.id) ? 'source starts again' : 'BAD'}`);
        } else {
          const resume = op(LIB.mine, x.exportSpec, x.A.env);
          const finished = resume.ok || /already tombstoned/.test(resume.msg || '');
          const left = grep(x.A.root, x.id.privateKey);
          const after = op(LIB.mine, { op: 'load', name: 'agent' }, x.A.env);
          const imp = fs.existsSync(x.out) ? op(LIB.mine, importSpec(x), x.B.env) : { ok: false, err: 'no bundle' };
          const onB = op(LIB.mine, { op: 'load', name: 'agent', nodeId: x.id.nodeId, create: false }, x.B.env);
          good = !unsafe && finished && !left.length && !after.ok && imp.ok && same(onB, x.id);
          line.push(`abort=${ab.ok ? 'nothing to abort' : 'refused'}`, `resume=${finished ? 'ok' : resume.msg}`, `key-left=${left.map((f) => path.relative(x.A.root, f)).join(',') || 0}`, `import=${imp.ok ? 'ok' : imp.err}`, `B=${same(onB, x.id) ? 'the agent' : onB.err}`);
        }
      } else {
        op(LIB.mine, x.exportSpec, x.A.env);
        if (!op(LIB.mine, importSpec(x), x.B.env, k, when).killed) { bump('not-reached'); done(x); continue; }
        const retry = op(LIB.mine, importSpec(x), x.B.env);
        const pinned = op(LIB.mine, { op: 'load', name: 'agent', nodeId: x.id.nodeId, create: false }, x.B.env);
        const byName = op(LIB.mine, { op: 'load', name: 'agent' }, x.B.env);
        const base = op(LIB.base, { op: 'load', name: 'agent' }, x.B.env);
        let store = 0; try { store = fs.readdirSync(path.join(x.B.root, 'state/nodes/by-id', x.id.nodeId, 'cmbs')).length; } catch { /* */ }
        good = (retry.ok || /already imported/.test(retry.msg || '')) && same(pinned, x.id) && same(byName, x.id) && same(base, x.id) && store === 5;
        line.push(`retry=${retry.ok ? 'ok' : retry.msg}`, `pinned=${same(pinned, x.id) ? 'the agent' : pinned.err}`, `byName=${same(byName, x.id) ? 'the agent' : byName.err}`, `0.14.2=${same(base, x.id) ? 'the agent' : base.err}`, `store=${store}`);
      }
      bump(good ? 'good' : 'BAD');
      if (!good) console.log(`k=${k} ${when}: ${line.join(' ')}`);
      done(x);
    }
  }
  console.log(`${what}${split ? '-split' : ''}: ${N} steps, ${2 * N} crash points`, JSON.stringify(tally));
}

if (SC[scenario]) migration();
else if (/^(export|import)(-split)?$/.test(scenario)) relocation(scenario.split('-')[0], scenario.endsWith('-split'));
else { console.error(`unknown scenario ${scenario}`); process.exit(2); }
