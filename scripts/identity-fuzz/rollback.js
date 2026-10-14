'use strict';
/**
 * node scripts/identity-fuzz/rollback.js: a host that 0.14.2 ran (0.13 agents it migrated, agents it made, one it
 * renamed, one whose name it re-pointed for a pinned start, a mixed-case name, SYM_IDENTITY_DIR agents), started twice
 * by this tree, then rolled back to 0.14.2: every agent must load by name and pinned as what 0.14.2 ran, in every phase.
 * Then timing: the first start of a 5,000-file 0.13 agent, and 12 0.13 agents in one process.
 */
const fs = require('fs'); const path = require('path');
const { LIB, makeIdentity, put, legacy, newRoot, envFor, op } = require('./common');
let bad = 0;
function host(split) {
  const root = newRoot(split ? 'rb-split' : 'rb'); const nodes = path.join(root, 'state', 'nodes'); const idvol = path.join(root, 'idvol');
  const env = envFor(root, split ? { SYM_IDENTITY_DIR: idvol } : {});
  const base = (spec) => op(LIB.base, spec, env);
  const expect = {};
  if (!split) {
    const a = makeIdentity('alpha'); legacy(path.join(nodes, 'alpha'), a, 20); base({ op: 'load', name: 'alpha' }); expect.alpha = a.nodeId;
    expect.gamma = base({ op: 'load', name: 'gamma' }).nodeId;
    const e = makeIdentity('eps'); legacy(path.join(nodes, 'eps'), e, 5); expect.eps = e.nodeId; // 0.14.2 never moved it (a pinned start was refused)
    put(path.join(nodes, 'theta', 'cmbs', 'c.json'), '{}'); expect.theta = base({ op: 'load', name: 'theta' }).nodeId;
    const i = makeIdentity('iota'); legacy(path.join(nodes, 'iota'), i, 5); base({ op: 'load', name: 'iota' });
    const ren = require('child_process').spawnSync(process.execPath, ['-e', `require(${JSON.stringify(LIB.base + '/config')}).renameIdentity('iota','iota2')`], { env }); if (ren.status) throw new Error('rename');
    expect.iota2 = i.nodeId;
    const k = makeIdentity('Kappa'); legacy(path.join(nodes, 'Kappa'), k, 5); base({ op: 'load', name: 'Kappa' }); expect.Kappa = k.nodeId;
    const appA = base({ op: 'load', name: 'app' }).nodeId; const appB = base({ op: 'load', name: 'app-b' }).nodeId;
    base({ op: 'load', name: 'app', nodeId: appB, create: false }); // 0.14.2 re-pointed "app" to B
    expect.app = appB; expect['app-b'] = appB;
  } else {
    const m1 = makeIdentity('m1'); legacy(path.join(nodes, 'm1'), m1, 5); fs.rmSync(path.join(nodes, 'm1', 'identity.json')); put(path.join(idvol, 'm1', 'identity.json'), JSON.stringify(m1));
    const m2 = makeIdentity('m2'); legacy(path.join(nodes, 'm2'), m2, 5); put(path.join(idvol, 'm2', 'identity.json'), JSON.stringify(m2));
    base({ op: 'load', name: 'm1' }); base({ op: 'load', name: 'm2' }); expect.m1 = m1.nodeId; expect.m2 = m2.nodeId;
    expect.new1 = base({ op: 'load', name: 'new1' }).nodeId;
  }
  for (const phase of ['this tree', 'this tree again', '0.14.2']) {
    const lib = phase === '0.14.2' ? LIB.base : LIB.mine;
    const line = [];
    for (const [name, want] of Object.entries(expect)) {
      const byName = op(lib, { op: 'load', name }, env);
      const pinned = op(lib, { op: 'load', name, nodeId: want, create: false }, env);
      const v = (r) => (r.ok ? (r.nodeId === want ? 'same' : 'NEW') : r.err);
      if (v(byName) !== 'same' || v(pinned) !== 'same') bad++;
      line.push(`${name}=${v(byName)}/${v(pinned)}`);
    }
    console.log(`${split ? 'SYM_IDENTITY_DIR host' : 'host'}, ${phase}: ${line.join(' ')}`);
  }
  fs.rmSync(root, { recursive: true, force: true });
}
host(false);
host(true);
// timing
for (const nf of [5000]) {
  const root = newRoot('t'); const id = makeIdentity('agent'); const dir = path.join(root, 'state', 'nodes', 'agent');
  put(path.join(dir, 'identity.json'), JSON.stringify(id)); fs.mkdirSync(path.join(dir, 'cmbs')); for (let i = 0; i < nf; i++) fs.writeFileSync(path.join(dir, 'cmbs', `c${i}.json`), '{"x":1}');
  const t0 = Date.now(); const r = op(LIB.mine, { op: 'load', name: 'agent' }, envFor(root));
  console.log(`first start of a ${nf}-file 0.13 agent: ${r.nodeId === id.nodeId ? 'same' : 'NEW'} in ${Date.now() - t0} ms (a child process, its start included)`);
  fs.rmSync(root, { recursive: true, force: true });
}
{
  const root = newRoot('t12'); const env = envFor(root);
  for (let i = 0; i < 12; i++) legacy(path.join(root, 'state', 'nodes', `agent-${i}`), makeIdentity(`agent-${i}`), 300, 3000);
  const code = `const t0 = Date.now(); const { SymNode } = require(${JSON.stringify(LIB.mine + '/node')}); const t1 = Date.now(); const ns = [];
    for (let i = 0; i < 12; i++) ns.push(new SymNode({ name: 'agent-' + i, silent: true }));
    console.log('12 x 0.13 agents (300 files each) constructed in one process in ' + (Date.now() - t1) + ' ms'); Promise.all(ns.map((n) => n.stop())).then(() => process.exit(0));`;
  const r = require('child_process').spawnSync(process.execPath, ['-e', code], { env, encoding: 'utf8' });
  console.log((r.stdout.split('\n').find((l) => l.startsWith('12 x')) || r.stderr.slice(0, 300)));
  fs.rmSync(root, { recursive: true, force: true });
}
console.log(bad ? `${bad} agent loads were not the agent 0.14.2 ran` : 'every agent loaded as what 0.14.2 ran, in every phase');
process.exitCode = bad ? 1 : 0;
