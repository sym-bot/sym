'use strict';
// node op.js <libdir> <json spec> [k] [before|after]: one identity operation; with k, SIGKILL at the k-th mutating fs call
// (k = 0 counts them). spec.op: load | export | abort | import. Prints one JSON line.
const fs = require('fs');
const [lib, specText, kText, when = 'before'] = process.argv.slice(2);
const spec = JSON.parse(specText); const k = kText === undefined ? null : Number(kText);
if (process.env.SYM_IDENTITY_DIR === '') delete process.env.SYM_IDENTITY_DIR;
let n = 0; let armed = false;
if (k !== null) {
  for (const fn of ['renameSync', 'symlinkSync', 'linkSync', 'unlinkSync', 'rmdirSync', 'rmSync', 'mkdirSync', 'writeSync', 'fsyncSync', 'chmodSync', 'copyFileSync', 'writeFileSync', 'appendFileSync', 'openSync']) {
    const orig = fs[fn];
    fs[fn] = function (...a) {
      if (!armed || (fn === 'openSync' && !/[wax+]/.test(String(a[1] || 'r')))) return orig.apply(this, a);
      n++;
      if (k && n === k && when === 'before') process.kill(process.pid, 'SIGKILL');
      const r = orig.apply(this, a);
      if (k && n === k && when === 'after') process.kill(process.pid, 'SIGKILL');
      return r;
    };
  }
}
const c = require(`${lib}/config`);
const out = (o) => process.stdout.write(`${JSON.stringify({ steps: n, ...o })}\n`);
armed = true;
try {
  if (spec.op === 'load') {
    const i = c.loadIdentity ? c.loadIdentity({ name: spec.name, nodeId: spec.nodeId, create: spec.create }) : c.loadOrCreateIdentity(spec.name);
    armed = false; out({ ok: true, nodeId: i.nodeId, key: i.privateKey });
  } else if (spec.op === 'export') {
    const x = require(`${lib}/relocation`).exportNode({ name: spec.name, out: spec.out, toHostKey: spec.toHostKey });
    armed = false; out({ ok: true, out: x.out, resumed: x.resumed || null });
  } else if (spec.op === 'abort') {
    const x = require(`${lib}/relocation`).abortExport({ name: spec.name }); armed = false; out({ ok: true, aborted: x.aborted });
  } else if (spec.op === 'import') {
    const x = require(`${lib}/relocation`).importNode({ from: spec.from, hostPrivateKey: spec.hostPrivateKey, expect: spec.expect });
    armed = false; out({ ok: true, imported: x.nodeId });
  } else if (spec.op === 'hostkey') {
    armed = false; out({ ok: true, ...require(`${lib}/relocation`).hostKey() });
  }
} catch (e) { armed = false; out({ ok: false, err: e.code || e.name, msg: String(e.message).split('\n').filter(Boolean).slice(0, 2).join(' ').slice(0, 300) }); }
