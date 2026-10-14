'use strict';
/**
 * Shared by the identity fuzz scripts (0.14.3, design v2). Nothing here touches ~/.sym: every run is in a state root of
 * its own under the work directory (SYM_FUZZ_WORK, default a temp dir).
 *
 *   node scripts/identity-fuzz/prepare.js            git archive v0.14.2 and v0.13.17 into the work dir (rollback trees)
 *   node scripts/identity-fuzz/kill.js <scenario>    kill -9 at every mutating step of one operation, then the checks
 *   node scripts/identity-fuzz/race.js <kind>         real processes starting one agent at once (and some SIGKILLed)
 *   node scripts/identity-fuzz/rollback.js           a 0.14.2 host upgraded to this tree and rolled back; timing
 *
 * FAR (SYM_FUZZ_FAR): a directory on ANOTHER volume (e.g. an hdiutil HFS+ sparse image on macOS, a tmpfs on Linux) for
 * the cross-volume scenarios. The 1-minute load is checked before each step (SYM_FUZZ_LOAD_MAX, default 10).
 */
const fs = require('fs'); const path = require('path'); const os = require('os'); const cp = require('child_process'); const crypto = require('crypto');

const WORK = process.env.SYM_FUZZ_WORK || path.join(os.tmpdir(), 'sym-identity-fuzz');
const REPO = path.resolve(__dirname, '../..');
const LIB = {
  mine: path.join(REPO, 'lib'),
  base: process.env.SYM_FUZZ_BASE || path.join(WORK, 'trees', '0.14.2', 'lib'),
  v013: process.env.SYM_FUZZ_V013 || path.join(WORK, 'trees', '0.13.17', 'lib'),
};
const FAR = process.env.SYM_FUZZ_FAR || null;
const sab = new Int32Array(new SharedArrayBuffer(4));
const waitForLoad = () => { const max = Number(process.env.SYM_FUZZ_LOAD_MAX || 10); while (os.loadavg()[0] >= max) Atomics.wait(sab, 0, 0, 3000); };

function makeIdentity(name) {
  const kp = crypto.generateKeyPairSync('ed25519'); const ts = Date.now(); const b = crypto.randomBytes(16);
  b[0] = (ts / 2 ** 40) & 0xff; b[1] = (ts / 2 ** 32) & 0xff; b[2] = (ts / 2 ** 24) & 0xff; b[3] = (ts / 2 ** 16) & 0xff; b[4] = (ts / 2 ** 8) & 0xff; b[5] = ts & 0xff;
  b[6] = (b[6] & 0x0f) | 0x70; b[8] = (b[8] & 0x3f) | 0x80; const hx = b.toString('hex');
  return {
    nodeId: `${hx.slice(0, 8)}-${hx.slice(8, 12)}-${hx.slice(12, 16)}-${hx.slice(16, 20)}-${hx.slice(20)}`, name, hostname: 'h.local', createdAt: 1,
    publicKey: kp.publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64url'),
    privateKey: kp.privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(16).toString('base64url'),
  };
}
const put = (f, t, m = 0o644) => { fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, t); fs.chmodSync(f, m); };
/** A 0.13 agent as 0.13 wrote it: identity.json and e2e-keypair.json at 0644, a store of `nf` files. */
function legacy(dir, id, nf = 12, size = 0) {
  put(path.join(dir, 'identity.json'), JSON.stringify(id, null, 2));
  put(path.join(dir, 'e2e-keypair.json'), JSON.stringify({ publicKey: 'p', privateKey: `e2e-${id.nodeId}` }));
  for (let i = 0; i < nf; i++) put(path.join(dir, 'cmbs', `c${i}.json`), JSON.stringify({ i, pad: 'x'.repeat(size) }));
}
function newRoot(tag) {
  fs.mkdirSync(path.join(WORK, 'runs'), { recursive: true });
  const root = fs.mkdtempSync(path.join(WORK, 'runs', `${tag}-`));
  fs.mkdirSync(path.join(root, 'state', 'nodes'), { recursive: true });
  return root;
}
const envFor = (root, extra = {}) => ({ ...process.env, HOME: root, USERPROFILE: root, SYM_STATE_DIR: path.join(root, 'state'), SYM_IDENTITY_DIR: '', ...extra });
/** One operation in a child process (op.js), optionally SIGKILLed at its k-th mutating fs call. */
function op(lib, spec, env, k, when = 'before') {
  const args = [path.join(__dirname, 'op.js'), lib, JSON.stringify(spec)];
  if (k !== undefined) args.push(String(k), when);
  const r = cp.spawnSync(process.execPath, args, { env, encoding: 'utf8', timeout: 120000 });
  if (r.signal === 'SIGKILL') return { killed: true };
  const line = (r.stdout || '').trim().split('\n').filter((l) => l.startsWith('{')).pop();
  try { return JSON.parse(line); } catch { return { ok: false, err: 'CRASH', msg: String(r.stderr || '').slice(0, 300) }; }
}
module.exports = { WORK, REPO, LIB, FAR, waitForLoad, makeIdentity, put, legacy, newRoot, envFor, op };
