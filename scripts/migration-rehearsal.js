#!/usr/bin/env node
'use strict';

/**
 * Rehearse the 0.14 migration (design §6, D3, D9) on COPIES of real node directories.
 *
 *   node scripts/migration-rehearsal.js [--from <nodes dir>] [--with-013 <0.13 checkout>]
 *
 * Copies each node's identity.json and roster-keys.jsonl from `--from` (default ~/.sym/nodes; only
 * READ) into a fresh temp state root, then, there:
 *   1. the key registry: every 0.13 roster file is migrated (handshake → legacy-claim, anchor
 *      dropped, a version marker written), and loading it again migrates nothing (idempotent);
 *   2. a 0.13 rollback: the 0.13 RosterKeyRegistry (from --with-013) reads each migrated file and
 *      holds a key for every binding (it skips the marker line as malformed);
 *   3. the identity layout: every node dir moves to nodes/by-id/<nodeId>/ with nodes/<name> left as
 *      a symlink; a second pass moves nothing; a 0.13 reader still finds nodes/<name>/identity.json.
 * Prints one JSON summary. Nothing outside the temp dir is written.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const argv = process.argv.slice(2);
const flag = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : null; };
const realHome = os.homedir();
const FROM = flag('--from') || path.join(realHome, '.sym', 'nodes');
const WITH013 = flag('--with-013') || path.resolve(__dirname, '..', '..', 'sym-0.13.17');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-migration-rehearsal-'));
process.env.HOME = tmp;
process.env.SYM_STATE_DIR = path.join(tmp, '.sym');
delete process.env.SYM_IDENTITY_DIR;
const NODES = path.join(tmp, '.sym', 'nodes');
fs.mkdirSync(NODES, { recursive: true });

// 1. Copy (read-only on the source).
const copied = { dirs: 0, identities: 0, rosters: 0, rosterLines: 0, handshakeLines: 0, skippedLinks: 0 };
for (const d of fs.readdirSync(FROM, { withFileTypes: true })) {
  if (d.isSymbolicLink()) { copied.skippedLinks++; continue; }
  if (!d.isDirectory() || d.name === 'by-id' || d.name === 'by-name') continue;
  const src = path.join(FROM, d.name);
  const dst = path.join(NODES, d.name);
  let any = false;
  const id = path.join(src, 'identity.json');
  if (fs.existsSync(id)) { fs.mkdirSync(dst, { recursive: true }); fs.copyFileSync(id, path.join(dst, 'identity.json')); copied.identities++; any = true; }
  const rk = path.join(src, 'roster-keys', 'roster-keys.jsonl');
  if (fs.existsSync(rk)) {
    fs.mkdirSync(path.join(dst, 'roster-keys'), { recursive: true });
    fs.copyFileSync(rk, path.join(dst, 'roster-keys', 'roster-keys.jsonl'));
    const text = fs.readFileSync(rk, 'utf8');
    for (const l of text.split('\n')) { if (!l.trim()) continue; copied.rosterLines++; try { if (JSON.parse(l).source === 'handshake') copied.handshakeLines++; } catch { /* */ } }
    copied.rosters++;
    any = true;
  }
  if (any) copied.dirs++;
}

const { RosterKeyRegistry, FORMAT_MARKER } = require('../lib/roster-keys');
const config = require('../lib/config');
let Roster013 = null;
try { Roster013 = require(path.join(WITH013, 'lib', 'roster-keys.js')).RosterKeyRegistry; } catch { /* no 0.13 checkout */ }

// 2. The key registry, file by file.
const roster = { files: 0, bindings: 0, legacyClaim: 0, grant: 0, droppedAnchor: 0, droppedMalformed: 0, verifyingAfter: 0, idempotent: true, markerOk: true, rollbackReadable: Roster013 ? true : null, rollbackBindings: 0, mismatches: [] };
for (const name of fs.readdirSync(NODES)) {
  const dir = path.join(NODES, name, 'roster-keys');
  if (!fs.existsSync(path.join(dir, 'roster-keys.jsonl'))) continue;
  roster.files++;
  const r = new RosterKeyRegistry({ dir });
  const m = r.migration();
  if (m) { roster.bindings += m.bindings; roster.legacyClaim += m.legacyClaim; roster.grant += m.grant; roster.droppedAnchor += m.droppedAnchor; roster.droppedMalformed += m.droppedMalformed; }
  roster.verifyingAfter += r.entries().filter((e) => r.get(e.nodeId)).length;
  const first = JSON.parse(fs.readFileSync(path.join(dir, 'roster-keys.jsonl'), 'utf8').split('\n')[0]);
  if (first.v !== FORMAT_MARKER.v) roster.markerOk = false;
  const again = new RosterKeyRegistry({ dir });
  if (again.migration() !== null || again.size() !== r.size()) roster.idempotent = false;
  if (Roster013) {
    const old = new Roster013({ dir });
    for (const e of r.entries()) {
      if (old.get(e.nodeId) === e.key) roster.rollbackBindings++;
      else { roster.rollbackReadable = false; if (roster.mismatches.length < 5) roster.mismatches.push({ dir: name, nodeId: e.nodeId }); }
    }
  }
}

// 3. The identity layout.
const before = fs.readdirSync(NODES).filter((n) => fs.existsSync(path.join(NODES, n, 'identity.json')));
const pass1 = config.migrateIdentities();
const pass2 = config.migrateIdentities();
let links = 0, oldPathReadable = 0, byIdReadable = 0;
for (const name of before) {
  const link = path.join(NODES, name);
  try { if (fs.lstatSync(link).isSymbolicLink()) links++; } catch { /* */ }
  try { JSON.parse(fs.readFileSync(path.join(link, 'identity.json'), 'utf8')); oldPathReadable++; } catch { /* */ }
  const id = config.nodeIdForName(name);
  try { if (id && config.loadIdentity({ nodeId: id, create: false })) byIdReadable++; } catch { /* */ }
}

const summary = {
  source: FROM, rehearsal: tmp, with013: Roster013 ? WITH013 : null,
  copied,
  roster,
  identities: { nodeDirs: before.length, pass1, pass2, symlinks: links, readableAtOldPath: oldPathReadable, loadableById: byIdReadable },
};
console.log(JSON.stringify(summary, null, 2));
if (!flag('--keep')) fs.rmSync(tmp, { recursive: true, force: true });
