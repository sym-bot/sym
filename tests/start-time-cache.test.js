'use strict';

require('./_isolate-home'); // sandbox HOME/USERPROFILE before anything reads os.homedir()

/**
 * Remembered process start times — the path every Windows identity-lock check takes.
 *
 * On Windows a start-time read is a PowerShell process (~0.45 s, synchronous). It used to run
 * once per pid per lock check, remembered for 10 s, so a daemon start that checked every node
 * directory's lock paid it per directory. A live process's start time cannot change, so a read
 * is now remembered until the pid is seen dead, and a pass over many locks reads all of their
 * holders in one lookup.
 *
 * Everything here runs through an injected lookup, so it is exercised on every platform; the
 * PowerShell lookup itself only runs on Windows (config.test.js has the win32-only checks).
 */

const { describe, it, before, after, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const cfg = require('../lib/config');
const { migrateStores } = require('../lib/node');
const { tmpdir } = require('./_tmpdir');

/** A lookup that answers from `table` and records every call it receives. */
function recordingLookup(table) {
  const calls = [];
  const lookup = (pids) => {
    calls.push([...pids].sort((a, b) => a - b));
    const out = new Map();
    for (const pid of pids) if (typeof table[pid] === 'string') out.set(pid, table[pid]);
    return out;
  };
  return { lookup, calls };
}

describe('createStartTimeCache', () => {
  it('a live pid is read once and remembered well past the old 10 s window', () => {
    let t = 0;
    const { lookup, calls } = recordingLookup({ 100: 'S100' });
    const cache = cfg._createStartTimeCache(lookup, { isAlive: () => true, now: () => t });
    assert.equal(cache.get(100), 'S100');
    t += 60 * 60 * 1000; // an hour later
    assert.equal(cache.get(100), 'S100');
    assert.equal(cache.get(100), 'S100');
    assert.equal(calls.length, 1, 'one lookup for a pid that stayed alive');
  });

  it('a pid seen dead is forgotten, and a reused pid is read afresh', () => {
    let alive = true;
    const table = { 200: 'old-process' };
    const { lookup, calls } = recordingLookup(table);
    const cache = cfg._createStartTimeCache(lookup, { isAlive: () => alive });
    assert.equal(cache.get(200), 'old-process');
    alive = false;
    assert.equal(cache.get(200), null, 'a dead pid has no start time');
    assert.equal(calls.length, 1, 'and is not looked up');
    alive = true;
    table[200] = 'new-process'; // the number was reused
    assert.equal(cache.get(200), 'new-process');
    assert.equal(calls.length, 2);
  });

  it('fresh re-reads, and a different start replaces the remembered one', () => {
    const table = { 300: 'A' };
    const { lookup, calls } = recordingLookup(table);
    const cache = cfg._createStartTimeCache(lookup, { isAlive: () => true });
    assert.equal(cache.get(300), 'A');
    table[300] = 'B'; // died and was reused between two checks, unobserved
    assert.equal(cache.get(300), 'A', 'memory cannot see an unobserved reuse');
    assert.equal(cache.get(300, { fresh: true }), 'B');
    assert.equal(cache.get(300), 'B', 'the new read replaced the old one');
    assert.equal(calls.length, 2);
  });

  it('prime reads every live, unremembered pid in ONE lookup', () => {
    const { lookup, calls } = recordingLookup({ 1: 'a', 2: 'b', 3: 'c', 4: 'd' });
    const cache = cfg._createStartTimeCache(lookup, { isAlive: (pid) => pid !== 9 });
    cache.prime([3, 1, 2, 2, 9]);
    assert.deepEqual(calls, [[1, 2, 3]], 'one call, duplicates folded, the dead pid skipped');
    assert.deepEqual([cache.get(1), cache.get(2), cache.get(3)], ['a', 'b', 'c']);
    assert.equal(calls.length, 1, 'answered from memory');
    cache.prime([1, 4]);
    assert.deepEqual(calls[1], [4], 'only the pid not already remembered');
  });

  it('a failed read is remembered only briefly, then retried', () => {
    let t = 0;
    let fail = true;
    const calls = [];
    const lookup = (pids) => {
      calls.push(pids);
      if (fail) throw new Error('powershell timed out');
      return new Map(pids.map((p) => [p, 'S']));
    };
    const cache = cfg._createStartTimeCache(lookup, { isAlive: () => true, now: () => t, failureTtlMs: 10000 });
    assert.equal(cache.get(500), null);
    t += 5000;
    assert.equal(cache.get(500), null);
    assert.equal(calls.length, 1, 'not retried on every check');
    t += 6000;
    fail = false;
    assert.equal(cache.get(500), 'S', 'retried once the failure has aged out');
    assert.equal(calls.length, 2);
  });

  it('a pid the lookup could not read (absent from its answer) is a failed read', () => {
    const { lookup } = recordingLookup({ 1: 'a' });
    const cache = cfg._createStartTimeCache(lookup, { isAlive: () => true });
    cache.prime([1, 2]);
    assert.equal(cache.get(1), 'a');
    assert.equal(cache.get(2), null);
  });
});

describe('the lock check on the remembered-start-time path', () => {
  let holderA;
  let holderB;
  before(() => {
    holderA = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
    holderB = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
  });
  after(() => {
    for (const c of [holderA, holderB]) { try { c.kill('SIGKILL'); } catch {} }
  });
  afterEach(() => cfg._setProcessStartTimeLookup(null));

  const lock = (pid, start) => ({ pid, start, mtimeMs: Date.now() });

  it('a lookup failure leaves the lock held, and warns once', async () => {
    cfg._setProcessStartTimeLookup(() => { throw new Error('no PowerShell'); });
    const warnings = [];
    const onWarning = (w) => { if (/SYM identity lock/.test(w.message)) warnings.push(w); };
    process.on('warning', onWarning);
    try {
      assert.equal(cfg.lockIsHeldByLiveProcess(lock(holderA.pid, 'S-A')), true);
      assert.equal(cfg.lockIsHeldByLiveProcess(lock(holderB.pid, 'S-B')), true);
      await new Promise((resolve) => setImmediate(resolve)); // emitWarning delivers on a later tick
      assert.equal(warnings.length, 1, 'one warning, not one per check');
    } finally {
      process.off('warning', onWarning);
    }
  });

  it('a mismatch on a remembered start is re-read before the lock is handed over', () => {
    const table = { [holderA.pid]: 'first-occupant' };
    const { lookup, calls } = recordingLookup(table);
    cfg._setProcessStartTimeLookup(lookup);
    assert.equal(cfg.processStartTime(holderA.pid), 'first-occupant');
    // The first occupant died and the pid was reused, unobserved; the new occupant wrote the lock.
    table[holderA.pid] = 'second-occupant';
    assert.equal(cfg.lockIsHeldByLiveProcess(lock(holderA.pid, 'second-occupant')), true,
      'a live holder must not lose its lock to a stale memory');
    assert.equal(calls.length, 2, 'the mismatch was confirmed by a fresh read');
    assert.equal(cfg.lockIsHeldByLiveProcess(lock(holderA.pid, 'recycled-away')), false, 'a real mismatch is still stale');
  });

  it('a match is answered from memory: one read per holder however often it is checked', () => {
    const { lookup, calls } = recordingLookup({ [holderA.pid]: 'S-A' });
    cfg._setProcessStartTimeLookup(lookup);
    for (let i = 0; i < 5; i++) assert.equal(cfg.lockIsHeldByLiveProcess(lock(holderA.pid, 'S-A')), true);
    assert.equal(calls.length, 1);
  });

  it('migrateStores reads every pending node\'s holder in ONE lookup, and only the pending ones', () => {
    const root = tmpdir('sym-migrate-');
    const DEAD = 2147483646;
    const nodes = {
      'held-by-a-1': { pid: holderA.pid, start: 'S-A', pending: true },
      'held-by-a-2': { pid: holderA.pid, start: 'S-A', pending: true },
      'held-by-b': { pid: holderB.pid, start: 'S-B', pending: true },
      'holder-dead': { pid: DEAD, start: 'S-dead', pending: true },
      'already-migrated': { pid: holderB.pid, start: 'S-B', pending: false },
    };
    for (const [name, n] of Object.entries(nodes)) {
      const dir = path.join(root, name);
      fs.mkdirSync(path.join(dir, n.pending ? 'meshmem' : 'cmbs'), { recursive: true });
      fs.writeFileSync(path.join(dir, 'lock.pid'), `${n.pid}\n${JSON.stringify({ start: n.start, createdAt: Date.now() })}\n`);
    }
    const { lookup, calls } = recordingLookup({ [holderA.pid]: 'S-A', [holderB.pid]: 'S-B' });
    cfg._setProcessStartTimeLookup(lookup);

    assert.equal(migrateStores(root), 1, 'only the node whose holder is dead is migrated');
    assert.deepEqual(calls, [[holderA.pid, holderB.pid].sort((x, y) => x - y)], 'one lookup for both live holders');
    assert.ok(fs.existsSync(path.join(root, 'holder-dead', 'cmbs')));
    for (const live of ['held-by-a-1', 'held-by-a-2', 'held-by-b']) {
      assert.ok(fs.existsSync(path.join(root, live, 'meshmem')), `${live} is live and left alone`);
    }
  });
});
