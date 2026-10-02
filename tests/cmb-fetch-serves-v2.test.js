'use strict';

require('./_isolate-home'); // redirect $HOME to a temp sandbox before lib/config loads

/**
 * B-R9 (part): cmb-fetch serves the record as stored. A served v2.0 record (mmp-sig-v2.0) must keep
 * signatureSuite, addressScheme, createdByNodeId, application and assertionId, or the requester
 * cannot verify it.
 *
 * The categories are served as signed too, each with its `meta` (0.14.0 review): the signature
 * commits to every category's parents, and serving text alone made a record with per-category
 * parents fail verification at the requester.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const { SymNode } = require('../lib/node');
const { NullDiscovery } = require('../lib/discovery');
const { nodeDir } = require('../lib/config');
const { createCMB, signCMB, verifyCMB, assertionIdV2_0 } = require('../lib/core');
const { admitAs, identity } = require('./_core-secure');

// Core Secure (design D1): a fetched record goes out as its own `cmb` frame (sealed cmb-encrypted),
// then a `cmb-fetch-result` with the correlation id and the returned / missing key lists.
function serve(node, key, reqId) {
  const requester = admitAs(node, identity('requester'));
  node._frameHandler.handle(requester, { type: 'cmb-fetch', key, reqId });
  const res = requester.sent.find((f) => f.type === 'cmb-fetch-result');
  const at = (t) => requester.sent.findIndex((f) => f.type === t);
  return { res, record: requester.sent.find((f) => f.type === 'cmb')?.cmb, recordFirst: at('cmb') !== -1 && at('cmb') < at('cmb-fetch-result') };
}

describe('cmb-fetch serving', () => {
  it('a served v2.0 record still verifies against its author', () => {
    const name = `fetchv2-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    try {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
        publicKeyEncoding: { type: 'spki', format: 'der' }, privateKeyEncoding: { type: 'pkcs8', format: 'der' },
      });
      const pub = publicKey.slice(-32).toString('base64url');
      const priv = privateKey.slice(-32).toString('base64url');
      const cmb = createCMB({ categories: { focus: 'served whole' }, createdBy: 'alice', emitV2: true, createdByNodeId: 'node-alice', room: 'default' });
      cmb.metadata.assertionId = assertionIdV2_0(cmb);
      signCMB(cmb, priv);
      assert.deepStrictEqual(verifyCMB(cmb, pub).valid, true, 'precondition: the stored record verifies');
      node._store.get = (k) => (k === cmb.metadata.key ? { key: k, cmb } : null);
      const { res, record, recordFirst } = serve(node, cmb.metadata.key, 'r1');
      assert.deepStrictEqual(res, { type: 'cmb-fetch-result', reqId: 'r1', returned: [cmb.metadata.key], missing: [], timestamp: res.timestamp }, 'the result carries only the id and the key lists');
      assert.ok(recordFirst, 'the record goes first, in its own frame');
      for (const k of ['signatureSuite', 'addressScheme', 'createdByNodeId', 'application', 'assertionId']) {
        assert.ok(k in record.metadata, `${k} is served`);
      }
      assert.strictEqual(verifyCMB(JSON.parse(JSON.stringify(record)), pub).valid, true, 'the served record verifies');
      record.metadata.key = 'tampered';
      assert.notStrictEqual(cmb.metadata.key, 'tampered', 'the store keeps its own copy');
    } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('a served record with per-category parents still verifies, and carries no vector', () => {
    const name = `fetchcp-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    try {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
        publicKeyEncoding: { type: 'spki', format: 'der' }, privateKeyEncoding: { type: 'pkcs8', format: 'der' },
      });
      const pub = publicKey.slice(-32).toString('base64url');
      const parent = createCMB({ categories: { focus: 'the issue it descends from', issue: 'an earlier issue' }, createdBy: 'alice' });
      const cmb = createCMB({
        categories: { focus: 'continues its own line', issue: 'descends from the peer\'s issue' },
        createdBy: 'alice', emitV2: true, createdByNodeId: 'node-alice', room: 'default',
        categoryParents: { issue: [parent.categories.issue.meta.key], focus: [parent.categories.focus.meta.key] },
      });
      cmb.metadata.assertionId = assertionIdV2_0(cmb);
      signCMB(cmb, privateKey.slice(-32).toString('base64url'));
      assert.strictEqual(verifyCMB(cmb, pub).valid, true, 'precondition: the stored record verifies');
      // As a store may hold it after a gate measured it: a vector beside the text.
      const stored = JSON.parse(JSON.stringify(cmb));
      stored.categories.focus.vector = [0.1, 0.2];
      node._store.get = (k) => (k === cmb.metadata.key ? { key: k, cmb: stored } : null);
      const served = JSON.parse(JSON.stringify(serve(node, cmb.metadata.key, 'r2').record));
      assert.deepStrictEqual(served.categories.issue.meta.parents, [parent.categories.issue.meta.key], 'each category\'s signed meta is served');
      assert.strictEqual(verifyCMB(served, pub).valid, true, 'the served record verifies at the requester');
      assert.strictEqual('vector' in served.categories.focus, false, 'vectors stay local');
      assert.deepStrictEqual(Object.keys(served).sort(), ['categories', 'metadata']);
    } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });

  it('a pre-v2.0 record is not served over Core Secure: listed missing, no record frame', () => {
    const name = `fetchold-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const node = new SymNode({ name, silent: true, discovery: new NullDiscovery() });
    try {
      const old = createCMB({ categories: { focus: 'an old record' }, createdBy: 'alice' });
      node._store.get = (k) => (k === old.metadata.key ? { key: k, cmb: old } : null);
      const { res, record } = serve(node, old.metadata.key, 'r3');
      assert.deepStrictEqual([res.returned, res.missing], [[], [old.metadata.key]]);
      assert.strictEqual(record, undefined);
    } finally { fs.rmSync(nodeDir(name), { recursive: true, force: true }); }
  });
});
