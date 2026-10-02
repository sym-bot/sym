'use strict';

// The product name is xmesh, all lowercase, in every README and doc (founder, 2026-10-02: "all XMesh letter
// must be lowercase. No any camel case"). This covers prose only: code identifiers (the XMesh class, the
// _handleXMeshInsight handler) and XMESH_* names are not the product's name in prose and are not checked here.

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
  if (e.name === 'node_modules' || e.name === '.git') return [];
  const p = path.join(dir, e.name);
  return e.isDirectory() ? walk(p) : [p];
});
const docs = [
  ...fs.readdirSync(ROOT).filter((f) => f.endsWith('.md')).map((f) => path.join(ROOT, f)),
  ...['docs', '.github', '.agents', '.claude'].filter((d) => fs.existsSync(path.join(ROOT, d)))
    .flatMap((d) => walk(path.join(ROOT, d))).filter((f) => f.endsWith('.md')),
];

describe('docs spell the product name xmesh', () => {
  it('finds the docs it checks', () => {
    assert.ok(docs.length >= 8, `scanned ${docs.length} docs`);
  });
  for (const f of docs) {
    it(path.relative(ROOT, f), () => {
      const text = fs.readFileSync(f, 'utf8').replace(/XMESH_[A-Z0-9_]*/g, '');
      assert.doesNotMatch(text, /\bXMesh\b|\bxMesh\b|\bXmesh\b|\bXMESH\b/);
    });
  }
});
