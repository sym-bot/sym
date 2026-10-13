'use strict';

// The product name is never "xMesh" (user, 2026-10-02: "don't use any xMesh, use xmesh in code, and XMesh in
// sentence and XMESH for brand or product name"). This walks every README, doc, comment and log string in the
// repo and fails on the camel-case spelling. Identifiers are untouched by it: the XMesh class, the
// _handleXMeshInsight handler and XMESH_* names do not match, and nothing in the code is named xMesh.
// Lowercase xmesh is the spelling for code (package, paths, CLI, wire ids) and is not checked here: telling a
// lowercase product name in a sentence from a command or path in the same doc cannot be done reliably by text.

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const SKIP = new Set(['node_modules', '.git', '.next', 'coverage']);
const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
  if (SKIP.has(e.name)) return [];
  const p = path.join(dir, e.name);
  return e.isDirectory() ? walk(p) : [p];
});
const files = walk(ROOT).filter((f) => f !== __filename && /\.(md|js|mjs|cjs|json|ts|txt|ya?ml)$/.test(f) && !f.endsWith('package-lock.json'));

describe('the product name is never xMesh', () => {
  it('finds the files it checks', () => {
    assert.ok(files.length >= 100, `scanned ${files.length} files`);
  });
  it('no README, doc, comment or log line spells it xMesh', () => {
    const hits = [];
    for (const f of files) {
      fs.readFileSync(f, 'utf8').split('\n').forEach((line, i) => {
        if (/\bxMesh\b/.test(line)) hits.push(`${path.relative(ROOT, f)}:${i + 1}`);
      });
    }
    assert.deepStrictEqual(hits, []);
  });
});
