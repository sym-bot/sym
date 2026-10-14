'use strict';

/**
 * The public surface (0.14.1). package.json declares an `exports` map; this test holds it, the code behind it and
 * README "Public API" to one another, on the artifact a consumer installs, not on the checkout:
 *
 *   - every documented subpath resolves and exports EXACTLY the documented names, and no underscore name;
 *   - a private path (`@sym-bot/sym/lib/node.js` and its kind) is refused with ERR_PACKAGE_PATH_NOT_EXPORTED,
 *     by require, by require.resolve and by import;
 *   - `require('@sym-bot/sym')`, `@sym-bot/sym/package.json` and both bins still work;
 *   - README and docs/reference.md say what the code exports.
 *
 * The installed copy is what `npm pack` makes, unpacked into a node_modules with this repository's dependencies
 * linked beside it (the gate, scripts/gate-two-stock-nodes.mjs, runs the same surface check against a real
 * `npm install` of the tarball). The check is a function, `surfaceProblems`, so that the MUTATION tests can show
 * it bites: each mutates the installed copy (or the README) the way a careless change would, and the check must
 * name the problem. A check that has never failed on a bad surface proves nothing.
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..');

// ── what is documented ────────────────────────────────────────────────────────────────────────────────────────
const DOCUMENTED = {
  exportsMap: {
    '.': './lib/node.js',
    './core': './lib/public/core.js',
    './decision-log': './lib/decision-log.js',
    './store': './lib/public/store.js',
    './package.json': './package.json',
  },
  main: ['MeshAgent', 'SymNode', 'claude', 'emit', 'identity', 'invite', 'llm', 'migrateStores', 'platform', 'relocation', 'rooms', 'version'],
  core: ['CAT7_CATEGORIES', 'FIELD_WEIGHT_PROFILES', 'categoryKeyV1', 'createCMB', 'encode', 'encodeCategory', 'encodeForSVAF', 'kernelId', 'renderContent', 'verifyCMB'],
  decisionLog: ['DecisionLog'],
  decisionLogMethods: ['count', 'list', 'record'],
  store: ['openStore'],
  options: ['svafEvaluator', 'cliHostMode', 'semanticEncoder', 'SYM_SEMANTIC_ENCODER'],
  methods: ['dismissCMB', 'validateCMB'],
};
const SUBPATHS = ['@sym-bot/sym/core', '@sym-bot/sym/decision-log', '@sym-bot/sym/store', '@sym-bot/sym/package.json'];
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// ── the check, on an installed copy ───────────────────────────────────────────────────────────────────────────────
/** Run the probe inside `root` (an install: root/node_modules/@sym-bot/sym) with the encoder off: nothing loads a model. */
function probe(root) {
  fs.copyFileSync(path.join(__dirname, 'fixtures', 'surface-probe.cjs'), path.join(root, 'probe.cjs'));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-surface-home-'));
  try {
    const r = spawnSync(process.execPath, ['probe.cjs'], { cwd: root, encoding: 'utf8', timeout: 60000, env: { ...process.env, HOME: home, USERPROFILE: home, SYM_SEMANTIC_ENCODER: 'off' } });
    const line = r.stdout.split('\n').filter((l) => l.startsWith('@@')).pop();
    if (!line) return { crashed: `the probe printed nothing (status ${r.status}): ${r.stderr.split('\n').filter(Boolean).slice(0, 3).join(' | ')}` };
    return JSON.parse(line.slice(2));
  } finally { fs.rmSync(home, { recursive: true, force: true }); }
}

/** What is wrong with the surface of the installed copy at `root`, as readable lines. [] when nothing. */
function surfaceProblems(root) {
  const p = probe(root);
  if (p.crashed) return [p.crashed];
  const out = [];
  const same = (what, got, want) => { if (!eq(got, want)) out.push(`${what}: ${JSON.stringify(got)}, documented ${JSON.stringify(want)}`); };
  same('package.json exports', p.exportsMap, DOCUMENTED.exportsMap);
  same('main entry names', p.main, DOCUMENTED.main);
  same('@sym-bot/sym/core names', p.core, DOCUMENTED.core);
  same('@sym-bot/sym/decision-log names', p.decisionLog, DOCUMENTED.decisionLog);
  same('DecisionLog methods', p.decisionLogMethods, DOCUMENTED.decisionLogMethods);
  same('@sym-bot/sym/store names', p.store, DOCUMENTED.store);
  same('names importing from ESM (core)', p.esm && p.esm.core, DOCUMENTED.core);
  same('names importing from ESM (decision-log)', p.esm && p.esm.log, DOCUMENTED.decisionLog);
  same('names importing from ESM (store)', p.esm && p.esm.store, DOCUMENTED.store);
  if (p.underscored.length) out.push(`underscore names exported: ${p.underscored.join(', ')}`);
  for (const [spec, code] of Object.entries(p.requireCodes)) if (code !== 'ERR_PACKAGE_PATH_NOT_EXPORTED') out.push(`require('${spec}') is not refused: ${code}`);
  for (const [spec, code] of Object.entries(p.resolveCodes)) if (code !== 'ERR_PACKAGE_PATH_NOT_EXPORTED') out.push(`require.resolve('${spec}') is not refused: ${code}`);
  if (p.esm && p.esm.privateImport !== 'ERR_PACKAGE_PATH_NOT_EXPORTED') out.push(`import('@sym-bot/sym/lib/node.js') is not refused: ${p.esm && p.esm.privateImport}`);
  for (const l of p.loadErrors) out.push(`a documented entry point does not load: ${l}`);
  if (p.symNode !== 'function') out.push('require(@sym-bot/sym).SymNode is not a function');
  if (p.mainVersion !== p.pkgVersion) out.push(`version ${p.mainVersion} is not package.json's ${p.pkgVersion}`);
  if (p.behaviour.error) out.push(`the documented names do not work: ${p.behaviour.error}`);
  if (!eq(p.coreFrozen, [true, true, true, true])) out.push(`the core constants are not frozen: ${JSON.stringify(p.coreFrozen)}`);
  return out;
}

// ── the installed copy ────────────────────────────────────────────────────────────────────────────────────────────
let work;
let tarball;
let unpacked; // the tarball's package/ directory

/** A fresh root with the installed package (copied from the unpacked tarball) and this repository's dependencies linked beside it. */
function install() {
  const root = fs.mkdtempSync(path.join(work, 'root-'));
  const nm = path.join(root, 'node_modules');
  fs.mkdirSync(path.join(nm, '@sym-bot'), { recursive: true });
  fs.cpSync(unpacked, path.join(nm, '@sym-bot', 'sym'), { recursive: true });
  for (const name of fs.readdirSync(path.join(REPO, 'node_modules'))) {
    if (name.startsWith('.') || name === '@sym-bot') continue;
    fs.symlinkSync(path.join(REPO, 'node_modules', name), path.join(nm, name));
  }
  return { root, pkg: path.join(nm, '@sym-bot', 'sym') };
}

before(() => {
  work = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-surface-'));
  const env = { ...process.env };
  delete env.npm_config_dry_run; // a rehearsal of `npm publish --dry-run` would otherwise write no tarball
  const out = execFileSync('npm', ['pack', '--pack-destination', work, '--ignore-scripts', '--json'], { cwd: REPO, encoding: 'utf8', env });
  tarball = path.join(work, JSON.parse(out)[0].filename);
  const x = path.join(work, 'x');
  fs.mkdirSync(x);
  execFileSync('tar', ['-xzf', tarball, '-C', x]);
  unpacked = path.join(x, 'package');
});
after(() => { fs.rmSync(work, { recursive: true, force: true }); });

// ── the tests ─────────────────────────────────────────────────────────────────────────────────────────────────────
describe('the public surface of the installed package', () => {
  it('the check passes on the package as published: documented subpaths, exactly the documented names, private paths refused', () => {
    const { root } = install();
    assert.deepEqual(surfaceProblems(root), []);
  });

  it('the details behind the check, read from the probe: refusals are ERR_PACKAGE_PATH_NOT_EXPORTED for require, require.resolve and import', () => {
    const { root } = install();
    const p = probe(root);
    assert.ok(Object.keys(p.requireCodes).length >= 10);
    for (const [spec, code] of Object.entries({ ...p.requireCodes, ...p.resolveCodes })) assert.equal(code, 'ERR_PACKAGE_PATH_NOT_EXPORTED', spec);
    assert.equal(p.esm.privateImport, 'ERR_PACKAGE_PATH_NOT_EXPORTED');
    assert.deepEqual(p.esm.coreDefault, DOCUMENTED.core, 'the default import is module.exports');
    assert.equal(p.esm.sameFunction, true, 'and a named import is the same function');
  });

  it('the documented names work on the installed copy', () => {
    const { root } = install();
    const b = probe(root).behaviour;
    assert.equal(b.keyShape, true, 'createCMB mints a content address');
    assert.deepEqual(b.sections, ['categories', 'metadata']);
    assert.equal(b.render, 'focus: a surface probe; mood: calm (v:0.2, a:0.1)');
    assert.equal(b.renderBad, '');
    assert.deepEqual(b.categories, ['focus', 'issue', 'intent', 'motivation', 'commitment', 'perspective', 'mood']);
    assert.deepEqual(b.uniform, { focus: 1, issue: 1, intent: 1, motivation: 1, commitment: 1, perspective: 1, mood: 1 });
    assert.deepEqual(b.encode, [32, 32, 32]);
    assert.match(b.categoryKey, /^[0-9a-f]{64}$/);
    assert.deepEqual(b.verifyUnsigned, { signed: false, valid: false });
    assert.equal(b.kernel, 'ngram-h32', 'with SYM_SEMANTIC_ENCODER=off the kernel is the n-gram one');
    assert.deepEqual(b.semantic, ['h1', 'h2']);
    assert.equal(b.cannotWrite, 'refused', 'the frozen constants cannot be written');
  });

  it('require(@sym-bot/sym) and @sym-bot/sym/package.json work, and both bins run from the installed package', () => {
    const { root, pkg } = install();
    const manifest = JSON.parse(fs.readFileSync(path.join(pkg, 'package.json'), 'utf8'));
    assert.deepEqual(manifest.bin, { sym: './bin/sym.js', 'sym-daemon': './bin/sym-daemon.js' });
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-surface-bin-'));
    const env = { ...process.env, HOME: home, USERPROFILE: home, SYM_SEMANTIC_ENCODER: 'off' };
    try {
      const v = execFileSync(process.execPath, [path.join(pkg, manifest.bin.sym), '--version'], { encoding: 'utf8', env, cwd: root });
      assert.equal(v.trim(), `sym ${manifest.version}`);
      const d = execFileSync(process.execPath, [path.join(pkg, manifest.bin['sym-daemon']), '--status'], { encoding: 'utf8', env, cwd: root });
      assert.match(d, /^sym-daemon: /);
      const m = execFileSync(process.execPath, ['-e', "const s = require('@sym-bot/sym'); process.stdout.write(JSON.stringify([typeof s.SymNode, s.version, require('@sym-bot/sym/package.json').version]))"], { encoding: 'utf8', env, cwd: root });
      assert.deepEqual(JSON.parse(m), ['function', manifest.version, manifest.version]);
    } finally { fs.rmSync(home, { recursive: true, force: true }); }
  });

  it('the tarball carries what the exports map points at, and no test fixture or probe', () => {
    const { pkg } = install();
    for (const target of Object.values(DOCUMENTED.exportsMap)) assert.ok(fs.existsSync(path.join(pkg, target)), target);
    for (const f of ['README.md', 'LICENSE', 'bin/sym.js', 'bin/sym-daemon.js']) assert.ok(fs.existsSync(path.join(pkg, f)), f);
    // every docs/ file that the shipped README Public API section and the shipped CHANGELOG entry point a reader at
    const readme = fs.readFileSync(path.join(pkg, 'README.md'), 'utf8');
    const changelog = fs.readFileSync(path.join(pkg, 'CHANGELOG.md'), 'utf8');
    const at = changelog.indexOf('## 0.14.1');
    const cited = [readme.slice(readme.indexOf('\n## Public API'), readme.indexOf('\n## Go deeper')), changelog.slice(at, changelog.indexOf('\n## ', at + 4))]
      .flatMap((t) => t.match(/docs\/[A-Za-z0-9._-]+\.md/g) || []);
    assert.ok(cited.includes('docs/reference.md'), 'the section points at docs/reference.md');
    for (const doc of new Set(cited)) assert.ok(fs.existsSync(path.join(pkg, doc)), `${doc} is cited by shipped text and must ship`);
    assert.equal(fs.existsSync(path.join(pkg, 'tests')), false);
    assert.equal(fs.existsSync(path.join(pkg, 'probe.cjs')), false);
  });
});

// ── the documentation says what the code exports ──────────────────────────────────────────────────────────────────
/** What is wrong with a README: the Public API section against DOCUMENTED. */
function docProblems(readme, what = 'README.md') {
  const at = readme.indexOf('\n## Public API');
  if (at < 0) return [`${what} has no "Public API" section`];
  const section = readme.slice(at + 1, readme.indexOf('\n## ', at + 4) < 0 ? undefined : readme.indexOf('\n## ', at + 4));
  const out = [];
  for (const s of SUBPATHS) if (!section.includes(`\`${s}\``) && !section.includes(`**\`${s}\`**`) && !section.includes(s)) out.push(`${what}: subpath ${s} is not documented`);
  const mentioned = new Set((section.match(/@sym-bot\/sym\/[A-Za-z0-9._/-]+/g) || []).map((m) => m.replace(/[.,;:)]+$/, '')));
  for (const m of mentioned) if (!SUBPATHS.includes(m) && !m.startsWith('@sym-bot/sym/lib/')) out.push(`${what}: documents ${m}, which is not a subpath`);
  const names = [...DOCUMENTED.core, ...DOCUMENTED.decisionLog, ...DOCUMENTED.store, ...DOCUMENTED.main.filter((n) => n !== 'claude'), ...DOCUMENTED.options, ...DOCUMENTED.methods];
  for (const n of names) if (!section.includes(n)) out.push(`${what}: ${n} is not mentioned`);
  for (const m of DOCUMENTED.decisionLogMethods) if (!section.includes(`${m}(`)) out.push(`${what}: DecisionLog.${m}() is not documented`);
  return out;
}

describe('the documentation says what the code exports', () => {
  const readme = fs.readFileSync(path.join(REPO, 'README.md'), 'utf8');
  const reference = fs.readFileSync(path.join(REPO, 'docs', 'reference.md'), 'utf8');

  it('README "Public API" names every subpath and every name, and nothing that is not exported', () => {
    assert.deepEqual(docProblems(readme), []);
  });

  it('docs/reference.md documents the subpaths, the host options and the encoder switch', () => {
    for (const s of SUBPATHS) assert.ok(reference.includes(s), `${s} in docs/reference.md`);
    for (const o of [...DOCUMENTED.options, ...DOCUMENTED.methods, 'ERR_PACKAGE_PATH_NOT_EXPORTED', 'ENOSTORE', 'EBADENCODER']) assert.ok(reference.includes(o), `${o} in docs/reference.md`);
  });

  it('the CHANGELOG has a 0.14.1 entry that lists the subpaths', () => {
    const log = fs.readFileSync(path.join(REPO, 'CHANGELOG.md'), 'utf8');
    const at = log.indexOf('## 0.14.1');
    assert.ok(at >= 0, 'a 0.14.1 heading');
    const entry = log.slice(at, log.indexOf('\n## ', at + 4));
    for (const s of SUBPATHS.slice(0, 3)) assert.ok(entry.includes(s), s);
    assert.match(entry, /ERR_PACKAGE_PATH_NOT_EXPORTED/);
  });

  it('package.json "files" ships what the tarball references: README and the lib the exports map points into', () => {
    const files = JSON.parse(fs.readFileSync(path.join(REPO, 'package.json'), 'utf8')).files;
    assert.ok(files.includes('README.md') && files.includes('lib/'));
  });
});

// ── MUTATION: the check must fail on a bad surface ────────────────────────────────────────────────────────────────
describe('mutation: the surface check bites', () => {
  /** Install, apply `mutate(pkgDir)`, and return the problems the check reports. */
  const mutated = (mutate) => {
    const { root, pkg } = install();
    mutate(pkg);
    return surfaceProblems(root);
  };
  const editJson = (file, fn) => { const j = JSON.parse(fs.readFileSync(file, 'utf8')); fn(j); fs.writeFileSync(file, JSON.stringify(j, null, 2)); };
  const editText = (file, fn) => fs.writeFileSync(file, fn(fs.readFileSync(file, 'utf8')));
  const has = (problems, re) => assert.ok(problems.some((l) => re.test(l)), `expected a problem matching ${re}, got:\n  ${problems.join('\n  ') || '(none)'}`);

  it('an extra name on @sym-bot/sym/core (a private function made public) is reported', () => {
    const problems = mutated((pkg) => editText(path.join(pkg, 'lib/public/core.js'), (t) => t.replace('Object.freeze(module.exports);', "exports.signCMB = core.signCMB;\nObject.freeze(module.exports);")));
    has(problems, /@sym-bot\/sym\/core names/);
    has(problems, /names importing from ESM \(core\)/);
  });

  it('a missing documented name is reported', () => {
    const problems = mutated((pkg) => editText(path.join(pkg, 'lib/public/core.js'), (t) => t.replace('exports.kernelId = core.kernelId;\n', '')));
    has(problems, /@sym-bot\/sym\/core names/);
  });

  it('an underscore name is reported', () => {
    const problems = mutated((pkg) => editText(path.join(pkg, 'lib/public/store.js'), (t) => t.replace('Object.freeze(module.exports);', "exports._open = openStore;\nObject.freeze(module.exports);")));
    has(problems, /underscore names exported: store\._open/);
  });

  it('a new subpath in the exports map is reported (the memory store made public by a one-line edit)', () => {
    const problems = mutated((pkg) => editJson(path.join(pkg, 'package.json'), (j) => { j.exports['./memory-store'] = './lib/memory-store.js'; }));
    has(problems, /package\.json exports/);
    has(problems, /require\('@sym-bot\/sym\/memory-store'\) is not refused/);
  });

  it('a wildcard that re-opens lib/ is reported, for require, require.resolve and import', () => {
    const problems = mutated((pkg) => editJson(path.join(pkg, 'package.json'), (j) => { j.exports['./lib/*'] = './lib/*'; }));
    has(problems, /require\('@sym-bot\/sym\/lib\/node\.js'\) is not refused/);
    has(problems, /require\.resolve\('@sym-bot\/sym\/lib\/node\.js'\) is not refused/);
    has(problems, /import\('@sym-bot\/sym\/lib\/node\.js'\) is not refused/);
  });

  it('removing the exports map altogether (every file importable again) is reported', () => {
    const problems = mutated((pkg) => editJson(path.join(pkg, 'package.json'), (j) => { delete j.exports; }));
    has(problems, /package\.json exports/);
    has(problems, /a documented entry point does not load: @sym-bot\/sym\/core/);
    has(problems, /require\('@sym-bot\/sym\/lib\/node\.js'\) is not refused/);
  });

  it('losing the ./package.json subpath is reported', () => {
    const problems = mutated((pkg) => editJson(path.join(pkg, 'package.json'), (j) => { delete j.exports['./package.json']; }));
    has(problems, /package\.json exports/);
    has(problems, /a documented entry point does not load: @sym-bot\/sym\/package\.json/);
  });

  it('a change to the main entry (a name dropped) is reported', () => {
    const problems = mutated((pkg) => editText(path.join(pkg, 'lib/node.js'), (t) => t.replace("Object.defineProperty(module.exports, 'invite', {", "Object.defineProperty(module.exports, 'inviteX', {")));
    has(problems, /main entry names/);
  });

  it('a DecisionLog method added to the public class is reported', () => {
    const problems = mutated((pkg) => editText(path.join(pkg, 'lib/decision-log.js'), (t) => t.replace('count() { return this._ring.length; }', 'count() { return this._ring.length; }\n  purge() { this._ring = []; }')));
    has(problems, /DecisionLog methods/);
  });

  it('an unfrozen constant is reported', () => {
    const problems = mutated((pkg) => editText(path.join(pkg, 'lib/public/core.js'), (t) => t.replace(/exports\.CAT7_CATEGORIES = .*\n/, 'exports.CAT7_CATEGORIES = core.CAT7_CATEGORIES;\n')));
    has(problems, /not frozen/);
  });

  it('the documentation check bites too: a README that drops a name, or documents a subpath that does not exist', () => {
    const readme = fs.readFileSync(path.join(REPO, 'README.md'), 'utf8');
    assert.deepEqual(docProblems(readme), []);
    assert.ok(docProblems(readme.replace(/verifyCMB/g, 'verifyXMB')).some((l) => /verifyCMB is not mentioned/.test(l)));
    assert.ok(docProblems(readme.replace(/svafEvaluator/g, 'evaluatorOption')).some((l) => /svafEvaluator is not mentioned/.test(l)));
    assert.ok(docProblems(readme.replace('`@sym-bot/sym/store`', '`@sym-bot/sym/stores`')).some((l) => /@sym-bot\/sym\/stores, which is not a subpath/.test(l)));
    assert.ok(docProblems(readme.replace('## Public API', '## API')).some((l) => /no "Public API" section/.test(l)));
  });
});
