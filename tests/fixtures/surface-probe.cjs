'use strict';

/**
 * Runs INSIDE an installed copy of the package (tests/public-surface.test.js copies it next to node_modules and
 * runs it there) and prints, as JSON, what a consumer of @sym-bot/sym can and cannot reach. It decides nothing:
 * the test compares what it prints with what README "Public API" documents.
 */

const names = (o) => Object.getOwnPropertyNames(o).sort();
const probe = {};

// A documented subpath that does not resolve is a finding, not a crash: the rest is still measured.
probe.loadErrors = [];
const load = (id, fallback = {}) => { try { return require(id); } catch (e) { probe.loadErrors.push(`${id}: ${e.code || e.message}`); return fallback; } };
const sym = load('@sym-bot/sym');
const core = load('@sym-bot/sym/core', { CAT7_CATEGORIES: [], FIELD_WEIGHT_PROFILES: { uniform: {} } });
const log = load('@sym-bot/sym/decision-log', { DecisionLog: { prototype: {} } });
const store = load('@sym-bot/sym/store');
const pkg = load('@sym-bot/sym/package.json');

probe.pkgVersion = pkg.version;
probe.exportsMap = pkg.exports;
probe.main = names(sym);
probe.mainVersion = sym.version;
probe.symNode = typeof sym.SymNode;
probe.core = names(core);
probe.coreFrozen = [Object.isFrozen(core), Object.isFrozen(core.CAT7_CATEGORIES), Object.isFrozen(core.FIELD_WEIGHT_PROFILES), Object.isFrozen(core.FIELD_WEIGHT_PROFILES.uniform)];
probe.decisionLog = names(log);
probe.decisionLogMethods = names(log.DecisionLog.prototype).filter((n) => n !== 'constructor' && !n.startsWith('_'));
probe.store = names(store);
probe.underscored = Object.entries({ main: names(sym), core: names(core), decisionLog: names(log), store: names(store) })
  .flatMap(([m, ns]) => ns.filter((n) => n.startsWith('_')).map((n) => `${m}.${n}`));

// What a consumer must NOT reach: private files, by package path, through require and through require.resolve.
const PRIVATE = [
  '@sym-bot/sym/lib/node.js', '@sym-bot/sym/lib/node', '@sym-bot/sym/lib/core/index.js', '@sym-bot/sym/lib/memory-store',
  '@sym-bot/sym/lib/discovery.js', '@sym-bot/sym/lib/rooms', '@sym-bot/sym/lib/ipc-client.js',
  '@sym-bot/sym/lib/decision-log.js', '@sym-bot/sym/lib/public/core.js', '@sym-bot/sym/lib/public/store.js',
  '@sym-bot/sym/lib', '@sym-bot/sym/core/index.js', '@sym-bot/sym/memory-store', '@sym-bot/sym/README.md',
];
// A bin runs the CLI when it is required, so it is only ever resolved.
const PRIVATE_RESOLVE_ONLY = ['@sym-bot/sym/bin/sym.js', '@sym-bot/sym/bin/sym-daemon.js'];
probe.requireCodes = {};
probe.resolveCodes = {};
for (const p of PRIVATE) {
  try { require(p); probe.requireCodes[p] = 'LOADED'; } catch (e) { probe.requireCodes[p] = e.code || e.message; }
}
for (const p of [...PRIVATE, ...PRIVATE_RESOLVE_ONLY]) {
  try { require.resolve(p); probe.resolveCodes[p] = 'RESOLVED'; } catch (e) { probe.resolveCodes[p] = e.code || e.message; }
}

// The documented names do what the README says, on the installed copy. A name that is missing makes this throw;
// that is recorded as `behaviour.error` so the names measured above are still reported.
probe.behaviour = (() => {
  try {
    const record = core.createCMB({ categories: { focus: 'a surface probe', mood: { text: 'calm', valence: 0.2, arousal: 0.1 } }, createdBy: 'probe' });
    return {
      keyShape: /^cmb-[0-9a-f]{64}$|^[0-9a-f]{64}$/.test(record.metadata.key) || record.metadata.key,
      sections: Object.keys(record).sort(),
      render: core.renderContent(record),
      renderBad: core.renderContent(null),
      categories: Array.from(core.CAT7_CATEGORIES),
      uniform: core.FIELD_WEIGHT_PROFILES.uniform,
      encode: [core.encode('hello world').h1.length, core.encode('hello world').h2.length, core.encodeCategory('hello world').length],
      categoryKey: core.categoryKeyV1('focus', 'a surface probe'),
      verifyUnsigned: core.verifyCMB(record, 'AAAA'),
      kernel: core.kernelId(),
      cannotWrite: (() => { try { core.CAT7_CATEGORIES.push('x'); return 'WROTE'; } catch { return 'refused'; } })(),
    };
  } catch (e) { return { error: e.message }; }
})();

(async () => {
  try { probe.behaviour.semantic = Object.keys(await core.encodeForSVAF('hello world')).sort(); } catch (e) { probe.behaviour.semanticError = e.message; }
  const imp = async (id) => { try { return await import(id); } catch (e) { probe.loadErrors.push(`import ${id}: ${e.code || e.message}`); return { default: {} }; } };
  const esm = { core: await imp('@sym-bot/sym/core'), log: await imp('@sym-bot/sym/decision-log'), store: await imp('@sym-bot/sym/store') };
  probe.esm = {
    core: Object.keys(esm.core).filter((k) => k !== 'default').sort(),
    coreDefault: Object.keys(esm.core.default).sort(),
    log: Object.keys(esm.log).filter((k) => k !== 'default').sort(),
    store: Object.keys(esm.store).filter((k) => k !== 'default').sort(),
    sameFunction: esm.core.createCMB === core.createCMB,
  };
  try { await import('@sym-bot/sym/lib/node.js'); probe.esm.privateImport = 'LOADED'; } catch (e) { probe.esm.privateImport = e.code; }
  process.stdout.write(`\n@@${JSON.stringify(probe)}\n`);
})().catch((e) => { console.error(e); process.exit(1); });
