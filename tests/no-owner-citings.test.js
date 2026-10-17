'use strict';

// The library never cites its owner. A public package carries what was decided and why, not who said it: no
// ruling or decision credited to a person, no quoted words, no personal name or address, in a comment, a doc, the
// CHANGELOG, a test title or an error string. This scans every tracked file (git ls-files; a directory walk when
// there is no .git, as in an export of the package) and fails on a citing.
//
// "founder" is also a ROLE in the authority model and part of the product's vocabulary, so the scan is deny-by-default:
// every "founder" in a line must be covered by the allowed vocabulary below, or it is a hit. The allowed vocabulary:
//   - identifiers and env vars: founderAction, _meta.founderAction, detectFounderAction, SYM_FOUNDER_ANCHOR
//   - the role: "founder key", "founder root", "founder anchor", "1-of-1 founder case"
//   - a node, task owner or source literally named 'founder', and the detector's keywords 'brief founder' and
//     'brief the founder'
//   - per-file entries (ALLOW_IN_FILE) for the words that describe the founderAction signal itself
// Skipped: tests/fixtures/** (hash-pinned vendored vectors), package-lock.json, binary files, node_modules, and this file
// (its own patterns would match themselves; the negative tests below run the same scanner on a planted tree).

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const SELF = 'tests/no-owner-citings.test.js';

const SKIP_DIRS = new Set(['node_modules', '.git', 'coverage']);
const SKIP_PREFIXES = ['tests/fixtures/'];
const SKIP_FILES = new Set(['package-lock.json', SELF]);
const BINARY = /\.(png|jpe?g|gif|ico|webp|pdf|woff2?|ttf|otf|zip|gz|tgz|mp4|mov)$/i;

// "founder" as vocabulary: stripped from a line before the line is judged.
const VOCABULARY = [
  /[A-Za-z0-9_]*[Ff]ounder[A-Z][A-Za-z0-9_]*/g,                // founderAction, detectFounderAction
  /[A-Z0-9_]*(?:_FOUNDER|FOUNDER_)[A-Z0-9_]*/g,                // SYM_FOUNDER_ANCHOR
  /\bfounder (?:key|root|anchor|case)s?\b/gi,                  // the role in the authority model
  /'(?:brief (?:the )?)?founder'/gi,                           // a node, task owner or source named 'founder'; the detector's keywords
];

// Words that describe the founderAction signal itself, allowed in the one file that implements it.
const ALLOW_IN_FILE = [
  { file: 'lib/mesh-agent.js', re: /Founder Action Detection|founder attention|the founder needs to see/gi,
    reason: 'describes the founderAction signal (a CMB a human should see)' },
];

// The owner's names and handles, built from parts so that this file holds none of them whole.
const NAMES = [['hong', 'wei'].join(''), ['hong', ' wei'].join(''), ['mx', 'michael'].join(''), ['symbot', 'dev'].join(''), 'michael'];

// Other citings, judged on the whole line.
const RULES = [
  { name: 'personal name or address', re: new RegExp(NAMES.join('|'), 'i') },
  { name: 'the user as the source of a decision', re: /\bthe user (?:said|asked|ruled|wants|approved|decided|told)\b|\buser ruling\b|\buser(?:'|’)s (?:ruling|word|rule)\b/i },
  { name: 'an executive or the owner as the source of a ruling', re: /\b(?:ceo|cto|coo|boss)(?:'s|’s)? (?:ruling|rulings|ruled|decision|decided|said|canon|approval)\b|\b(?:owner|user)(?:'s|’s)? (?:ruling|rulings|ruled|canon)\b/i },
  { name: 'a request or approval attributed to someone', re: /\b(?:as|per) (?:requested|asked|ruled|decided|instructed) by\b|\bper the (?:user|owner|ceo|cto|boss)\b/i },
  { name: 'a dated attribution, "(user, 2026-10-02: ...)"', re: /\((?:user|owner|boss|ceo|cto|coo),? *\d{4}-\d{2}-\d{2}/i },
];

/** The files of a tree: git ls-files when it is a checkout, a directory walk when it is not. */
function listFiles(root) {
  if (fs.existsSync(path.join(root, '.git'))) {
    try {
      return execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8', maxBuffer: 1 << 26 })
        .split('\0').filter(Boolean);
    } catch { /* git missing or not usable: walk */ }
  }
  const out = [];
  const walk = (dir, rel) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (SKIP_DIRS.has(e.name)) continue;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) walk(path.join(dir, e.name), r);
      else out.push(r);
    }
  };
  walk(root, '');
  return out;
}

const skipped = (rel) => SKIP_FILES.has(rel) || BINARY.test(rel) || SKIP_PREFIXES.some((p) => rel.startsWith(p));

/** Every citing in `root`: [{ file, line, rule, text }]. */
function scan(root, files = listFiles(root)) {
  const hits = [];
  for (const rel of files) {
    if (skipped(rel)) continue;
    let text;
    try {
      if (!fs.statSync(path.join(root, rel)).isFile()) continue;
      text = fs.readFileSync(path.join(root, rel), 'utf8');
    } catch { continue; } // tracked but not on disk (a staged removal)
    if (text.includes('\0')) continue; // binary
    const allow = ALLOW_IN_FILE.filter((a) => a.file === rel);
    text.split('\n').forEach((raw, i) => {
      const at = (rule) => hits.push({ file: rel, line: i + 1, rule, text: raw.trim().slice(0, 160) });
      let residue = raw;
      for (const re of VOCABULARY) residue = residue.replace(re, ' ');
      for (const a of allow) residue = residue.replace(a.re, ' ');
      if (/founder/i.test(residue)) at('"founder" outside the allowed vocabulary');
      for (const r of RULES) if (r.re.test(raw)) at(r.name);
    });
    if (RULES.some((r) => r.re.test(rel))) hits.push({ file: rel, line: 0, rule: 'personal name in a file name', text: rel });
  }
  return hits;
}

const show = (hits) => hits.map((h) => `${h.file}:${h.line}  [${h.rule}]  ${h.text}`).join('\n');

describe('the library does not cite its owner', () => {
  it('finds the files it checks', () => {
    const files = listFiles(ROOT).filter((f) => !skipped(f));
    assert.ok(files.length >= 100, `scanned ${files.length} files`);
  });

  it('no tracked file cites the owner (a ruling, a bug report, quoted words, a name)', () => {
    const hits = scan(ROOT);
    assert.deepStrictEqual(hits, [], `state the decision or the rule, not who gave it:\n${show(hits)}`);
  });

  it('every per-file allowance still matches something (the allowlist does not rot)', () => {
    for (const a of ALLOW_IN_FILE) {
      const p = path.join(ROOT, a.file);
      if (!fs.existsSync(p)) continue; // an export without this file
      assert.ok(new RegExp(a.re.source, a.re.flags.replace('g', '')).test(fs.readFileSync(p, 'utf8')),
        `${a.file}: allowance for "${a.reason}" matches nothing; remove it`);
    }
  });
});

describe('the scanner itself (a planted tree, no .git: the directory-walk path)', () => {
  const plant = (files) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sym-citings-'));
    for (const [rel, body] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), body);
    }
    return dir;
  };
  const withTree = (files, fn) => {
    const dir = plant(files);
    try { return fn(dir); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  };

  // The words the scanner looks for are built from parts, so this file holds no citing of its own.
  const T = {
    f: 'found' + 'er', F: 'Found' + 'er', FF: 'FOUND' + 'ER', u: 'us' + 'er',
    name: ['Hong', 'wei'].join(''), mail: ['symbot', 'dev@gmail.com'].join(''), handle: ['mx', 'michael'].join(''),
  };
  const CITINGS = {
    'a ruling in a comment':         `// the key is kept (${T.f} ruling 2026-08-04)`,
    'a ruling in capitals':          `**Status:** v2; ${T.FF} RULED 2026-08-26: ship it`,
    'a possessive ruling':           `/** The ${T.f}'s ruling, carried into the error. */`,
    'a decision label':              ` * ${T.F} decision D5: ship this fix on its own`,
    'a changelog sentence':          `The ${T.f} ruled three design changes.`,
    'a bug report':                  `### Redelivery (${T.f}'s bug report, 2026-10)`,
    'a relayed report':              ` * The bugs (${T.f}, via agent-b, 2026-10; mesh-channel 0.10.1)`,
    'words attributed to the owner': ` * two of them ${T.f} words, lost for three days`,
    'a line the owner drew':         ` * hold the line the ${T.f} drew`,
    'a canon reference':             ` * FROZEN (${T.f} canon §17)`,
    'a statement credited to the user': `// the ${T.u} said to drop the fallback`,
    'a ruling credited to the user': `// per the ${T.u} ruling, no suffixes`,
    'a dated user attribution':      '// the name is never spelled so (user, 2026-10-02: "use it in code")',
    'an executive ruling':           '// (CTO ruling, 2026-08-07)',
    'a requested-by line':           '// added as requested by the boss',
    'the owner\'s name':             `// agreed with ${T.name} on the call`,
    'the owner\'s address':          `contact: ${T.mail}`,
    'a handle':                      `// ask ${T.handle}`,
  };

  for (const [what, line] of Object.entries(CITINGS)) {
    it(`catches ${what}`, () => {
      const hits = withTree({ 'lib/x.js': `'use strict';\n${line}\nmodule.exports = 1;\n` }, (dir) => scan(dir));
      assert.strictEqual(hits.length >= 1, true, `not caught: ${line}`);
      assert.ok(hits.every((h) => h.file === 'lib/x.js' && h.line === 2), show(hits));
    });
  }

  it('catches a citing in a doc, a test title and the CHANGELOG, and in a file name', () => {
    const hits = withTree({
      'docs/a.md': `The ${T.f} ruled that it ships.\n`,
      'tests/t.test.js': `it('does it (${T.f} ruling, #26)', () => {});\n`,
      'CHANGELOG.md': `- **Thing** (${T.f} ruling 2026-08-27)\n`,
      [`notes-${T.name.toLowerCase()}.md`]: 'clean text\n',
    }, (dir) => scan(dir));
    assert.deepStrictEqual([...new Set(hits.map((h) => h.file))].sort(),
      ['CHANGELOG.md', 'docs/a.md', `notes-${T.name.toLowerCase()}.md`, 'tests/t.test.js']);
  });

  it('lets the vocabulary through: identifiers, the role, a node named founder, the detector\'s keywords', () => {
    const clean = [
      "if (!meta?.founderAction && detectFounderAction(categories)) meta.founderAction = true;",
      "const pin = process.env.SYM_FOUNDER_ANCHOR || null;",
      "// One founder key (the 1-of-1 case). The nodeId lets that node act as the anchor itself.",
      "canonization is reserved to anchor authority (the founder root or an anchor-rooted grantee)",
      "new SymNode({ name: 'founder', anchor: { threshold: 1, keys: [] } });",
      "t.agent !== 'founder'",
      "f.source = 'founder';",
      "'founder', 'human', 'decision', 'brief founder', 'brief the founder',",
      "/** A node pinned as its own 1-of-1 anchor (the founder case). */",
      "_meta.founderAction=true ONLY if your role definition's rules for it are satisfied",
    ].join('\n');
    assert.deepStrictEqual(withTree({ 'lib/x.js': clean + '\n' }, (dir) => scan(dir)), []);
  });

  it('lets a per-file allowance through in its own file only', () => {
    const body = '// Auto-detect whether a CMB warrants founder attention.\n';
    assert.deepStrictEqual(withTree({ 'lib/mesh-agent.js': body }, (dir) => scan(dir)), []);
    assert.strictEqual(withTree({ 'lib/other.js': body }, (dir) => scan(dir)).length, 1);
  });

  it('still catches a citing on a line that also holds vocabulary', () => {
    const hits = withTree({ 'lib/x.js': `// founderAction is set by the ${T.f}'s ruling\n` }, (dir) => scan(dir));
    assert.strictEqual(hits.length, 1);
  });

  it('skips the vendored fixtures, the lockfile, binaries and node_modules', () => {
    const hits = withTree({
      'tests/fixtures/vec.json': `{"note":"${T.f} ruling"}\n`,
      'package-lock.json': `{"name":"${T.f} ruling"}\n`,
      'docs/pic.png': `${T.f} ruling`,
      'node_modules/x/index.js': `// ${T.f} ruling\n`,
    }, (dir) => scan(dir));
    assert.deepStrictEqual(hits, []);
  });

  it('reports the file, the line and the rule', () => {
    const hits = withTree({ 'docs/a.md': `fine\nfine\nThe ${T.f} said so.\n` }, (dir) => scan(dir));
    assert.deepStrictEqual(hits.map((h) => [h.file, h.line, h.rule]), [['docs/a.md', 3, '"founder" outside the allowed vocabulary']]);
  });
});
