'use strict';
// node scripts/identity-fuzz/prepare.js: git archive the 0.14.2 and 0.13.17 releases into the work dir (never a stash).
const fs = require('fs'); const path = require('path'); const cp = require('child_process');
const { WORK, REPO } = require('./common');
for (const [tag, dir] of [['v0.14.2', '0.14.2'], ['v0.13.17', '0.13.17']]) {
  const to = path.join(WORK, 'trees', dir);
  fs.rmSync(to, { recursive: true, force: true }); fs.mkdirSync(to, { recursive: true });
  cp.execSync(`git -C ${JSON.stringify(REPO)} archive ${tag} | tar -x -C ${JSON.stringify(to)}`);
  fs.symlinkSync(path.join(REPO, 'node_modules'), path.join(to, 'node_modules'));
  console.log(`${tag} -> ${to}`);
}
