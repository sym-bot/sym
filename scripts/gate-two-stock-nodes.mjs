#!/usr/bin/env node
/**
 * The two-stock-nodes release gate.
 *
 * The milestone this gate belongs to is stated behaviourally, not as a version number: TWO STOCK
 * sym NODES CREATE, SIGN, EXCHANGE, VERIFY, EVALUATE, ADMIT AND STORE WITH LINEAGE, ACROSS A
 * RESTART. Every clause is checked below, in that order, because they fail differently — a record
 * that arrives but is never admitted, and one that is admitted but does not survive a restart, are
 * two different broken products, and both look like "it worked" from the sender's side.
 *
 * STOCK means two things this file enforces rather than assumes:
 *
 *   1. The artifact, not the checkout. `npm pack` → install into an EMPTY directory → drive the
 *      INSTALLED copy. A `files` whitelist that omits a required module is invisible to every
 *      test in the repo and fatal on the user's machine; that has shipped here before.
 *   2. No engine. The install tree is asserted free of @sym-bot/core, so nothing in this run can
 *      be silently supplied by the package sym is meant to have absorbed. The gate proves the open
 *      implementation is self-sufficient — which is the entire claim of the release.
 *
 * The two nodes are wired with in-process transports rather than mDNS: the gate must fail on
 * sym's behaviour, never on the CI host's multicast. Everything above the transport — frame
 * handling, signature verification, SVAF evaluation, admission, the store — is the real path.
 *
 * Usage:  node scripts/gate-two-stock-nodes.mjs   (exits non-zero and says which clause failed)
 */

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const work = fs.mkdtempSync(path.join(os.tmpdir(), "sym-stock-gate-"));
const install = path.join(work, "install");
fs.mkdirSync(install);

const run = (cmd, args, opts = {}) => {
  // npm config propagates to CHILD npm processes through npm_config_* environment
  // variables, so rehearsing a release with `npm publish --dry-run` sets
  // npm_config_dry_run=true for everything this gate spawns: `npm pack` then writes no
  // tarball and the gate dies with ENOENT on a file it just asked for. It reads exactly like
  // a real regression in the artifact. Scrubbed here at the single spawn point rather than at
  // each call site, because the next child added would inherit the trap again — the safest
  // rehearsal of a publish must not be the one thing guaranteed to fail. (Found by
  // dev-team-2, 2026-08-27, by prediction: setting the variable reproduces it, clearing it
  // passes.)
  const env = { ...process.env, ...(opts.env ?? {}) };
  delete env.npm_config_dry_run;
  return execFileSync(cmd, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    ...opts,
    env,
  });
};

const step = (msg) => console.log(`\n▸ ${msg}`);
let packed;

try {
  step("packing the artifact users receive");
  const packOut = run("npm", ["pack", "--pack-destination", work], { cwd: repo });
  packed = path.join(work, packOut.trim().split("\n").pop().trim());
  console.log(`  ${path.basename(packed)}`);

  step("installing it into an empty directory");
  fs.writeFileSync(
    path.join(install, "package.json"),
    JSON.stringify({ name: "stock-node-gate", version: "0.0.0", private: true }, null, 2),
  );
  run("npm", ["install", packed, "--no-audit", "--no-fund", "--loglevel", "error"], { cwd: install });

  step("asserting the install carries no engine");
  const engine = path.join(install, "node_modules", "@sym-bot", "core");
  if (fs.existsSync(engine)) {
    throw new Error(
      "@sym-bot/core is present in the stock install — this run would prove nothing about sym's " +
      "self-sufficiency, which is the claim the release makes",
    );
  }
  console.log("  no @sym-bot/core in the tree");

  step("driving two stock nodes through the full path");
  fs.copyFileSync(path.join(repo, "scripts", "two-stock-nodes-driver.cjs"), path.join(install, "gate.cjs"));
  const out = run("node", ["gate.cjs"], { cwd: install, stdio: ["ignore", "pipe", "inherit"] });
  process.stdout.write(out);

  console.log("\nGATE PASSED — two stock sym nodes created, signed, exchanged, verified, evaluated,");
  console.log("admitted and stored with lineage, and the record survived a restart.");
} catch (err) {
  console.error(`\nGATE FAILED — ${err.message}`);
  if (err.stdout) process.stdout.write(String(err.stdout));
  if (err.stderr) process.stderr.write(String(err.stderr));
  process.exitCode = 1;
} finally {
  // Kept on failure: the install tree and the node dirs under it are the evidence.
  if (process.exitCode !== 1) fs.rmSync(work, { recursive: true, force: true });
  else console.error(`\nevidence kept at ${work}`);
}
