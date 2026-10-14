'use strict';

/**
 * @module @sym-bot/sym/core
 * @description The documented public surface of sym's CMB library: ten names, no more. It is the
 * subpath `@sym-bot/sym/core` (package.json "exports"); everything else under lib/ is private and not
 * importable by package path. README "Public API" says what each name promises and what it does not.
 *
 * This file picks names from lib/core/index.js and adds nothing of its own, except that the two
 * constants are deep-frozen copies: they are shared values the node itself reads, and a host that wrote
 * to the live ones would change every node's behaviour in its process; and that `verifyCMB` here is core's
 * `verifyRecord` (sym 0.14.3, security review R2-12): the whole check of a record's own bytes — schema,
 * bounds, assertion identity, signature, address — with the suite it was signed under and whether it is
 * Core Secure. Core's own `verifyCMB` is the signature step a node runs on a record it already projected.
 *
 * @copyright 2026 SYM.BOT Ltd
 * @license Apache-2.0
 */

const core = require('../core');

/** The documented names. tests/public-surface.test.js holds what is exported to README "Public API". */
const NAMES = Object.freeze([
  'createCMB',
  'renderContent',
  'CAT7_CATEGORIES',
  'FIELD_WEIGHT_PROFILES',
  'encode',
  'encodeCategory',
  'encodeForSVAF',
  'categoryKeyV1',
  'kernelId',
  'verifyCMB',
]);

const deepFreeze = (v) => {
  if (v && typeof v === 'object' && !Object.isFrozen(v)) {
    for (const k of Object.keys(v)) deepFreeze(v[k]);
    Object.freeze(v);
  }
  return v;
};

for (const name of NAMES) {
  if (typeof core[name] === 'undefined') throw new Error(`sym/core public surface: "${name}" is not exported by lib/core`);
}

// One assignment per name, spelled out, so that an ES module can import them by name
// (`import { createCMB } from '@sym-bot/sym/core'`): Node reads a CommonJS module's names from assignments like
// these and cannot from a loop. tests/public-surface.test.js holds the result to the documented names.
exports.createCMB = core.createCMB;
exports.renderContent = core.renderContent;
exports.CAT7_CATEGORIES = deepFreeze(JSON.parse(JSON.stringify(core.CAT7_CATEGORIES)));
exports.FIELD_WEIGHT_PROFILES = deepFreeze(JSON.parse(JSON.stringify(core.FIELD_WEIGHT_PROFILES)));
exports.encode = core.encode;
exports.encodeCategory = core.encodeCategory;
exports.encodeForSVAF = core.encodeForSVAF;
exports.categoryKeyV1 = core.categoryKeyV1;
exports.kernelId = core.kernelId;
exports.verifyCMB = core.verifyRecord;
Object.freeze(module.exports);
