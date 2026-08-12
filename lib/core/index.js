'use strict';

/**
 * @module sym/core
 * @description The open runtime core — CMB records, signing, admission, coupling,
 * lineage, attestation, wake, and store-root plumbing.
 *
 * Absorbed from @sym-bot/core under the sym-core split (2026-08). Every module
 * here implements published MMP surface or is runtime plumbing; the admission
 * and coupling ENGINES are injectable at their seams (frame handler `opts.admit`,
 * MeshNode `opts.coupler`) and the defaults exported here are the open reference
 * implementations a stock node runs.
 *
 * @copyright 2026 SYM.BOT Ltd
 * @license Apache-2.0
 */

const modules = [
  require('./cmb'),
  require('./cmb-encoder'),
  require('./cmb-signing'),
  require('./record-shape'),
  require('./ref'),
  require('./role-grant'),
  require('./lineage-tether'),
  require('./tether-attestation'),
  require('./attestation'),
  require('./merkle'),
  require('./e2e-crypto'),
  require('./context-encoder'),
  require('./state-root'),
  require('./wake'),
  require('./metrics'),
  require('./mesh-node'),
  require('./default-coupler'),
  require('./svaf-baseline'),
];

// One name, one home. A duplicate export is a refactor hazard surfacing as a
// silent clobber, so it throws at require time instead of shipping.
const out = {};
for (const m of modules) {
  for (const [name, value] of Object.entries(m)) {
    if (name === '__esModule') continue;
    if (Object.prototype.hasOwnProperty.call(out, name)) {
      // A re-export of the SAME value (cmb-encoder re-exports CAT7_CATEGORIES from cmb) is
      // one name with one home; only two DIFFERENT values under one name is the hazard.
      if (out[name] === value) continue;
      throw new Error(`sym/core: duplicate export "${name}" — two core modules claim the same name`);
    }
    out[name] = value;
  }
}

// The e2e keypair helpers ship under prefixed names — generateKeyPair alone reads
// as an identity-key operation, and this is the ONE module where it must not.
out.e2eGenerateKeyPair = out.generateKeyPair;
out.e2eDeriveSharedSecret = out.deriveSharedSecret;

module.exports = out;
