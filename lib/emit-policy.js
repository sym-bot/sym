'use strict';

/**
 * The single mesh-wide switch for the MMP v2.0 emitter flip (reader-first migration).
 *
 * OFF until the v2.0 READER (verifyCMB accepting mmp-sig-v2.0) is released and deployed across
 * the mesh. A peer still on the old verifier rejects a v2.0-signed record, so flipping before
 * readers are live splits the mesh. Every emit path — the Class 1 emitter (lib/emit.js) and the
 * resident node (lib/node.js) — reads THIS constant, so the flip is one deliberate edit in one
 * place, made after reader rollout is confirmed.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const MMP_EMIT_V2 = false;

module.exports = { MMP_EMIT_V2 };
