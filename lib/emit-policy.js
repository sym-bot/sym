'use strict';

/**
 * The single mesh-wide switch for the MMP v2.0 emitter flip (reader-first migration).
 *
 * ON since sym 0.14.0 (Core Secure, design D4). The v2.0 reader (verifyCMB accepting mmp-sig-v2.0)
 * shipped in 0.13.x and is deployed, and a Core Secure session carries only signed v2.0 records
 * (§18.3.1): every emit path — the Class 1 emitter (lib/emit.js) and the resident node
 * (lib/node.js) — mints mmp-sig-v2.0 records whose author is the signed createdByNodeId.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const MMP_EMIT_V2 = true;

module.exports = { MMP_EMIT_V2 };
