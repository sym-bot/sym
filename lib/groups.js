'use strict';

/**
 * Mesh groups (MMP §5.8) — the shared source of truth for how a group name
 * maps to a Bonjour/mDNS service type, and what a valid group name is.
 *
 * This MUST match the mapping used by sym-mesh-channel (the Claude MCP node)
 * and sym-swift, or CLI nodes won't discover app/Claude nodes in the same
 * group. Convention:
 *   - "default"        -> _sym._tcp   (the global/public mesh)
 *   - "<kebab-group>"  -> _<group>._tcp   (a private group / "group chat")
 *
 * Group names are kebab-case (e.g. "backend-team") or the literal "default".
 *
 * Copyright (c) 2026 SYM.BOT. Apache 2.0 License.
 */

const KEBAB_CASE_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

/** A valid group name is "default" or kebab-case. */
function isValidGroup(group) {
  return group === 'default' || (typeof group === 'string' && KEBAB_CASE_RE.test(group));
}

/** Map a group name to its Bonjour service type. */
function groupServiceType(group) {
  return (group && group !== 'default') ? `_${group}._tcp` : '_sym._tcp';
}

/** Inverse: derive a group name from a service type (`_acme._tcp` -> "acme"). */
function serviceTypeToGroup(serviceType) {
  if (!serviceType || serviceType === '_sym._tcp') return 'default';
  return serviceType.replace(/^_/, '').replace(/\._tcp$/, '');
}

module.exports = { isValidGroup, groupServiceType, serviceTypeToGroup, KEBAB_CASE_RE };
