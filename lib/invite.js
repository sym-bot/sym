'use strict';

/**
 * @module @sym-bot/sym/invite
 * @description Room and team invites with the issuer's identity (sym 0.14, design D5).
 *
 *   sym://room/<room>?node=<nodeId>&key=<identity key>
 *   sym://team/<room>?relay=<url>&token=<token>&node=<nodeId>&key=<identity key>
 *   <app>://room/<id>[/<name>]?…        (app-scoped rooms: the room is `<app>-<id>`)
 *
 * `node` and `key` name the ISSUER. Accepting an invite pins the issuer's key at `pinned` in the key
 * registry — an out-of-band binding — ONLY when that nodeId is unbound. A nodeId already bound to a
 * different key is a conflict for the operator (design D3), never an override: an invite cannot
 * repoint a proven key.
 *
 * AN INVITE IS A SECRET. A team invite carries the relay token, which admits its holder to the relay
 * channel (review M8). It is also integrity-sensitive: whoever edits `key` before it is accepted
 * chooses whom the acceptor pins. Send it over a channel you trust for both.
 *
 * The grammar matches mesh-channel's INVITE_URL_RE (which already takes a query string); `node` and
 * `key` are new query parameters, ignored by a parser that does not know them.
 *
 * @copyright 2026 SYM.BOT. Apache 2.0 License.
 */

const { isIdentityKey } = require('./roster-keys');

const INVITE_URL_RE = /^([a-z][a-z0-9-]+):\/\/(room|team)\/([^/?#]+)(?:\/([^?#]+))?(?:\?([^#]*))?$/i;
// The canonical lowercase form only (§3.1.1; security review B): an upper-case nodeId is refused.
const NODE_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Build an invite URL.
 * @param {object} o
 * @param {string} o.room
 * @param {'room'|'team'} [o.kind] - 'team' when a relay is given
 * @param {string} [o.relay]
 * @param {string} [o.token]
 * @param {{ nodeId: string, publicKey: string }} [o.issuer] - the issuing node (its key is pinned by acceptors)
 * @param {string} [o.scheme='sym']
 * @returns {string}
 */
function buildInvite({ room, kind, relay, token, issuer, scheme = 'sym' } = {}) {
  if (typeof room !== 'string' || !room) throw new Error('buildInvite: room is required');
  const k = kind || (relay ? 'team' : 'room');
  const q = [];
  if (relay) q.push(`relay=${encodeURIComponent(relay)}`);
  if (token) q.push(`token=${encodeURIComponent(token)}`);
  if (issuer) {
    if (!NODE_ID_RE.test(String(issuer.nodeId || '')) || !isIdentityKey(issuer.publicKey)) throw new Error('buildInvite: issuer must be { nodeId (UUID), publicKey (base64url Ed25519) }');
    q.push(`node=${encodeURIComponent(issuer.nodeId)}`, `key=${encodeURIComponent(issuer.publicKey)}`);
  }
  return `${scheme}://${k}/${encodeURIComponent(room)}${q.length ? `?${q.join('&')}` : ''}`;
}

/**
 * Parse an invite URL. Never throws: an invite that is not one comes back with `error`.
 * @returns {{ error?: string, appScheme?: string, kind?: string, room?: string, roomId?: string,
 *   roomName?: string, relayUrl?: string|null, relayToken?: string|null,
 *   issuer?: { nodeId: string, publicKey: string }|null }}
 */
function parseInvite(url) {
  const m = typeof url === 'string' ? INVITE_URL_RE.exec(url.trim()) : null;
  if (!m) return { error: `not an invite URL: ${String(url).slice(0, 120)}` };
  const appScheme = m[1].toLowerCase();
  let rawId, rawName, query;
  try {
    rawId = decodeURIComponent(m[3]);
    rawName = m[4] ? decodeURIComponent(m[4]) : rawId;
    query = Object.fromEntries((m[5] || '').split('&').filter(Boolean).map((kv) => {
      const i = kv.indexOf('=');
      const k = i < 0 ? kv : kv.slice(0, i);
      const v = i < 0 ? '' : kv.slice(i + 1);
      return [decodeURIComponent(k), decodeURIComponent(v)];
    }));
  } catch { return { error: 'the invite URL is not validly encoded' }; }
  const room = appScheme === 'sym' ? rawId : `${appScheme}-${rawId}`;
  let issuer = null;
  if (query.node !== undefined || query.key !== undefined) {
    if (!NODE_ID_RE.test(String(query.node || '')) || !isIdentityKey(query.key)) {
      return { error: 'the invite names an issuer, but its node is not a lowercase UUID or its key is not a base64url Ed25519 public key' };
    }
    issuer = { nodeId: query.node, publicKey: query.key };
  }
  return {
    appScheme, kind: m[2].toLowerCase(), room, roomId: rawId, roomName: rawName,
    relayUrl: query.relay || null, relayToken: query.token || null, issuer,
  };
}

module.exports = { buildInvite, parseInvite, INVITE_URL_RE };
