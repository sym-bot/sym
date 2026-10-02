'use strict';

/**
 * @module @sym-bot/sym/wire-identity
 * @description The identity a peer declares on the wire, taken at the door as what it must be.
 *
 * A peer's nodeId and name arrive as JSON: in a handshake, a relay envelope (`from`, `fromName`),
 * a relay's peer list or join notice (which carries what the joiner put in its relay-auth). JSON
 * can carry any type there, including an object whose `toString` is not callable, which throws
 * the moment anything turns it into text — a log line, a template string, `.slice`. Until 0.13.17
 * these values were stored as given (in the peer table, the relay transports) and turned into
 * text later, much of it in timers and transport callbacks where a throw is uncaught: a peer could
 * crash a node by choosing its own name. Taken here instead: a nodeId that is not a non-empty
 * string is no nodeId (the announcement or connection is refused), and a name that is not a
 * string is no name ('unknown'). Both are bounded, since both are kept and repeated.
 *
 * @copyright 2026 SYM.BOT. Apache 2.0 License.
 */

const MAX_NODE_ID = 256;
const MAX_NAME = 256;

/** A nodeId off the wire, or null when it is not one. */
function wireNodeId(x) {
  return typeof x === 'string' && x.length > 0 && x.length <= MAX_NODE_ID ? x : null;
}

/** A display name off the wire: the sender's own label, a bounded string, or 'unknown'. */
function wireName(x) {
  return typeof x === 'string' && x.length > 0 ? x.slice(0, MAX_NAME) : 'unknown';
}

/** A public key off the wire (base64url text), or null when it is not one. */
function wireKey(x) {
  return typeof x === 'string' && x.length > 0 && x.length <= 512 ? x : null;
}

module.exports = { wireNodeId, wireName, wireKey, MAX_NODE_ID, MAX_NAME };
