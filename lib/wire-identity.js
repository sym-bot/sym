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
 * string is no name ('unknown'). Both are bounded, since both are kept and repeated. The same
 * holds for the other peer-supplied values a node keeps and passes on: keys and wake channels.
 *
 * @copyright 2026 SYM.BOT. Apache 2.0 License.
 */

const { isCanonicalNodeId } = require('./core/record-canonical');

const MAX_NODE_ID = 256;
const MAX_NAME = 256;

/**
 * A nodeId off the wire, or null when it is not one. Only its canonical lowercase form is one
 * (§3.1.1; security review B): an upper-case spelling of a nodeId is not a second identity, and it
 * is not this one either, so it is refused at the door (a relay `from`, an announcement, a discovery
 * record, a gossip entry).
 */
function wireNodeId(x) {
  return typeof x === 'string' && x.length > 0 && x.length <= MAX_NODE_ID && isCanonicalNodeId(x) ? x : null;
}

/**
 * A display name off the wire: the sender's own label, a bounded string, or `fallback` ('unknown').
 * A frame's own `fromName` falls back to the name its transport already took (`wireName(msg.fromName,
 * peerName)`), so it is never kept, printed or passed on as given.
 */
function wireName(x, fallback = 'unknown') {
  return typeof x === 'string' && x.length > 0 ? x.slice(0, MAX_NAME) : fallback;
}

/** A public key off the wire (base64url text), or null when it is not one. */
function wireKey(x) {
  return typeof x === 'string' && x.length > 0 && x.length <= 512 ? x : null;
}

/**
 * A wake channel off the wire (a `wake-channel` frame, a `peer-info` entry, the relay's peer list):
 * `{ platform, token, environment }`, each text (token and environment may be absent), or null.
 * Only those three are kept — they are all a wake uses — since a channel is stored, written to
 * wake-channels.json and gossiped on to every peer this node meets.
 */
function wireWakeChannel(ch) {
  if (!ch || typeof ch !== 'object') return null;
  const { platform, token, environment } = ch;
  if (typeof platform !== 'string' || !platform || platform.length > 32) return null;
  // null is how some encoders (sym-swift's optionals) spell absent.
  if (token != null && (typeof token !== 'string' || token.length > 4096)) return null;
  if (environment != null && (typeof environment !== 'string' || environment.length > 64)) return null;
  return { platform, token: token ?? undefined, environment: environment ?? undefined };
}

module.exports = { wireNodeId, wireName, wireKey, wireWakeChannel, MAX_NODE_ID, MAX_NAME };
