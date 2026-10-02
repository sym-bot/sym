'use strict';

/**
 * @module @sym-bot/sym/peer-state
 * @description The bound on what a node keeps per peer from the wire.
 *
 * A node keeps small facts per peer, learned from what the peer sent: its room-admission verdict,
 * its E2E shared secret and the key it was derived from, its identity key, its declared lifecycle
 * role, when anchors were last sent to it. Each is keyed by the peerId the frame came with, and
 * until 0.13.17 none was ever pruned or bounded, so a peer (or a relay) presenting new peerIds, or
 * one link re-sending its handshake with new keys, grew them without limit. Two rules now:
 *   - what is learned from a connection's handshake and is learned again on the next one (the
 *     lifecycle role, the derived-key cache, an ADMIT verdict) is forgotten when the peer leaves
 *     the peer table (SymNode#_forgetPeer). A REFUSAL verdict is kept: it is what shuts a refused
 *     peer that keeps speaking (over the relay, a peer is not disconnected by being refused);
 *   - every such map is bounded (`keepPeerState`): past MAX_PEER_STATE entries, the oldest entries
 *     for peers NOT in the peer table are dropped first. A connected peer's entry is never dropped
 *     for room (dropping its shared secret would downgrade its CMBs to cleartext on LAN), so a map
 *     holds at most MAX_PEER_STATE entries plus one per connected peer.
 *
 * @copyright 2026 SYM.BOT. Apache 2.0 License.
 */

const MAX_PEER_STATE = 4096;

/**
 * Set `map[peerId] = value` as the newest entry, then trim the map to `max`, dropping the oldest
 * entries whose peer is not live (never `peerId` itself).
 * @param {Map} map
 * @param {string} peerId
 * @param {*} value
 * @param {{has: function(string): boolean}} [livePeers] the peer table; absent: none is live
 * @param {number} [max=MAX_PEER_STATE]
 */
function keepPeerState(map, peerId, value, livePeers, max = MAX_PEER_STATE) {
  map.delete(peerId);
  map.set(peerId, value);
  if (map.size <= max) return;
  for (const id of map.keys()) {
    if (map.size <= max) break;
    if (id === peerId || (livePeers && livePeers.has(id))) continue;
    map.delete(id);
  }
}

module.exports = { keepPeerState, MAX_PEER_STATE };
