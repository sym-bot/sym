# Security

This file says what `@sym-bot/sym` 0.13.x does not protect, so nobody has to find out the hard
way. It covers the 0.13 line. sym 0.14.0 (MMP 2.0 Core Secure) proves each peer's identity at
the handshake, and that removes the cause of the first limit below.

## Reporting

Report a vulnerability privately to info@sym.bot (the address in package.json). Please do not
open a public issue for it.

## Peer identity in 0.13.x is trust on first use

A 0.13 handshake does not prove anything. A peer names its nodeId and its keys, and the node
believes the first key it sees for a nodeId (the roster key registry). Signatures are checked
against that key from then on, but the first contact is taken on trust. What follows from that:

- **A handshake that claims a connected peer's nodeId can reset that peer's room verdict.** A
  node records one room-admission verdict per nodeId, from the latest handshake that named it.
  A handshake from anyone, naming a connected peer's nodeId and a different room, is refused,
  and the refusal replaces the peer's own verdict, so the node refuses that peer's frames until
  the peer handshakes again (on its next connection). The peer's connection is not closed and
  nothing is learned from the refused handshake: no key is pinned and no secret is derived. The
  cause is unproven identity. 0.14.0 fixes it by proving identity before it keeps any per-peer
  state.

## Bounds on what peers can make a node keep

These stores are fed by what peers send, so each has a fixed bound. Reaching one never stops the
node; it is said once in the log and counted.

- **Key bindings: at most 16,384.** The roster key registry adds a binding for each nodeId a
  handshake (or an anchor-rooted grant) names. When it holds 16,384, a new binding is refused and
  no binding is ever evicted: forgetting one would let its nodeId be pinned again with another
  key. A record signed by a key that could not be pinned fails verification, as one signed by
  an unknown key does. `status().roster.refusedFull` counts the refusals.
- **Peers added by relay announcements: at most 4,096.** The relay's join notices and peer list
  can name any number of nodeIds, and each one becomes a peer in the table. At most 4,096 peers
  that only an announcement introduced are held; an announcement for another unknown nodeId is
  ignored and counted (`status().relayState.announcementsIgnored`). Peers this node already knows,
  including any with a live LAN connection, are not affected, and a peer that leaves the relay
  frees its place.

The other bounds 0.13.17 sets (wake channels, per-peer state, pending role grants, the nesting
of a frame) are listed in its CHANGELOG entry.
