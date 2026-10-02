# Security

This file says what `@sym-bot/sym` protects, how, and what it does not. It is kept honest on
purpose: a property stated here is one the code enforces and a test exercises.

## Reporting

Report a vulnerability privately to info@sym.bot (the address in package.json). Please do not open a public issue for it.

## What sym 0.14 (Core Secure) enforces

- **Proven sessions.** Every peer connection — LAN TCP, loopback, relay — runs the MMP v2.0
  §5.2 handshake: client-hello, server-hello, client-finish. Each side proves its Ed25519
  identity key over the transcript (both nonces, nodeIds, identity and X25519 keys, names,
  implementations, room, protocol version, offered and selected extensions) and confirms the
  HKDF key schedule. A failed proof, a wrong confirmation, an unechoed nonce, a stripped
  extension, a room mismatch, an all-zero shared secret or any frame before client-finish
  closes the connection with no peer state kept. The listener takes `client-hello` first and
  nothing else; a legacy one-frame `handshake` is refused at once.
- **Fresh keys per handshake.** Each handshake uses a fresh X25519 key pair; there is no
  persistent encryption key and no per-peer secret map.
- **Sealed, ordered channel.** Records travel only as `cmb-encrypted` (ChaCha20-Poly1305 under
  the session's directional traffic key, AEAD-bound to session, direction, sequence and the
  record's identity). Every other post-handshake frame except ping, pong and error travels as a
  sealed `control-encrypted` frame on the same ordered sequence. The receive counter advances
  only after a frame authenticates, so a forged frame moves nothing; an authentic frame out of
  order (replay, rollback, gap) closes the session, which re-handshakes.
- **One key per nodeId.** The key registry binds a nodeId to the first key a proven session, an
  out-of-band pin (invite, Legacy Import route) or an anchor-rooted grant gives it, and never
  replaces it: a different key from any source is a recorded conflict an operator resolves.
  Keys pinned before 0.14 from unproven hellos become `legacy-claim`: expected, never trusted
  to verify, so a squatter racing the upgrade cannot take an honest node's id.
- **Records verified by author node id.** A record is admitted, delivered or exposed to a host
  (`verified-record`) only after §8.8.5: application bytes, category keys and cognition key,
  assertion identity, the Ed25519 signature against the key resolved by `createdByNodeId`, and
  the signed audience (room, recipient). Directed versus room-bound delivery is decided by the
  signed `metadata.to`, never by a relay envelope.
- **Authority follows the key.** A role grant must name `granteeKey`; it confers its role only
  on that key, and a chain is verified top-down with each grant's vouched key. A grantor whose
  nodeId an impostor holds keeps exactly its vouched authority; the impostor gets none.
- **Gated rooms on proven keys.** A gated room admits its owner by the owner's pinned key and a
  grantee when its room-join grant binds the key its session proved. A copied grant admits
  nobody.
- **Moved, not copied.** `sym node export` tombstones a node before its encrypted bundle exists,
  so the source refuses to start it; `sym node import` verifies the bundle against an
  independently pinned key and refuses a re-keyed bundle.
- **The interior.** A node's mind submits through the node's local interior socket with a
  per-mission capability; the node checks audience, size, rate, declared kinds and lineage
  before it signs. One mind per node.

## What it does not solve

- **First contact is trust on first proven use.** Without an anchor, an invite carrying the
  issuer's key, or a grant, the first key a session proves for a nodeId is the one bound. The
  handshake proves possession, not intent.
- **Relay eviction.** `relay-auth` identity is not proven (MMP §4.4.1), and the relay replaces a
  connection that re-authenticates under the same nodeId (close 4004, §4.4.7). A token holder
  can therefore interrupt another node's relay path. It cannot impersonate it: it gets no
  session without the key. The client stops for good on 4004, 4006 (the existing holder is the
  legitimate one) and 4007 (a relay that binds this nodeId to another key), and says so in
  status, so an eviction is visible rather than a reconnect loop. The fix (relay-auth proving key
  possession, MMP spec PR meshcognition-website#20) is drafted, not implemented.
- **No key rotation** (MMP §3.4). A compromised key means a new identity.
- **The local machine.** Identity files are readable by any process running as the same user.
  Operating-system isolation is out of scope.
- **Legacy Import is weaker, and temporary.** A route to a 0.13 node uses the legacy encryption
  (X25519 + AES-256-GCM per connection: no forward secrecy, no transcript proof). Everything
  received over it is stored `verified: false`, `profile: legacy-import`, and given no
  authority. A nodeId that has proven itself over Core Secure has its legacy route refused (a
  persisted floor) until an operator resets it. Network Legacy Import is removed in 0.15.0.
- **Metadata.** The relay operator sees routing envelopes: who, to whom, room, timing, sizes.
- **A room name or relay token is not an enterprise trust boundary.** Anyone holding the token
  is in the channel, and an invite that carries a token is a secret.
