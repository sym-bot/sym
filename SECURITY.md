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
  record's identity). Every other post-handshake frame except ping and pong — an `error` included —
  travels as a sealed `control-encrypted` frame on the same ordered sequence. The receive counter
  advances only after a frame authenticates, so a forged frame moves nothing; an authentic replay
  or rollback is discarded, and a gap closes the session, which re-handshakes.
- **Errors are information, never commands.** A clear `error` frame is anyone's to write: it is
  ignored, except 1011 UNKNOWN_SESSION, which prompts a new handshake and never tears a session
  down. A session ends on its peer's sealed 1010 SESSION_CLOSED or 1009 IDENTITY_CONFLICT only.
- **A record goes only where its author signed it to.** The one seal point refuses a record whose
  signed `metadata.to` names anyone but the session's proven peer, whatever path offered it
  (a broadcast, an anchor replay, a fetch answer, a queued frame).
- **One key per nodeId.** Every confirmed session runs with a binding: the key it proved, held for
  that nodeId while the session lives. The durable key registry binds a nodeId only when the
  binding is earned — an admitted verified record, a verified record its author signed to this
  node and this node accepted for delivery (directed exchange is a relationship, so a squatter
  cannot take over a conversation once its peer's sessions end), an out-of-band pin (invite, Legacy
  Import route), or an in-force grant (MMP §6.6.9: a view over the in-force set, never stored, binding
  only an unbound nodeId, and ending with the grant) — and never replaces it: a different key, from any source or
  while a session holds the nodeId, is a recorded conflict an operator resolves (a session
  proving it is closed with error 1009 `IDENTITY_CONFLICT`, sealed). A handshake, or a second one,
  earns nothing; nothing is evicted before it expires; a `proven` binding that verified nothing
  expires after 30 days unseen. This node's own nodeId is always its own key. Keys pinned before
  0.14 — from unproven hellos, or from 0.13 grants never checked against their grantors — become
  `legacy-claim`: expected, never trusted to verify, so a squatter racing the upgrade cannot take
  an honest node's id.
- **Records verified by author node id, and kept as their signed projection.** A record is
  admitted, delivered or exposed to a host (`verified-record`, once per assertion, after
  de-duplication) only after §8.8.5: a strict schema check (closed objects, no coercion, canonical
  lowercase ids, each category key recomputed and a mismatch refused), application bytes, cognition
  key, assertion identity, the Ed25519 signature against the key resolved by `createdByNodeId`, and
  the signed audience (room, recipient). Members no signature covers (`valence`, `arousal`,
  `lineage.method`) are dropped, and what is stored, delivered and served is the projection.
  Directed versus room-bound delivery is decided by the signed `metadata.to`, never by a relay
  envelope; a directed record older than 24 h by its signed time is refused.
- **Authority is a function of a set of signed statements (MMP §6.6, as merged at
  meshcognition-website 8c3381d).** Grants, revokes and endorses are identified by the SHA-256 of
  their canonical signed bytes and name one another by those ids (`authorisedBy`, `targets`), so the
  graph is fixed when it is signed. They root at a pinned anchor: a key set with a threshold
  (`anchor` option or `SYM_FOUNDER_ANCHOR`; a pin that does not parse stops the node, and with none
  pinned nothing is in force). A node resolves what it holds by §6.6.4's two-phase, depth-ordered
  rule, and nothing else enters: no clock, no receipt time, no arrival order, no session. `issuedAt`
  is signed and ignored. Two nodes holding the same statements under the same pin compute the same
  in-force set and the same authority root. Tested: every case of the published vectors
  (authority-v2.json, vendored with its hash) resolved as listed, reversed, shuffled and with forged
  copies mixed in; random meshes in many orders; two nodes fed in different orders over TCP.
- **Roles follow the key.** A grant names a nodeId and a key, and confers its role on that pair only.
  A statement's signing key comes from its authorising grant, or the pin, never from the key
  registry, so every node verifies it alike. A grant naming this node's nodeId with a foreign key
  confers nothing here and is reported (`authority-foreign-self-key`).
- **Delegation is bounded by the rule, not by arrival.** At most 4 links from the anchor. An admin
  grants any role and revokes and endorses below itself; a validator or an issuer grants
  non-authority roles only and revokes below itself. A scope only narrows, by whole path segments,
  compared exactly (`w1/../w2`, `w1/./x` are not well formed; `w10` is not inside `w1`). A bucket
  (the statements one grant authorises) keeps at most 256 (the anchor's 4,096), of them at most 16
  delegating grants, its revokes and endorses first, then by ascending id. A revoke removes only
  below its signer. A statement a quota cut off is never rescued; one a revoke cut off is kept only
  by an in-force endorse from above, charged to the endorser's own bucket, falling through to the
  next endorser when that bucket is full. So the reviewers' attacks fail: admins hung under
  over-quota grants stay dead, a self-revoke cannot launder them past a full delegate quota, and 17
  issuers in one bucket leave 16 in force. What one depth-1 grant can hold in force below it is at
  most 69,888 statements, 4,368 of them delegating.
- **Authority is judged when it is used.** The origin weight of a received record, this node's
  lifecycle transitions on a CMB (`validateCMB`, `canonizeCMB`: judged on that CMB's own signed
  fields, a scoped grant only inside its scope) and the weight of an attestation are each judged
  against the in-force set at the moment they are applied. There is no role "at a time": once a
  signer's grant is not in force, nothing it signs carries authority, whatever time it claims.
- **One Ed25519 rule (MMP §18.3.2).** Every signature sym checks (records, handshake proofs,
  attestations, checkpoints, witnesses, room-join grants, tether attestations, relocation bundles,
  authority statements) goes through one verifier: A a canonical encoding of a point of prime order
  (cached per key), R not the identity's encoding, S < L, then OpenSSL's check. A grant's subject key
  must be of prime order too. Tested with the published vectors (ed25519-strict-v2.json) and, at each
  of those sites, with two signatures Node's `crypto.verify` accepts and the rule rejects (the
  identity key's universal forgery, and R = identity with S = k·a).
- **A forgery in a session's own name ends the session.** A statement that names the session's own
  peer as its signer and does not verify under the key that session proved closes it, and its
  nodeId is not admitted again for 60 s. A statement the session relays for another signer is
  verified under this node's binding for that signer, which may differ from the relayer's (a local
  view); one that fails is dropped and counted (`relayed-signature-unverified`), and the relayer is
  not charged. Not charging it does not make forgeries free: each session's records spend a
  verification lane (32 a second, burst 128) before any work is done on them, and once 8 of one
  peer's statements for one signer have failed within a minute, that peer's statements for that
  signer are dropped unverified for the rest of the minute. A refused record is logged and recorded
  in the decision log at most once a minute per peer and reason. Authority statements are verified
  under the keys their own chains name, so this question does not arise for them: one that fails is
  dropped and counted against the delivering session, and past 8 failures a minute under one signing
  key that session's statements under that key are dropped unread.
- **Admission attestations under `sym-attest-v1`.** Attestations, checkpoints and witnesses are
  signed under their own domain tags with every field covered, verified against the signer's bound
  key (never the delivering session), and exchanged only with sessions that negotiated the
  extension. They describe a decision; they never change the receiver's own.
- **Gated rooms on proven keys.** A gated room admits its owner by the owner's pinned key and a
  grantee when its room-join grant binds the key its session proved. A copied grant admits
  nobody.
- **Moved, and copied only when asked.** `sym node export` refuses while the node runs (in another
  process or this one), holds the identity's lock, tombstones the node before its encrypted bundle
  exists (so the source refuses to start it), signs the bundle with the node's key, and once the
  bundle is durable removes the private key from the source and the 0.13 path to it. By default the
  bundle is sealed to the target host's key, so only that host can open it. A passphrase bundle
  opens on any host that has the passphrase, so it is a copy, and is made only with
  `--allow-copies`. `sym node import` checks the bundle's header against an explicit pin and the
  node's signature before it uses anything the header says, verifies the contents the same way,
  refuses a re-keyed or altered bundle, a bundle this host imported before, and one exported at or
  before this host's own move of that node away (a replay), and installs nothing until everything
  is written, keeping each file's mode.
- **The interior.** A node's mind submits through the node's local interior socket, which lives in
  a 0700 directory the node made (a fresh one under the temp directory when the path is too long),
  with a per-mission capability bound to the first connection that presents it (another local
  process cannot replay it; the connection closing ends the mind); the node checks audience, size,
  rate, declared kinds (the kind is the signed intent) and lineage before it signs. One mind per
  identity. A mind reads only its own mission's view: deliveries that arrived while it runs,
  directed ones only from nodes its mission may address, and room broadcasts; its recall returns
  only those and its own submissions (and context the host gives the mission); it has its own
  cursor and acks, never moves the host's inbox, and its reads are rate-limited. On Windows the named pipe takes Node's default DACL, which sym cannot narrow, so the
  socket is refused unless the host passes `{ allowDefaultPipeAcl: true }`.

## Bounds on what peers can make a node keep

Every store a peer can feed has a fixed bound. Reaching one never stops the node: it is counted
(and said in the log at most once a minute, or once).

- **Key bindings** (the key registry): at most 65,536, earned only (see above); the session-scoped
  bindings are one per confirmed session. Nothing is evicted before it expires: in a full registry
  a newcomer is refused a durable binding and its live session still verifies what it signs. Key
  conflicts: at most 8 kept per nodeId and 1,024 in all, every one counted
  (`status().coreSecure.keyConflicts`).
- **Authority statements** (MMP §6.6): what is in force is bounded by the quotas above. What is
  held: at most 200,000 statements; past that the ones not in the live set go first (highest id
  first), and a new one is refused only when the live set alone fills the store. A statement is at
  most 16 signature entries, 64 targets and a 256-character scope, in the schema's shape (anything
  else is refused before any work). A statement whose chain is not held is pending: its own
  signature checked first, at most 64 held per session, keyed by id and signing key, for at most
  10 s or until the session closes, never persisted, relayed or counted, with one fetch in flight per
  missing id. An `authority-set` carries at most 64 statements. A node answers `authority-fetch` at 4
  a second per session (burst 16); over that a request waits, at most 64 of them, and past that one
  is dropped. One pull in flight per session.
- **Gossip** (attestations, checkpoints, witnesses, authority statements): 2,000 new statements a
  second per proven peer (burst 10,000; a new peer starts at 100), spent before a signature is
  checked (an authority statement also spends 16 for each key it makes this node check for the first
  time, since that check is a scalar multiplication; a repeat or a statement not of the shape spends
  nothing; an answer to this node's own pull is charged as a debt that paces the next page, never
  dropped), and
  4,000 verified statements a second in all (burst 20,000), spent only after it; checkpoints at most
  4 a second per attester (burst 128); at most 1,024 attesters, 32 checkpoints each, 256 witnesses
  per position.
- **Records** (MMP §8.8.6 as draft spec PR #37 states it): a category's text at most 256 KiB after
  NFC, the seven at most 512 KiB, the record's JSON encoding at most 720 KiB, so every record fits
  one sealed frame. This node mints nothing larger, and refuses a received record over any limit
  before anything validates, verifies or encodes it; a sealed frame longer than a 720 KiB record can
  produce (983,062 base64url characters) is refused before it is opened. At most 8 new records a
  second per session are evaluated (burst 32).
- **Wake channels**: at most 1,024, learned only from a confirmed session's own nodeId (a peer's
  word about another node is never stored), dropped after 30 days unseen; when the table is full a
  new first-hand channel displaces the least recently seen one of the weakest source, so many
  identities cannot lock a phone out. At most 16 frames wait per sleeping peer; a wake that failed
  is not retried within the cooldown (5 minutes); a `peer-info` frame is read for its first 256
  entries.
- **Relay**: at most 4,096 announced candidates (a peer with a live session is not counted
  against it); at most 256 relay handshakes in flight, of which unknown candidates (no binding, no
  peer, no route) hold at most 32 — the oldest evicted for a newer one, the rest waiting known peers
  first, a failed one backing off up to 10 minutes — one in flight per relay `from`, and a `from`'s
  hellos at 1 a second (burst 4); a 5 s handshake timeout. The pacer is fair: confirmed-session
  traffic first, then handshakes, then the rest (at most 64 such frames), destinations served in
  turn, at most 8 MiB and 2,048 frames per destination and 10,000 frames in all. 1011 replies to
  strangers: at most once a second per relay `from` and 2 a second in all (burst 8), dropped past
  it. A message off the relay is bounded in size before it is parsed.
- **LAN listener**: at most 256 connections before their first frame (16 per address) and 128
  authenticating sessions (8 per host); past either the oldest is closed. A peer whose dial or
  handshake failed is dialled again after 15 s, doubling to 10 minutes.
- **JSON nesting**: at most 128 levels, checked before parsing wherever a peer's JSON is read: TCP
  frames, relay messages, decrypted `cmb-encrypted` and `control-encrypted` plaintext, the legacy
  E2E plaintext, interior requests.
- **Per-peer state**: room verdicts and the anchor-replay debounce hold at most 4,096 entries for
  peers that are not connected (a connected peer's is never dropped); an admit verdict and the
  debounce go when the peer leaves, a refusal is kept (so a refused peer stays refused). The gossip
  budget and checkpoint-rate tables hold at most 4,096 peers each; the log-line deduplication maps
  1,024 keys each.
- **Fetch and interior**: a `cmb-fetch` names at most 32 keys, a session expects at most 64 fetched
  records; a node serves at most 2 fetches a second per session (burst 8), a record at most once a
  minute per session, and nothing while 2 MiB to that session is unsent; an interior submission is
  at most 64 KiB of category text and 512 KiB of application data, at the mission's rate (60 a
  minute by default); an IPC line to the daemon at most 8 MiB.
- **The store** keeps what it admits without a count or byte bound by default (retention is
  unlimited unless the host sets one); what bounds its growth from one peer is the record budget
  above and SVAF admission.

## What it does not solve

- **First contact is trust on first use, and one directed record makes it permanent.** A nodeId is
  not derived from its key. Without an anchor, an invite carrying the issuer's key, or a grant, the
  first key a session proves for a nodeId is the one this node uses for it, and the handshake
  proves possession, not intent. Whoever reaches this node first under a nodeId and has one record
  it signed to this node accepted (or one broadcast admitted) holds that nodeId here durably: the
  genuine node is then refused with 1009, and a node refused with 1009 does not retry until it
  restarts. A nodeId that never earned a durable binding is first contact again once its sessions
  end. Pin a key out of band (an invite) where that matters. Deriving a nodeId from its key would
  remove the squat; it is a future MMP change, not this release.
- **The revoke window (MMP §6.6.12).** Until a node holds a revoke it treats the removed grant as
  in force. A revoke is relayed as it enters, and a digest exchange reconciles the rest when a
  session is confirmed and whenever a set changes; a partitioned node stays exposed until it
  reconnects.
- **The threshold holders are the root.** Any t pinned keys together can grant, revoke and endorse
  anything; under a threshold of 1 every pinned key alone is the root. Compromise of t keys is
  recovered only by pinning again, out of band.
- **A compromised authority holder acts until it is removed.** Within its quotas it can grant,
  revoke and endorse below itself until a signer above revokes its grant; endorsements then keep
  what should stand.
- **Grants are visible.** Every node that holds the set can read who holds which role.
- **A new key costs a scalar multiplication.** The prime-order check of a key not seen before
  (§18.3.2) is one multiplication by L, about fifteen signature checks here. The gossip lane is
  charged for it before it is done; a flood of fresh keys buys a sixteenth of a lane's checks.
- **The upgrade is a flag day (MMP §6.6.11).** sym 0.14 resolves no authority from the role grants
  0.13 (and earlier 0.14 builds) signed: until the anchor and each grantor re-issue what should stand
  as §6.6 grants, every node resolves as a participant. `node.legacyRoleGrants()` lists the old store
  as plain data (never verified, never resolved, never sent) for the operator who re-issues.
- **Scopes need their namespace.** sym implements no scope namespace by itself: a scoped grant
  confers nothing on any CMB until the host passes the extension's resolver (`authorityScopes`).
- **A received validation CMB advances its parent only to remixed.** MMP §6.5 has a receiver advance
  a parent to validated (action completed) or dismissed (not actionable) when a validator or above
  authored the CMB naming it; a record carries no signed field saying which, so sym does not. It
  weighs the author's authority on each parent (the feedback flag) and leaves validation to the
  node's own `validateCMB`, gated on its own authority over that CMB.
- **Relay eviction.** `relay-auth` identity is not proven (MMP §4.4.1), and the relay replaces a
  connection that re-authenticates under the same nodeId (close 4004, §4.4.7). A token holder
  can therefore interrupt another node's relay path. It cannot impersonate it: it gets no
  session without the key. The client stops for good on 4004, 4006 (the existing holder is the
  legitimate one) and 4007 (a relay that binds this nodeId to another key), and says so in
  status, so an eviction is visible rather than a reconnect loop. The fix (relay-auth proving key
  possession, MMP spec PR meshcognition-website#20) is drafted, not implemented.
- **No key rotation** (MMP §3.4). A compromised key means a new identity.
- **The local machine.** Identity files are readable by any process running as the same user.
  Operating-system isolation is out of scope. The daemon's IPC socket trusts the same user the same
  way: any process running as that user can connect to it and act as the daemon's node (remember,
  send, recall); it is not a boundary between processes of one user.
- **Legacy Import is weaker, and temporary.** A route to a 0.13 node uses the legacy encryption
  (X25519 + AES-256-GCM: this node's per-session key against the routed node's pinned persistent
  key — no forward secrecy, no transcript proof). A 0.13 hello proves nothing, so over the relay a
  token holder can answer as the routed node; it cannot read what this node sends (encrypted to
  the pinned key), and what it sends is taken only if the route's pinned identity key signed it.
  Anyone who later obtains the routed node's X25519 private key can read what was recorded.
  Everything received over a route is stored `verified: false`, `profile: legacy-import`, raised as
  `legacy-record`, and given no authority; a legacy peer never passes a gated room's door. A
  nodeId that has proven itself over Core Secure has its legacy route refused (a persisted floor)
  until an operator resets it. Network Legacy Import is removed in 0.15.0.
- **Metadata.** The relay operator sees routing envelopes: who, to whom, room, timing, sizes.
- **Attestations disclose decisions.** With `sym-attest-v1` (offered by default) every peer in the
  room learns which records a node gated and what it decided; a content address is a confirmation
  oracle for whoever holds the text. Leave the extension out (`extensions` option) where that
  disclosure is not acceptable. An attestation proves who decided, not that the decision was
  honest; the chain and witnesses make a forked history detectable, not impossible.
- **A room name or relay token is not an enterprise trust boundary.** Anyone holding the token
  is in the channel, and an invite that carries a token is a secret.
