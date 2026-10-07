# Core Secure identity: a peer is a proven session, never a hint

**Date:** 2026-10-02 · **Author:** agent-a (core libs) · **Status:** v2. Independent design review
folded in (PART 1: SHIP-WITH-FIXES; H1-H13 and M3-M12 are answered below). The user ruled on
2026-10-02 that the decisions follow my recommendation.
**Target:** sym 0.14.0. It blocks that release: the 0.14.0 candidate (f775581) is not a Core Secure
participant (conformance audit 2026-10-02).
**Spec:** MMP v2.0 at meshcognition.org/spec/mmp (14 Sep 2026). Spec changes this design needs are
listed in §10. They are drafted as pull requests, not assumed.

## 1. The root cause (confirmed by review against the code)

A sym peer exists before anything has been proven about it:
- **LAN outbound:** `_connectToPeer` creates the peer on TCP connect, named by the DNS-SD instance.
- **LAN inbound:** any first frame of type `handshake` is accepted (`discovery.js` 243-249). Its
  keys are pinned (`_pinPeerKey`) and its secret derived (`_deriveAndStoreSecret`).
- **Relay:** `relay-peer-joined` creates a peer. Any envelope is dispatched by the relay's `from`,
  even with no peer entry (`relay.js` 316-326).

Everything per-peer hangs off those unproven ids: keys, the E2E secret (`_peerSharedSecrets`),
roles, room admission, budgets, attribution. The proving handshake (`lib/core/handshake-v2*.js`,
`mmp-session.js`, `mmp-ingress.js`, `cmb-encrypted-frame.js`) reproduces the published vectors, and
nothing calls it.

On disk, 9,259 `roster-keys.jsonl` entries across 1,661 node directories are all source
`handshake`, all learned from unproven hellos.

**The change:** trust has one unit, the authenticated session. A peer is the set of confirmed
sessions that proved the same nodeId with the same identity key. Nothing per-peer exists before
confirmation.

## 2. The spec's identity model (and the correction to my first proposal)

- §18.3: "Node identity is a UUID bound to an Ed25519 key through the authenticated transcript."
- §3.1.1: the nodeId is a UUID v7, so key-derived ids would be a spec change.
- §6.6: one anchor pinned out of band; grants vouch keys; "a grant-sourced key MUST NOT override a
  key already learned from a stronger source".
- §3.4: one key per nodeId for life.
- §5.2: nothing pinned before both proofs; failure keeps no state.
- §17.3: Legacy Import is never selected by negotiation failure, is shown to the operator, and its
  network admission ends after a declared window.

## 3. Design

### D1. The session is the unit of trust

- A **candidate** (a DNS-SD record, a relay roster entry, a loopback registry entry) is an endpoint
  and the nodeId it claims. It decides only whom to dial.
- A **session** is a confirmed §5.2 exchange. It carries the proven nodeId, identity key, this
  session's ephemeral X25519 key, sessionId, room, selected extensions, directional keys and
  sequence counters.
- A **peer** is a proven (nodeId, key) with one or more sessions (§4.6: a second transport adds a
  secondary path; it does not replace the first).
- The frame handler takes `(session, frame)`. Every per-peer structure is keyed by the proven
  nodeId. A name is a label.
- **One public hook for hosts (review H9):** `node.on('verified-record', { record, session, verification })`.
  It fires after §8.8.5's checks, with the proven session facts. Hosts never reach into
  `_frameHandler`, `_peerSharedSecrets` or `_identityKey`; those internals are removed or private
  in 0.14.0.

**Every frame type, classified (review H7).** Each of the 18 types the handler takes today:

| Frame | In a Core Secure session |
|---|---|
| `client-hello`, `server-hello`, `client-finish` | the handshake (§5.2) |
| `cmb-encrypted` | the only carrier of CMBs (§18.2.1) |
| `cmb` | refused (Legacy Import sessions only) |
| `cmb-fetch` | allowed: it carries keys only |
| `cmb-fetch-result` | each returned CMB is sent as its own `cmb-encrypted` frame. It was plaintext, which §18.2.1 forbids |
| `role-grant`, `role-revoke` | signed by the grantor, verified against the key registry, never against the delivering session |
| `mood` | carries mood text, so it is cognitive content (§9.3). Sent and accepted only inside the session's AEAD, as a sealed control frame (§10 spec PR) |
| `peer-info`, `wake-channel` | core §7.1 control frames. Accepted only on a confirmed session, and learned only for that session's own nodeId. A relay-delivered `wake-channel` naming another node is a hint, never stored. iOS wake learning keeps working for the peer itself |
| `message` | retired in Core Secure. A message is a directed CMB (`to` = recipient), and the local `message` event (§14.9.1) is raised from it |
| `attestation`, `checkpoint`, `witness`, `node-stats` | sent only to peers that selected the extension `sym-attest-v1` in the handshake. Unregistered, so §10 drafts the registry entry |
| `xmesh-insight` | an extension, `xmesh-insight-v1`, negotiated the same way |
| `state-sync` | retired (§5.2: "hidden state never crosses the wire"), refused |
| `handshake` | Legacy Import only (D7) |
| `ping`, `pong` | liveness, no state |

### D2. The v2 handshake on every transport

- **LAN TCP and loopback:** the dialler is the client. The Core Secure listener accepts
  `client-hello` and nothing else, and no other frame before `client-finish`. A legacy
  `handshake` on it is refused at once, rate-limited per address (review H1).
- **Discovery:** Core Secure advertises `_sym._tcp` with TXT `mmp=2.0` and `room=<room>` (§5.1).
  A 0.14 node dials a record as Core Secure only when it carries `mmp=2.0`. A record without it
  is a legacy node: it is dialled only by a Legacy Import route (D7), never as Core Secure
  (review H1).
- **Relay (review H8):**
  - When `relay-peers` or `relay-peer-joined` names a peer, the node with the smaller nodeId
    sends `client-hello` in an envelope addressed to it.
  - The timeout is 10 s.
  - A session is bound to the relay `from` it was established on, and is torn down on
    `relay-peer-left`.
  - A new *confirmed* session for the same (nodeId, key) supersedes the old one, which covers a
    peer restart under 4004.
  - An unconfirmed hello never tears down a confirmed session.
  - Closing a relay session means sending an `error` frame with `to`, then dropping the session.
- **Sequence discipline (review H8):**
  - The receive counter advances only after the AEAD opens. Today `acceptRecv` advances first
    (`mmp-session.js` 116-118), so one forged frame with the right sequence would desynchronise
    the session.
  - A gap or replay closes the session and re-handshakes. It never stalls.
- **Fresh X25519 per handshake:** private keys may be injected only into the pure handshake
  functions, for the vectors, never through configuration. An all-zero shared secret aborts
  (§5.2.1), and the test suite includes that case.

### D3. One key registry with an explicit conflict matrix (review H3, H4, M10)

`roster-keys.js` stays the single place where a nodeId gets a key, with these rules. **No source
ever overrides a different key**; the old code's "strictly stronger source overrides" is removed.

| Situation | Result |
|---|---|
| nodeId unbound, proven session | bind (`proven`) |
| nodeId unbound, anchor-rooted grant vouches a key | bind (`grant`) |
| nodeId unbound, accepted invite names a key | bind (`pinned`) |
| nodeId bound, same key from any source | keep; record the stronger source. The order is anchor, then `pinned`, then `grant`, then `proven`: a pin outranks a proof of the same key (decided in the 0.14.0 security round: an invite's pin was being relabelled `proven` by the first session that proved it) |
| nodeId bound, **different** key from any source | **conflict**: refused, recorded, shown in `sym status`; the operator resolves it |
| the configured anchor | always its configured key. It is read from configuration at every start and **never persisted to or replayed from** `roster-keys.jsonl`, so re-pinning a fresh anchor out of band (§6.6) takes effect |
| a `legacy-claim` entry (every pre-0.14 `handshake` entry, relabelled on first load) | the **expected** key. A proven session presenting it binds `proven`. A proven session presenting a different key is a conflict, not a fresh binding. Identity files do not change on upgrade, so an honest peer always matches, and a squatter racing the upgrade cannot win |

**Binding lifetime (revised in the 0.14.0 security round; it replaces the 0.13.17 re-review's rule).**
- **Every confirmed session runs with a binding:** the key it proved, held for that nodeId while
  the session lives. That table is bounded by the session caps. A second key for a nodeId with a
  live session binding is a conflict (sealed 1009 `IDENTITY_CONFLICT`), recorded.
- **The durable registry takes only earned bindings:** an admitted verified record, a verified
  record its author signed to this node and this node accepted for delivery (stored or surfaced
  `remixed: false`; corrected in the 0.14.0 re-review, N3), an out-of-band pin (an invite, a
  Legacy Import route), an anchor-rooted grant in effect now (a view, never stored), or the
  anchor. A handshake, or a second one, earns nothing, so identity churn cannot fill the registry.
  Nothing is evicted before it expires. A newcomer to a full registry keeps its session binding
  and gets no durable one.
- **The rule: a binding is earned by a relationship (corrected in the 0.14.0 re-review, N3; it
  replaces the "residual, kept on purpose" paragraph of 9305836).** That paragraph said a nodeId
  that never earned a durable binding "left nothing this node protects". That was wrong. A peer
  that only exchanged directed records (a conversation: requests, replies, messages, none admitted
  to memory) earned nothing, so once its sessions ended a squatter could claim its nodeId, be
  bound, and receive this node's further directed records to it (the addressee is a nodeId, not a
  key), while the genuine peer, refused with 1009, did not retry until it restarted. A
  conversation is exactly what the binding protects. So the rule is: **a binding is earned by what
  this node accepted from that key** — a record it admitted (history), or a record the author
  signed to this node and this node accepted for delivery (a relationship) — or by a pin or a
  grant. What stays first contact, on purpose: a nodeId this node never accepted anything from (a
  peer that only handshook, or only broadcast records SVAF refused) has nothing here to take, and
  another key may claim it after its sessions end. Hosts show signers by key fingerprint
  (mesh-channel 0.11.0), so a change of key under one nodeId is visible. An expiring first-contact
  binding stays rejected: any table a stranger can fill is a table a stranger can use to push
  honest bindings out.
- **A failed signature is charged only to its signer's own session (0.14.0 re-review, N1).**
  Bindings are local views: a statement relayed on a session (a record, an attestation, a
  checkpoint, a witness, a grant) is verified under this node's binding for its signer, which may
  be a squatter's session-scoped binding, or may lack a vouch the relayer holds. So a session is
  closed and refused for a bad signature only when the statement names that session's own proven
  peer as its signer and the key that failed is the one the session proved. A relayed statement
  that fails is dropped and counted (`relayed-signature-unverified`), never charged to the
  relayer: the old penalty closed every honest peer that relayed the genuine statements of a node
  whose nodeId a squatter held here.
- "Last verified" and "last seen" persist with each durable binding.
- Test: a flood of 20,000 one-shot identities ages out, and an honest long-lived peer survives.

**Authority follows the key.**
- `resolveRole(nodeId, key, at)`: a grant confers its role only when its `granteeKey` equals the
  grantee's bound key.
- **A revoke carries a cutoff; receipt time is no part of authority (0.14.0 re-review, N2; the
  founder's ruling).** The security round's "both times" rule (a statement counts only if its
  signer was authorised when it signed and when this node received it; draft spec PR #33) failed
  open: a validator's genuine revoke, received after the validator was itself revoked (by a
  newcomer, an anti-entropy sync, or a store upgraded from 0.13), no longer counted, so authority
  depended on arrival order. Now a revocation of a validator signs a cutoff, an invalidity date at
  or before the revoke's own time (by default that time). What the validator signed before the
  cutoff stands for every receiver, whenever it arrives; what it signed at or after the cutoff
  never counts, even at times before the revoke was signed. That stops backdating without
  depending on arrival: the revoker chooses how far back trust is withdrawn. A revoke counts only
  when its revoker held the rank both at the revoke's signed time and at its cutoff, so a revoker
  reaches back only over time it was itself authorised for. Grants keep §6.6's cascade (a grant
  confers only while its grantor holds rank). Every time in the rule is signed; nothing stores a
  receipt time, and the 0.13 grant file needs no rewrite (0.14.0 re-review, N5: the rewrite lost
  the records skipped at load). The exact rule for the spec PR is in `docs/WIRE-0.14.0.md` §6 on
  the release branch.
- **No cap refuses a revoke (0.14.0 re-review, N4).** Grant caps (per grantor, per pair, in all)
  bound grants only: a revoke refused by a full store leaves authority standing, which fails open.
  Revokes are bounded by their grants: a non-anchor revoker keeps at most as many revokes for a
  grantee as the node holds grants for it, and one that arrives before the grant waits for it
  (`role-chain-fetch` naming the grantee).
- Grant chains are verified top-down **with the key each verified grant vouches** (§6.6: "using
  each verified grant's vouched key to reach the next"), not with whatever key the registry
  holds for the grantor.
- `grantRole` refuses to emit a grant without a known proven key for the grantee. Every grant
  carries `granteeKey`.
- **A grant or revoke that arrives before its root (added after the 0.13.17 re-review).** The
  node asks the delivering session for the missing chain, with a directed `role-chain-fetch`
  naming the grantor grants it lacks.
  - The record is held only for that fetch, at most 64 per session, with a timeout.
  - The answer is ordinary signed grants, verified top-down.
  - This replaces 0.13.17's pending set, which any connected peer can flood.
  - The frame needs spec text (§10, item 10).

### D4. Ephemeral E2E and the encrypted envelope

- The per-peer persistent X25519 secret map (`_peerSharedSecrets`) goes. Session keys come from
  §5.2.1 through `MmpSession`.
- CMBs travel only as `cmb-encrypted`, on every transport.
- **Broadcast binding (review H5):** a room broadcast is sent as one sealed frame per peer
  session, because each session has its own keys.
  - The receiver takes the CMB's binding (room-bound or directed, §9.2.2) from the
    authenticated `metadata.to`, which is signed (§8.8.4) and AAD-bound. It never comes from the
    relay envelope, which now always names a recipient.
  - `metadata.to` absent means room-bound and SVAF-gated.
  - §10 drafts the change to §9.2.2/§4.4.4, and a `to`-absent E2E vector.
- **Relay fan-out (review H6):** N sealed frames per broadcast would trip the relay's limit (25
  frames/s, then 4008). So sym-relay 0.6.0 ships in the same release with a fan-out envelope:
  `{ fanout: [{ to, payload }, …] }`. It is one client frame, counted once, and routed per
  recipient within the channel. §10 drafts it for §4.4.4. sym also paces broadcasts under the
  relay's limit when talking to an older relay.
- **Records are v2.0** (`MMP_EMIT_V2` on).
  - The author key is resolved by `createdByNodeId` through D3.
  - Unsigned, legacy-suite or unresolvable records are refused in Core Secure.
  - Release note (review M12): "X via Y" deliveries from authors this node has never proven and
    no grant vouches will no longer surface. That is §18.3.1's rule, not a regression.

### D5. Out-of-band bindings: the anchor and invites

- Production pins an anchor (§6.5). `SYM_FOUNDER_ANCHOR` is read from configuration on every
  start (D3).
- **Invites** (`sym://room/…`, `sym://team/…?relay=&token=`) gain `node=<nodeId>&key=<identity key>`
  for the issuer. Accepting one pins the issuer at `pinned`, **only if that nodeId is unbound**;
  otherwise the operator resolves it (D3).
  - The invite is *secret*: a team invite carries the relay token (review M8). It is also
    integrity-sensitive.
  - The parser (`INVITE_URL_RE` in mesh-channel and the apps) already takes a query string. The
    apps' parsers are checked before the new parameters ship.
- A room grant already binds the grantee's key under the owner's signature.

### D6. Room admission on proven identity

- The room is explicit and inside the transcript. A mismatch closes the connection before admission.
- **Gated rooms:** the owner is recognised by its pinned key, and a grantee when the grant's
  bound key equals the session's proven key.
- `provenPublicKey` becomes a session property. The strip code and the "refuses everyone"
  fallback go.

### D7. Legacy Import: explicit, outbound, temporary (review H1, H2, H3)

- **Off by default.** A route names a peer's nodeId, its endpoint (host:port, loopback entry or
  relay channel) and its identity key fingerprint. **The fingerprint is mandatory** and is pinned
  at rank `pinned` for that nodeId.
- **The 0.14 node always dials a route itself, and never accepts a legacy hello.** That covers
  both id orders: 0.13 dials only when its own id is smaller (`discovery.js` 329), so the 0.14
  side cannot wait. It also keeps the first-frame rule: the profile is chosen by the configured
  route before any byte is read.
- **Over the relay:** a route's legacy session is the 0.14 node sending a legacy `handshake` to
  the routed nodeId.
  - Relay-auth is unproven (§4.4.1), so a squatter could answer as that nodeId. Records are
    therefore accepted only when their internal-suite signature verifies against the pinned
    fingerprint.
  - Connection-level frames from a legacy session are hints.
- **What 0.14 sends on a legacy session:** legacy `cmb` frames under the legacy E2E construction,
  encrypted to the routed node's persistent X25519 key, which the route pins. A relay token holder
  can answer as the routed node, because a 0.13 hello proves nothing, but it cannot read what this
  node sends. Anyone who later obtains that X25519 private key can read what was recorded. `sym status` says plainly that the session uses legacy
  encryption, with no forward secrecy and no transcript proof.
- **Quarantine:** everything received is stored with `verified: false` and `profile: legacy-import`.
  It is never given authority, never shown as verified, and flagged on the channel surface.
- **The sticky floor is persisted:** it is derived from `proven` bindings in the registry, not
  kept in memory. Once a nodeId has a proven binding, its legacy route is refused until an
  operator reset.
- **The window:** the release notes name it. Network Legacy Import is removed in 0.15.0; offline
  store import stays.

### D8. One agent, one node; a node's mind is its interior (review M3)

**One rule:** an autonomous agent is its own node. A node's reasoning process is its interior and
has no mesh identity.

Removed in Core Secure:
- the daemon's `register-agent` path;
- its `register` virtual nodes;
- its `agent-cmb` path, which broadcasts a plain `cmb` with a client-supplied `from`
  (`sym-daemon.js` 354-411).

`register-agent` has no consumer outside the daemon. XMesh's `mesh-bridge.ts` virtual nodes are
ported under the XMesh design: each becomes a real node or goes.

### D9. What sym gives cognitive nodes (reworked with XMesh C2/C5; review H11, H13, M4)

1. **Identity addressed by nodeId, loaded without minting.**
   - Identities live at `nodes/by-id/<nodeId>/`, with the name as an index.
   - `loadIdentity({ nodeId | name, create: false })` throws when the identity is absent. A host
     restoring a known agent can never mint a replacement silently.
   - `create: true` (the default for a brand-new agent) stays the only path that mints.
   - Renaming changes the index, never the identity.
2. **Relocation, not copying (§3.1.3: "The private key MUST NOT leave the node").** A node can be
   *moved*:
   - `sym node export` writes a bundle encrypted under an operator passphrase or a target host
     key. It contains the identity, store, registry, grants and the host's learned profile.
   - The export also writes a **tombstone** at the source. The source then refuses to start that
     identity, so no copy remains.
   - Import verifies the bundle against an **independently pinned** (nodeId, key): the target
     host's roster entry or the validator's preserve act naming the key fingerprint. It never
     relies on the bundle's own signature.
   - The relay's 4004 replacement cannot produce two live copies, because the source is
     tombstoned before the bundle exists.
3. **The interior submission path (review H13).** A node exposes a local submission socket to
   its interior. A submission carries a **per-mind capability**: a random token the node issues
   when it starts a mind for one mission, revoked when that mind exits. A submission without a
   live capability is refused.
   - **The node's checks before it signs:**
     - audience: `to` must be in the mission's allowlist, or the room;
     - size: ≤ 64 KiB of categories, ≤ 512 KiB of application data;
     - rate: per capability;
     - intent: the mission's declared kinds only;
     - no `parents` outside the node's store.
   - **One mind per node at a time.** A node busy with a mission queues the next, and the runtime
     may offer it elsewhere. A node with several concurrent minds would be several agents under
     one identity (§3.2), unless it is declared a gateway (§5.10).
   - This is not §4.5's coupled agent: the mind does not couple, keep its own store or evaluate
     SVAF. The node does all three.
   - The 2026-08-02 Q1a fallback (a scoped signing grant to a worker) is superseded by this
     path, and recorded as such.

### D10. The 0.13.17 hotfix comes first (review H10)

release/0.13.17 merges into the 0.14.0 branch **before D1-D3 start**. Its five security commits
are:
- ee107c6: role grants rooted;
- 3c961df: one guarded dispatch;
- ccbb340: the daemon's engine check;
- 3cd1ff8: wire identity at the door;
- cf0854c: wake channels as text.

Their tests stay as invariants through the rewrite. The 0.14 grant store's skipped signature check
on load (`role-grant-store.js` 107, `if (!this._loading)`) is replaced by 0.13.17's `record()` path,
which §6.6 requires. The Legacy Import interop test runs against a real 0.13.17 node.

## 4. What this removes

- the legacy `handshake` and `_buildHandshake` (except inside D7);
- the inbound legacy check in `discovery.js`;
- `_peerSharedSecrets`, `_pinPeerKey` from hellos, and the "stronger source overrides" rule;
- the `provenPublicKey` strip code and the owner-only gate;
- trust in the relay's `from`;
- per-connection gossip lanes as an identity workaround;
- the daemon's `register`, `register-agent` and `agent-cmb` paths;
- `state-sync`;
- plaintext `cmb-fetch-result`.

## 5. What this does not solve (said in README and SECURITY.md)

- **First contact with no anchor, invite or grant** is trust on first proven use.
- **Relay eviction:** `relay-auth` is unproven (§4.4.1), and 4004 lets a token holder evict a
  node (§4.4.7). §10 drafts the fix. Until then the session layer limits the damage: an evicted
  node re-handshakes, and a squatter gets no session.
- **Key compromise:** no rotation (§3.4).
- **A same-user process on the host** can read identity files. OS isolation is out of scope.

## 6. Release and migration (review M9)

- **Order:**
  1. sym 0.14.0, with 0.13.17 merged in.
  2. sym-relay 0.6.0 (fan-out) in the same window.
  3. mesh-channel on `^0.14.0`.
  4. XMesh on `^0.14.0`.
  5. Upgrade my nodes and :8790.
  6. Upgrade :8787, with Legacy Import routes for every seat still on 0.13, and with the user's
     confirmation.
  7. The other seats, coordinated with them; dev-team-3 restarts on its own timing.
- Mesh-channel and XMesh pin `^0.13.15` today, and a caret on 0.x does not take 0.14. Their
  releases are steps 3 and 4, not later.
- Identity files keep the nodeId and key. Their location moves to `by-id/` with the name index
  (D9.1) through a one-time, idempotent move. A 0.13 rollback reads the old path, which is kept
  as a symlink for one release.
- `roster-keys.jsonl` gets a version marker line; a 0.13 rollback skips it as malformed.
  `handshake` entries become `legacy-claim`.

## 7. Tests

- **The public corpus:** the handshake and E2E vectors.
- **Negative cases (§17.4):**
  - a bad proof, a wrong confirmation, an unechoed nonce;
  - a stripped extension, a room mismatch;
  - a data frame before `client-finish`, a legacy hello on the Core Secure listener;
  - an all-zero shared secret;
  - a fresh X25519 per handshake.
- **The conflict matrix, every row:**
  - a squatter racing the upgrade against a `legacy-claim`;
  - an invite against an existing binding;
  - an anchor re-pin;
  - a grantor bound to an impostor;
  - a grant chain verified with vouched keys.
- **Relay sessions:**
  - frame loss leading to a re-handshake;
  - restart supersession under 4004;
  - a forged sequence frame not desynchronising the session;
  - binding taken from `metadata.to`;
  - fan-out under the relay's limit with 30 peers.
- **Legacy Import:**
  - the default room on `_sym._tcp` with and without TXT `mmp`;
  - an outbound dial with the local id smaller and larger;
  - the floor surviving a restart;
  - against a real 0.13.17 node over LAN and over the relay;
  - a 0.13.17 node with no route refused.
- **Migration:** the roster across 1,661 node directories (copied), and a 0.13 rollback.
- **D9:**
  - `create: false` on a missing identity;
  - export then source start refused;
  - import with a re-signed key refused;
  - an interior submission without a capability refused;
  - a second concurrent mind refused.
- **The host hook:** XMesh's control plane on 0.14 sees verified records through
  `verified-record` (a test in XMesh's suite).
- **0.13.17's tests** stay green throughout.

## 8. Decisions (ruled 2026-10-02: follow the recommendations)

1. The spec's identity model: proven first use, plus out-of-band pins, plus grants, with
   authority following the key.
2. Core Secure-only by default, Legacy Import by explicit route, until 0.15.0.
3. The nodeId, minted once per agent, is the agent's identity, and `<agent>@<xmesh name>` is its
   name.

## 9. Spec gaps found while writing and reviewing this

- No defined behaviour for a bound nodeId proving a different key (§3.4, §5.2, §6.6).
- `relay-auth` identity is unproven, so 4004 is an eviction primitive (§4.4).
- Only CMBs are bound to the session. Other control frames over a relay can be injected (§4.4.4,
  §18.2.1).
- §5.1 mandates `_sym._tcp` for every room, so legacy and Core Secure share a service type. There
  is no TXT marker for the profile.
- §9.2.2/§4.4.4 tie directed-vs-room binding to the relay envelope, which per-session encryption
  cannot keep.
- §5.2/§5.3 define the handshake for TCP/WebSocket connect and accept, not for relay sessions
  between two diallers.
- §3.4 rejects a duplicate nodeId, while §4.4.7 replaces it.
- §17.3 names no wire format, selection or window for Legacy Import.
- §14.12 "one member per session" against reused cognitive nodes (XMesh design).

## 10. Spec pull requests to draft (meshcognition-website; none merged without the user)

1. §4.4.1/§4.4.7: `relay-auth` proves key possession over a relay nonce, and the relay replaces
   a connection only for the same key.
2. §3.4/§5.2: a bound nodeId proving a different key is a conflict, and it is reported.
3. §5.1: TXT `mmp=2.0` marks a Core Secure advertisement.
4. §5.2/§5.3: the handshake over a relay (trigger, client choice, timeout, supersession,
   teardown on peer-left).
5. §9.2.2/§4.4.4: binding from the authenticated `metadata.to`, plus a `to`-absent E2E vector.
6. §4.4.4: the fan-out envelope.
7. §7.1/§18.2.1: sealed control frames (`mood`) and signed control frames.
8. §16: register `sym-attest-v1` (attestation, checkpoint, witness, node-stats).
9. §14.12: a member is a node, and a session is a trail within it.
10. §6.6/§7.1: `role-chain-fetch`, a directed request for the grant chain that roots a record.
11. §6.6: the revoke's signed `cutoff` and the resolution rule without receipt time (replaces draft
    #33's both-times rule; text in `docs/WIRE-0.14.0.md` §6).
12. §6.6/§18: a failed signature is attributable only to the session that signed in its own name
    (`docs/WIRE-0.14.0.md` §7).
13. §8.8.6: record size limits that fit one sealed frame (draft #37: 256 KiB, 512 KiB, 720 KiB).
