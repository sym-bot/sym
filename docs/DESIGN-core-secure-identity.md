# Core Secure identity: a peer is a proven session, never a hint

**Date:** 2026-10-02 · **Author:** agent-a (core libs) · **Status:** DRAFT for review. No code until
it is reviewed and the user has ruled on the decisions at the end.
**Target:** sym 0.14.0. It blocks that release: the 0.14.0 candidate (f775581) is not a Core Secure
participant (conformance audit 2026-10-02, findings S-A1…S-A12, S-B1…S-B3, S-D3, S-D4, S-F1).
**Spec:** MMP v2.0 as published at meshcognition.org/spec/mmp (last updated 14 Sep 2026).

## 1. The root cause

A sym peer comes into existence before anything has been proven about it. Three code paths
create peer state from hints:

| Path | What names the peer | Where |
|---|---|---|
| LAN, outbound | the nodeId in the DNS-SD instance name the remote advertised | `node.js` `_connectToPeer` 3009-3032 creates the peer on TCP connect, before any frame |
| LAN, inbound | the nodeId in the first frame, a one-frame legacy `handshake` with no proof | `discovery.js` 238-252, then `node.js` 1872-1979 pins its keys and creates the peer |
| Relay | `relay-peer-joined` announcements, and the `from` the relay writes on each envelope | `relay.js` 316-326, 402-416 |

Everything this node keeps per peer hangs off that unproven id: the identity key used to verify
records (`_pinPeerKey`, roster rank `handshake`), the E2E secret (`_deriveAndStoreSecret` from one
persistent X25519 key), the lifecycle role, room admission, gossip budgets, delivery attribution
and dedup lanes.

The proving handshake exists. `lib/core/handshake-v2.js`, `handshake-v2-flow.js`,
`mmp-session.js`, `e2e-v2.js`, `cmb-encrypted-frame.js` and `mmp-ingress.js` reproduce the
published handshake and E2E vectors. Nothing on the connection path calls them.

Several recent fixes were compensations for that one fact:
- stripping a peer-written `provenPublicKey` (`node.js` 1873, `frame-handler.js` 225-228);
- the owner-only gated room that "refuses every peer, holder or not" (`node.js` 3263-3276);
- per-connection gossip lanes, because a budget keyed by a claimable id can be drained by whoever claims it;
- and the F3 restart crash, which is reachable only because a self-signed grant from any connected peer gets persisted.

Each one closed a symptom. The cause stayed open, so each review round found the next symptom.

**The design change:** trust has one unit, the authenticated session. A peer is the set of
confirmed sessions that proved the same nodeId with the same identity key. Discovery and relay
presence produce *candidates* to dial, never peers. Nothing per-peer exists until a session is
confirmed.

## 2. What the spec requires, and one correction

- §18.3: "Node identity is a UUID bound to an Ed25519 key through the authenticated transcript in §5.2."
- §5.2: "No peer identity, key, role or room membership MUST be pinned before both required proofs
  validate. Failure closes the connection without retained peer state." The listener requires
  `client-hello` first and `client-finish` before any other frame.
- §5.3: "Implementations MUST NOT process any non-handshake frame in the AUTHENTICATING state."
- §3.1.3: the X25519 key is for *ephemeral* agreement.
- §18.2.1: CAT7 categories and application bytes are encrypted end to end "on every transport".
- §6.6: exactly one anchor is pinned out of band. Grants vouch grantee keys. "A grant-sourced key
  MUST NOT override a key already learned from a stronger source (a direct handshake or the anchor)."
- §3.4: a compromised key means a new identity (new nodeId and key). A nodeId has one key for life.
- §17.3: Legacy Import "MUST NOT be selected through negotiation failure", must be exposed to the
  operator, and network admission ends after a declared migration window.
- §18.3: "A peer MUST NOT pin their identity or E2E key from DNS-SD, relay discovery or an unproven hello."

**Correction to my earlier proposal.** I proposed self-certifying ids, with the nodeId derived from
the public key. §3.1.1 requires the nodeId to be a UUID v7, and §18.3 binds it to the key through
the transcript. A key-derived id would be a spec change, not a sym change. Decision 1 at the end
covers that option. This design stays inside MMP v2.0.

## 3. Design

### D1. The session is the unit of trust

```
transport accepted/dialled ──► AUTHENTICATING (10 s) ──► confirmed Session ──► Peer
          ▲                         │ any failure: close, keep nothing
  Candidate (hint only):            ▼
  DNS-SD record, relay-peers,   DISCONNECTED
  loopback registry entry
```

- A **Candidate** is an endpoint plus the nodeId it claims. It decides only whom to dial and who
  dials (§5.1: the smaller nodeId initiates). A lie in a candidate can change who dials. It cannot
  create a peer.
- A **Session** is what `handshake-v2-flow` already returns, with the proven facts attached:
  nodeId, identity key, this session's ephemeral E2E key, sessionId, room, selected extensions,
  directional traffic keys and sequence counters.
- A **Peer** is a proven `(nodeId, identityKey)` with one or more sessions, one per transport (§4.6).
  Transport priority, failover and dual-dial tie-breaks run over sessions, after confirmation. Two
  confirmed sessions for one peer on one transport resolve by the existing nodeId rule. That rule
  now compares proven ids.
- The frame handler takes `(session, frame)`, not `(peerId, peerName, frame)`. Every per-peer map
  is keyed by the session's proven nodeId. The display name is a label from the transcript and
  identifies nothing (§3.1.2).
- After an outbound handshake, the proven nodeId must equal the candidate's claimed one.
  Otherwise the node closes and logs the mismatch: the advertiser lied, or its record is stale.

**Frames after the handshake.** On a confirmed session the node acts on three kinds of frame:
1. `cmb-encrypted`, which is bound to the session by its AEAD;
2. frames that carry their originator's own signature (`role-grant`, `role-revoke`), verified
   against the key registry and never against the delivering session;
3. liveness frames (`ping`, `pong`), which change no state.

Every other frame type sym sends today gets classified before code starts: `peer-info`,
`wake-channel`, `mood`, `node-stats`, `attestation`, `checkpoint`, `witness` and `error`. Each is
either signed by its originator, carried as a registered extension (§16.2, finding S-C1), or
removed. A frame that is none of these stays a hint and changes no state. Over a relay this
matters more, because MMP binds only CMBs to the session (§9 below).

### D2. The v2 handshake on every transport

- **LAN TCP and the loopback registry:** the dialler is the client. The Core Secure listener
  accepts `client-hello` and nothing else (`mmp-ingress.admitCoreSecureFirstFrame`). It accepts no
  other frame until `client-finish` verifies (`admitCoreSecureFrame`).
- **Relay:** the handshake runs end to end inside relay envelopes. The client is the smaller
  nodeId, as on the LAN. A session over the relay is bound to the relay `from` it was established
  on. A frame for that session arriving under a different `from` is dropped. The relay is never a
  party to the transcript; it carries opaque envelopes (§4.4).
- The timeout, close codes and error frames follow §5.3 and §7.2. The `sendError` that currently
  has no callers gets used on every refusal (S-C4).

### D3. One key-binding registry, with the spec's ranks

`roster-keys.js` stays the single place where a nodeId gets a key. Its sources change:

| Rank | Source | How it is learned |
|---|---|---|
| 3 `pinned` | operator configuration: the anchor (`SYM_FOUNDER_ANCHOR`) and invite pins (D5) | out of band, before any wire byte |
| 2 `proven` | a confirmed session | §5.2 proofs |
| 1 `grant` | the `granteeKey` of a grant reachable from the anchor | §6.6 vouching |
| 0 `legacy-claim` | an unproven hello. Used only inside a Legacy Import session (D7) | never counts as a binding for Core Secure |

The rules:
- **First contact** binds the proven key. This is the spec's model: trust on first *proven* use.
- **A different key for a bound nodeId** is refused before peer admission. It is recorded as an
  identity conflict and surfaced in `sym status` and the log, never swapped silently. By §3.4, a
  nodeId never legitimately changes key.
- **Unproven sources never bind.** That covers DNS-SD TXT `public-key`, relay announcements and
  legacy hellos.
- **Existing `roster-keys.jsonl` entries at rank `handshake`** were all learned from unproven
  legacy hellos. On first load under 0.14.0 they are relabelled `legacy-claim`, using a version
  marker in the file. The first proven session after upgrade binds afresh. A disagreement between
  a legacy claim and the proven key is logged as evidence of an earlier squat, or of a bug.
- **Authority follows the key, not the id.** `role-grant-store.resolveRole(nodeId, at)` becomes
  `resolveRole(nodeId, key, at)`, and a grant confers its role only when its `granteeKey` equals
  the grantee's bound key.

  This resolves finding S-A4 inside §6.6. Suppose an impostor proves its own key under a
  validator's nodeId before the real validator connects. The anchor's grant cannot override the
  impostor's binding (the MUST), but the grant vouches a different key, so the impostor's binding
  carries no role. The conflict is visible to the operator.

### D4. Ephemeral E2E and the encrypted envelope

- Each handshake makes a fresh X25519 keypair (§3.1.3). The persistent X25519 key, the per-peer
  `_e2eSecrets` map and `_deriveAndStoreSecret` are removed (S-A5). The session keys come from the
  §5.2.1 schedule that `MmpSession` already implements.
- On a Core Secure session, CMBs travel only as `cmb-encrypted`, on every transport, LAN included
  (S-D9). A plain `cmb` frame on a Core Secure session is refused (`admitCoreSecureFrame` already
  does this).
- **Cost:** a relay broadcast (no `to`) cannot carry one sealed frame to many sessions, so a room
  broadcast becomes one sealed send per peer session. The relay still routes, but no longer fans out.
- **Dependency:** the envelope's AAD binds `assertionId` and `createdByNodeId`, so this ships
  together with v2.0 record emission (`MMP_EMIT_V2` on: S-D1, S-D2) and author-key resolution by
  `createdByNodeId` through D3 (S-D4). Records whose author key cannot be resolved are refused in
  Core Secure, not accepted unverified (S-D3). That is the record-model half of this release. It
  shares the key registry, and its own design note follows this one.

### D5. Out-of-band bindings: the anchor and invites

- Production pins an anchor (§6.5). `SYM_FOUNDER_ANCHOR="nodeId:publicKey"` already exists. With D3
  it becomes rank 3 and is never overridden.
- **Invites close the first-contact window for invited peers.** A `sym://` invite (mesh-channel
  `sym_invite_create`) today carries only a room name. It will also carry the issuer's nodeId and
  identity key. Accepting it pins the issuer at rank 3, so a squatter who reaches the joiner first
  is a conflict, not a binding. The invite is integrity-sensitive, not secret: whoever relays it
  must not alter it. That is the trust the person who passes it on already exercises.
- A room grant already carries the grantee's key and the owner's signature. With D1, the owner's
  check compares that key with the session's proven key.

### D6. Room admission on proven identity

- The room is in the transcript. A mismatch closes the connection before admission (§5.2). The room
  is explicit in Core Secure, with the literal `default` for the default room (S-B1).
- **Gated rooms:** the owner is recognised by its pinned key, not by its nodeId claim (S-B2). A
  grantee is admitted when the grant's bound key equals the session's proven key (§5.8.1).
  `provenPublicKey` becomes a property of the session, never a field anyone can write in a frame.
  The strip code and the "refuses everyone" fallback go away.

### D7. Legacy Import: explicit, separate, temporary

- **Off by default.** The operator turns it on with a route list. Each route names a peer's nodeId,
  its endpoint (`host:port`, the loopback registry, or the relay channel) and optionally its key
  fingerprint. This is `mmp-ingress.admitLegacyImport`, which already refuses an unconfigured route.
- **Separation before any peer byte.** On the LAN, Core Secure advertises on `_sym._tcp` with the
  room in TXT (§5.1, finding S-B4; spec PR #17 settles the Room Directory contradiction the same
  way). The legacy listener advertises on the old `_<room>._tcp` type that 0.13.x nodes browse, and
  only while Legacy Import is on. The service type selects the profile, never the first frame.
- **Relay:** a 0.13.x peer's legacy `handshake` is accepted only from a routed nodeId that has never
  completed v2 here. That is the sticky floor in `mmp-ingress`: once a nodeId has spoken v2, its
  legacy route is disabled until an operator reset.
- **Quarantine.** Everything from a Legacy Import session is labelled non-Core-Secure: stored with
  `verified: false` and its profile, never given authority, and never shown as verified. The
  channel surfaces it with a flag (mesh-channel finding C-2.4).
- **A declared window.** The release notes name the window, and the release that removes legacy
  network admission (proposed: 0.15.0). Offline store import stays.
- **Who needs it during the window:**
  - sym-swift 0.6.1 / SYMCore 0.4.2;
  - sym-py;
  - any xmesh or mesh-channel install still on sym 0.13.x;
  - the dev-team-3 seats, which control their own upgrade timing.

### D8. One agent, one node

The daemon's `register-agent` path sends an agent's CMBs over the daemon's own transport, under a
nodeId the agent declared over IPC (S-A12, §3.2, §4.5). It ends in Core Secure: a coupled agent
runs its own node. mesh-channel already does; it has no reference to `register-agent`. Before code,
the consumers of `register-agent` across the estate get listed and each one moved.

### D9. Cognitive nodes: one verified identity, reused

**The concept (the user, 2026-10-02).** A cognitive node is a reusable, verified agent. Instead of
making a new agent for each job, a verified one is kept and used again. XMesh already has the
workflow: in Station, a validator turns a proven mission worker into a "cognition node"
(`POST /api/v1/_/workers/:name/preserve`). That node is roster-persisted, restored on boot,
re-embodied with its learned α profile, and volunteers for matching work:
"prove → preserve → volunteer → earn". Preserved rooms keep their operator node and store the
same way (`preserveRoom`). The xmesh ruling of 2026-08-02 (`docs/agent-identity-and-persistence.md`)
already says the same thing:
- a run has no identity of its own;
- a worker authors as the durable agent doing the work;
- the worker submits to its agent, and the agent signs (Q1a);
- the durable unit is a signed agent bundle of identity, keypair and store (Q3).

**Why this design is what makes reuse mean anything.** "Verified" and "reused" both hang on the
identity being the same, and in MMP the identity is the proven `(nodeId, key)` pair (§18.3):
- a peer recognises a reused cognitive node because its proven key equals the key bound to its nodeId (D3);
- its standing is bound to that key (D3, authority follows the key);
- its memory store and learned α weights belong to that identity (§3.2).

A node rebuilt under the same *name* with a new key is a different identity. It cannot sign as
the old one, the old one's records do not verify against it, and grants vouched for the old key
give it nothing. Preserve and reuse therefore have to carry the identity itself, never a
name-matched twin.

What sym provides for this:

1. **Identity is minted once per agent and never per run.** Already true: `loadOrCreateIdentity`
   has one path that mints, and a single-writer lock refuses a second process. What changes is
   that the nodeId, not the directory name, is what everything binds to. A name is a label
   (§3.1.2), so renaming a cognitive node must not create a new identity.
2. **A signed agent bundle.** Export and import of one identity as one unit:
   - the identity file and key;
   - the memory store;
   - the key registry and role grants;
   - the node's learned admission profile, if its host keeps one.

   The bundle is signed by the identity's own key, so a tampered bundle fails to import. On
   import, a live holder of the same nodeId is refused, both locally (the lock) and on the relay
   (4006). This is the substrate half of the xmesh Q3 ruling, and the "persist any verified
   agent" step in Station becomes this export, nothing weaker.
3. **The interior submits; the node signs.** A per-mission worker or mind is the node's
   *interior* (§2.4: "a membrane over an arbitrary interior"), not a node of its own. sym gives
   the node a local submission path: an interior process hands it a draft. The node runs its own
   checks, signs as itself and emits. The private key stays in exactly one process, and the
   interior never appears on the mesh (§3.2, §5.9). This replaces the daemon's `register-agent`
   forwarding (D8), which does the opposite: other processes speak under a nodeId they declared.
4. **Verification is portable.** A verified cognitive node has a proven binding wherever it goes
   (D3), and its role resolves from the anchor through grants bound to its key, on any node
   (§6.6). Preserving it means a validator's signed act that anyone can resolve: a role grant, or
   a validation CMB whose parents are the node's grounded outcomes (§6.5, §6.7). A server-side
   roster entry is not that. Nor is a CV the node writes about itself, which is a self-report
   (§6.7: self-reported outcomes "SHOULD NOT elevate").

**One reconciliation with the 2026-08-02 xmesh ruling, for the user to confirm.** That document
says the uuid "identifies a process instance, not an agent" and is "never written to a CMB field".
The measurement behind it holds: 292 node directories for 5 agents, because every run minted a
fresh uuid. But MMP v2.0, published later (14 Sep 2026), signs every record over
`createdByNodeId` (§8.8.4) and forbids names as identity (§3.1.2). The two fit together once
identities stop being minted per run (Q1): the uuid then identifies the agent. `<agent>@<xMesh
name>` stays as the agent's name, and its licensed-mesh qualifier can be carried and checked as
a signed claim. It does not replace the nodeId. The xmesh side (preserve, reuse, aliases) is
changed in the xmesh runtime's own design, which this one feeds.

## 4. What this removes

- the legacy one-frame `handshake`, `_buildHandshake`, and the inbound legacy check in `discovery.js`;
- `_peerIdentityKeys`, `_pinPeerKey` from hellos, and rank `handshake` pins from unproven frames;
- the persistent X25519 key and `_e2eSecrets`;
- the `provenPublicKey` strip code and the owner-only gate fallback;
- trust in the relay's `from` as an identity;
- per-connection gossip lanes as an identity workaround, since budgets key on proven ids.

## 5. What this does not solve (stated in the README and SECURITY.md)

- **First contact with no anchor, invite or grant** is trust on first proven use. Someone who
  reaches a node first under an unused nodeId keeps that nodeId on that node. The conflict
  becomes visible when the real holder arrives. This is MMP's model, and §9 proposes a spec note.
- **Relay eviction.** `relay-auth` carries an unproven nodeId (§4.4.1). Any holder of a channel
  token can register as an existing node's id. The relay replaces a connection older than 5 s
  with close code 4004, and §4.4.7 tells the evicted client it "MUST NOT automatically reconnect".
  That is a remote denial of service, and the spec has to change to close it (§9).
- **Key compromise** has no rotation (§3.4): the node takes a new identity.

## 6. Release and migration

- 0.14.0 is Core Secure by default. A 0.13.x peer reaches it only through a configured Legacy Import
  route, so the estate is partitioned during the upgrade unless routes are set.
- **Upgrade order:**
  1. my nodes and :8790;
  2. :8787, deployed with the user's confirmation;
  3. the other seats, coordinated with them. dev-team-3 restarts on its own timing.
  Routes cover what cannot upgrade yet, chiefly sym-swift devices.
- **Identity files do not change.** The nodeId and Ed25519 key are kept, so no agent loses its
  identity or its history.
- The F3, G2 and C3 crash fixes from the 0.13.17 hotfix carry into 0.14.0 unchanged.

## 7. Tests: the public corpus first

- The handshake and E2E vectors are already consumed. The suite adds negative cases (§17.4):
  - a bad proof, a wrong key confirmation, a replayed or unechoed nonce;
  - a stripped extension, a room mismatch;
  - a data frame before `client-finish`, a legacy frame on the Core Secure listener;
  - a different key for a bound nodeId, a relay `from` that differs from the session's nodeId;
  - a grant whose `granteeKey` differs from the bound key, a plain `cmb` on a Core Secure session.
- Two 0.14.0 nodes interoperate on each transport (LAN, loopback, relay).
- A Legacy Import route is tested against a real published 0.13.16 node, and a 0.13.16 node with no
  route is refused.
- No private vector is reported as conformance (§17.4).

## 8. Decisions for the user

1. **Identity binding.**
   - (a) The spec's model, recommended: proven first use plus out-of-band pins (anchor and invites)
     plus grants, with authority bound to the key.
   - (b) Propose an MMP change to key-derived nodeIds. A UUID v7 whose 74 random bits come from a
     key hash stays inside RFC 9562, but 74 bits is below the 128-bit level the rest of MMP
     targets. A full-strength id (for example UUID v8 over the key hash) needs §3.1.1 changed.
2. **Default posture and window.** 0.14.0 ships Core Secure-only, with Legacy Import opt-in per
   route, until 0.15.0 (recommended). The alternative, Legacy Import on by default, is what §17.3
   forbids for network admission once the window closes, and it keeps the partition invisible.
3. **Cognitive-node identity (D9).** Confirm that the nodeId, minted once per agent, is the
   agent's identity, with `<agent>@<xMesh name>` as its name. This supersedes the 2026-08-02
   sentence "never written to a CMB field", which MMP v2.0 contradicts. Also confirm that
   preserving means exporting the signed bundle of the same identity, made visible by a
   validator's signed act.
4. **Spec pull requests to draft for review** (on meshcognition-website, not merged without you):
   - §4.4.1 and §4.4.7: `relay-auth` proves key possession over a relay nonce, and the relay
     replaces a connection only for the same key;
   - §3.4 and §5.2: what a node does when a bound nodeId proves a different key, plus the §3.4 vs
     §4.6 duplicate-nodeId contradiction;
   - §5 and §18: non-CMB frames after the handshake have no session binding on a relay;
   - §18.3: name trust on first proven use as the residual, with invites as the out-of-band
     answer.

## 9. Spec gaps found while writing this

- No defined behaviour for a bound nodeId proving a different key (§3.4, §5.2, §6.6).
- `relay-auth` identity is unproven, so close code 4004 is an eviction primitive (§4.4).
- Only CMBs are bound to the session. Other post-handshake frames over a relay can be injected by
  the relay operator (§4.4.4, §18.2.1).
- §3.4 rejects a duplicate nodeId (1005), while §4.6 describes replacing one.
- §17.3 names no wire format, selection mechanism or migration window for Legacy Import. The
  separate listener by service type (D7) is sym's answer, and it should be written down.
