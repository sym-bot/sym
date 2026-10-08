# sym 0.14.0: the wire, against MMP 2.0 update 1

This file began as the wire elements sym 0.14.0 sends that MMP v2.0 did not define, written so that
spec PRs could be drafted from them. Those drafts are now folded into **MMP 2.0 update 1**
(sym-bot/meshcognition-website PR #43, branch spec/mmp-2.0-update-1 at 2660ab9, pending the
founder's merge): `control-encrypted` (§7.1, §18.2.1), `cmb-anchors` (§9.4), `room-join` (§5.8.1),
the relay handshake and the error rules (§5.2.2, §7.2), the record size limits and the canonical
projection (§8.8.5, §8.8.6), discovery's TXT `mmp` and `room` (§5.1), the relay fan-out envelope
(§4.4.4) and `sym-attest-v1` (§16.4). What remains here is what sym chooses where the spec leaves a
choice, and where sym does not yet do what the update says.

Notation follows MMP v2.0. `lp(x)` is the §8.8.4 length prefix (`<utf8-byte-length>:<utf8 bytes>`).
A **sealed control frame** is the inner frame of a `control-encrypted` envelope. It shares the
session's single per-direction sequence with `cmb-encrypted`, so the frames below are ordered with
the records around them, and none is ever sent in the clear on a Core Secure session.

Not in the update, and not in sym 0.14.0: relay-auth key proof and its close code 4007 (#20,
deferred past 0.14.0; sym treats 4007 as an ordinary close, reconnected with backoff), and the
Near Band extension (#39).

---

## 1. `cmb-anchors`: MMP 2.0 update 1, §9.4

The frame is §9.4's: `{ "type": "cmb-anchors", "keys": [...] }`, sealed, at most 50 cognition keys,
the first sealed frame after admission (after `room-join`, where the server holds a grant), with
`keys: []` when nothing is replayed. What sym chooses:

- It replays at most 5 records, the newest of its own `mmp-sig-v2.0` records in the session's room
  with no recipient, and sends a **non-empty** list to one peer at most once a minute; only a list
  that was sent starts that minute. The empty list goes on every admission.
- Receiving, it keeps the key set for that session (replacing any earlier one) and marks a record
  as replayed context (`anchor: true` on the `verified-record` event and the stored entry) only when
  its signed `createdByNodeId` is the session's proven nodeId. A frame that is not the schema's (more
  than 50 keys, a non-key, another member) is refused whole and counted.
- Because it is always sent, it is the first sealed frame a relay client hears on a new session:
  the client supersedes its old session only when a sealed frame of the new one, other than an
  `error`, opens, and abandons a new one that hears nothing within the handshake timeout
  (`unconfirmed-by-peer`), keeping the old.

---

## 2. `room-join`: MMP 2.0 update 1, §5.8.1

As §5.8.1 states it: a sealed control frame carrying the owner-signed grant, sent first on a newly
confirmed session; the grant checked against its schema (closed, integer times, lowercase ids)
before any signature work, then verified under §18.3.2 against the owner's pinned key, the
session's proven nodeId and key and this room, with 5 minutes of skew either way; admission
decided before the session's next frame; the session closed when the grant expires
(`room-grant-expired`). sym sends only the schema's members of the grant it holds.

---

## 3. `role-chain-fetch`, `role-chain`, `role-digest`: retired

sym 0.14.0 carried role grants and revokes with three frames of its own (`role-chain-fetch`,
`role-chain` and `role-digest`) and resolved them by replaying signed times (the earlier sections 3,
5 and 6 of this file). MMP §6.6 as merged (meshcognition-website main at 8c3381d, PR #40) replaces
that rule and its frames: authority is a function of a set of hash-linked statements with no time in
it, carried by `authority-statement`, `authority-digest`, `authority-fetch` and `authority-set`
(§6.6.8, authority-frame.schema.json). sym implements §6.6 as written (lib/core/authority.js,
lib/authority-store.js, lib/node-authority.js) and treats `role-grant`, `role-revoke`,
`role-chain-fetch`, `role-chain` and `role-digest` as retired (§6.6.11): received, they are ignored and
counted (`authorityStatus().stats.retired`), and they are never sent. Nothing in this file adds to
§6.6; where sym chooses among what §6.6 allows, it is said here.

- **Pacing (§6.6.8).** A responder answers `authority-fetch` at 4 a second per session (burst 16).
  Over the rate a request waits its turn (at most 64 wait; past that one is dropped), so an asker
  that keeps one pull in flight gets every page. sym does not take the MAY to refuse a fresh full
  pull within 60 s: the pacing bounds the work, and a refused pull would leave differing roots
  apart until the peer's set next changed.
- **The cost of a statement (§6.6.12).** Every statement a session delivers spends that peer's
  gossip lane before it is checked, asked for or not: one check (one per pinned-key entry of an
  anchor-level statement, each of which may be verified), plus 16 for each key it makes this node
  check for the first time (a grant's subject key; the signing key, when it will be verified). Rules
  1 and 2 of §18.3.2 cost one scalar multiplication for a new key, about fifteen signature checks
  here; pinned keys are checked once, at the pin, and kept. So a statement costs at most 33. A
  statement not of the schema's shape, a repeat of one held, a pending statement already held, and
  one the session's pending holds (64) have no room for cost nothing: they are dropped before any
  check. Unsolicited statements the lane cannot pay for are dropped (a pull brings them later).
- **The asking rule.** This node asks a session (a pull page, or a fetch by ids for the missing
  links of its pending statements, up to 64 ids at once) only when that peer's lane holds a full
  answer's worst case, 64 × 33 = 2,112 checks, and reserves it while the ask is out: the answer is
  paid from the reservation and what it did not spend goes back. One ask is in flight per session.
  So an answer is never dropped for budget, and nothing the peer sends makes this node verify more
  than the peer's lane pays for, whatever triggered the ask (a digest, a pending statement, the
  answer before). An answer is verified in slices, the event loop free between them. Resolving the
  set is not charged to a lane; it is paced: a node resolves when it settles, at most once per twice
  its last resolution's time, a pull's end is decided at the next settle (never by a resolution forced
  for it), and an eviction pass resolves once per batch of arrivals.
- **Pulls.** An unanswered page is asked again from the same cursor, up to 3 times. A digest that
  arrives during a pull is remembered, and if the roots still differ when the pull ends, the pull
  starts again at once (under the asking rule). A pull that ends with the roots apart and no new
  digest is started again after a backoff, 2 s doubling to 5 minutes, reset when either set changes,
  until the roots meet. A pull that stopped early (its page retries spent, or its session closed)
  resumes from its cursor.
- **Capacity (errata 1).** At most 200,000 statements are held, and beyond that only in-force revokes
  and in-force anchor-level statements, which the quotas bound; between eviction passes up to
  EVICT_SLACK (3,125 at the default bound) more can be held, and the protected floor is judged again
  at the next pass. Past the bound the store drops
  everything outside the live set first, whatever its kind, then live statements in reverse authority
  order (deepest first, grants before revokes and endorses, highest id first), a batch at a time. An
  anchor-level statement or a revoke that is in force is never dropped or refused; a dead or
  over-quota one is an ordinary candidate. A statement refused for capacity is not a relay failure.
  The file is compacted once it holds twice what the store keeps.
- **Unique signature keys (errata 1).** A statement whose signature entries repeat a key is not well
  formed, refused before any signature is checked.
- **Persistence (§6.6.8).** Held statements are written as their canonical members only, each on a
  line of its own, to one file, `authority/statements.jsonl`, whatever the pin. At load every
  statement is judged again against the pin in force, chain by chain, and the set resolved afresh;
  what does not count under that pin is kept in the file as the bytes it was, never deleted, so a
  re-pin keeps what still counts (§6.6.1) and a corrected pin finds everything again. Only lines that
  are not a statement (torn, not JSON, not of the shape) and statements dropped for capacity are left
  out. No status, root or receipt time is stored.
- **No anchor pinned.** A node with no pin sends no digest, pulls nothing,
  answers no fetch, stores and relays nothing, and counts no statement it cannot judge against the
  session that sent it.
- **Scopes (§6.6.2).** A scope's namespace is implemented by an extension. sym implements none by
  itself: a host passes `authorityScopes: { <namespace>: (path, cmb, scope) => boolean }`, judged on
  the CMB's own signed fields. Where a namespace is not implemented a scoped grant is still resolved
  (it counts toward quotas and roots), and confers nothing on any CMB.

---

## 4. Errors and the relay handshake: MMP 2.0 update 1, §5.2.2 and §7.2

sym follows §5.2.2 and §7.2 as the update states them: every error on a confirmed session is sealed;
a clear error changes nothing, except that 1011 `UNKNOWN_SESSION` may prompt a new handshake; a
sealed error whose action is Close ends the session (1001, 1003 to 1010: 1009 `IDENTITY_CONFLICT`
and 1010 `SESSION_CLOSED` among them); a replay is discarded on every transport; a gap closes the
session with a sealed 1010. What sym chooses:

- **1011 replies.** At most once a second per relay `from` (the table of froms bounded at 1,024,
  least recently said first out), and at most 2 a second in all (burst 8), dropped past it, never
  queued. `detail` is `session:<32 hex>` when the triggering frame named a session, absent for a
  `ping`.
- **Acting on 1011.** Only the client-role side, only while the peer is present on the relay, only
  when `detail` names a session it holds with that peer or a probe ping to it is outstanding, only
  while no newer session with it is waiting to supersede, and no faster than 1 s doubling to 30 s
  (starting over after a quiet minute). It keeps the session it has until the new one supersedes it.
- **Probe.** A repeated announcement (`relay-peer-joined`, `relay-peers`) for a peer with a live
  relay session sends a `ping` on it, at most once a second; a pong (clear or sealed) ends the probe.
  ping and pong may travel sealed; a sealed ping is answered with a pong.
- **The server supersedes when it admits the new session** (in a gated room, after `room-join`).
- **A failed handshake sends nothing.** 1009 is found only after both proofs validate, so it is sent
  sealed on the session, and a node refused with 1009 does not re-handshake over the relay or
  re-dial over the LAN (discovery's 15 s re-offer included) until it restarts.
- **`sendError`** sends only 1002 and 2xxx; the protocol's own codes are the node's to send.

## 4a. Records, fetch and the mood frame: MMP 2.0 update 1, §8.8, §7.1, §9.3

- **The projection.** sym holds and serves the canonical signed projection (§8.8.5 step 1) and passes
  record-projection-v2 byte for byte: NFC refused, never normalised, on receipt (minted NFC), parents
  sorted bytewise, an empty lineage and an absent application null. The 256-character caps count
  code points. A room is a §5.8 identifier everywhere.
- **The size measure.** `MAX_RECORD_BYTES` is the RFC 8785 length of the two-section record
  (record-size-v2), never a node's annotations beside it.
- **Fetch.** `cmb-fetch` is `{ type, reqId, key, timestamp? }` and names one key;
  `cmb-fetch-result` is `{ type, reqId, returned, missing }`; both are refused when they carry any
  other member. A fetched record is verified by the whole of §8.8.5 before `fetchCMB()` attributes
  it; otherwise only its categories are handed back (`verified: false`), for §15.8 lineage use.
- **mood.** `{ type, mood, context, timestamp }`, attributed to the session's proven nodeId and name;
  1,024 and 4,096 characters at most; refused when it carries `from`, `fromName` or anything else.

## 4b. Discovery and the relay client: MMP 2.0 update 1, §5.1, §4.4

- Every node, the daemon included, advertises `_sym._tcp` with TXT `room` and `mmp=2.0`, and dials
  only advertisements whose TXT room is its own and whose `mmp` list contains 2.0. TXT keys are read
  case-insensitively, the first occurrence winning. The daemon also browses `_<room>._tcp` where
  that is a valid RFC 6335 name (the §5.1 migration browse), and never advertises it.
- The relay client reconnects with backoff after every close but 4004 and 4006 (4005, 4008, 1001,
  1009, 1011, 1013, and 4007); forgets a relay's `features` with its socket; and sends relay-auth's
  nodeId lowercase, with `room` (when not default) and `engine`. It paces at 20 frames a second,
  burst 200, under the update's floors (§19.1: 25 a second, burst 300), counting relay-auth and
  relay-pong inside the same bucket, ahead of every other frame.

## 4c. sym-attest-v1: what sym chooses (§16.4, the extension text)

- An attester checkpoints every 8 attestations (`checkpointInterval`), each over the segment since
  its last, chained to that root. The segment and the checkpoint are appended to the attestation
  logs before anything that depends on them is gossiped (appended, not fsynced). A node that no
  longer holds its segment ends its chain and signs no further checkpoint until its state changes.
- Only two conflicting checkpoints the attester signed are equivocation evidence (a witness is not
  attester-signed). A verified witness that names the range of an attester-signed checkpoint held,
  with another root, counts against the witness: it is refused (`disagrees`), said once, and that
  witness's further witnesses are dropped unverified for 10 minutes (`witness-muted`). One that
  overlaps a held checkpoint without matching it is a lead: refused and said (`witness-lead`), no more.
- §6's order: sym drops a duplicate (step 4) and applies the prev link (step 5) before it checks the
  signature's spelling (step 3); all three discard the frame with no state changed, so only the
  reason a refusal names differs.
- Unchained checkpoints in a log written before update 1 are kept and read as before (one per
  position, a second root for one a conflict); none is accepted from the wire.

---

## 5. Who a failed signature is charged to

**Why.** A statement relayed on a session (a record, an attestation, a checkpoint, a witness) is
verified under the receiver's binding for its signer, and bindings are local views: the
receiver may hold a squatter's session-scoped binding for that nodeId, or lack a vouch the relayer
holds. Closing the relayer's session for a statement that fails there closed honest relaying peers
whenever a squatter held a signer's nodeId (sym 0.14.0 re-review N1).

**Rule.** A receiver ends a session for a signature that does not verify (sym: close, and refuse the
nodeId for 60 s) only when the statement names the session's own proven peer as its signer and the
key that failed is the key that session proved. Any other statement that fails is dropped, counted
and never charged to the session that delivered it. Its frame is not marked seen, so a genuine copy
from another peer is still taken.

**Cost.** Not charging a relayer must not make forgeries free. A receiver therefore:
- spends a per-session record lane before it does any work on a record (sym: 32 a second, burst
  128), as it spends a per-peer gossip lane before verifying a statement; past it, records are
  dropped unverified and unmarked;
- counts, per (delivering peer, named signer), the statements that failed under its binding for
  that signer: past 8 in a minute, that peer's statements for that signer are dropped unverified
  until the minute ends. The peer is not blamed and its other statements are taken;
- says each refused record at most once a minute per peer and reason, and records it in its
  decision log at most as often.

**Authority statements are not charged this way.** An `authority-statement` is verified under the
key its own chain names (the subject key of its authorising grant, or the pinned keys), never a
registry binding (MMP §6.6.9), so the views above cannot differ and no session is closed for one.
One that fails is dropped and counted against the delivering session (§6.6.8: rate-limited): past 8
failures in a minute, that peer's authority statements are dropped unread for the rest of the minute.
The mute is keyed on the session's peer, never on a key the statement names (a sender chooses those).
A statement refused for capacity is not a failure.
