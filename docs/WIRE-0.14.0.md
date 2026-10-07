# sym 0.14.0: wire elements that need spec text

These are the wire elements that sym 0.14.0 (Core Secure) sends and that MMP v2.0 does not
define yet, written so that a spec PR can be drafted from them. Each section gives the element's
fields, how it is signed or sealed, when it is sent, and what a receiver does.

Notation follows MMP v2.0. `lp(x)` is the §8.8.4 length prefix (`<utf8-byte-length>:<utf8 bytes>`).
A **sealed control frame** is the inner frame of a `control-encrypted` envelope (draft spec PR
meshcognition-website#26). It shares the session's single per-direction sequence with
`cmb-encrypted`, so the frames below are ordered with the records around them, and none is ever
sent in the clear on a Core Secure session.

Frames that the published spec, or a draft PR, already defines are not repeated here. That
includes `control-encrypted` (#26), `cmb-fetch` and `cmb-fetch-result` (#26: the result is
`{reqId, returned[], missing[]}`, and each record travels in its own `cmb-encrypted` frame ahead
of it), the `sym-attest-*` frames (#27), the error code 1009 `IDENTITY_CONFLICT` (#21), and the
relay close code 4007 (#20).

---

## 1. `cmb-anchors`: the records that follow are replayed context

**Why.** When a session is admitted, a node replays a few of its own recent records as context,
so that a newly joined peer has something to couple against. In 0.13 the replayed record frame
carried an `_anchor: true` flag. In Core Secure the record frame is fixed by §18.2.1 (an
`cmb-encrypted` envelope carries the record and nothing else), so the flag cannot ride on it.

**Frame** (sealed control frame):

```json
{ "type": "cmb-anchors", "keys": ["cmb-<64 lowercase hex>", "..."] }
```

- `keys`: the cognition keys (`metadata.key`, §8.2.1) of the records about to be replayed, in the
  order they will be sent. At most 50 keys. The sender sends at most 5 records.

**Sealing and signing.** Sealed on the session (`control-encrypted`), unsigned. It is
session-bound: it speaks only for the session's proven peer, about records that peer authored.

**When it is sent.** At most once a minute per peer, when a session is admitted. It goes
immediately before the replayed records, which follow it on the same session as ordinary
`cmb-encrypted` frames. Only records the sender itself authored are replayed (anti-echo,
§15.7), and only signed `mmp-sig-v2.0` records.

**Receiver.**
- Keeps the key set for that session, replacing any earlier set from the same session. It keeps
  at most 50 string keys and ignores entries that are not strings.
- A record that then arrives on that session with a listed key goes through §8.8.5 verification
  and admission like any other, and is marked as replayed context (`anchor: true` on the
  `verified-record` event and on the stored entry) only when its signed `createdByNodeId` is the
  session's proven nodeId: an anchor is the sender's own record.
- Only room-bound records are replayed: a record signed to one node (`to` set) is never replayed
  to another, whoever's session it is (the seal point refuses it in any case).
- Nothing about the record's authority or verification changes. `cmb-anchors` never causes a
  record to be accepted.

---

## 2. `room-join`: now draft spec PR #31

sym 0.14.0 sent this frame as `mesh-room-join` until the security review. It now sends and reads
`room-join`, as draft spec PR meshcognition-website#31 names and defines it (§5.8.1: a sealed
control frame carrying the owner-signed grant, sent as the first control frame of a newly
confirmed session; pending admission for up to the handshake timeout; verified against the
owner's pinned key, the session's proven nodeId and key, this room, and the grant's expiry). One
behaviour beyond the draft: an admitted session whose grant expires is closed when it does
(`room-grant-expired`), not kept for as long as the session lasts.

---

## 3. `role-chain-fetch` and `role-chain`: fetching the chain a grant needs

**Why.** A role grant or revoke is kept only when it is rooted at the anchor (§6.5, §6.6).
Gossip has no order, so a grant can arrive before the grant that roots its grantor. A pending set
that holds whatever might later be rooted can be flooded. Instead, the receiver asks the session
that delivered the record for the missing chain.

**Request** (sealed control frame, sent to the delivering session only):

```json
{ "type": "role-chain-fetch", "reqId": "rc-<16 hex>", "grantees": ["<grantor nodeId>"] }
```

- `reqId`: a correlation id of at most 128 characters.
- `grantees`: the nodeIds whose own rooting grants are missing (the `grantedBy` of the record that
  could not be rooted). At most 16 are read.

**Answer** (sealed control frame, on the same session):

```json
{ "type": "role-chain", "reqId": "<the request's reqId>",
  "grants": [ { "type": "role-grant", "grantee": "...", "role": "validator", "grantedBy": "...",
                "grantedAt": 1786611600000, "granteeKey": "...", "sigAlg": "ed25519", "sig": "..." } ] }
```

- `grants`: at most 64 role-grant or role-revoke records, each the canonical object of its signed
  fields only (`type, grantee, role?, grantedBy, grantedAt, granteeKey?, cutoff?, ratify?, sig,
  sigAlg`; `cutoff` and `ratify` on a revoke only, section 6). They are
  ordered top-down: each record comes after the records that root its grantor, up to the anchor
  (depth at most 8). For each named grantee the answer holds the records the server holds whose
  grantee it is, revokes included, each preceded by its grantor's chain.

**Whole-store sync** (anti-entropy, security review D). The same pair carries a paged copy of the
server's whole store:

```json
{ "type": "role-chain-fetch", "reqId": "rs-<16 hex>", "sync": true, "after": 0 }
{ "type": "role-chain", "reqId": "<the request's reqId>", "grants": [ ... ], "next": 64 }
```

- `after`: where the page starts, in the server's sync order: the anchor's records first, then
  those of each grantor the earlier ones reach, breadth first, each grantor's own records by
  signed time; records no chain reaches come last. A page holds at most 64 records.
- `next`: present when another page follows; the client asks for it with `after: next`. A client
  asks for at most 1,024 pages per session, one page in flight at a time.

**Signing.** Neither frame is signed. Each grant in `grants` keeps its grantor's signature
(§6.5) and is verified as gossip is: top-down, against the key that the chain vouches for its
grantor, or the anchor's configured key. Its authority never comes from the session that served
it.

**When they are sent.**
- A node sends a whole-store `role-chain-fetch` when a peer's `role-digest` (section 5) differs
  from its own.
- A node sends `role-chain-fetch` when a role grant or revoke that arrived on a session is refused
  as `unknown-grantor-key` (no record it holds vouches a key for its grantor), naming the grantor.
  That is the only reason a verifiable record waits: no record is refused for its authority
  (section 6).
  - It sends at most one fetch in flight per (session, grantor). Further early records for the
    same grantor join the fetch already in flight.
  - The early record is held in memory only for that fetch, as its signed fields only, under a key
    made of every signed field plus the signature, so a forged copy cannot displace the genuine
    one. At most 64 records, and at most 64 KiB, are held per session. A held record is never
    written and never relayed. A record whose fields are malformed (a nodeId that is not canonical
    lowercase or is over 128 characters, a role name over 32) is never held.
- A node answers `role-chain` for each fetch it receives, paced per session by a token bucket of
  4 a second (burst 16). Fetches past that are dropped and counted.

**Receiver of the answer.**
- Reads an answer only if it matches a fetch in flight on that same session. An answer that
  nobody asked for, or that arrives on another session, is ignored.
- Offers the grants to its store until a pass stores nothing, so their order does not matter.
  Each goes through the ordinary ingest: the gossip budget, verification with the vouched key and
  the cutoff rule (section 6), storing as its signed fields only, and relaying once. A grant in the
  answer whose signature does not verify ends the session only when its grantor is the session's
  own peer and the key that failed is the one the session proved; any other is dropped and counted,
  since it was verified under this node's view of its grantor's keys, which the server's may not
  share (section 7).
- Then offers the held records again, in passes until one stores nothing (a held record can wait
  for another held record that vouches its grantor's key), and drops what is left. Neither the answer's grants nor the held records
  start a further fetch.
- A fetch that is not answered within 10 s, or whose session closes, releases its held records.
  They are dropped.

---

## 4. Errors on a session: 1011 `UNKNOWN_SESSION` in the clear, everything else sealed

sym 0.14.0 used sym-local codes 4404 ("unknown session") and 4400 ("session closed") until the
security review. It now uses the renumbering draft spec PR meshcognition-website#23 adopts: **1011
`UNKNOWN_SESSION`** and **1010 `SESSION_CLOSED`**, beside #21's 1009 `IDENTITY_CONFLICT`, and the
rule that an error is information, never a command.

**On a confirmed session every error is sealed** (`control-encrypted`): 1010 when a node closes the
session, 1009 when the peer's proven key conflicts with the binding, and any 2xxx. A sealed 1010
or 1009 ends the session at the receiver; any other sealed code is counted and changes nothing.
A handshake that does not confirm sends nothing, and a superseded session sends nothing (the
peer's own new session supersedes it): it leaves any confirmed session exactly as it was.

**A clear `error`** on a confirmed session, or over the relay, is anyone's to write, and is
ignored (counted as `clear-error-ignored`), with one exception:

```json
{ "type": "error", "code": 1011, "message": "unknown session", "detail": "session:<32 lowercase hex>" }
```

**Why.** A relay session is bound to the relay `from` (draft #23). When a peer restarts behind the
relay, the relay replaces its connection (4004) and, since sym-relay 0.5.4, sends no
`relay-peer-left`. The other node still holds the old confirmed session and cannot tell the
restart from a repeated announcement. So the peer's new process says, in the clear (it has no
session to seal under), that it holds no such session.

- `detail` names the sessionId when the triggering frame carried one (a sealed frame), and is
  absent when it did not (a `ping`).

**When it is sent.** A node that receives, from a relay `from`, either a sealed frame naming a
session it does not hold, or a `ping` from a `from` it holds no relay session with, answers with
1011: at most once a second per relay `from` (the table of froms is bounded at 1,024, least
recently said first out), and at most 2 a second in all (burst 8) across every `from`, past which
replies are dropped, never queued (security review D, pacer-starve).

**Receiver.**
- If it is the client for that peer (the smaller nodeId, §5.2.2), and the peer is present on the
  relay, it starts a new handshake. It **keeps** the session it has until the new one confirms
  and supersedes it, so a restart produces no `peer-left`.
- The server ignores it: the client will re-handshake.
- 1011 never tears a session down. At most it prompts a new handshake.

**A replayed frame.** An authentic sealed frame whose sequence the receiver has already passed (a
relay repeating what it carried) is discarded and counted (`replay`); the session is unharmed. A
gap still closes the session (a lost frame cannot heal).

**1009 is not retried.** A node refused with 1009 does not re-handshake over the relay and is not
re-dialled over the LAN (discovery's 15 s re-offer included) until it restarts.

**Probe.** A node that sees a repeated announcement (`relay-peer-joined`, `relay-peers`) for a
peer it holds a live relay session with does not re-handshake. It sends a `ping` on that session,
at most once a second. A live peer answers `pong`; a restarted one answers 1011.

---

## 5. `role-digest`: anti-entropy for grants and revokes

**Why.** Gossip is relay-once. A grant or revoke dropped on its way (a full hold, a budget, a
session that ended) was never sent again, and a revoke lost that way left a revoked node's
authority standing (security review D, p7-ceiling).

**Frame** (sealed control frame):

```json
{ "type": "role-digest", "count": 12, "digest": "<64 lowercase hex>" }
```

- `count`: the role-grant and role-revoke records the sender holds.
- `digest`: lowercase hex SHA-256 over the canonical spellings of those records' signatures,
  sorted, each followed by `\n`. Two nodes holding the same records give the same digest.

**When it is sent.** To every newly admitted session, after `cmb-anchors`, whatever the sender
holds (`count` 0 for an empty store). It is therefore also the first authenticated frame a relay
client hears from its server on a new session: a client that re-handshakes while it holds a
confirmed session keeps the old one until the new one carries such a frame (it cannot otherwise
know the server took its `client-finish`), and closes a new one that hears nothing within the
handshake timeout (`unconfirmed-by-peer`).

**Receiver.** If `count` is above 0, the digest differs from its own, and no whole-store sync is
in flight on that session, it asks for the sender's store with a whole-store `role-chain-fetch` (section 3), page
by page. Each record goes through the ordinary ingest, so what the receiver already holds costs
nothing and what is new is relayed once. A digest is a hint: nothing is taken on its word.

---

## 6. Grants and revokes: what is kept, and what counts (replaces draft spec PR #33's rule)

**Why.** Two things went wrong in 0.14.0's first two designs, and both made the mesh disagree.
Draft spec PR #33 counted a statement only if its signer was authorised both at its signed time and
when the receiver received it, so nodes that received a genuine revoke at different times resolved
different authority. Its first replacement still decided at ingest whether a record was rooted, and
bounded records with caps that refused newcomers, so two nodes holding the same records kept
different subsets depending on arrival order, their digests never matched, and every session between
them ran a whole-store sync. The rule below makes the kept set and the resolved authority functions
of the records held: no receipt time, no arrival order. (The founder's rulings, 2026-10.)

### 6.1 Fields

A `role-revoke` carries:

- `cutoff`: an integer, milliseconds since the epoch, `0 <= cutoff <= grantedAt`: the time from
  which the revoked node is no longer trusted. sym 0.14.0 requires it on every revoke it signs
  (`revokeRole(nodeId, { cutoff })` has no default). A revoke without one (0.13) has
  `cutoff = grantedAt`.
- `ratify` (optional): the revoked node's statements that stay valid, as their canonical signatures
  (86 unpadded base64url characters), sorted ascending, no repeats, 1 to 64 entries. Only on a revoke
  that carries `cutoff`. A revoker that must ratify more issues several revokes; each counts.

Both are signed. The §6.5 grant payload gains `|<cutoff>` at its end when the revoke carries a
cutoff, and then `|<ratify joined by ",">` when it carries `ratify`:

```
role-revoke|<grantee>|<role or empty>|<grantedBy>|<grantedAt>|<granteeKey or empty>|<cutoff>|<sig1>,<sig2>
```

A revoke without `cutoff` signs exactly the bytes MMP v2.0 signs today. Malformed: a `cutoff` or
`ratify` on a `role-grant`; a cutoff after `grantedAt`; `ratify` without `cutoff`, empty, unsorted,
repeated, over 64 entries or holding anything but a canonical signature; a revoke `granteeKey` that
is neither empty nor a 43-character key; a `role` containing `|`. So no two records sign the same
bytes.

### 6.2 What is kept: a deterministic function of the records held

1. **Verifiable.** A record is kept only when its signature verifies under the anchor's configured
   key (its grantor is the anchor) or under a key that a kept `role-grant` vouches for its grantor
   (`granteeKey`). Whether the grantor had authority is not asked here: a verifiable record is kept
   and its effect is decided at resolution (6.3), so no record is refused for an order in which
   records happened to arrive. A record whose grantor no kept grant vouches is refused
   (`unknown-grantor-key`) and held for a `role-chain-fetch` (section 3).
2. **Depth and subtree.** The anchor signs at depth 0. A grant kept at depth d makes its
   (grantee, granteeKey) a signer at depth d + 1, in the subtree of the anchor grantee at the top of
   that chain. A signer reachable by several chains takes the shallowest, then the one whose subtree
   root has the smallest nodeId.
3. **Budget per delegation subtree.** The anchor's own records are not bounded. Every other record
   counts against the subtree of its signer: everything an anchor grantee and its descendants sign
   shares that one budget (sym: 4,096 records). One subtree, however compromised, cannot fill
   another's budget, so a revoke signed in another subtree is never refused by it.
4. **Selection.** Inside a subtree the kept records are the first, up to the budget, in this total
   order on signed fields: the signer's depth (shallower first); revokes before grants; a revoke's
   cutoff, or a grant's `grantedAt` (earlier first); the canonical signature (smaller first). A
   record that loses is replaced: a record that ranks above the last one kept takes its place, and
   one that ranks below it is refused (`outranked`). Several revokes by one revoker for one grantee
   are all kept while they fit; the earliest cutoff is the one that matters, so a revoker can always
   tighten its cutoff by signing another revoke.
5. **Equal stores.** Two nodes that hold the same records keep the same records and give the same
   `role-digest`, whatever order they learned them in.

Selection is computed over the records held: a record refused or replaced is not kept for later.
Where a later grant gives a signer a shallower chain through another subtree, that signer's
records move between budgets, and a record refused earlier in the budget they left is not
reconsidered until a peer offers it again (the next whole-store sync after `role-digest`s differ).

### 6.3 What counts: resolution

For a node N holding key K, its role at time T is resolved from the kept records. "Now" is the
resolving node's clock.

1. The anchor holding its configured key is `anchor`.
2. Otherwise take N's grants with `granteeKey = K` and `grantedAt <= T`, and N's revokes with
   `cutoff <= T`. Replay them in `grantedAt` order (a revoke at its own `grantedAt`, even when that
   is after T), from `participant`.
3. **Every statement by a signer S (key k), signed at s, counts only if S held the rank it needs at
   s** (a revoke of S whose cutoff is at or before s has already cleared S there, so a statement
   S signs at or after its cutoff never counts), **and either S still holds that rank now, or an
   effective revoke of S ratifies it** (lists its signature, with s before that revoke's cutoff).
   So a revoked key gains nothing by backdating: what it signs after its revoke, dated before its
   cutoff, is not ratified and its signer no longer holds rank.
4. A grant G by S confers G's role if step 3 holds and, unless G is ratified, S holds at least G's
   role at T as well (§6.6's cascade). A ratified grant keeps conferring after its grantor's
   revoke.
5. A revoke R by revoker Q clears N to `participant` if step 3 holds for R and Q's rank is at least
   `validator`, and at least the role being cleared, **at every time from R's cutoff to R's signed
   time** (roles change only where some record's time is crossed, so it is checked at each of those
   breakpoints in that span): a revoker reaches back only over time it was itself authorised for. An
   effective revoke is one for which this holds; only an effective revoke ratifies.
6. A rank is 0 when the resolved node already sits at the delegation depth (8, draft spec PR #36).
   Cycles and chains that do not reach the anchor confer nothing.

Every time in the rule is a signed time, or now. Nothing depends on when a node received a record.

**Attestations.** An attestation's signer counts with its role at the attestation's signed time,
under step 3: if it no longer holds that role now and no effective revoke of it ratifies the
attestation (by its signature), it counts as `participant`. An attestation dated before the attested
record's signed `createdTimestamp` is refused where the record is known (it attests to what did not
yet exist).

---

## 7. Who a failed signature is charged to

**Why.** A statement relayed on a session (a record, an attestation, a checkpoint, a witness, a
grant) is verified under the receiver's binding for its signer, and bindings are local views: the
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
