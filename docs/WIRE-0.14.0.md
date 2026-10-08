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

**When it is sent.** To every admitted session, first: with the keys of the records about to be
replayed (at most once a minute per peer), or with `keys: []` when none follow. It goes immediately
before the replayed records, which follow it on the same session as ordinary `cmb-encrypted`
frames. Only records the sender itself authored are replayed (anti-echo, §15.7), and only signed
`mmp-sig-v2.0` records. Because it is always sent, it is also the first authenticated frame a relay
client hears from its server on a new session: a client that re-handshakes while it holds a
confirmed session keeps the old one until the new one carries a sealed frame from the server (it
cannot otherwise know the server took its `client-finish`), and closes a new one that hears nothing
within the handshake timeout (`unconfirmed-by-peer`). (0.14.0 used `role-digest` for this until
§6.6 retired it; with no anchor pinned there is no `authority-digest` to send.)

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
- **The cost of a new key (§6.6.12).** Every statement a session delivers spends that peer's gossip
  lane before it is checked: one check, plus 16 for each key it names that this node has not seen
  (a grant's subject key; the signing key, when it will be verified; pinned keys an anchor-level
  statement's entries name). Rules 1 and 2 of §18.3.2 cost one scalar multiplication for a new key,
  about fifteen signature checks here. A statement not of the schema's shape, and a repeat of one
  held, cost nothing. Unsolicited statements over the lane are dropped (a pull brings them later);
  an answer to this node's own fetch or pull is never dropped: its cost is charged as a debt, and
  the next page is asked for only once the debt is repaid.
- **Pulls.** An unanswered page is asked again from the same cursor, up to 3 times. A digest that
  arrives during a pull is remembered, and if the roots still differ when the pull ends, the pull
  starts again.
- **Persistence (§6.6.8).** Held statements are written as their canonical members only, to
  `authority/statements-<pin digest>.jsonl` in the node's directory: a statement means something only
  under the pin it was verified against, so a node started under another pin reads another file and
  leaves this one as it was. At load every statement is verified again, chain by chain, and the set
  resolved afresh; no status, root or receipt time is stored.
- **Scopes (§6.6.2).** A scope's namespace is implemented by an extension. sym implements none by
  itself: a host passes `authorityScopes: { <namespace>: (path, cmb, scope) => boolean }`, judged on
  the CMB's own signed fields. Where a namespace is not implemented a scoped grant is still resolved
  (it counts toward quotas and roots), and confers nothing on any CMB.

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
failures in a minute for one signing key, that session's statements under that key are dropped
unread for the rest of the minute.
