# sym 0.14.0: wire elements that need spec text

These are the four wire elements that sym 0.14.0 (Core Secure) sends and that MMP v2.0 does not
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
  `verified-record` event and on the stored entry).
- Nothing about the record's authority or verification changes. `cmb-anchors` never causes a
  record to be accepted.

---

## 2. `mesh-room-join`: presenting a room-join grant after the handshake

**Why.** A gated room (§5.8.1) admits a non-owner only on a room-join grant whose `granteeKey` is
the key that the session proved. The v2.0 handshake transcript has no field for the grant, and a
grant carried in a hello would be replayable. So the grant is presented inside the confirmed
session, where it is bound to the proven key.

**Frame** (sealed control frame):

```json
{ "type": "mesh-room-join",
  "grant": {
    "type": "room-join", "room": "<room>", "grantee": "<grantee nodeId>", "granteeKey": "<43-char base64url>",
    "grantedBy": "<owner nodeId>", "grantedAt": 1786611600000, "expiresAt": 1786698000000,
    "sigAlg": "ed25519", "sig": "<unpadded base64url>" } }
```

**Signing.** `grant` is the existing room-join grant, signed by the room owner's identity key
over:

```
UTF8("mmp-room-join-v1\n") || lp(room) || lp(grantee) || lp(granteeKey) || lp(grantedBy) ||
lp(decimal(grantedAt)) || lp(decimal(expiresAt))
```

The lifetime is at most 24 h (`expiresAt − grantedAt`). The frame itself is sealed and adds no
signature of its own.

**When it is sent.** A node that holds a grant for its room sends this frame as the first frame
after both proofs validate (and after its own key-registry check of the peer). It is sent to
every newly confirmed session, before any other control frame.

**Receiver** (a gated room):
- A newly confirmed session is held in `pending` admission. The owner, recognised by its pinned
  key, is admitted at once. Any other session waits for a `mesh-room-join` frame, for up to the
  handshake timeout (10 s), and is refused if none arrives.
- The grant is verified against the owner's pinned key for this room. It must name the session's
  proven nodeId as `grantee`, its proven key as `granteeKey`, and this node's room, and it must
  not have expired. Then the session is admitted, otherwise it is refused (closed).
- A copied grant presented on another key's session is refused. A `mesh-room-join` on an
  already admitted session is ignored. In an ungated room the frame is ignored.

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
  fields only (`type, grantee, role?, grantedBy, grantedAt, granteeKey?, sig, sigAlg`). They are
  ordered top-down: each record comes after the records that root its grantor, up to the anchor
  (depth at most 8). For each named grantee the answer holds the records the server holds whose
  grantee it is, each preceded by its grantor's chain.

**Signing.** Neither frame is signed. Each grant in `grants` keeps its grantor's signature
(§6.5) and is verified as gossip is: top-down, against the key that the chain vouches for its
grantor, or the anchor's configured key. Its authority never comes from the session that served
it.

**When they are sent.**
- A node sends `role-chain-fetch` when a role grant or revoke that arrived on a session is refused
  as `unknown-grantor-key` (no chain reaches its grantor) or `unrooted`.
  - It sends at most one fetch in flight per (session, grantor). Further early records for the
    same grantor join the fetch already in flight.
  - The early record is held in memory only for that fetch, under a key made of every signed field
    plus the signature, so a forged copy cannot displace the genuine one. At most 64 records are
    held per session. A held record is never written and never relayed.
- A node answers `role-chain` for each fetch it receives, paced per session by a token bucket of
  4 a second (burst 16). Fetches past that are dropped and counted.

**Receiver of the answer.**
- Reads an answer only if it matches a fetch in flight on that same session. An answer that
  nobody asked for, or that arrives on another session, is ignored.
- Offers the grants to its store until a pass stores nothing, so their order does not matter.
  Each goes through the ordinary ingest: the gossip budget, verification with the vouched key,
  storing as its signed fields only, and relaying once.
- Then offers each held record once more and drops it either way. Neither the answer's grants nor
  the held records start a further fetch.
- A fetch that is not answered within 10 s, or whose session closes, releases its held records.
  They are dropped.

---

## 4. Relay `error` 4404: "unknown session"

**Why.** A relay session is bound to the relay `from` (draft #23). When a peer restarts behind the
relay, the relay replaces its connection (4004) and, since sym-relay 0.5.4, sends no
`relay-peer-left`. The other node still holds the old confirmed session and cannot tell the
restart from a repeated announcement. Re-handshaking on every announcement would only supersede
working sessions (0.13.17 re-review A2). So the peer's new process says that it holds no such
session.

**Frame** (a plain MMP error frame §7.2, sent as a relay envelope payload; it cannot be sealed,
because the sender has no session to seal it under):

```json
{ "type": "error", "code": 4404, "message": "unknown session", "detail": "session:<32 lowercase hex>" }
```

- `detail` names the sessionId when the triggering frame carried one (a sealed frame), and is
  absent when it did not (a `ping`).

**When it is sent.** A node that receives, from a relay `from`, either a `cmb-encrypted` or
`control-encrypted` frame naming a session it does not hold, or a `ping` from a `from` it holds
no relay session with, answers with this error. It answers at most once a second per relay
`from`, to bound the reply rate.

**Receiver.**
- If it is the client for that peer (the smaller nodeId, §5.2.2), and the peer is present on the
  relay, it starts a new handshake. It **keeps** the session it has until the new one confirms
  and supersedes it, so a restart produces no `peer-left`.
- The server ignores the error: the client will re-handshake.
- 4404 never tears a session down on its own. Like every error frame it is informational (§7.2):
  at most it prompts a new handshake, and only the new confirmed session replaces the old one.

**Probe.** A node that sees a repeated announcement (`relay-peer-joined`, `relay-peers`) for a
peer it holds a live relay session with does not re-handshake. It sends a `ping` on that session,
at most once a second. A live peer answers `pong`; a restarted one answers 4404.

**Code space.** 4404 sits beside the relay close codes (§4.4.9) but is an error-frame code between
endpoints, not a relay close code. 4400 is sym's error code for "session closed: <reason>",
which a node sends to its relay peer when it closes a relay session. Both should be registered,
or renumbered in the 1xxx connection-level range, when #23 is finalised.
