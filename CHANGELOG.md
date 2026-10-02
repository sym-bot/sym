# Changelog

## 0.14.0 (unreleased)

A minor version because one change breaks readers outside sym: the store's annotations moved from
the stored record to the entry (see Changed). It includes 0.13.15 and 0.13.16 (the witness-storm fix and
its follow-ups).

Fixes from the MMP 2.0 conformance audit's open findings, the 0.13.12 known limits, the Windows test
debt, and the daemon's log flood. Every item has a test that fails without its fix.

### Fixed — security

- **A relay could replay a signed directed record.** The directed de-duplication mark was the raw
  base64url signature or the carried `assertionId`. Base64url decoding ignores padding and the
  unused bits of the last character, and no signature covers `assertionId`, so a relay could
  re-spell either and make one signed directed record surface again and again. The mark is now
  the hash of the decoded signature bytes.
- **A peer could vouch for a v2.0 record by signing it under another node's id (B-R4).** A
  published v2.0 record (mmp-sig-v2.0) signs its author's node id, but it was verified against the
  key of whichever peer delivered it. It is now verified against the key held for its
  `createdByNodeId`, so a genuine relay also verifies. A v2.0 record whose carried `assertionId`
  is not the one its preimage yields is refused (B-R6). On other suites a carried `assertionId`,
  which nothing signs, is dropped.
- **A record signed for another room or another node was stored.** The audience check (§18.3.1)
  ran only on the older suite's direct path: a verified v2.0 record returned before it, and so did an
  older-suite record verified against its author on relay, so a record its author addressed to
  another node, or signed for another room, was stored, remixed and gossiped by every node it
  reached. Every signed record's `room` and `to` are now checked, on every path, whether or not its
  signature could be verified here, and a record addressed elsewhere is refused before it is stored
  or surfaced. Each refusal is counted (`cmb-audience-rejected`, with `verified`) and said once a
  minute per peer and reason.
- **Stripping the frame's `directed` flag turned a signed directed CMB into a broadcast (B-R8).**
  A signed addressee could only veto directed treatment. When the author signed one, it now alone
  decides.
- **Unauthenticated gossip could repoint a phone's wake token.** Any room peer's `peer-info` could
  overwrite a wake channel the phone had given this node itself. A channel learned from a weaker
  source (gossip < relay < the peer itself) now never replaces a stronger one's token. A channel kept
  by an earlier release, which recorded no source, ranks with the relay: gossip cannot repoint it.
  At most 1024 channels are kept (gossip only ever displaces gossip), and one `peer-info` frame is
  read for at most 256 entries, so fabricated node ids cannot grow the map, its file or the gossip
  this node sends.
- **A frame whose handling threw ended a relay-connected daemon.** The LAN path caught a throw from
  frame handling, but the relay path had nothing above it, so the exception reached the process. A
  frame that throws is now dropped with a log line and a `frame-handler-error` metric. A record that
  declares the v2.0 suite but has no buildable preimage is rejected as a signature mismatch.
- **A record with no room was admitted in every room it was replayed into (B-R10).** A record that
  names no room is now in the literal room `default` (§7). `createCMB` names `default` instead of
  null (which signed the string `"null"`), and the v2.0 preimage refuses a record without a room.
- **A record that could not be signed was sent unsigned (B-R12).** `remember()` now throws `ESIGN`
  before anything is stored or dispatched (§18.3.1). A `MeshAgent` whose node cannot sign says so
  once and stops remixing and observing.

### Fixed — delivery and records

- **An emitter that named no room was admitted and then not heard.** `connect()` and `sym emit`
  without `--room` make no room claim, and a node in a named room admits them, but their records
  named no room, which is the room `default` (B-R10), so that node refused every block. An emitter
  that names no room now authors for the room the node's handshake reply states.
- **Two copies of one record arriving together could both surface (K1).** A key is held in flight
  from the de-duplication check until its SVAF pass settles.
- **A broadcast flood could evict directed de-duplication marks (K3).** They have their own map and
  cap now. A directed assertion is marked by the digest of the preimage its signature covers,
  recomputed on receipt, not by the signature bytes: a hedged Ed25519 signer (WebKit) signs one
  assertion differently each time, and its re-signed copy surfaced twice.
- **`inbox()`'s limit counted acked items (K4).** It counts unread deliveries. Acked ones still come
  back, marked, up to the same limit, and are passed over beyond it, so the limit bounds the reply.
- **The inbox `from` was the author's label whether or not anything proved it (K5).** It is now the
  author when the signature proved who that is, and otherwise the peer that delivered it. The claim
  stays in `author.name`. A v2.0 record verified against its signed node id carries `author.nodeId`,
  even when relayed. `from` is a display label (two node ids can sign the same `createdBy`):
  authorize on `author.nodeId`.
- **Record timestamps ran ahead of the clock after a backward step, and restarted every process
  (K6).** The ratchet starts from this node's newest stored record. After a step back of more than a
  minute, timestamps follow the clock again, with a `clock-stepped-back` metric.
- **Mood values were invented or lost (B-R11).** `valence` and `arousal` are kept only when measured,
  must be numbers in [-1, 1], and a mood given only as numbers keeps them.
- **Records had no size bound below the 1 MiB frame (B-R13).** A category is at most 256 KiB of text
  and the seven at most 960 KiB, and a record is minted only if the frame it travels in fits the
  1 MiB frame bound with its categories sealed for a peer. Text bytes are not frame bytes: JSON
  writes a `"` as two bytes and a control character as six, and the end-to-end seal is base64, a 4/3
  expansion, so a record within the text bounds could be one no transport would carry. In plain text
  the frame bound allows about 766 KiB. An agent id is at most 64 bytes (§3.1.2). `createCMB` throws
  `ECMBSIZE`, and so does `remember()`, before anything is stored or sent, for a record or payload
  that would not fit. These are minting rules. A receiver applies no record bound beyond the frame a
  record arrives in: earlier releases minted larger categories and longer agent ids, and refusing
  them would stop a node hearing such a peer at all.
- **A served v2.0 record no longer verified (B-R9, part).** `cmb-fetch` now serves a record's two
  sections exactly as signed, as a copy: the metadata whole, and each category with its `meta`. Text
  alone dropped the per-category parents the signature commits to, so a record that declared them
  failed verification at the requester.
- **A frame written to a destroyed socket counted as sent (B-D6, residual).**
- **A send that failed for any reason was reported as "not connected".** `sendFrame` and the
  transports returned one `false` for a frame over the bound, a closed socket and a failed write.
  `writeFrame` and the transports' `trySend` now say which (`too-large`, `not-connected`,
  `write-failed`); `sendFrame` and `send` still return a boolean. A directed `remember()` that was not
  sent carries `delivery.reason`, its log line names the reason, and a frame over the bound is counted
  (`cmb-frame-too-large`). `shareWithPeers` counts only the peers a frame reached.
- **Unsigned records are now counted (B-R3, interim).** They are still accepted as unverified for
  interop, but each is counted (`cmb-unsigned-received`) and the sending peer is named once in the
  log, so the emitters a signed-only default would cut off can be found first.

### Fixed — lineage

- **The root walk trusted unverified records (B-L4).** It walks only through records whose address
  recomputes and that this node wrote or admitted as verified. A remix with no verified ancestor in
  reach resolves to no anchor, instead of being anchored to itself, and the result says whether the
  walk was `complete`. The walk is bounded in work as well as in records: at most 64 hops, 4,096
  stored records and 16,384 parent keys queued, and it stops at a bound instead of draining its
  queue. A record can name about 14,700 parents within one frame, and before this the queue grew
  with every long parent list the walk stepped onto.
- **A tether could not be reproduced by another node (B-L5).** It is measured on the stored record's
  text, encoded in one kernel, instead of on vectors blended with local memory.
- **Cold-start admissions had no tether (B-L6).**
- The tether audit's fetch fallback no longer returns a local record the walk had refused.

### Changed — read these before upgrading

- **A stored record is what its author sent, and nothing this node computed.** The store used to add
  members to a two-section record: `admission`, `tether`, `provenance` and `collapsed`, plus an
  expanded top-level `lineage`. The record now stays `{categories, metadata}` as signed (§8.8.1), and
  those annotations live on the store **entry**. The one other member it can carry is the `payload`
  its author sent beside the two sections (as the author's own stored record does): no signature or
  address covers it, so a record that verifies says nothing about its payload, and `cmb-fetch`
  serves the two sections without it. Stored files from earlier releases are read as before and
  moved on first touch. **Code outside sym that reads `entry.cmb.admission`, `.tether`,
  `.provenance` or `.collapsed`, from stored entries or from `cmb-accepted` / `memory-received`
  events, must read them from the entry.** xmesh 0.10.11 reads both places.
- **A record that names no room is in the room `default`, from any sender.** Earlier releases read
  it as addressed to every room. A 0.13.x `connect()` or `sym emit` without `--room` mints exactly
  such records, so a 0.14.0 node in any other room refuses what it sends (`cmb-audience-rejected`,
  `wrong-audience`): a receiver cannot tell a room-less record its author just sent from one
  replayed out of another room. Upgrade the emitter, or pass `--room` (`connect({ room })`) naming
  the node's room.
- **SVAF anchors decay with age (§9.2.1).** The gate treated every stored anchor as fresh at full
  weight, because the anchor view carried neither the entry's age nor its weight. Anchors now carry
  both: `storedAt`, and the store's §6.4 `anchorWeight` (2.0 once validated, 0.5 once dismissed, never
  the sender's unsigned confidence). At the default freshness of 1800 s, an anchor older than about
  nine hours carries no weight. **A node whose recent memory is all older than that admits the next
  block under the empty-memory rule**, as §9.2.1 specifies. The spec discloses what that rule costs:
  while it applies, the §16 influence bound does not cover the node. With decay that window recurs
  after every quiet period of about 18.4 × `freshnessSeconds` (about nine hours at the default), not
  only on a fresh node. `freshnessSeconds` is the dial: a larger value keeps older memory gating.
- **The attestation logs are rotated, and older lines are deleted.** `attestations.jsonl`,
  `checkpoints.jsonl` and `witnesses.jsonl` (in the node's `attestations/` directory) only ever grew.
  Now a rotation replaces each live log with the records the store holds and moves the old log, whole,
  into `attestations/archive/`. `archive/` keeps at most 128 MiB per log, **its newest archive
  included**: the oldest go first, and an archive larger than 128 MiB on its own is deleted. **What
  stays on disk is the records the store holds (50,000 attestations, 32 checkpoints for each of 1,024
  attesters, 50,000 witnesses), the lines appended since the last rotation, and as many of the most
  recent archived logs as fit in 128 MiB per log. Anything older is deleted.** On the first start, a
  log already over its budget is rotated at once: the storm's 257 MB `witnesses.jsonl` is archived and,
  being over 128 MiB, deleted.

### Fixed — SVAF and the store

- Anchor vectors are measured through a side map and are never written onto stored records, where a
  later save persisted them.
- A vector is cached under the kernel that produced it. When the semantic encoder finished loading
  during a gate, lexical vectors were cached under the semantic key.
- The neural admission path applies the §15.8 tether exactly as the heuristic path does, through the
  same helpers. It stores a copy, never the caller's record. When a carried address did not match
  the content, it now mints this node's own remix, as the heuristic path does; before, it rewrote the
  author's record under the author's name with a signature that no longer covered it.
- §15.8 severance no longer edits a signed record (that broke the author's signature). Severance is
  recorded on the entry and in the lineage index, and every reader of stored lineage honours it:
  the anchor walk, an index rebuild from disk, the tether audit, and mesh-agent's remix check.
- The tether audit reads the store's lineage, not an `ancestors` list a sender chose, and never
  fetches a local record the walk had refused.
- A frame cannot supply `admission`, `tether`, `provenance`, `collapsed` or `svaf` that this node
  would then store as its own.
- The semantic encoder no longer starts a second model load while the first is loading.
  `semanticSettled()` resolves when it is ready or has failed.

### Fixed — the attestation logs

- **The logs are rotated (0.13.15's known limit).** A log is rotated once the bytes in it beyond the
  records the store holds (appended since its last rotation, then evicted or superseded) exceed the
  larger of 8 MiB and the bytes of the records it holds. So a rotation always reclaims more than it
  writes. It is never followed by another until that much more has been appended and dropped: a held
  set larger than 8 MiB does not make every append rotate. A start applies the same rule to the log as
  it finds it, so a node does not rotate on every start. Rotating a full attestation log (50,000,
  ~27 MB) took about 100 ms here.
- **A rotation cannot lose the live log.** It writes the records held to a temp file, checks every
  byte reached the file (a write may be short) and fsyncs it. It then hard-links the old log into
  `archive/` as `<log>.<sequence>.<time>.<pid>.jsonl`, never over an existing name, or copies it where
  the filesystem has no hard links. Only then does it rename the temp file over the live log, so the
  live path holds a complete log at every instant. A failure at any step removes what the rotation
  made (no archive name is left on the live log), leaves the live log as it was, is logged once per
  distinct error, and is retried after another budget. A start removes what a crashed rotation left
  behind. Archives are pruned in sequence order, not by file time.
- **A rotation keeps everything held:** every attestation, checkpoint and witness the store holds;
  each conflicting checkpoint copy for a held position, so a restart still reports the conflict; and
  this node's memory of the checkpoints it witnessed itself (one line per attester), so it still signs
  a witness once across restarts. A witness waiting for its checkpoint stays in memory only, as before.
- **A start reads all of each log.** A record can stay held at the head of its log while newer ones
  churn past it: a quiet attester's attestations or checkpoints, a quiet position's witnesses. So each
  log is read whole, up to twice what its caps hold: 68.7 MiB for attestations (50,000 at 720 bytes;
  measured ~520), 28 MiB for checkpoints and 47.7 MiB for witnesses, 144 MiB in all. 0.13.16 read at
  most 112 MiB but only the newest part of each log, which could miss a quiet attester. On logs over
  every budget, reading them took 0.8–0.9 s here against 1.0–1.4 s for 0.13.16. A first start that
  also rotates all three took 1.0–1.3 s, once; the next start took 0.25 s.
- **One attester cannot flush another's chain.** The 50,000-attestation cap was one queue across all
  attesters, so one attester signing many attestations pushed every other attester's chain out, and
  the omission evidence with it. Now, when the store is full, the attester holding the most loses its
  oldest. Each attester keeps its newest up to its share (50,000 / attesters held), and never fewer
  than 48: at most 1,024 chains are held, and a new attester takes the place of the one updated least
  recently, never this node's own.
- **A conflict on a held position is remembered as long as the position is held.** 0.13.16's
  32,768-entry list also counted positions already dropped, so another attester's conflicts could push
  out the mark of a position still held.
- **A dropped position is unlisted in O(1).** Each checkpoint dropped searched every witnessed
  position (up to 32,768) for its own; the positions are now indexed by key, and the witness cap takes
  the oldest from the head.

### Fixed — attestation gossip is budgeted, per peer and per attester

- **A peer's new statements are budgeted (0.13.15's other known limit).** The attestations,
  checkpoints and witnesses one peer delivers may make this node check at most 2,000 new statements a
  second, after a burst of 10,000. Past that a frame is dropped before its signature is checked, so no
  peer buys more signature checks than that (~40 µs each: under a tenth of a core). Attestations are
  covered as well as checkpoints and witnesses.
- **Only a new statement spends it.** These are dropped first, for nothing: a repeat (an attestation
  whose signature is held, however it is spelled; a checkpoint or witness held, waiting for its
  checkpoint, or already refused as a conflict), a checkpoint older than every position held, an
  unsigned frame, and a frame whose signer's key this node does not hold.
- **Sized above a busy room.** A room of R nodes, each gating G CMBs a second, makes R·G
  attestations, R·G/8 checkpoints and R·G/8·(R−1) witnesses a second: 640 at R = 32, G = 4. Only the
  first copy of a statement is new, so a peer spends the budget only for what it delivers first:
  about what it signs itself (~20 a second there), and at most all 640 when it is this node's only
  path to the room. 2,000 is three times that. `gossipBudget: { perSecond, burst }` changes it.
- **A forged frame spends only its sender's budget.** The budget is the delivering peer's, never the
  claimed signer's. A peer that floods forgeries loses its own frames while it floods, and no one
  else's. An honest peer relays only what it has verified, so its budget is never spent on forgeries.
  A dropped frame is not marked seen, so the same statement from another peer is taken. The budget
  refills, so a peer that stops flooding is heard again.
- **A drop is attributable.** A `gossip-over-budget` metric (`fromPeerId`, `from`, `dropped`,
  `frames` by type, and up to 16 `authors` whose statements were dropped) and one log line name the
  peer, at most once per 10 s per peer: the first drop at once, the rest when the 10 s close, so every
  drop is counted (`gossipOverBudget` in `metrics()` keeps the total). A gap it leaves is told apart
  from an omission by the attester. Budgets are kept for at most 4,096 peers, the least recently active
  evicted in O(1), without scanning.
- **One attester's checkpoints cannot make the room sign witnesses without end.** Each checkpoint a
  node takes costs every node in the room a witness signed, gossiped and verified. The per-peer budget
  bounds what one peer delivers, not what one attester signs: an attester sending new checkpoints
  through every peer at once had every node witness each one. A node now takes one attester's new
  checkpoints at most at 4 a second, after a burst of 128, whichever peer brings them. The rate is
  spent after the signature is checked, so only that attester spends it. Past it a checkpoint is not
  stored, witnessed or relayed; it is counted (`checkpointsOverRate` in `metrics()`) and said once per
  10 s (`checkpoint-over-rate`, naming the attester and the peers that brought it). An attester commits
  a checkpoint every 8 attestations: 0.5 a second in the busy room above. 4 a second is 8× that, and
  the burst holds 1,024 attestations gated back to back. A second root for a position already held is
  still recorded as a conflict. `checkpointRate: { perSecond, burst }` changes it.
- **Only the spelling a signer writes is stored.** Base64url decoding ignores padding, whitespace and
  stray characters, so one signature could be spelled any number of ways that all verify. Each spelling
  was stored and relayed as a new attestation. The chain hash and the Merkle root are computed over the
  signature as written, so a re-spelling that arrived first made its attester's chain look broken. A
  gossiped attestation, checkpoint or witness whose signature is not 64 bytes in unpadded base64url is
  now refused before anything is spent on it. It is counted (`signaturesNotCanonical` in `metrics()`)
  and said like a budget drop (`signature-not-canonical`). A re-spelling of an attestation already
  held is a repeat. Every signer sym knows writes the canonical spelling, and this node checks its own
  before recording one.
- **A dropped attestation is logged once a minute per peer and reason, with a count.** It was logged
  once per frame, and one naming a signer whose key is not held is dropped before any budget.

### Fixed — dependencies

- `npm audit` is clean. Floors are raised past the vulnerable versions, because `overrides` do not
  reach a consumer's install: `ws` `^8.20.2`, `@huggingface/transformers` `^4.3.0`, and `sharp` and
  `adm-zip` as overrides.

### Fixed — the daemon

- **The log flood.** Every peer re-sends its whole wake-channel list on every connect, and the
  receiver logged a line and rewrote `wake-channels.json` per entry per frame, so the daemon's
  `stdout.log` reached 1 GB of `learned wake channel for unknown`. A repeat now changes nothing and
  logs nothing; a frame that does teach something logs one line. Channels carry the time of the last
  first-hand sighting (gossip forwards it instead of the time of sending) and expire after 30 days
  unseen. A channel saved before this release gets one 30-day grace period, once.
- **A daemon rooted with `SYM_STATE_DIR` kept its room, tasks and relay.env in `~/.sym`.** It uses
  the state root now, and so does the `sym` CLI: its pid file, room, relay.env and node directory.
  Two rooted deployments sharing a home shared one pid file, so `sym stop` for one stopped the other.
- **A second daemon start took the socket from the one serving it.** The daemon removed any socket
  file at start, assuming it stale, so a second start unlinked a live daemon's socket; that daemon
  ran on, reachable by no client, and every client reported "sym-daemon not running". A socket file
  is now removed only when nothing answers on it (otherwise the second start exits), a daemon
  removes only its own socket at shutdown, and a daemon whose socket file is removed listens on it
  again within 30 s.
- **A daemon IPC request whose handler threw went unanswered.** It is answered with the error, and a
  refused `remember` carries the SDK's code (`ECMBSIZE`, `ESIGN`).
- **A relay-only daemon still announced its room on the LAN.** It no longer does.
- **IPC on Windows.** The daemon and every client now resolve the IPC endpoint one way, and on
  Windows a file path becomes a named pipe. `SymDaemonClient` defaulted to `/tmp/sym.sock`, which no
  daemon listens on (every OS).
- **Windows lock checks.** A live pid's start time is cached until the pid is seen dead, and several
  pids are read in one PowerShell call. A mismatch is re-read before a lock is reclaimed.
- The daemon reports a failed IPC command as that command's error instead of a parse error.

### Fixed — tests and conformance

- **A test node can no longer reach the real `~/.sym`.** Under the Node test runner, a `SymNode` (or
  the daemon) throws `ETESTHOME` when its home, state root or identity dir is outside the temp dir.
  `SYM_TEST_REAL_HOME=1` opts out. **This affects other projects:** a suite that builds a `SymNode`
  under `node --test` with the real HOME now fails until it sandboxes HOME and USERPROFILE.
- The published v2 conformance vectors are consumed verbatim, with their errata, plus a new
  application-v2 test. The handshake transcript and AAD normalise room and names to NFC, as the
  reference does (B-R17).
- Windows test debt is fixed. The SIGTERM lock test is skipped on Windows, with a hard-kill reclaim
  test on every platform. The lease test uses a live foreign holder with a real start time; it never
  reached the start-time check before, on any OS. The relay-only test uses the platform's IPC endpoint.
- Admission-as-collapse (B-L3) is pinned by a test: the conformance boundary of spec PR #17.
- Tests wait on what they test instead of fixed sleeps: in-flight frames, and the encoder's own load.

## 0.13.16 (2026-10-02)

Follow-ups to the 0.13.15 witness-storm fix, from its last review.

### Fixed

- **The checkpoint log is read at start up to what its caps hold** (32 checkpoints for each of 1,024
  attesters, 16 MiB), not 8 MiB.
- **A waiting witness that signs a second root is a conflict**, surfaced once, as it is for a stored
  one; it was taken for a duplicate.
- **This node remembers a witness it signed even while that witness waits** for its checkpoint or is
  refused. One its position is too full to hold is still written to the log, so after a restart the
  node knows it signed it and does not sign it again.
- **A conflict on a held position is remembered as long as the position is held**, so the conflicting
  copy is appended and reported once; a position that is dropped takes its mark with it.
- **A waiting witness read from the log is not appended to it again** when its checkpoint arrives.
- **Peer-info gossip no longer floods the log.** Every peer re-sends its whole list on every connect,
  and each frame logged one line per entry and rewrote the wake-channel file, so a daemon's log
  reached 1 GB. Only a channel that changed is set and saved, with one line per frame, and a frame is
  read for its first 256 entries (a longer one is said). The relay's peer list, sent on every connect,
  is handled the same way. (Which source may replace a phone's token is fixed in 0.14.0.)

## 0.13.15 (2026-10-01)

A hotfix for one fault: the witness storm. Every node should take it: a node keeps relaying the
storm until it runs this release.

### Fixed

- **Two signed copies of one witness were relayed by every node without end.** A node that
  witnessed a checkpoint again after a restart signed a second copy of the same statement. The store
  kept only the latest copy per witness, so each copy was new whenever the other arrived, and every
  node stored and relayed it again. On one host this grew one node's `witnesses.jsonl` to 625,079
  lines (257 MB) of two witnesses, and kept every node in the room busy relaying them. A checkpoint
  is now held once per (attester, position) and a witness once per (attester, position, witness): a
  later copy is a duplicate and is not relayed. A node witnesses a checkpoint once, across restarts.
- **A second root for a held position is a conflict.** It is not stored or relayed; the first copy
  stays held. The first time a checkpoint position conflicts, the conflicting copy is appended once
  (so a restart re-derives the conflict), an `attestation-conflict` metric names both roots, and
  `reconcileChain` reports `conflicted: true`, so an attester that signed two roots (by
  equivocating, or by restarting its chain after losing its log) is told apart from tampering. A
  witness that signs a second root raises the same metric (`kind: 'witness'`).
- **A position is an integer.** The signed payload spells a position as text, so `8` and `"8"`
  verified alike and a replayed checkpoint could be stored under many positions; a position that is
  not a non-negative integer is refused, before any signature check.
- **Repeats are cheap.** An attestation, checkpoint or witness already held is dropped before its
  signature is checked.
- **A witness is kept only for a checkpoint this node holds.** One that arrives first waits in memory
  (at most 2,048) until its checkpoint does, so no peer can grow the witness log with positions
  nobody committed. A node also remembers the checkpoints it witnessed itself, so it signs a witness
  once even after its witness index has dropped it.
- **Checkpoints and witnesses are bounded.** At most 32 checkpoints per attester (dropping the oldest
  with its witnesses), for at most 1,024 attesters, and 256 witnesses per checkpoint (50,000 in all,
  the oldest checkpoints' witnesses dropped first).
- **An oversized attestation log is read from its newest part only.** Each log is read at start up
  to a budget that covers what its cap holds (attestations 64 MiB, witnesses 32 MiB, checkpoints
  8 MiB); reading the whole of one grown by the storm held a node's thread for minutes. The logs are
  append-only and are not rewritten: one grown by the storm keeps its size on disk, and stops growing.

### Not in this release

The logs are still not rotated, and gossiped attestations still have no per-peer budget beyond the
existing per-(CMB, attester) limit (whose table now drops closed windows); both are planned for
0.14.0.

## 0.13.14 (2026-10-01)

### Added — a peer's admission verdict is observable as it lands (`attestation-received`)

A receiver signs an Admission Attestation for every CMB it gates and gossips it to the room. Until now the
author, or anything watching the mesh, could see those verdicts only by polling `attestationsFor(cmbKey)`.
The node now emits `attestation-received` the first time it verifies and records a peer's attestation.

Fields covered by the attester's signature, passed on as signed:

- `of` (the gated CMB key), `by` (the attester's nodeId), `at`, `roster`, `seq` and `prev` (its place on the
  attester's hash chain);
- `verdict`, and `categories`: the seven CAT7 fields (focus / issue / intent / motivation / commitment /
  perspective / mood), each carrying one of admit / guard / redundant / reject / silent, as the strings the
  signature covers. Any other key in the frame is unsigned and dropped;
- `role`, the role the attester claims. A node can stamp any role and still sign validly;
- `sig` and `sigAlg`, so a consumer holding the attester's key can re-check the event with
  `verifyAttestation(event, key)` instead of trusting `verified`.

Fields this node adds, which the signature does not vouch for:

- `verified: true`, and `keySource`, where the verifying key came from: `anchor`, `grant`, or `handshake`. A
  `handshake` key is trusted on first use: it belongs to whoever completed the handshake under that nodeId;
- `roleResolved` and `roleMatches`, the role this node's grant chain resolves for the attester, and
  `roleClaimed`, the claim `roleMatches` compares against (`participant` when the attester stamped none).
  Both are compared as strings, the form the signature covers, so a claim that signs identically matches
  identically.
  Weight a verdict by these, not by `role`;
- `methodUnsigned`, the evaluation method (`heuristic` / `neural`). It is outside the signed bytes, so a relay
  could have changed it;
- `byName`, the name the attester announced when it connected, only when it is a direct peer. It is a label,
  not an authenticated name: `by` is the identity;
- `from` / `fromPeerId`, the peer that delivered the frame, and `relayed`: true when that peer is not the
  attester, false when it is, null when the deliverer is unknown;
- `receivedAt`, this node's clock, not the attester's `at`.

A duplicate, a rate-limited copy, a roster mismatch, an unknown attester or a bad signature emits nothing.
Neither does this node's own verdict: read that from `svaf-decision` or `attestationsFor()`.

The event holds only primitives and is frozen. A field the attester filled with an object is given as the
string its signature covers, so a listener cannot change the stored record or what the next listener sees.
Each listener is called on its own, in registration order, from a snapshot taken when dispatch starts. The
calls are synchronous, on the frame-ingest path: gossip to the room has already gone out, but a listener that
blocks delays this node's next frames, so hand heavy work to a queue. A
listener that throws (any value), or an async listener whose promise rejects, is logged with the attestation
it was handling. It does not stop later listeners, undo the ingest, or become an unhandled rejection. An event
that cannot be built is reported on `metric` as `attestation-event-dropped`. That one metric is delivered to
each `metric` listener the same isolated way, not through `emit()`, so code that wraps `emit` does not see it.
The attestation is still recorded. With no listener, none of this work is done.

## 0.13.13 (2026-10-01)

### Fixed — a crashed Windows session no longer locks its node name until reboot

The identity lock records its holder's process start time, so a later start can tell a live holder from an
unrelated process that reused the holder's PID. On Windows the start time came from `ps`, which does not
exist there, so no start time was recorded. After a crash or a hard-killed terminal, once Windows reused the
PID, the name stayed locked (`EIDENTITYLOCK`) for the rest of the boot.

- **Windows start time.** Windows now reads the start time through the system PowerShell, by absolute path,
  as UTC ISO-8601. The lock writer and a later reader use the same form.
- **Caching.** Results are cached for 10 s per PID. A daemon checking many node directories held by one
  process therefore pays one lookup, about 0.45 s on Windows, measured.
- **Failed lookups.** When the start time cannot be read (no PowerShell, a timeout, access denied), the lock
  is treated as held, as before, and the process warns once. A failed lookup of the node's own start time is
  retried at the next acquire instead of being remembered.

Limits:

- A lock written by 0.13.12 or earlier carries no start time, so it can still only be cleared by a reboot or
  by deleting `~/.sym/nodes/<name>/lock.pid`. Guessing from the file's timestamp was considered and dropped:
  a clock step could make a live holder look stale, and a live holder must never lose its lock.
- Locks written from 0.13.13 on are covered.

## 0.13.12 (2026-10-01)

Fixes from an MMP 2.0 conformance audit of sym-mesh-channel and the SDK it runs, revised after an independent
review of the first cut. Every bug listed here has a test that fails on 0.13.11.

### Fixed — a directed CMB always reaches the agent it was sent to (MMP §9.2.2)

§9.2.2 says a CMB addressed to this node surfaces regardless of the SVAF verdict. Three paths dropped one anyway:

- A directed reply citing one of the receiver's own CMBs as its parent was skipped as an echo.
  - A reply its author signed to this node (the signed `metadata.to`) is now processed normally.
  - A reply only the unsigned frame calls directed is delivered once (`decision: 'echo'`) but never admitted,
    stored or remixed, so no peer can reopen the §14 ping-pong.
  - A verified record that signs a different addressee, such as a signed broadcast with a forged frame, is not
    treated as directed. One that signs no addressee field at all is judged by the frame.
- Receive-path de-duplication used the content key for seven days, so a new directed send of words this node had
  already seen (a repeated "please review", or the same text earlier as a broadcast) never surfaced. A directed
  CMB that verifies is now de-duplicated on its assertion identity, or its signature until records carry
  `assertionId` (§8.8.2). A replay of the same signed record is still suppressed. A record that does not verify
  keeps the content key, so no unsigned field can widen the key.
- A directed CMB SVAF admitted, but whose key the store already held, surfaced nowhere. It now surfaces as
  delivered-not-stored (`remixed: false`), with `decision: 'redundant'`, or `'not-stored'` when the store's
  write failed. The rest of the admitted path runs as before, for directed and broadcast CMBs alike.

A rejected directed CMB with a non-neutral mood still delivers its mood on the separate §9.3 channel
(`mood-delivered`) as well as surfacing.

### Fixed — admission no longer re-authors a peer's record (MMP §8.8.4, §15.2)

When an admitted CMB added nothing new, the receiver stored it at the author's address but with `createdBy`
set to the receiver, a fresh timestamp and no signature, and served that record to anyone who fetched the
address. The author's record is now kept as signed, on the heuristic and the neural path:

- its categories: text, each category's signed `meta`, and the mood's valence and arousal (which no signature
  covers); fields the record format does not define are dropped;
- its metadata, signature and lineage.

The stored record verifies under the author's key. A pre-boundary record (§7.8) cannot be kept as signed in
that shape, but its author name is kept.

### Fixed — a directed send reports what happened to it

- A directed send of the same words as the node's latest CMB, or of a record already stored, used to send
  nothing (returning `{collapsed: true}` or `null`). It now sends the freshly signed record to that peer, a new
  assertion that the peer surfaces, and carries the same `delivery` result as any other send.
  - The already-stored case returns an entry built from the caller's record, with `duplicate: true`. When the
    store's write failed instead, it returns `duplicate: false, persisted: false`.
  - A caller-supplied `opts.cmb` that collapses cannot be re-signed, so it is not sent. Its `delivery` says
    `undelivered`, with a reason, and the record is returned unmodified.
- A node's own records get strictly increasing `createdTimestamp`, so two sends of the same words in one
  millisecond are still two assertions.
- A record that collapses onto HEAD is re-signed after its self-edge lineage is cleared, so what is returned or
  sent still verifies.
- `delivery.dispatched` counted frames handed to a closed socket or an unopened relay. Transports now return
  `false` from `send()` when the socket is closed, the relay is not open or the frame exceeds 1 MiB, and only
  accepted frames are counted.

### Fixed — malformed frames (MMP §4.1, §19.1)

- One malformed frame (a bad length, invalid JSON or `null`) cancelled the 10-second inbound identification
  deadline, so an unauthenticated connection could stay open indefinitely. Only a handshake or a close clears
  it now.
- A zero or oversize length prefix left the parser reading payload bytes as the next length. It now stops
  parsing and the TCP connection is closed, as §4.1 requires.
- A relay message `null` threw inside the WebSocket listener and ended the process. Relay messages that are
  not objects, envelopes whose payload has no string `type`, and payloads over 1 MiB are ignored.
- Frames that are `null`, not an object or have no string `type` are discarded silently; invalid UTF-8 is
  rejected instead of being replaced; a handler exception is no longer reported as "Invalid JSON".

### Added — `author` and a shared inbox id on delivered entries

Every `cmb-accepted` entry carries `author: { name, nodeId, via: { name, nodeId } }`:

- `name` is the record's `createdBy` (a display label, not a verified identity).
- `nodeId` is set only when the record verified under the delivering peer's key and names that peer as its
  author; otherwise it is `null`.
- `via` is the peer that delivered it.

The store envelope's `source` (`"<receiver>+<sender>"`) is receiver-local bookkeeping and should not be
displayed as the sender. A `source` field in an incoming CMB frame is now ignored, so it can no longer name
the deliverer. Before, a peer could pose as another peer, or as the receiver itself. Inbox items read `from` from the author.

The inbox listener sets `entry.inboxId` and `entry.inboxSeq` before other `cmb-accepted` listeners run.
`node.inboxAck(id)` marks one item read out of cursor order:

- it stops counting as undrained;
- `inbox()` still returns it, with `acked: true`;
- the ack is persisted.

`inboxStatus()` adds `ackedEvicted` (read items evicted before a drain). `neverDrained` clears only when every
item has been read, and stays set when every item was evicted undrained. `stop()` flushes a pending inbox write, so a drain or an ack in the last second before
shutdown is kept.

### Fixed — validator and anchor admissions are weighted again (§6.4)

The node's wrapper around the store's `receiveFromPeer` dropped its third argument, so the creator role never
reached the store and every admission was weighted 1.0. Validator- and anchor-origin CMBs now enter at 2.0, as
§6.4 and §11.1 specify.

### Changed — relay message bound

The relay WebSocket is opened with `maxPayload` at the frame bound, so `ws` refuses an oversize message before
buffering it, and relay frames dropped for size are logged.

### Tests

- The two integration tests that failed on 0.13.11 were stale, not broken code. `e2e-admission` put its nodes
  in different rooms, which 0.13.11 correctly refuses. `e2e-cmb-path` expected a remix record where content
  addressing collapses onto the author's record.
- Both integration tests now stop their nodes independently in `finally`, so a failed assertion no longer
  hangs the run for 30 seconds.
- `e2e-cmb-path` now requires an admission, not just a liveness bump, and asserts the collapse directly.

Known limits, tracked for a later release:

- Identical arrivals handled concurrently can each pass de-duplication before SVAF finishes the first. This is
  pre-existing and affects broadcasts too.
- A directed CMB surfaced as `not-stored` is not stored on a retry of the same record. It was delivered, and
  the de-duplication mark suppresses the retry.
- Directed assertion marks share the broadcast de-duplication map and its 10,000-entry cap.
- Acked inbox items still count toward `inbox()`'s `limit`.
- The inbox `from` field is the author's unauthenticated label. Authorize on `author.via`.
- The `createdTimestamp` ratchet is per process and unbounded: after a backward clock step, a node's
  timestamps run ahead of its clock until the clock catches up.

## 0.13.11 (2026-09-28)

### Fixed — a dropped network no longer takes the daemon down

The daemon's room beacon (the `_symrooms._tcp` advertisement behind `sym rooms`) was made without an mDNS
error callback, so a failed multicast send, which happens when the network drops (a sleep/wake, an interface
change), was thrown where nothing could catch it: `send EHOSTUNREACH 224.0.0.251:5353` stopped the daemon
three times in September. Discovery's guard against a multicast socket that cannot bind looked for the
socket's emitter where bonjour-service 1.4 does not put it, so it never took effect either. Every bonjour
instance sym makes now reports these failures and carries on (the beacon logs at most once a minute), and
`sym rooms` does the same.

### Fixed — a LAN peer that vanished is dropped, not re-dialled forever

A peer that went away without an mDNS goodbye (killed, crashed, its host asleep) stayed in the reconnect cache
and was dialled every 15 seconds for as long as the node ran: one daemon's log held 8.6 million
"Connect failed" lines. A peer not announced for five minutes now leaves the cache, and its next announcement
brings it back.

### Changed — one exit hook per process

Each discovery added its own `exit` listener to remove its loopback registration on an abrupt exit, so a
process hosting many nodes carried one per node, and Node warned past ten (`MaxListenersExceededWarning`).
One hook per process now cleans up every live registration.

### Tests — discovery tests never touch the host's live registry

The discovery tests registered throwaway nodes in the real `~/.sym/loopback`, and their scans collected the
host's registrations. They now run under a sandbox HOME.

## 0.13.10 (2026-09-28)

### Fixed — a dead node's loopback registration is collected whatever its room

Every node scans the same-host loopback registry (`~/.sym/loopback`) every 5 seconds, and it removed
a dead node's registration only when that node shared its room. A node that ran in a room no live node
remains in (every finished mission's crew, say) left its registration for good: on one host, 516
registrations in 495 rooms, 24 of them live. Every live node re-read all of them every 5 seconds.
A registration whose process is gone is now removed by whichever node scans it, in any room. Room
isolation still decides whom a node dials. A registration whose process belongs to another user, or
that names no process, is kept as before.

## 0.13.9 (2026-09-26)

### Security — the lineage anchor is found from records this node stored

Upgrade every node: the §15.8 lineage tether is on by default, and this changes whose input it
trusts. The tether compares a remix against the earliest resolvable ancestor, and that choice decides
whether the remix keeps its lineage. Two inputs the SENDER controls could make it: the ancestor list
the sender writes into the record, and the author's own unsigned timestamp. The anchor is now found
by walking direct parents through records this node has stored — following each stored record's own
parents, bounded at 64 hops and 4,096 records, cycle-safe — and ranked by the time THIS node stored
them. A parent this node never stored ends the walk there; it is never taken on the sender's word.
This is the resolution `@sym-bot/xmesh-core` already used; the open copy had not been brought level.

### Fixed — admission no longer treats disagreeing memory as empty memory

SVAF decided whether a category could be judged from its similarity-weighted readout, and that sum is
near zero in two opposite cases: nothing in memory carries the category, and everything that carries
it points the other way. Both were read as "no memory yet", so a record that contradicted a populated
store was admitted on the cold-start rule. A small category weight had the same effect.

- Whether a category can be judged is now decided by COVERAGE — how much live memory carries it
  (age-decayed and confidence-weighted), independent of similarity. Coverage fades with age as the
  readout always did.
- Covered but pointing away scores full drift for that category instead of being skipped.
- Category weights no longer enter the per-category readout (they cancelled there); they act only
  where categories are combined, in the aggregate and the redundancy test.
- A weight of 0 now DISABLES a category: it is reported `silent` with cause `zero-weight`, and it
  never makes covered memory count as missing. It used to be read as full weight.
- When memory covers only disabled categories, the record is admitted as `guarded`, not `aligned`,
  with `coldStartCause: 'lens-uncovered'` on the result. An empty store still bootstraps as before.
- Weights that are not finite, are negative, or are all zero are refused with an error naming them,
  rather than replaced by a default. Every shipped weight profile is valid.
- The §15.8 tether excludes a category weighted 0 instead of counting it at full weight.

The matching MMP §9.2.1 text is in review. `@sym-bot/xmesh-core` 0.3.1 carries the same change;
both answer the same 24 corner cases.

### Fixed — a refused node no longer reports "connecting" while it retries

After a relay refuses a node's token (4003), the node keeps retrying at a slow cadence, and the
refusal was meant to stand for the whole episode. Each retry dial relabelled it `connecting` until the
relay refused again, so a status read at that moment hid the refusal. The phase now stays `refused`
until the relay admits the node.

### Fixed — a node starts without reading its whole store first

The memory store read and parsed every file synchronously in its constructor, so a process that
starts several nodes paid for each store in turn before answering anything. `SymNode.start()` now
builds the index asynchronously, in batches that yield to the event loop. Nothing can observe a
half-built store: any read before the load finishes builds the index synchronously, as before, and
the asynchronous result is then discarded rather than merged.

### Fixed — the room-admission door runs in the frame handler the node actually loads

The per-frame admission check had been written into a module no node loaded. It now runs in the live
handler, together with the handshake check that records each peer's verdict. In a room with no pinned
owner — every shipped deployment — behaviour is unchanged: frames from a peer with no verdict pass
and are counted. In a room with a pinned owner, a peer that never presented a grant is refused on
every frame except handshake and ping/pong.

- `node.roomGate()` reports `{ room, gated, owner, admits, why }`. `admits` is what the gate enforces
  today: `anyone`, `grant-holders`, or `nobody`. A gated room currently answers `nobody`, because the
  key-proving handshake is not yet on the connection path, and says so in `why`.
- A room-join grant must record its signer as the room's owner when the caller supplies the owner.
- Downgrade protection names the extensions it protects (`cmb-encrypted-v2`), so a new extension
  must be registered or its absence justified.

### Removed — two modules nothing loaded

`lib/core/frame-handler.js` and `lib/core/svaf-heuristic.js` were never on the running path. Tests
that measured them now measure the live evaluator and handler, including new MMP §9.2 conformance
cases.

## 0.13.8 (2026-09-14)

### Changed — the byte-identity vector check is Node determinism, not conformance

`tests/mmp-v2-signing.test.js` asserted that signing the published payload reproduces the published
signature. That is true under Node and will stay true — RFC 8032 derives the nonce from the key and
the message — but it is NOT a conformance property: Apple hedges in both its implementations
(measured 2026-09-14, CryptoKit: five signings of RFC 8032 vector 2 under one imported key gave five
distinct valid signatures, none matching the published one; WebKit the same on Safari 26.5). A
correct implementation on those platforms fails that assertion, which is why meshcognition.org now
excludes Ed25519 signature bytes from the reproduction requirement. The check is kept as a
regression guard on OUR signer under THIS runtime, renamed to say so, with the conformance property
added beside it: sign the same payload twice and require both to verify.

### Added — relay-only nodes, for hosts with no usable multicast

`sym start --relay-only` (or `SYM_RELAY_ONLY=1`) skips LAN discovery entirely and joins over the
relay alone — Termux on Android, a locked-down container, a VPN that drops mDNS. `--lan-too` turns
discovery back on. Measured: a daemon started relay-only authenticates to the relay with no
Bonjour started. The option existed in `lib/node.js` (`relayOnly`) but the daemon never exposed it.

### Changed — a failing multicast socket no longer takes the node down

LAN discovery is one transport of several: a Bonjour socket that cannot bind or send now degrades
to "no LAN peers", said once in the log, and relay peers are unaffected. Before, the error was
unhandled.

### Changed — relay-auth declares the node's room (wire note D4)

The relay partitions delivery and roster by the declared room; sym-swift and sym-py declare
theirs, and a Node that stayed silent landed in the unnamed partition where its roommates could
not see it (measured 2026-09-06: 0/0 peers in a room of three). The default room is not declared —
absent means default on the relay from 0.5.2. The first patch landed on the wrong options object
and was caught by probing the live auth frame; the second is probed in the same way.

### Fixed — `shareWithPeers` threw after every send

It returned `frame.timestamp` with no `frame` in scope — a ReferenceError on every call, after the
frames had already gone out. Found by the wire-alignment review reading the code; confirmed by
running it; pinned by a test.

### Added — the relay-auth frame carries the engine version

One field, no payload, no confidentiality cost; the relay records it, so "which engines ever
reached path X through the relay" becomes a query on the relay's log instead of a question nobody
can answer after the fact.

## 0.13.7 (2026-09-05)

### Changed — never in the clear through a relay

A peer reached only over a relay whose handshake carried no encryption key used to receive a
CMB's categories in plaintext, through a server that promises it cannot read them. The sender
now refuses: nothing is sent to that peer over the relay, the refusal is logged once with the
peer named, and `peers()` / `sym status` carry `e2e` and `clearRefused` per peer. A peer on the
local network without a key still receives (the frame never leaves that network); a relay peer
with a key receives ciphertext exactly as before. Every current engine and the Swift SDK send
the key, so this changes nothing for them.

**Scope of what this closes, stated rather than implied.** The plaintext fallback entered the
engine together with the key exchange in 0.3.6 (2026-03-29). Every published engine from 0.3.6
to 0.13.6 sends its key at the handshake, so between any two of them the relay never carried a
CMB's categories in the clear. The fallback could have been reached only by an engine older
than 0.3.6 — which had no encryption at all — talking to a current node through the relay, or by
a failed key derivation. Whether either ever happened cannot be checked after the fact: the
relay never logged payloads, and the auth frame carried no engine version (it does from 0.13.8).
If it did happen, what was readable was readable by the relay operator — the party already
running the relay on that node's behalf — not by a third party, and there is no key to rotate
and no version to abandon that any current user is not already past. That is why this is a note
and not an advisory. No evidence of exposure was looked for and none is claimed; the honest
statement is that it cannot be known, not that nothing happened.

### Changed — a short hosted-relay token is refused before it is saved

`sym start --relay-token` for the hosted relay refuses a token under 32 characters, names the
floor and how to mint one, and saves nothing. Persisted, such a token was knocked at the relay
every ~23 s for the life of the daemon, on an engine that never printed the reason.

### Docs — security stated as mechanisms with limits

README gains "Security, and what the relay can and cannot see"; README_zh and the reference
state the token floor beside the relay flags.

## 0.13.6 (2026-09-03)

### Added — the relay's state is visible to whoever drives the node

`sym status` printed `relay: disconnected wss://…` for every case that is not "connected":
a relay that is down, a token the relay refuses, an identity another process already holds.
The session behind the plugin saw even less — the plugin's `sym_status` reduced the same
state to one word. A node could knock on a relay every ~23 s for hours, refused each time,
and nothing on the node's side could say so.

Now `node.status()` carries `relayState` — `{url, phase, since, attempts, nextRetryAt,
lastClose, lastError, refused, peers}` with phase one of `off | idle | connecting |
authenticating | connected | reconnecting | refused | collision` — and `relayStatus`, one
line that puts the fix in the same sentence as the fault (a 4003 names the code, the relay's
reason, and that `sym_invite_create` / `sym_join_room` / `SYM_RELAY_TOKEN` are the ways out; a
4004 says it will not reconnect and why; an unreachable relay gives the last close, the next
retry, and that LAN peers are unaffected). `sym status` prints that line, red when refused.
`node.awaitRelayOutcome(timeoutMs = 10000)` resolves the first time the relay answers —
admitted, refused, or stopped — so a join over a relay can report the relay's actual answer
instead of "discovering peers". The token is never part of any of it.

## 0.13.5 (2026-09-03)

### Fixed — a relay's auth refusal is said once, with the fix, instead of retried forever in silence

A node whose token is not in the relay's channel table was refused with close 4003, logged
"Relay error: Invalid token", and reconnected on the normal backoff — one rejection every
~23 s in the relay's log for as long as the process lived, and nothing an operator could act
on in the host's. The refusal is deterministic (the token comes from the node's environment,
the table from the operator's), so retrying it fast is noise, not persistence. Now the relay
layer logs ONE `FATAL: relay <url> refused <name> (4003: …)` line naming `SYM_RELAY_TOKEN` as
the fix, emits `relay-auth-refused` on the node once per episode, and keeps retrying at a
slow cadence (10 min, `authRefusedRetryMs`) — not a hard stop like 4004, because a retry
harms no other node and the one production open-mode incident began with a channel table
being edited live. A successful auth ends the episode. 4001 (auth timeout) is unchanged.

### Changed — `setup-claude.sh` no longer names a hosted relay or offers "open access"

The interactive setup prompted with one hosted relay as the example URL and described an
empty token as "open access". The relay refuses to start in open mode and admits only the
channel tokens its operator configured, so both prompts pointed at a door that does not
open. The prompts now ask for the URL of a relay the team runs and for the channel token
issued by whoever runs it. No behaviour changes.


## 0.13.4 (2026-08-31)

### Fixed — a stale directive can no longer dress as fresh: the replay-dedup TTL now exceeds the slowest sender's horizon

The receive-path dedup suppressed an already-surfaced CMB for one hour — sized for
Bonjour reconnect replay storms, minutes apart. The daemon's delivery spool replays
directed envelopes on a seat's reconnect at a ~30-HOUR horizon, so three
already-drained messages re-surfaced as live pushes with fresh inbox ids and
seconds-old ages — one of them an imperative to redo work its own successor
recorded as committed (dev-team-3, 2026-08-31). Record-after-surface semantics make
a long window safe (only genuinely delivered keys are suppressed; deliberate
identical re-sends already salt themselves), so the TTL is now seven days.
Regression test replays a surfaced directive 30 hours later and requires silence.


## 0.13.3 (2026-08-31)

### Fixed — legacy inbox entries restore fetchable instead of lost or unaddressable

`_loadInbox()` trusted persisted messages verbatim. seq and id were introduced together
(v0.10.0) and the durable feed crossed that boundary, so real disks hold entries with
seq-but-no-id — which surfaced in a receiver as "[undefined]" and could never be fetched
(reported by codex-mac, 2026-08-31, as truncated directed replies with no retrievable id) —
and entries with neither field, which the `seq > cursor` drain silently filtered out forever:
loss wearing a working inbox.

Restore now normalizes: known seqs advance the counter first, missing seqs are minted above
it and above the cursor so a legacy entry surfaces once — redelivery is recoverable, silent
loss is not — and every entry gets the id its seq implies. Three regression tests pin both
legacy shapes and mint-vs-push uniqueness.


> **Note:** Versions 0.3.26 – 0.3.55 were released as git tags without changelog entries. Changelog resumes at 0.3.56 below.

## 0.13.2 (2026-08-27)

### Fixed — the absent-claim log asserted a cause it cannot observe

The admission for a peer that claims no room logged `peer predates room
comparison`. That was true while the absent set was pre-0.11.1 nodes and the
iOS fleet. 0.13.1 added a second population to the same line: an `emit()` caller
that names no room predates nothing — it is current code exercising a documented
default, and that is a caller-side choice which may be legitimate indefinitely.

The two need opposite responses. One is a fleet that *cannot* speak rooms and has
to be waited out or upgraded; the other is a caller that *chose* not to claim and
can be left alone. This line exists to be **counted**, because the count is what
says when the receiving rule can be tightened — and a count that mixes them can
never reach zero, so it would either hold the tightening forever or be overridden
on a hunch.

Absence is byte-identical on the wire, so the cause is not observable at this
point at all. The log now reports what was seen — `no room claimed` — and leaves
the inference to whoever reads the count. A test pins the observation and
forbids the inference, so the reason cannot creep back in.

Behaviour is unchanged: absence is still admitted, a mismatched claim is still
refused. Found by dev-team-1 verifying 0.13.1 from a tarball they fetched
themselves.

## 0.13.1 (2026-08-27)

### Fixed — emit() made a claim when it meant to stay silent

`connect()` defaulted `room` to `'default'` and always sent the field, so a
caller who named no room made a **positive claim** of the public square. 0.13.0
requires a receiver to close on a mismatched claim, so the documented default of
a first-class API was precisely the value refused by every named room — and the
caller saw only `closed before handshake`, with no mention of rooms anywhere in
the error it received. The node logged the reason; the client did not, so it
presented as a connectivity fault rather than a naming one, and a script that
worked yesterday against a named-room node simply stopped connecting.

`room` now has no default and is omitted from the handshake when the caller
names none — silence, matching the rule 0.13.0 added on the receiving side.
`connect({ room: 'default' })` still claims `default` deliberately, and is still
refused by a node in a named room, which is correct: that is a claim.

Reproduced before fixing and confirmed against the published 0.13.0 tarball, not
against the source: a node in room `acme`, then `connect({ server })` fails
while the node logs `room-mismatch (claims 'default', this node is in 'acme')`;
passing `room: 'acme'` connects. Found by dev-team-1 reviewing the release.

### Fixed — two comments in 0.13.0 that stated the wrong thing

- The handshake `room` field arrived in **0.11.1**, not 0.11.0, and what 0.11.1
  renamed from `group` was `emit.js`'s field on the CMB *record* — a different
  object from the handshake frame, which carried no room at all through 0.11.0.
  Both halves of the published note were wrong. Corrected rather than dropped,
  since the boundary decides which nodes are in the absent set.
- The note claiming an absent room over the relay is "unfiltered" is wrong and
  is replaced. `relay-auth` carries a client-declared room and the relay scopes
  delivery, roster and departures by it, with an undeclared room becoming its
  own unnamed partition rather than the global mesh. sym-swift already sends it
  there. The residual is a design position, now stated as one: inside a channel
  a peer already holds a token for, the room is addressing, not a boundary.

## 0.13.0 (2026-08-27)

Room naming and room isolation. Minor rather than patch: names that were
accepted before are now refused, and peers that were admitted before are now
disconnected.

### Changed

- **Room names must be canonical** (founder ruling 2026-08-27): one name per
  room, one room per name. `isValidRoom` now requires the round trip through
  the service type to be identity, so **`sym` is refused**. It satisfies the
  kebab grammar, maps to `_sym._tcp`, and comes back as `default` — a second
  spelling of the global mesh, which meant a node asking for a room named `sym`
  sat in the public square while reporting it was somewhere specific. `default`
  is the canonical name for the global mesh. The round trip was already the
  ownability rule (`isOwnableRoom`); confining it there meant an *unowned* room
  could still be an alias, which is where the silent collapse happened.
- **A peer that CLAIMS a different room is now disconnected.** MMP §5.8 has
  always required a receiver to refuse a peer whose declared room differs from
  its own, but nothing compared the two, so a peer announcing any room joined
  the peer set. It is now checked on **both** the dialling and accepting paths,
  because the loopback tie-break means a stranger dials us in half of all nodeId
  orderings and a one-sided check is dead code for those pairs.
- **A peer that claims NO room is admitted, and the admission is logged.**
  Absent is not `default`. A handshake with no `room` means the peer does not
  speak room comparison — a version difference — not a claim to be in the public
  square, and §5.8 closes on *mismatch*, which silence is not. This matters
  concretely: sym-swift's handshake carries no room at all, so every shipped
  MeloTune and MeloMove device sends one without it, and treating absence as a
  claim would have partitioned the entire iOS fleet out of every named room —
  silently, on both sides. The `room` field arrived in 0.11.0 as a rename of
  `group` (which nothing reads today), so pre-0.11.0 nodes are in the same set.
  An empty string counts as absent. The log makes the population countable so
  the rule can tighten once Swift nodes send a room in the handshake.

  **On the relay path, which is narrower than it first appears.** A relay token
  is the security boundary and decides which *channel* a connection may reach,
  from server-held state no client can influence. The `room` is a
  client-declared *partition inside* that channel — addressing, not permission —
  and the relay (≥ 0.1.3) partitions delivery, roster and departures by it. It
  is safe to let a client name its room there because naming one can only ever
  narrow what that connection receives, never widen it. An undeclared room is
  the empty string, so pre-room clients share one unnamed partition rather than
  leaking into named ones. sym-swift already sends `room` in `relay-auth` even
  though its MMP handshake carries none, so iOS devices are partitioned
  correctly over the relay today. What remains true, and is a design position
  rather than a defect: within a channel you already hold a token for, the room
  is addressing, so it is not a security boundary on that path.

### Added

- `canonicalRoom(name)` — the sanctioned way to accept a room name from outside
  (config, CLI flag, invite URL, UI field). Trims surrounding whitespace, which
  is not part of a name, and otherwise returns the name or `null`. It returns
  `null` rather than a best effort deliberately: **refuse, never repair.** Every
  repair — lowercasing, substituting illegal characters, collapsing runs,
  truncating to fit a length cap — is many-to-one, so it sends nodes that asked
  for different rooms into one room and tells none of them.
- `rooms` is exported from the main entry, so consumers can
  `require('@sym-bot/sym').rooms` instead of deep-importing `lib/`. Six
  hand-rolled copies of this mapping existed across the tree and every one
  disagreed with at least one other; a shared mapping that is hard to reach is
  a mapping that gets copied.
- Room ownership and room-join grants (`lib/room-ownership.js`,
  `lib/core/room-grant.js`). **Dormant unless a room has an owner** — with no
  owner, admission is unchanged. Unlike the mismatch check above, this half
  genuinely does nothing until ownership is used.

### Fixed

- The grammar's stated rationale was wrong. A comment claimed a 15-character
  truncating consumer collapses two tenants' `x-review--team-<id>` rooms onto
  one service type. Measured against the actual source, it does not — that
  consumer emits a 9-character prefix plus a digest, so the two stay distinct.
  The real harm is different and worse for interop: such a consumer emits a
  type **no other implementation emits**, so it is invisible rather than
  misrouted.

## 0.12.3 (2026-08-26)

### Changed

- **Tenant-suffixed room names are legal.** The room grammar accepts a double hyphen as a
  segment separator (`x-review--team-02779b…`) — the shape xMesh scopes recipe rooms with.
  Before this, `sym join`, the daemon, and `sym_invite_create` all refused the very rooms
  the product creates, and only a direct service-type bypass made them work. Triple hyphens,
  leading/trailing hyphens and bare suffixes stay invalid.
- **The mapping's limits are stated where the next reader looks.** `roomServiceType` feeds
  the room name into a DNS-SD Service Name unmodified; suffixed names are knowingly outside
  RFC 6335's Service Name rules (consecutive hyphens, 15-char label), isolation rests on
  responders not enforcing them, and one shipped consumer that truncates at 15 chars is
  named in the comment. Names were never the boundary; room join authorization (the adopted
  design in docs/DESIGN-room-join-authorization.md) is.

## 0.12.2 (2026-08-24)

### Fixed

- **A node's local state never moved when it admitted a peer's cognition.** Every
  `updateLocalState` call was reached from init, broadcast, or the node's own `remember` — nothing
  on admit. The neural gate re-encoded state after storing an admitted remix; the heuristic gate,
  which is the production default, did not. This package ships no `svaf_v2.pt` and the neural path
  additionally spawns a Python subprocess, so in practice the state simply never moved: a node that
  had admitted five hundred peer blocks carried exactly the same local state as one that had
  admitted none, even though the context it encodes is built from the store those blocks land in.
  Both gate paths now take the same step, through one shared method rather than a copied line —
  the defect was never a wrong line, it was the difference between two paths that are supposed to
  be interchangeable.

  **What this does not change.** It is still a stateless re-encode: prior state is discarded and
  recomputed from the store, so nothing here is recurrent and nothing learns. SVAF scores
  per-category CMB vectors against anchor memory and does not read the hidden state, so no
  admission decision changes as a result of this fix. What it buys is that local state is real,
  so something can be built on it.

  The regression test is structural on purpose: each path worked as written, and the defect was
  the difference between them, so a behavioural test on either one would have passed throughout.

## 0.12.1 (2026-08-18)

### Fixed

- **A rooted deployment keeps its identity, keys, stores and lock inside its own root.** Setting
  `SYM_STATE_DIR` already moved a node's memory; it did not move the tree that holds each node's
  identity, keypair and single-writer lock, which stayed at `~/.sym/nodes` for every deployment
  on the machine. Two independent deployments on one host — each with its own `SYM_STATE_DIR` —
  therefore shared one identity tree, and the second to start was refused the lock the first
  held, while appearing healthy in every other respect. The identity tree, the daemon socket and
  the logs now follow `SYM_STATE_DIR` too. Nothing moves for a deployment that sets nothing:
  `~/.sym` remains the default, in the same place, with the same contents.

## 0.12.0 (2026-08-17)

### Added

- **The runtime is now self-sufficient — everything a node needs to think is in this package.**
  Semantic category encoding and SVAF evaluation, which previously lived in the separate
  `@sym-bot/core` package, are part of the open runtime. A node can create, sign, exchange,
  verify, evaluate, admit and store records with no additional engine installed, which is what
  makes this package a complete, independently usable implementation of MMP 2.0 rather than the
  open half of a pair.

- **Every release is gated on two stock nodes.** Before publishing, the packed tarball is
  installed into an empty directory and two plain nodes are driven through the entire path —
  create, sign, exchange, verify, evaluate, admit, store with lineage — and then one is restarted
  and the record must still be there, with the signed record of why it was admitted. The gate runs
  against the artifact you install, not the source tree, because those are not the same thing.

### Changed

- **Nothing existing behaves differently.** The absorbed code is additive: where both lineages had
  an implementation, this package keeps its own — measured, not assumed, by the signing and
  interoperability conformance suites, which decide any disagreement. Existing nodes upgrade with
  no change to the wire, to record addresses, or to stored data.

## 0.11.3 (2026-08-13)

### Added

- **Reads the published MMP v2.0 record signature suite.** A record signed under
  `mmp-sig-v2.0` now verifies against the published preimage, so a v2.0 record
  from an independent implementation interoperates with this one. Signature
  verification, the end-to-end category encryption, the handshake proof-of-
  possession, and the session key schedule all match the published v2.0 spec
  byte-for-byte. Records signed under the previous suite continue to verify
  unchanged — this release **reads** v2.0; it still **emits** the previous suite,
  so nothing on the wire changes for peers on earlier versions. Emission moves to
  v2.0 in a later release, once v2.0 readers are widely deployed.

- **Verification receipt for verified-record consumers.** After this node
  verifies a v2.0 record it can emit a compact receipt bound to the exact record
  bytes, so a downstream consumer can admit the record without re-verifying it
  and detect any mutation between verification and use.

### Changed

- **Lineage is walked from verified local records only.** A record's provenance
  is resolved by traversing parents this node has actually stored, never a
  sender-supplied ancestor list — a non-conforming peer can no longer inject an
  apparent root. Admission freshness is derived from the signed timestamp of a
  verified record rather than a transport field.

## 0.10.2 (2026-08-04)

### Fixed

- **The delivery inbox survives a session restart.** Communication is addressed to the NODE, and a
  new session relinks to it — including what was delivered while no session was attached. The inbox
  was process memory only, so a restart silently wiped the delivery feed while every sender believed
  it had delivered (observed live: four gate requests, and separately five broadcasts, vanished into
  restarted peers that showed as live on Bonjour throughout). Ring, sequence and drain cursor now
  persist together in the node directory: messages without the cursor would replay what was already
  drained; the cursor without the messages would silently skip the backlog. A missing or corrupt
  inbox file starts fresh, exactly like the old behaviour.

## 0.10.1 (2026-08-01)

- **Pinned to `@sym-bot/core` 0.7.0.** Shadow samples are now persisted per node rather than
  reduced to counts in a log line — the receive path writes one row per admission, carrying the
  receiving node and per-field values. No behaviour change to admission.

## 0.10.0 (2026-08-01)

- **Pinned to `@sym-bot/core` 0.6.0.** Adds an observe-only admission diagnostic on the
  receive path: computed alongside the five-valued band on every admission, logged beside it,
  and **deciding nothing**. No peer can observe it — it never enters the signed attestation
  payload — so nothing on the mesh can come to depend on its behaviour.
- **feat:** `svafRedundancyThreshold` node option. Every other SVAF threshold has been settable
  for a long time; the redundancy floor was not settable anywhere, and it is the whole of the
  redundancy cut. Deliberately carries **no default here** — unset, core applies its own, so the
  value keeps exactly one home across the two packages.
- **⚠ Note on that option:** while C is derived from the five-valued band, C's floor *is* the
  acting gate's floor. Setting `svafRedundancyThreshold` therefore changes what the node
  **admits**, not just what the shadow records. Treat it as a production gating change until C
  becomes an independent cut.

## 0.9.0 (2026-08-01)

> *Entry written retroactively on 2026-08-01. This version and 0.8.0 were published without a
> changelog entry or a git tag; both tags were created after the fact at their own release
> commits.*

- **Pinned to `@sym-bot/core` 0.5.0 — the boundary record model.** Two-section records,
  content-only addressing, per-field keys, and signatures that verify against the author's key
  rather than the delivering peer's.
- **Every consumer read migrated.** Authorship is resolved from the signed author field; an
  unattributed block is skipped rather than published under an invented name.
- **Pre-boundary history stays readable** — older blocks carried as unverified-legacy, not
  refused.

## 0.8.0 (2026-07-31)

> *Entry written retroactively on 2026-08-01 — see the note above.*

- **cmb-only cutover.** v1 key derivation throughout; pinned to `@sym-bot/core` 0.4.0.

## 0.7.30 (2026-07-07)

- **fix (cross-peer grounding):** `remember()` with parents now mints the
  REMIX-scheme `cmb1-` key (§8.2.1 role dispatch). Previously a lineage-bearing
  authored CMB carried a root-scheme key, failed the receiver's content
  re-verification, and was hard-rejected as forged — agent-authored grounding
  CMBs silently never landed on any peer. Two-node regression test included.
- **feat (`sym emit` + `sym/emit`):** MMP Class 1 Emitter (§17.1) — one-shot,
  signed CAT7 emission to a remote mesh node with the emitter's own persistent
  identity. No daemon, no store, no identity lock. CLI:
  `sym emit --server <host:port> [--group] [--name] [--to] [--parents] '{...}'`;
  programmatic: `require('sym').emit` → `emitOnce()` / `connect()`. LAN TCP;
  relay emission lands with one-shot E2E (§18.2.1). Real-TCP e2e tests.
- deps: @sym-bot/core ^0.3.48 (tether attestations, recomputeKey export,
  retroactive-audit evaluation, conformance vectors + schemas).

## 0.7.27 — 2026-07-01

### Fixed

- **Stop a cross-node echo/replay storm — own-only anchors + reload-durable dedup.** Two in-memory safeguards that a plugin reload or process restart wiped, plus a missing origin filter, let already-seen CMBs re-circulate across a multi-node mesh:
  - **Origin filter on anchor exchange (`node.js`).** On peer connect a node sent its 5 most-recent *store* entries as SVAF anchors with no origin check, so it re-forwarded CMBs it had merely *received* from other peers — the A→B→C→A amplifier. Anchors are now the node's **own** emissions only (`peerId == null`); a peer learns each node's state from that node directly, so own-origin anchors suffice.
  - **Reload-durable receive dedup (`frame-handler.js`).** The receive-path dedup cache (`_seenCmbKeys`) was in-memory only, so a reload made every already-processed CMB look new again. It now persists to a dotfile beside the store (TTL-pruned on load, throttled write, best-effort — any FS error degrades to in-memory), so reloads and version skew are non-fatal.
  - Verified: own-only anchors forward 0 peer CMBs; the dedup cache rehydrates across a simulated reload; expired keys prune on load. Suite 258/258.

## 0.7.26 — 2026-06-30

### Added

- **Nodes self-report their memory stats over the mesh.** A node is sovereign over its store, so an observer on another machine can never read it — it could only see a node's broadcasts, never what it admitted. Each node now EMITS its own tally to the roster as a lightweight `node-stats` frame (metadata, NOT a CAT7 CMB — it never enters a cognition stream or SVAF): `emitted` = CMBs it authored (store local count), `admitted` = CMBs it accepted from peers (store peer count), `memory` = total. Gossiped on start and every `statsInterval` (default 15s). `frame-handler` ingests a peer's `node-stats` and the node re-emits it as a `node-stats` event for hosts (e.g. the Mesh Edge observer) to render. Self-reported and unsigned — a convenience metric, not stored or treated as authority. Lets any observer show real emitted/admitted counts for every node, including cross-machine agents whose stores are unreadable locally. 3 tests; suite 258/258.

## 0.7.25 — 2026-06-29

### Added

- **Earned-authority-weighted attestation aggregation (EA6).** `node.aggregateAttestations(cmbKey)` folds every attestation about a CMB into a single roster verdict weighted by who actually holds rank. Each attestation is signature-gated against the attester's key from the roster registry (unverifiable ones are *excluded* as evidence, never weighted), then its attester's role is resolved at its own attestation time (role-at-time) from the rooted grant chain; weight is `2^rank` (participant 1, validator 2, anchor 4). Overall and per-CAT7-field verdicts become weighted tallies with a deterministic `dominant` + `confidence` (dominant's share of total weight); over-claims (claimed role ≠ resolved) are down-weighted to the resolved rank and surfaced in `mismatches`. So an anchor's admit outweighs a participant's and a node asserting unearned authority cannot inflate consensus. With no anchor pinned, every attester resolves to participant (uniform weight 1) and this reduces to an unweighted tally — it sharpens the moment authority is activated. 2 tests; suite 255/255.

## 0.7.24 — 2026-06-29

### Added

- **Roster key registry (EA5) — verify signatures from peers you never directly met.** A `nodeId` is a uuidv7, independent of its Ed25519 key, so until now a node could only verify CMBs/attestations/grants from *direct* handshake peers; a relayed frame from a non-adjacent node failed as unknown-key (invisible on a fully connected LAN, but it capped the protocol at direct connectivity).
  - `lib/roster-keys.js` — `RosterKeyRegistry` pins `nodeId→publicKey` by **source precedence** (`anchor` > `handshake` > `grant`-vouched). A weaker-or-equal source can never repoint a stronger binding; equal-strength key conflicts are refused and recorded as evidence; duck-types `Map` `get`/`set` so it drops in where the raw key map was used. Persisted append-only.
  - **Keys ride the rooted authority chain.** A grant now binds the grantee's key into its *signed* payload (`granteeKey`, `@sym-bot/core` 0.3.45), so a node that never handshook the grantee learns its key from a rooted grant — tamper-evidently, because swapping the key breaks the grantor's signature (the relayer never vouches). The store pins a grantee key only when the grant is **role-effective** (grantor actually held the rank), so an unrooted or over-reaching grant vouches for nothing and cannot poison the registry.
  - **Node wiring** — handshake pins at `handshake` strength (`_pinPeerKey`, writing both the legacy CMB map and the registry); attestation / checkpoint / witness verification now resolves keys via `_identityKey` (registry first, covering relayed + persisted bindings); `grantRole` binds the grantee's known key. 9 tests; suite 253/253.

## 0.7.23 — 2026-06-29

### Added

- **Earned authority — the lifecycle role a node claims is now earned and verifiable, not self-asserted (MMP §6.5).** A node's validator/anchor authority flows only along signed role-grant chains that terminate at a pinned, non-earnable **anchor** (the founder root); over-reaching, unrooted, and cyclic grants confer nothing (Douceur — authority must bottom out at a pinned root).
  - `lib/role-grant-store.js` — `RoleGrantStore` holds signed role-grant / role-revoke records and resolves "what role did node N hold at time T" by walking the chain. Signatures verify on ingest against the grantor's announced key (anchor key pinned); whether the grantor actually *held* the rank is a resolve-time, role-at-time property, so an unentitled grant is stored but inert. Persisted append-only, reloaded on construction.
  - `lib/node.js` — the node pins an anchor (`opts.anchor` or `SYM_FOUNDER_ANCHOR="nodeId:publicKey"`), holds the grant store, and stamps its **resolved** role into attestations + witnesses (so `verifyAttestationRole` checks the stamp against the chain). `grantRole` / `revokeRole` sign + gossip a grant; `resolveRole(nodeId, at)` exposes chain resolution. With no anchor configured the node falls back to the static `lifecycleRole` (backward compatible).
  - `lib/frame-handler.js` — ingests `role-grant` / `role-revoke` frames (store verifies, relay-once).
  - **§6.5 enforcement** — `MemoryStore.validateCMB` now requires the caller's resolved role to rank validator-or-above; `canonizeCMB` requires anchor. `node.validateCMB` / `node.canonizeCMB` resolve this node's earned role and let the store enforce, so a participant can advance no CMB's lifecycle.
  - 17 tests (10 store + 7 node). Earned authority is **dormant until an anchor is pinned** — until then every node uses its static role, unchanged.

## 0.7.22 — 2026-06-29

### Added

- **Admission Attestation audit trail is now durable across restarts.** The attestation index persists every record append-only under the node dir (`attestations.jsonl` / `checkpoints.jsonl` / `witnesses.jsonl`) and reloads it on startup, so the cross-mesh audit trail — attestations, Merkle checkpoints, and witness countersignatures — no longer evaporates from memory when a node restarts. Append-only matches the compliance model (never rewrite); a corrupt line is skipped, never fatal; persistence failures never break gating. On reload the node restores its per-attester chain cursor (`seq`/`head`) from its own reloaded chain, so `seq` stays monotonic and `prev` keeps linking across the restart boundary — otherwise a restart would reset the chain to genesis and read as a false omission. The guarantee is now: tamper-evident + omission-evident to the last witnessed checkpoint, **and durable across restarts**.

## 0.7.21 — 2026-06-29

### Added

- **Admission Attestation gossip + cross-mesh audit trail with omission-evidence** (Phases D1–D3; requires `@sym-bot/core` `^0.3.43`).
  - **D1 — index + every gate attested.** `lib/attestation-store.js`: a per-node index keyed by gated-CMB (the audit trail for a CMB) and by attester chain (`seq`). The gate now attests `reject` and `redundant` too (a refusal is the compliance-critical event), so the per-attester chain covers every gating event. `verifyChain` flags `seq` gaps and `prev` breaks — local omission-detection.
  - **D2 — roster gossip.** Every attestation is gossiped on a dedicated `attestation` frame to roster peers (same-group by mDNS isolation). On receipt the node verifies the attester's *original* Ed25519 signature against its authenticated identity key (a relay never vouches), rate-limits per `(of,by)` against a flood, records, and relays once (epidemic spread). Forged/invalid dropped.
  - **D3 — checkpoints + witnessing.** The node periodically commits a signed Merkle checkpoint over its attestation chain (`merkleRoot` of the ordered signatures to seq N); roster peers verify and *countersign* it (witness). `reconcileChain(by)` recomputes the root over the held chain vs the witnessed commitment — so dropping any attestation ≤ N after it is witnessed makes the root diverge. Cross-node omission-evidence.
  - Guarantee: **tamper-evident + omission-evident to the last witnessed checkpoint**, not real-time completeness. Remaining (D4): roster key registry for *relayed*-attester verification + role-at-time, witness-quorum tuning, durable persistence.

## 0.7.20 — 2026-06-29

### Added

- **Admission Attestations persisted on the gated remix** (Phase C; requires `@sym-bot/core` `^0.3.42`). When the SVAF gate ADMITS a CMB, the node signs an Admission Attestation and attaches it to the stored remix (`cmb.admission`) as the durable, attributable audit record: `{ of, by, at, roster, method, verdict, fields, role, seq, prev }`, signed with the node's Ed25519 identity key. `of` binds the original gated CMB key; the per-field `fields` come from the gate's verdict (heuristic) or `field_drifts` mapped through `computeFieldVerdicts` (neural). A per-attester hash-chain (`seq` monotonic, `prev` = sha256 of the previous signature) makes a dropped attestation a detectable gap (omission-evidence backbone; in-memory for now). `role` is the node's *claimed* lifecycle role — consumers verify it against the rooted role-grant chain, never the stamp. The attestation is a CMB-envelope sibling, so it does not affect `cmbKey` or any existing signature. (Reject/redundant attestation, the queryable index, and mesh-wide gossip are the next phase.)

## 0.7.19 — 2026-06-29

### Fixed

- **Opaque payload survives the SVAF-admit remix path.** A directed CMB's `payload` (the substrate-level data riding alongside CAT7 — e.g. the LLM request/response primitive) was dropped whenever the *receiver* SVAF-**admitted** it: the fused remix is rebuilt from CAT7 fields and the heuristic fusion returns a fresh `cmb` with no payload, so the payload vanished before reaching the inbox. The same CMB **rejected**-but-directed surfaced the raw message and kept its payload — so payload delivery silently depended on the receiver's per-node SVAF drift. That was the root of the cross-device "payload arrives on some peers, not others" asymmetry (a receiver that admits drops it; one that rejects keeps it) — not an OS or transport difference. `_preserveIncomingPayload` re-attaches the incoming payload onto the fused remix on both the neural and heuristic store paths; payload rides alongside CAT7 and is never part of the `cmbKey` hash, so an admitted `llm-request`/`llm-response` remix correctly carries its substrate data. Regression-tested in `tests/frame-handler-payload.test.js` (unit) and `tests/integration/e2e-payload-receive.js` (two-node e2e). Completes the cross-device payload fix begun in 0.7.18 (which covered only the inbox pull path).

## 0.7.18 — 2026-06-28

### Fixed

- **Inbox pull path preserves the opaque payload.** A CMB's `payload` is a sibling of `cmb.fields`, but `_pushInbox` copied only `fields` — so any CMB pulled via `node.inbox()` (the `sym_receive` / `sym_fetch` path) silently lost its payload, while the channel-push path (reading `entry.cmb.payload`) kept it. Structured agent-to-agent data now survives cross-device directed delivery on both paths. Regression-tested in `tests/inbox.test.js`.

## 0.7.17 — 2026-06-27

### Notes

- Reconciliation release: 0.7.16 (store rename + migration + role/EIP renames) was published off a stale main; 0.7.17 is the same content rebased onto origin, now also including #31 (lib-level resolveAvailableName) and #33 (ws 8.21.0). No new changes beyond the merge.

## 0.7.16 — 2026-06-27

### Changed

- **Per-node CMB store dir renamed `meshmem/` → `cmbs/`** (it stores CMBs). A fresh node self-migrates its own dir on construct; `migrateStores()` (exported) bulk-renames every NON-live node at sym/mesh-channel install (live nodes are skipped — they self-migrate on restart). Readers read `cmbs/` only — clean break, no fallback. Very old `memories/` stores still migrate via the field-mapped path.

## 0.7.15 — 2026-06-27

### Changed

- **CLI `sym observe` → `sym publish`** (+ the bundled `sym` skill), matching the MCP tool rename to canonical EIP verbs. Publishing emits a projection of the agent's state; the cognitive mechanism terms stay in the spec. Clean break — no alias.

## 0.7.14 — 2026-06-27

### Changed

- **Lifecycle role `observer` renamed to `participant`** (MMP normalization). Frees the "observ-" stem for the projection/observation distinction (an emitted CMB is a *projection*; an admitted one a peer's *observation*). `participant → validator → anchor`; handshake `lifecycleRole` default is now `participant`. Clean break — no backward-compat alias.

## 0.7.13 — 2026-06-27

### Fixed

- **Loopback registry self-cleans on abrupt exit.** A node writes
  `~/.sym/loopback/<nodeId>.json` on start and `stop()` unlinks it on graceful
  teardown — but a process that exits or is killed without calling `stop()`
  (test runs that just finish, Ctrl-C) left the registration behind as a stale
  "group" until a pid-liveness check filtered it out. Now a one-shot sync unlink
  is registered on `process.on('exit')` so the common case self-cleans; the
  listener is removed again in `stop()`. (SIGKILL still can't be caught — that
  residue is what the pid-liveness check in readers is for.)

## 0.7.12 — 2026-06-25

### Added

- **IPC `remember` carries lineage `parents`.** The daemon IPC `remember` now forwards
  `opts.parents` (each `{ key }`) through to `node.remember`, so a CMB emitted via the IPC
  client (e.g. mesh-edge's `emitCMB`) can declare its source as a remix edge (MMP §14)
  rather than bare fields.

- **Adaptive integration timescale plumbing for SVAF (the liquid substrate).** New node
  options `svafAdaptiveTimescale` / `svafMinFreshnessSeconds` / `svafReactivity` /
  `svafChangeWeights` / `svafRecentWindow`, a bounded ring of recent SVAF verdicts, and
  call-site plumbing passing `recentDecisions` + the adaptive config into `@sym-bot/core`'s
  `processHeuristicSVAF` (requires `@sym-bot/core ^0.3.39`). When enabled, the SVAF
  memory-decay timescale shortens after recent `guarded`/`rejected` verdicts and lengthens
  when stable — the content gate driving the temporal timescale, instead of a fixed-gain
  integrator. Off by default. The decision log now records `effectiveTau` + `changeSignal`
  per heuristic admission.

## 0.7.9

### Added

- **Ingestion flag on surfaced CMBs (MMP §9.2.2).** Because directed delivery and SVAF memory admission are decoupled, a surfaced CMB now declares whether the receiver **ingested** it (remixed into memory with lineage → `remixed: true`) or only **delivered** it (surfaced to the agent but not stored → `remixed: false`, the directed-but-SVAF-rejected case), alongside the SVAF `decision`. Consumers check `remixed` to know whether a directed request is recallable from memory later or transient. Covered by four cases in `tests/inbound-cmb-surfacing.test.js`.

## 0.7.8

### Fixed

- **Directed (peer-bound) CMBs now surface unconditionally (MMP §4.4.4 / §9.2.2).** A CMB sent to a specific recipient (`sym_send to=X`) is a request between two agents and must reach the receiving agent regardless of the SVAF verdict — previously every inbound CMB (directed or broadcast) ran through the group-autonomous SVAF surfacing gate, so a directed coordination CMB scored low (redundant/foreign) by SVAF was silently dropped. Now the send path marks the wire frame with `to` + `directed`, and the receiver surfaces a directed CMB exactly once: on SVAF admit via the existing store path, on SVAF reject/redundant via a dedicated delivery path. SVAF governs memory admission only for directed CMBs, never delivery. Group-bound broadcasts (`sym_observe`, no `to`) stay fully SVAF-gated for surfacing — unchanged.

## 0.7.7

### Fixed

- **Inbound-CMB receive fix — record dedup key after surfacing, not before.** The receive-path dedup recorded a CMB's content-hash key as "seen" before it had actually surfaced, so a first pass that surfaced nothing (an SVAF reject with neutral mood) still poisoned the key — the same CMB re-arriving on the next reconnect was deduped and silently dropped, leaving the node receive-blind. The key is now recorded only after the CMB genuinely surfaces, preserving the anti-replay-storm guarantee without swallowing undelivered CMBs.

## 0.7.6

### Added

- **SVAF decision log.** Every SVAF evaluation — `aligned` / `guarded` / `redundant` / **`rejected`** — is now persisted and emitted, not just the admitted CMBs. A node's autonomous, per-field admission — including the rejections the memory store never keeps — is observable: `node.decisions({ limit, since, decision, source })`, a live `svaf-decision` event, and an append-only, capped log at `~/.sym/nodes/<name>/decisions/log.jsonl`. Each record carries the per-field `fieldDrifts` + `gateValues`, the evaluated CMB key, and a short focus label — **never the rejected payload** (local-first, label-only). Capped (default 2000; `SYM_DECISION_LOG_CAP`); opt out with `SYM_DECISION_LOG=0`. Additive + backward compatible — `meshmem` and all existing readers are unchanged.

## 0.7.5

### Fixed

- **Mesh replay-storm receive-path dedup (#32).** Received CMBs are deduped by content-hash, so already-seen CMBs are no longer re-surfaced or re-broadcast. Stops the loop where nodes re-dumped their stored history on every (re)connection, flooding the mesh with stale CMBs.

## 0.7.4

### Added

- **Same-host loopback discovery** — co-resident SymNodes now mesh with no network interface. mDNS multicasts over an interface, so with Wi-Fi off two nodes on one host couldn't discover each other even though each already listens on a TCP port and could connect over `127.0.0.1`. `BonjourDiscovery` now runs a filesystem-registry path alongside Bonjour: each node advertises its loopback endpoint to `~/.sym/loopback/<nodeId>.json` (`{nodeId, name, port, pid, serviceType, ts}`) on a 5s heartbeat, scans for **live** (pid-alive + `ts < 30s`), same-`serviceType` peers, and emits the existing `peer-found` event over `127.0.0.1`. No transport/protocol change — the connection + handshake path is identical to Bonjour. Group isolation by `serviceType` (MMP §5.8); the lower `nodeId` dials (mirrors the Bonjour tie-break) so the pair connects exactly once; quick catch-up scans (300/1200/3000ms) mesh near-simultaneous starts in ~1s.

### Notes

- Additive + backward-compatible: activates on next node start — no config, no forced restart, Bonjour path byte-for-byte unchanged. Both nodes must run ≥0.7.4 for same-host loopback meshing (each side must register *and* scan).

## 0.7.3

### Changed

- **`sym groups` now lists groups cross-platform (including Windows)** via a discovery beacon, replacing the `dns-sd` shell-out (which doesn't exist on Windows, and which `bonjour-service` can't substitute for because it doesn't answer the DNS-SD meta-query). Every running daemon now advertises its group on a shared `_symgroups._tcp` service (group name in TXT) via the bundled pure-JS `bonjour-service`; `sym groups` browses that beacon and lists the live groups with their nodes. Discovery-only — comms stay isolated on each group's own `_<group>._tcp`. **Group names may be anonymous** (opaque codes), so the LAN listing need not reveal a group's purpose.

### Notes

- Groups are **open-join** in this release (anyone who knows the name can join). **Invite-gated private groups** (admin-set, join-by-invite, LAN handshake gating) are the planned fast-follow.

## 0.7.2

### Fixed (Windows — COO bisected it on re-test)

- **`sym ask` still crashed on Windows in 0.7.1** — the 0.7.1 broadcast-socket fix was necessary but not the culprit. COO bisected the crash to the **synthesis path**: `process.exit(0)` was firing while the LLM call's handles (a spawned `claude` subprocess's stdio pipes, or a fetch socket) were still closing, tripping the libuv `UV_HANDLE_CLOSING` assertion (`0xC0000409`). Fix: `sym ask` no longer force-exits — it sets the exit code and lets the event loop drain naturally (so closing handles finish cleanly), with a deferred unref'd fallback that force-exits only if an idle keep-alive handle lingers (by which point nothing is mid-close). Verified prompt clean exit (≈130ms, no provider).

## 0.7.1

### Fixed (Windows — found by COO's cross-machine test on a real Windows box)

- **`sym ask` crashed on exit on Windows** with a libuv assertion (`!(handle->flags & UV_HANDLE_CLOSING)`, `win/async.c`, exit `0xC0000409`). The best-effort broadcast socket was closed with `socket.end()`, which leaves the named-pipe handle mid-close; when the command then `process.exit`s, Windows aborts. Now `socket.destroy()` tears the handle down fully (and the timeout is cleared) before exit. Mac/Linux unaffected either way.
- **`sym groups` errored with `spawn dns-sd ENOENT` on Windows** (Apple Bonjour's `dns-sd` isn't installed). It now degrades gracefully — a clear message that LAN group *enumeration* needs the tool, while noting the node still meshes via the bundled pure-JS `bonjour-service` and you can `sym join <name>` directly. Also fixed a timer-ordering bug in the discovery path.

*(Cross-machine mesh, install, and daemon lifecycle all PASSED on Windows in 0.7.0 — these two were the only issues.)*

## 0.7.0

### Added

- **Mesh group commands (MMP §5.8).** `sym start --group <name>` joins a group at launch (+ `--relay-url` / `--relay-token` for WAN); `sym join <name>` switches into one, `sym leave` returns to the default mesh, `sym groups` discovers groups live on the LAN, `sym group` shows the current one. A group is the "group chat" boundary — only nodes in the same group discover each other and exchange CMBs. `lib/groups.js` is the single source of truth for the group↔serviceType mapping (`default → _sym._tcp`, `<kebab> → _<group>._tcp`), matching `sym-mesh-channel` (the Claude MCP node) and sym-swift so CLI, app, and Claude peers meet in the same group. The daemon resolves the group from `SYM_GROUP` env → persisted `~/.sym/group` → default (the file is the cross-platform source of truth across launchd/spawn restarts) and logs it on startup.

### Fixed

- **Windows portability.** `sym stop` no longer shells out to `pgrep` (POSIX-only, absent on Windows): the daemon's pid is tracked in `~/.sym/daemon.pid` and stopped via `process.kill` (pgrep kept only as a Linux fallback). `isDaemonRunning` now checks pid-file liveness on Windows instead of always returning `true`. The group-switch restart uses a portable `Atomics.wait` sleep instead of `execSync('sleep')`. macOS (launchd) path unchanged.

### Docs

- README (EN + ZH) reframed around the node × reach × scope model: the daemon is the polyglot, real-time node (any language joins via shell-out + `sym listen`), not optional; a new Groups section; Privacy reconciled with the relay (local stays local; remote forwards E2E-encrypted bodies through your own authenticated relay). The agent SKILL teaches the group commands.

## 0.6.0

### Added

- **`sym ask "<question>"`** — ask the whole mesh one question and get one synthesized answer. Broadcasts the question to the mesh (best-effort; live agents can contribute and it's logged with lineage), gathers the contributions every peer has fused into shared memory (`~/.sym/nodes/*/meshmem`, ranked by keyword overlap with the question, falling back to most-recent for context), and synthesizes a single answer with the configured LLM provider — each point cited to the agent that supplied it. With no provider configured it prints the ranked raw contributions and their sources instead of erroring, so it always returns what the mesh knows. Flag: `--raw` (skip synthesis, show contributions). This is the headline experience: ask the mesh directly, instead of asking one agent and getting one perspective.
- **`complete(opts)` + `hasProvider(opts)` exported from `lib/llm-reason`.** `complete()` is a free-form sibling of `invoke()` — same Anthropic / OpenAI-compatible / Claude-CLI providers, returns raw text instead of extracting CAT7 (throws `code: 'NO_PROVIDER'` when no key / CLI provider is configured). `hasProvider()` reports whether a provider is configured without making a network call. Used by `sym ask`; available to any caller needing plain LLM completion over the mesh's provider config.

### Changed

- **Skill teaches `sym ask`.** The SYM agent skill gains an "Asking the mesh a question" section so agents query the whole mesh when a question spans other agents' domains. The `.agents/` and `.claude/` skill copies — which had drifted — are reconciled to one canonical source (`.agents/`), with the `.claude/`-only "Real-time listener" section ported in so nothing is lost.
- **README refocused** on a single capability — collective intelligence: ask the mesh, answer as one mind. Defines "the mesh" in plain language up front, answers What / Why / How in the first screen, headlines `sym ask`, and moves the heavy config / drift-math inline reference to spec pointers.

### Tests

- 6 offline tests for `sym ask` (gather + relevance ranking, empty-mesh, no-provider fallback, usage) plus the `llm-reason` synthesis exports. No paid API in CI. Full suite 162 passing.

## 0.5.8

### Added

- **`opts.payload` on `SymNode.remember(fields, opts)`** — optional opaque payload attached to the CMB alongside CAT7 fields. Rides the wire frame (the existing `peer.transport.send({ type: 'cmb', timestamp, cmb })` path serializes the whole cmb object, so payload propagates automatically) and the local store. NOT part of `cmbKey` — CAT7 fields alone remain the content-addressed identity, preserving cross-SDK CMB dedup with sym-core-swift. Substrate-level protocols (LLM request/response primitive, sym.day ATTACH-DATABASE) carry data beyond CAT7 through this slot without violating MMP §8 semantics by smuggling JSON through `motivation` or other CAT7 fields. Senders ensure CAT7 fields differ when payloads differ (e.g. unique request_id in `focus`) to avoid store-side dedup collisions on the CAT7 hash. Backward-compat: when `opts.payload` is omitted, CMB serialization is identical to v0.5.7.

### Compatibility

- Old peers receiving payload-bearing CMBs ignore the unknown field (existing `cmb-accepted` handlers only read `entry.cmb.fields` / `entry.content`). Forward-compat.
- New peers receiving non-payload CMBs from old peers see `cmb.payload === undefined`. Backward-compat.
- `cmbKey()` algorithm unchanged → CMB identity remains stable across the v0.5.7 / v0.5.8 boundary.

## 0.5.7

### Added

- **Origin-aware retention.** `MemoryStore.compactByOrigin(localFreshnessMs, peerFreshnessMs)` lets callers move self-authored CMBs (`peerId == null`) and peer-received CMBs to cold tier on independent freshness thresholds. Useful when the agent's own lineage chains carry more retrospective value than peer chatter — apps configure local > peer freshness so their own emissions survive longer.
- **`SymNode` constructor opts `localRetentionSeconds` + `peerRetentionSeconds`.** Optional overrides of the uniform `retentionSeconds`. When omitted, both fall through to `retentionSeconds` (back-compat preserved). When set, `_runRetentionPurge` (run on start + hourly) uses the new origin-aware path and logs both values when they differ.

### Compatibility

- `MemoryStore.compact(freshnessMs)` is now a back-compat shim that calls `compactByOrigin(freshnessMs, freshnessMs)`. No behavioral change for callers that don't explicitly opt into origin-aware retention.
- Existing apps configured with only `retentionSeconds` see no behavioral change. The new opts are purely additive.

### Tests

- 2 new tests in `tests/memory-store.test.js`: shim equivalence (back-compat) + origin discrimination (peer compacts past peer cutoff while self stays hot under local cutoff). 18/18 pass.

## 0.5.6

### Fixed

- **Apply 1s stale-prior threshold to `_createPeer` path.** v0.5.5
  lowered the threshold to 1s in the inbound-connection handler but
  left the `_createPeer` path on the old `_heartbeatInterval` (10s).
  When both sides of a peer pair dialled each other in rapid
  succession, the inbound handler accepted with the 1s rule but the
  merged `_createPeer` re-evaluated with 10s and could pick the
  opposite winner. Mac-side and Node-side then kept different
  connections, each killing the other's choice — visible in field
  testing as a continuous ~6s join → disconnect cycle even after
  v0.5.5. Aligned both sites on 1s.

## 0.5.5

### Fixed

- **Stale-prior threshold lowered from 10s to 1s.** v0.5.3+v0.5.4
  introduced lastSeen-aware stale detection in the inbound-connection
  and `_createPeer` dedup paths, with the threshold tied to
  `_heartbeatInterval` (default 10s). Field testing showed this was too
  lenient: when a peer process was killed and quickly relaunched, the
  old run had typically sent a CMB seconds before death, so `lastSeen`
  was still within the 10s window. The dedup logic then rejected the
  legitimate redial as a same-direction-duplicate, producing
  `connection ready → immediate disconnect` with no handshake-complete
  on the dialing side.

  Lowered to a hardcoded 1s threshold in both dedup paths.
  Sub-second TCP-retry races during initial handshake still keep prior
  (the case the same-direction-duplicate rule was designed for); peer
  restarts with ≥1s between kill and re-dial now recover within the
  application layer instead of being blocked until OS keepalive reaps
  the underlying socket (~100s).

## 0.5.4

### Fixed

- **Replacement transports never received a handshake; remote rejected the
  next heartbeat-`ping` as a protocol violation.** Companion fix to v0.5.3.
  When the dual-dial dedup or stale-prior swap path in `_createPeer` replaced
  an existing transport, the new transport was registered in
  `existingPeer.transports` but no handshake was sent on it — `_addPeer`
  (which sends the handshake) is only called for brand-new peers, not
  transport replacements. The remote (sym-swift) saw the new connection
  reach `.ready`, sent its own handshake, and waited for ours. Ours never
  arrived. ~10 seconds later the heartbeat tick fired `ping` on every
  transport, the remote saw `ping` as the first frame, and disconnected
  with `[SYM] session: expected handshake, got ping` — protocol violation.
  Net result: a flap loop where every reconnect was killed within 10s by
  the protocol-violation trip-wire.

  Fix: extracted handshake-build into `_buildHandshake()` helper; the
  existing-peer branch in `_createPeer` now sends the handshake on every
  newly-registered transport. Idempotent — if the remote already sent
  its handshake, it processes both fine.

  Verified end-to-end on Mac Catalyst MeloMove ↔ claude-code-mac (Node)
  on the same Mac. Connection stays stable, peers persist in the UI,
  CMBs flow continuously without the periodic 10s drop.

## 0.5.3

### Fixed

- **Same-host loopback peers stayed permanently rejected after one peer
  restarted.** Companion fix to 0.5.2's same-host dedup. v0.5.2's stale-prior
  check looked only at the transport's `_closed` flag — set when
  `transport.close()` had been called explicitly. But the common
  dead-but-ESTABLISHED case (peer process killed; OS doesn't deliver FIN to
  the survivor before macOS keepalive reaps it) leaves `_closed=false`
  forever. On loopback this is a hard block — macOS default TCP_KEEPALIVE is
  7200 seconds (2 hours) before the first probe. The survivor sees the dead
  socket as alive, and the dedup logic against this zombie entry rejects
  every redial from the restarted peer.

  On Wi-Fi the same logical bug is much less visible — mobile TCP routes are
  noisy (route flaps, ARP timeouts, AP transitions) and keepalive idle
  defaults are short, so stale sockets die in seconds. On loopback there's
  zero noise; the dead socket sits in ESTABLISHED indefinitely.

  Observed: Mac Catalyst MeloMove ↔ claude-code-mac (Node) on the same Mac.
  Each Mac MeloMove rebuild → claude-code-mac retains a dead ESTABLISHED
  socket → new Mac MeloMove's redial is rejected for 2h. iPhone ↔
  claude-code-mac on Wi-Fi recovers within seconds because Wi-Fi noise
  reaps stale sockets quickly.

  Three-part fix:

  1. **`TcpTransport` enables TCP keepalive on the socket** —
     `socket.setKeepAlive(true, 1000)`. 1-second initial idle delay before
     OS keepalive probes start, then OS-default probe cadence. macOS detects
     dead remote in ~10s instead of ~2h.

  2. **`inbound-connection` handler and `_createPeer` now treat stale-by-
     `lastSeen` as stale.** A prior peer entry whose `lastSeen` is older
     than `_heartbeatInterval` (default 10s) is now considered stale
     regardless of the `_closed` flag. The remote re-dialling is itself
     strong evidence its prior is dead — a healthy peer wouldn't dial
     again. Closes the dead prior explicitly so its close handler runs and
     removes the dict entry before the new transport is registered.

  3. **Identity-aware close handlers.** When a stale prior is closed and
     replaced, its eventual close handler must NOT clobber the new transport
     entry. Both close handlers in `_createPeer` now guard with
     `transports.get(source) === transport` before mutating the transports
     dict. Prevents a late-firing close from a swapped-out prior tearing
     down its replacement.

  Affects all peers running on the same host as another sym instance, and
  any peer-restart scenario where the peer's TCP socket on the survivor
  side stays in ESTABLISHED state past the OS-level FIN.

## 0.5.2

### Fixed

- **Same-host Bonjour peers permanently rejected each other.** When two
  `@sym-bot/sym` (or sym-swift) processes ran on the same host and
  Bonjour-discovered each other, neither could maintain a peer relationship.
  The `inbound-connection` handler and `_createPeer` short-circuited the
  moment a same-source transport key was present in `peer.transports`,
  regardless of whether that prior was actually alive or what direction it
  was in. Three real failure modes collapsed into the same bug:

  1. **Stale prior** — the previous transport's `_closed` flag was set but
     its close handler hadn't fired yet. Apple's Network framework doesn't
     always deliver FIN promptly when a peer process exits abruptly, leaving
     a dead entry in the transports map. Any reconnect attempt was
     permanently rejected until the OS reaped the dead entry.
  2. **Same-direction duplicate** — listener fires `newConnectionHandler`
     twice for the same advertised service (TCP retry, multipath race,
     repeated Bonjour resolution). Silently replacing the established
     healthy inbound with the duplicate tore down the wire pair on the
     remote side and triggered peer-left storms.
  3. **Dual-dial collision** — both peers Bonjour-discovered each other
     within ~50ms and both initiated outbound TCP. Each side held one
     outbound + one inbound for the same nodeId. The unconditional reject
     killed one side's view of the connection, leaving asymmetric peer
     state.

  Observed in the field on macOS: a Mac Catalyst app (sym-swift) and a
  Node CLI (`@sym-bot/sym`) on the same Mac would never maintain a peer
  relationship — the Node side silently rejected the Catalyst side's
  inbound dial via `transport.close(); return;`. Cross-host LAN peers
  worked because the timing windows differ.

  Fix is two-part, applied in both `inbound-connection` handler and
  `_createPeer`:

  1. **Stale-aware dedup** — short-circuit only when the prior transport
     is alive (`!_closed`). A stale `_closed=true` entry is treated as no
     prior; the new connection replaces it.
  2. **Direction-aware dedup with deterministic tie-break** — for a live
     prior:
     - **Same-direction duplicate** (both inbound or both outbound) →
       keep prior, drop new (no wire-pair teardown on the remote).
     - **Dual-dial collision** (different directions) → nodeId-based
       tie-break. The lower nodeId acts as client and keeps its outbound;
       the higher keeps the matching inbound. Both peers independently
       compute the same physical-socket winner without exchanging
       coordination frames.

  Mirrors the equivalent fix shipped in `@sym-bot/sym-swift` v0.3.79 +
  v0.3.80 so cross-runtime peers (sym-swift ↔ sym Node) now agree on the
  same dedup convention.

  Affects all peers running on the same host with another sym instance,
  and any deployment where Bonjour discovery races finish within ~50ms
  of each other.

## 0.5.1

### Fixed

- **Mac↔Windows peer connections over LAN.** `BonjourDiscovery` now
  publishes an explicit `host` field with a normalized mDNS-valid hostname
  (`.local` suffix). On Windows, `os.hostname()` returns a bare NetBIOS
  name (e.g. `xmesh-hp`) with no domain suffix; `bonjour-service`
  previously advertised that verbatim as the SRV target. macOS
  mDNSResponder only resolves the `.local.` TLD, so the Mac could
  discover the Windows peer via mDNS browse but failed to open an
  outbound TCP connection — hostname resolution returned `No Such
  Record`. CMBs sent to Windows peers never arrived; no replies ever
  came back. (Same class of bug as the 0.3.72 cross-platform resolve
  fix; regression path was the `host` field being unset.)

  Fix is two-part:
  1. `config.loadOrCreateIdentity()` normalizes `identity.hostname` via
     the new `normalizeMdnsHostname()` helper — bare names get `.local`
     appended, FQDNs and already-`.local` names pass through. Existing
     identities with bare hostnames are auto-migrated on next load.
  2. `BonjourDiscovery._startBonjourFallback()` passes the normalized
     `identity.hostname` as the `host` field to `bonjour.publish()` so
     the SRV target matches.

  Affects all peers; Windows nodes must upgrade (their advertisement
  was broken). Mac nodes benefit from the explicit `host:` field for
  determinism even though `os.hostname()` happens to produce
  `.local`-suffixed output on macOS.

## 0.5.0

### Added

- **`node.buildStartupPrimer({ maxCount, maxAgeMs })`** — reconstitute an
  agent's remix memory as a human-readable primer, suitable for injection
  into the LLM context at session start. Operationalises MMP §4.2 O2
  (rejoin-without-replay). A fresh agent session wakes with its prior
  cognitive state already loaded — zero first-turn `sym_recall` overhead.
  Returns `{ text, count, dropped, totalInStore }`. Defaults:
  `maxCount=20`, `maxAgeMs=86_400_000` (24h). Recency window applied
  first, then count cap. Empty store yields an empty primer.

  Intended use — call as the final step of plugin initialisation:

  ```js
  const node = new SymNode({ name, ... });
  await node.start();
  // ... transport, tool surface, subscriptions ...
  const primer = node.buildStartupPrimer();
  mcpServer.instructions += '\n\n' + primer.text;
  ```

  Inherits to every plugin that depends on `@sym-bot/sym`. Consumers:
  `@sym-bot/mesh-channel` v0.3.0, `@sym-bot/melotune-plugin` v0.1.7.

## 0.3.82

### Fixed

- **Remix CMB key self-reference on first-observation (MMP §14).**
  Pairs with the `@sym-bot/core` 0.3.36 fix. When neural SVAF admits
  an incoming CMB, `_processNeuralSVAF` now mints a fresh remix key
  via `remixKey(fusedFields, incomingKey, this._node.name)` and
  overwrites both `fusedEntry.cmb.key` and `fusedEntry.key` before
  remix-store. Previously the receiver preserved the sender's CMB
  key on the stored remix, producing `lineage.parents=[remix.key]` —
  a self-edge that broke DAG traversal. Fix guarantees remix key ≠
  parent key by construction while keeping idempotent dedup for
  retries from the same sender to the same receiver. The heuristic
  SVAF path is fixed in `@sym-bot/core` 0.3.36.

### Changed

- **`@sym-bot/core` dep bumped to `^0.3.36`** for `remixKey` +
  heuristic-SVAF fix.

## 0.3.81

### Added

- **MMP §5.8 mesh group membership.** `SymNode` accepts `opts.group`
  (default `"default"`) and `opts.discoveryServiceType` (default
  `"_sym._tcp"`); both are propagated into `BonjourDiscovery` for
  LAN-layer isolation. The handshake frame version is bumped `0.2.2` →
  `0.2.3` and carries the optional `group` field per §5.2. Matches the
  `sym-swift` `SymNode(discoveryServiceType:)` parameter so Node and
  Swift implementations align.
- **MMP §4.4.4 targeted CMB send.** `SymNode.remember(fields, opts)`
  now accepts `opts.to` (full peerId). When set, the CMB frame is
  emitted only to that connected peer; when omitted, behaviour is
  unchanged (broadcast to all peers). The local store write runs in
  both cases — lineage and §14.7 remix-guard invariants are enforced
  identically.
- **`peers()` exposes `peerId`** (full nodeId) alongside the truncated
  `id` display form, so external callers can resolve a peer by name to
  a full peerId without reaching into internal `_peers` state.
- `tests/remember-targeted.test.js` covering broadcast regression,
  targeted send to connected peer, targeted send to disconnected peer,
  and `peers().peerId` exposure.

## 0.3.80

### Added

- **`frame-handler.js` moved from `@sym-bot/core`.**  FrameHandler is
  protocol plumbing — frame routing, store writes, event emission — and
  belongs in the protocol/node package. Imports now resolve to the local
  copy; `@sym-bot/core` retains a backward-compat re-export.
- **Echo loop prevention (MMP Section 14).** `_handleMemoryShare()` now
  checks whether incoming CMB lineage parents exist as local keys in the
  memory store. If so, the CMB is a derivative of our own broadcast and
  is silently dropped — preventing ping-pong between same-app peers.
- **`MemoryStore.hasLocalKey(key)`** — returns true if a CMB key exists
  in local (non-peer) entries. Used by the echo loop guard.

### Changed

- Bump `@sym-bot/core` dependency to `^0.3.35`.

## 0.3.78

### Changed

- Bump `@sym-bot/core` to 0.3.33. Migrates `@xenova/transformers` →
  `@huggingface/transformers@^4.0.1`. Eliminates deprecated
  `prebuild-install` and the EBUSY DLL lock on Windows.

## 0.3.77

### Fixed

- **Clear socket timeout after TCP connect.** `_connectToPeer` set a
  10-second `socket.setTimeout` as a connect timeout but never cleared
  it after success. The timeout kept firing on the CONNECTED socket,
  killing any LAN connection idle for >10 seconds. Connections now
  stay open indefinitely after establishment.

## 0.3.76

### Fixed

- **Fresh mDNS re-browse on reconnect timer.** The 15s reconnect timer
  now restarts the bonjour-service browser (fresh mDNS query) instead
  of retrying stale cached addresses/ports.
- **On-demand reconnect on send failure.** `node.send()` triggers an
  immediate `discovery.reconnect()` when delivery returns 0 peers,
  instead of waiting for the next 15s timer tick.

## 0.3.75

### Added

- **LAN reconnect timer.** Discovered peers are cached. Every 15 seconds,
  `peer-found` is re-emitted for cached peers not currently connected.
  Handles TCP drops without requiring a process restart.

## 0.3.74

### Fixed

- **Removed leader-election gate from bonjour discovery.** Both sides
  now emit `peer-found` and attempt to connect. The old gate (only
  the lower nodeId initiates) was fragile: stale bonjour cache on the
  initiator side → no connection, because the other side was gated.

## 0.3.73

### Fixed

- **Prefer IPv4 in bonjour-service discovery.** `service.addresses`
  from bonjour-service can include IPv6 link-local (`fe80::...`) which
  requires a scope ID for TCP. Now picks the first IPv4 address.

## 0.3.72

### Fixed

- **Cross-platform LAN discovery: use `bonjour-service` instead of
  native `dns-sd` binary.** The macOS `dns-sd -L` resolve step uses
  unicast DNS-SD queries that fail to resolve services advertised by
  Windows' Bonjour implementation. Browse (multicast) works, but
  resolve (unicast) returns empty — so Mac discovers Windows peers
  but can't get their port, and the TCP connection never happens.
  The `bonjour-service` npm package uses multicast for both browse
  AND resolve, which works cross-platform. Verified Mac↔Windows on
  the same wifi (2026-04-09). The `dns-sd` binary code path remains
  in `lib/discovery.js` as dead code for reference but is no longer
  called.

## 0.3.71

### Fixed

- **`windowsHide: true` added to all 10 child_process spawn sites** so
  Windows agents (especially the four Centro pm2 agents) no longer
  flood the desktop with cmd.exe popup windows on every git query,
  python resolution, port lookup, etc. Sites: 7 in `lib/platform.js`
  (`resolvePython` × 2, `resolveClaudeCLI`, `findProcessByPort` × 2,
  `findProcessByName` × 2, `safeExec` defaults) and 3 in
  `lib/discovery.js` (`dns-sd -R` register, `dns-sd -B` browse,
  `dns-sd -L` resolve). `lib/llm-cli.js` already had it. No-op on
  macOS/Linux. Catalogued by claude-code-win during the 2026-04-09
  cross-machine round-trip session.

## 0.3.70

### Fixed

- **Identity lockfile prevents two SymNode processes from claiming the
  same nodeId on the same host.** `~/.sym/nodes/<name>/lock.pid` is
  acquired in the constructor and released in `stop()`. Cross-process
  duplicates throw `EIDENTITYLOCK`; same-PID re-acquisition (tests,
  hot-reload) is allowed; stale locks (dead PID) are reclaimed
  automatically. Catches the `sym-daemon` + MCP server collision that
  silently broke real-time push on Windows. See `cliHostMode-vs-MCP`
  bug from 2026-04-09 round-trip test.
- **`node.send()` now returns the actual delivered count.** Previously
  returned undefined; sym-mesh-channel had to read `peers().length`
  separately, which could disagree with reality (peers in `_peers`
  with broken transports). `_broadcastToPeers()` now wraps each
  `transport.send()` in try/catch and counts successes. Backwards
  compatible — existing callers ignoring the return value continue
  to work.

### Migration

`SymNode` now acquires a lockfile on construction. Hosts MUST wire
`SIGTERM`/`SIGINT` to call `node.stop()` so the lockfile is cleaned
up — otherwise stale locks accumulate (they're auto-reclaimed on
next startup, but cleaner shutdown is better). sym-mesh-channel
v0.1.3+ already does this.

If two of your processes legitimately need different identities,
set `SYM_NODE_NAME` to distinct values per process. If they're
fighting for the same identity by mistake (e.g. inherited shell
env), the lockfile error message will tell you which PID holds the
existing claim.

## 0.3.69

### Fixed

- Excluded `*.bak`, `*.swp`, `.DS_Store` from published tarball via
  `.npmignore`. 0.3.68 accidentally shipped local backup files. Same
  code as 0.3.68; deprecate 0.3.68.

## 0.3.68

### Fixed

- `RelayConnection` no longer silently reconnects on close code 4004
  ("Replaced by new connection"). Logs FATAL, sets a hard-stop flag,
  fires the new `identity-collision` event, and exits the close
  handler. Breaks the duplicate-identity ping-pong loop. See `d6a17f6`.

### Added

- `identity-collision` event on `SymNode` — `{ nodeId, name, code }`.
  Optional listener; default behavior is loud-log + stop reconnecting.
  Hosts wanting hard-exit semantics should listen and call
  `process.exit()` themselves.

### Why

Two processes holding the same nodeId would enter a 1s ping-pong loop
on the relay, flooding peer-left/peer-joined events. MMP principle:
identity is bound to a keypair, so two simultaneous holders is an
error condition — refuse loudly instead of silently retrying.

## 0.3.67

### Added

- **`sym observe --standalone`** — daemon-less one-shot CMB emission.
  Spins up a fresh `SymNode` inside the CLI process, reads relay
  credentials from `~/.sym/relay.env`, emits one CMB, and disconnects.
  Works even when `sym-daemon` is not running — the daemon becomes an
  optimisation, not a requirement. Auto-enabled as a graceful fallback
  whenever the daemon is down, so existing `sym observe` commands no
  longer fail with "sym-daemon is not running."
- **`sym observe --name <id>`** — set the mesh identity for
  standalone-mode emissions. Defaults to `sym-cli`. Identity is stable
  across invocations via the cached `SymIdentity` keypair in
  `~/.sym/nodes/<name>/`, so repeated calls with the same name resolve
  to the same `nodeId`. Claude Code users should pass
  `--name claude-code-mac` (or `claude-code-win` / `claude-code-linux`)
  so their CMBs are attributable on the mesh grid.
- **`sym observe --parents <key1,key2>`** — comma-separated parent CMB
  keys for remix lineage. Using this flag implies `--standalone` (the
  daemon IPC `remember` handler does not accept lineage parents). Makes
  it trivial to emit resolution CMBs that close upstream tickets on the
  Review Board via the SVAF lineage graph.

### Why

Before this release, `sym observe` required `sym-daemon` to be running
— any user who had stopped the daemon (or never started it) hit a hard
failure. This was the main friction for Claude Code sessions that want
to participate in the mesh as real peers without running a persistent
background daemon. The daemon-less path makes the entire mesh emission
surface usable out of the box after `npm install -g @sym-bot/sym`.

### Migration

No breaking changes. Existing `sym observe '<json>'` calls continue
to work unchanged when the daemon is running (same IPC fast path).
When the daemon is down, the CLI now falls back to standalone mode
instead of failing.

## 0.3.66

### Changed (MMP v0.2.2 spec conformance)

- **`state-sync` frame is now deprecated.** CfC hidden states never cross
  the wire under SVAF (Xu, 2026, *Symbolic-Vector Attention Fusion for
  Collective Intelligence*, [arXiv:2604.03955](https://arxiv.org/abs/2604.03955),
  §3.4). Cognitive coupling propagates as **CMBs** at SVAF Layer 4 only;
  the per-agent CfC at Layer 6 stays private to each agent.
- `_reencodeAndBroadcast()` updates the local CfC only; no `state-sync`
  broadcast.
- `updateContext(text)` updates the local CfC only; no `state-sync`
  broadcast.
- The per-handshake `state-sync` send is removed. Handshake exchanges
  identity, version, and lifecycle role only; cognitive bootstrap
  happens via the anchor CMB exchange that follows.
- Coordinated with `@sym-bot/core` 0.3.32, which silently drops inbound
  `state-sync` frames at the frame-handler with a deprecation log.
- The wire format is preserved (the `state-sync` frame type is still
  parseable for backward compatibility with v0.2.0 / v0.2.1 peers); only
  the *send* paths are removed.

### Migration

If you previously listened for `coupling-decision` events driven by
state-sync, switch to events emitted by the CMB pipeline
(`memoryReceived`, `cmbAccepted`) and read `(valence, arousal)` from
`cmb.fields.mood`. The mood field is delivered across domain boundaries
even when SVAF rejects the rest of the CMB (MMP §9.3 protocol guarantee R5).

## 0.3.65

### Fixed
- `sym-daemon` default node name is now platform-scoped (`sym-daemon-mac` / `sym-daemon-win` / `sym-daemon-linux`) instead of the hardcoded `sym-daemon-win`. The hardcoded fallback caused Mac daemons to identify as `sym-daemon-win`, leading to identity collisions and stale `~/.sym/nodes/` directories on cross-platform development machines.

## 0.3.64

### Fixed
- Bumped `@sym-bot/core` to `^0.3.31` to restore `cmb-accepted` event emission in `cliHostMode`. Without this bump, `bin/sym-daemon.js`'s `cmb-accepted` listener never fires under `cliHostMode`, silently disabling `sym sub` IPC subscribers and the daemon→hosted-agent fanout path.

## 0.3.63

### Changed (BREAKING)
- `sym-daemon` now uses `cliHostMode: true` (renamed from `relayMode`). Daemon no longer stores forwarded CMBs — eliminates ~5x duplication on multi-agent hosts.
- `sym recall` is now federated: scans `~/.sym/nodes/*/meshmem/` directly, deduped by CMB key, sorted by recency. Works without the daemon. New `--node <name>` flag scopes the scan.
- Requires `@sym-bot/core@^0.3.31` (originally shipped against 0.3.30; 0.3.30 had a regression — see sym-core CHANGELOG).

## 0.3.61

### Fixed
- **High-quality CMBs were silently buried**, never promoted to the Review Board, because of two compounding bugs:
  1. `lib/llm-reason.js` appended a hardcoded "Return a JSON object with 7 CAT7 fields" suffix to every prompt, **with no mention of `_meta`**. This overrode any `_meta.founderAction` instructions the agent's role definition (SKILL.md) tried to convey, so the model emitted just the 7 fields and the founderAction signal was lost. Suffix now requests the optional `_meta` tag explicitly: `_meta:{founderAction, urgency, reason}` and instructs the model to set it per role rules.
  2. `lib/mesh-agent.js` `detectFounderAction` (the fallback when `_meta` is missing) only scanned `intent + issue` and only matched a hedge-paraphrase vocabulary list (`prioritize`, `monitor`, `competitive`, etc.). Disciplined extraction prompts produce CMBs with concrete verbs like `fetch`, `flag`, `draft`, `endorser`, `arxiv`, `cite`, `respond`, `submit` — none of which were in the list, so high-quality CMBs failed to promote. Now scans `intent + issue + commitment + mood.text` (wider field surface) and the keyword list is expanded with concrete-action verbs, research vocabulary, and stakes-signalling affect words.

Verified: a real research-win arxiv CMB ("Fetch full PDF today. Check author list for endorser candidates...") now correctly promotes via the keyword fallback path. Going forward, disciplined agents using the `_meta` schema in their prompt suffix will set founderAction explicitly and bypass the keyword fallback entirely.

## 0.3.59

### Fixed
- **Windows terminal popups in CLI provider** (`lib/llm-cli.js`) — `claude` resolved to a `.cmd` shim that opened visible cmd.exe windows on every spawn. Now uses `platform.resolveClaudeCLI()` to get the node binary + `cli.js` path directly, plus `windowsHide: true` on the spawn options.
- **Per-agent env vars not loaded at module-load time** (`lib/mesh-agent.js`) — agents read `SYM_RESEARCH_PROVIDER`, `SYM_COO_MODEL`, etc. at top-of-file constants before the `MeshAgent` constructor runs. Added a top-level `loadRelayEnv()` IIFE that loads `~/.sym/relay.env` when `mesh-agent.js` is first required, so per-agent env overrides resolve correctly.

## 0.3.58

### Added
- **Claude Code CLI provider** (`provider: 'cli'`). Spawns `claude -p --output-format json` as a subprocess instead of hitting an HTTP API. Gives every agent the full Claude Code tool surface — Read, Write, Bash, Grep, WebFetch, Skill, etc. — and auto-loads `CLAUDE.md` / `.claude/settings.json` / project skills from the agent's working directory. Uses local Claude Code auth (no API key needed). Per-call options: `model` (opus/sonnet/haiku alias or full id), `addDirs`, `allowedTools`, `permissionMode` (default `bypassPermissions`), `maxBudget` (passed as `--max-budget-usd`), `timeoutMs`. Selectable via `provider: 'cli'` per call or `SYM_LLM_PROVIDER=cli` globally. See `lib/llm-cli.js`.
- This is the path for the existing `addDirs` parameter that HTTP providers were silently ignoring — agents that already passed `addDirs: [...]` get directory access for free as soon as they switch provider.

### Changed
- `lib/llm-reason.js` `getProviderConfig` and `invoke` updated to dispatch `cli` / `anthropic` / `openai`. CLI provider skips the API-key check (uses local Claude Code auth) and skips `withRetry` (subprocess errors aren't typically transient).

## 0.3.57

### Changed
- **`MemoryStore._cmbKey` now delegates to `@sym-bot/core` `cmbKey()`** instead of re-implementing the SHA256-truncate logic. Eliminates duplicated CMB key code that had drifted multiple times. Single source of truth lives in `sym-core/lib/cmb-encoder.js`. The raw-content fallback path remains a direct SHA256 (distinct input space, cannot collide with the field-keyed path).
- **`@sym-bot/core` dependency bumped** to `^0.3.29` to pick up the new `cmbKey` export and the FNV-1a context encoder fix. The encoder fix restores cross-SDK n-gram embedding parity with `sym-core-swift` for the first time — see `@sym-bot/core` 0.3.29 changelog for the wire-impact details.

## 0.3.56

### Changed
- **CMB content key algorithm: MD5 → SHA256 (truncated to 32 hex chars).** `MemoryStore._cmbKey()` now uses `crypto.createHash('sha256').digest('hex').slice(0, 32)` for both the field-text and raw-content code paths. This duplicated CMB-key logic (separate from `@sym-bot/core` `cmb-encoder.js`) is now back in sync. Wire-breaking with respect to dedup against pre-0.3.56 stored CMBs. Coordinated with `@sym-bot/core` 0.3.28 and `sym-core-swift` 0.3.6.
- **`@sym-bot/core` dependency bumped** to `^0.3.28`.

### Fixed
- Removed accidental self-dependency `@sym-bot/sym: ^0.3.43` from `package.json` `dependencies`. The package now declares only its real runtime deps (`@sym-bot/core`, `bonjour-service`, `ws`).

## 0.3.25

### Changed
- **sym-core 0.2.0** — semantic encoder for SVAF evaluation. Paraphrase similarity: 0.31 (n-gram) → 0.69 (semantic). Per-field evaluation quality bounded by encoder quality, not model capacity.

## 0.3.24

### Added
- **Catchup via mesh broadcast.** Daemon broadcasts `"catchup"` message to all peers. `MeshAgent` listens for it and triggers immediate domain poll. Replaces the old hosted-agent-only catchup path.

## 0.3.23

### Added
- **Handshake: `version` and `extensions` fields** per MMP v0.2.1 Section 5.2. Handshake now sends `version: "0.2.1"` and `extensions: []`.
- **Error frame support** per MMP v0.2.1 Section 7.2. `sendError(peerId, code, message, detail)` sends protocol-level error frames. Codes 1xxx close connection; 2xxx informational.

### Parity
- 100% feature parity with sym-swift (Swift SDK). Both SDKs implement all 10 frame types, handshake with version/extensions/e2ePublicKey, error frames, multi-transport per peer, SVAF per-field evaluation, MD5 content-addressable CMB keys, lineage, remix guard, and metrics.

## 0.3.22

### Changed
- **MeshAgent: every agent is a standalone peer node** (MMP v0.2.1). Removed hosted/daemon mode. Every `MeshAgent` creates its own `SymNode` with own identity, transport, coupling engine, and memory store. Coupling is per-node — agents that share another node's identity cannot have independent SVAF weights.
- **`sym recall --json`** — new flag returns full entry objects (source, peerId, CMB fields, lineage) as JSON. Enables sym.day to get real source data from daemon memory.

### Tests
- 119 tests (was 100). MeshAgent test updated for standalone-only constructor.

## 0.3.21

### Added
- **MeshAgent** — protocol-level agent lifecycle class. Agents provide `fetchDomain()`, `reason()`, `remix()`. Protocol handles event-driven remix, `canRemix()` gate, fingerprint dedup, lineage, silence. No LLM code in SDK.
- **`sym metrics`** — new CLI command exposing protocol-level metrics (CMBs, peers, LLM cost, uptime)
- **`--json` flag** for `sym status`, `sym peers`, `sym metrics` — structured output for programmatic consumers

### Fixed
- **Remix guard**: `remember()` with parents now resets `hasNewDomainData`. Previously a remix counted as new domain data, allowing infinite remix chains from a single observation.
- **Startup race**: relay disconnect handlers directly deleted peers, bypassing multi-transport failover (Section 4.6/5.5). Now only closes the relay transport — Bonjour survives.
- **Undefined variables** in `_handleRelayPeerLeft` (`peers`, `peer`) — leftover from refactoring.

### Changed
- IPC socket moved from `/tmp/sym.sock` to `~/.sym/daemon.sock` per spec Section 4.5. `SYM_SOCKET` env var still overrides.

### Tests
- 100 tests (was 83). Added: remix guard reset, MeshAgent validation, CLI --json, socket path.

## 0.11.1 (2026-08-10)

### ⚠ Wire changes — every node must move together

**The CAT7 container is `categories`.** A record is `{ categories, metadata }`. Nodes on 0.11.0 and
earlier do not read this container name.

**The LAN rendezvous is `_symrooms._tcp`.** A node on this version and one on 0.11.0 **cannot
discover each other, in either direction, with no error to explain the silence.** The word there is
not a concept, it is an address.

**The persisted room moved filename.** The retired file is *not* read — one name, no fallback — but
its presence is now announced: the daemon names the file, the room it held, and the command that
restores it. Without that, an upgraded node silently starts in `default`, loses every peer, and says
nothing.

### Changed — group is now room, with one meaning

Identifiers, the `SYM_ROOM` environment variable, the persisted state file, the module files, and
the beacon. The audience of a record has been `room` since the two-section record; the discovery
group is the same concept and now carries the same word.

### Changed — `@sym-bot/core` 0.8.1 → 0.9.3

Adopts the renamed core surface (`computeCategoryVerdicts`, `categoryKeyV1`,
`encryptCategories`/`decryptCategories`, `encodeCategory`, `categoryWeights`, `categoryDrifts`,
`categoryVerdicts`, `categoryParents`) and core's fallback removals. **Drift arithmetic changes** for
stores whose anchors carry no confidence — core no longer invents one.

### Removed — grandfathering of pre-boundary records

A pre-boundary record carried its audience under the retired name, so its audience can no longer be
established, and core refuses it rather than treating an absent room as a broadcast. **A node holding
genuine pre-boundary history will now see it refused rather than surfaced.** Refused is still not
forged: such a record does not touch the forgery counter, because an operator watching that counter
at cutover must not see ordinary history in it.

