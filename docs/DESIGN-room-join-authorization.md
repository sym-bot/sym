# Room join authorization — membership by grant, not by knowledge of a string

**Date:** 2026-08-26 · **Author:** dev1 (sym runtime lane) · **Status:** v2 — mesh review SHIP-WITH-FIXES folded (x-review cmb-3e58586f…, 12 findings, all applied); FOUNDER RULED 2026-08-26: (1) grammar fix NOW, ahead of the gate; (2) ADOPT B AS FOLDED (owner-only, 24h lifetime, join-time expiry, handshake enforcement, default+sym public). Implementation = ordinary mesh-reviewed sym-lane work
**Prior:** the C+D standing-rooms ruling (xmesh docs/DESIGN-tenancy-standing-rooms.md, founder
2026-08-26) names this as its residual: "sym resolves rooms by string … full closure needs
sym-side join authorization." This is that design.

## What a room IS today (measured, 2026-08-26, not recalled)

A room is a NAME. Three independent paths turn knowledge of the name into membership, and
none of them asks anyone's permission:

1. **LAN (mDNS).** `lib/rooms.js` maps name → service type; whoever advertises/browses the
   type is in the room. Probed today: a 43-byte tenant-suffixed type
   (`_probe-room--team-<24hex>._tcp`) registers, browses, and does NOT leak onto `_sym._tcp`
   — macOS does not enforce RFC 6763's 15-byte service name cap, so isolation-by-name works ON
   MACOS (review F10: responders that enforce the cap are unmeasured, and a truncating
   responder collides long names onto shorter ones — false-ADMIT, the silent class); nothing
   anywhere makes it isolation-by-right.
1b. **The handshake checks nothing (review F2).** The handshake frame CARRIES the room
   (`lib/node.js:2516`) and binds it into the transcript (`core/handshake-v2.js:78`), but the
   ingest side never compares it — a peer handshaking with a foreign room claim is admitted to
   the peer set today. LAN isolation is a property of the browse filter alone. The enforcement
   point below is BUILT, not extended.
2. **Same host (loopback registry).** `lib/discovery.js _scanLoopback()` dials every fresh
   endpoint file whose `serviceType` string equals ours. Exact string match — this is what has
   isolated the three tenants on one Mac since the desk-room suffix (2026-08-18). Any process
   that can write a JSON file with the right string is a member.
3. **Relay.** `sym://team/{name}?relay=…&token=…` — the token authenticates to the RELAY, not
   to the room: any relay-token holder joins any room string on that relay. Invites
   (`sym-mesh-channel server.js`) are pure name carriage.

The receiving node's SVAF membrane governs what it ADMITS INTO MEMORY — it has never governed
who may stand in the room, hear broadcasts, and speak. The week of 2026-08-19..26 measured
what that costs: four cross-tenant deliveries, three seats' debugging time, and a product
release (xmesh 0.9.23 C+D) built to fence the WRITE path because the JOIN path could not
refuse anyone.

## The inconsistency found while probing (fix first, separately)

`lib/rooms.js isValidRoom` rejects `--` (kebab-case, single hyphens), so **sym's own CLI and
daemon cannot join the tenant-suffixed rooms xmesh now standardizes on** — xmesh only works
because it passes `discoveryServiceType` directly, bypassing validation. Either the suffix
grammar becomes legal sym-wide or the substrate and its flagship product disagree about what
a room name is. THREE sites, not one (review F4): the `lib/rooms.js` regex; the existing test
that pins `a--b` invalid (`tests/rooms.test.js:42` — a wrong expectation corrected, named so
the red test is not reasoned backwards); and sym-mesh-channel's independent copy of the same
regex (`server.js:59`, enforced inside `sym_invite_create` at `:1139`) — leave that one and
the inconsistency moves instead of closing. Shippable ahead of everything below, and a
PREREQUISITE for B's invite path (review F12): until `sym_invite_create` accepts the suffix,
B cannot mint an invite for any room xmesh actually creates.

## What already exists to build on (read, not imagined)

- **Ed25519 node identity** and **roster-keys** (`lib/roster-keys.js`): authenticated
  nodeId→publicKey bindings with source precedence — anchor (2) > handshake (1) > grant (0);
  a gossiped grant can never overwrite a handshake-learned key; the relayer never vouches.
- **Signed grants** along the rooted authority chain (`lib/role-grant-store.js`): a grant
  binds the grantee's key into the grantor's signed payload — tamper-evident vouching that
  already teaches third parties a key they never handshook.
- **Frame-level shared-secret encryption** (consumed by xmesh's control plane: "opened with
  the peer's shared secret"). The crypto for content protection exists; this design does not
  add any.
- **Invites** as the human-shaped carrier: `sym_invite_create` already produces the URL a
  teammate pastes. Today it carries a name; it can carry a grant.

## Options

**A — Room secret.** The room's creator mints a symmetric key; invites carry it; room frames
are MAC'd/encrypted with it. Strongest confidentiality, worst lifecycle: removing a member
means rekeying everyone, losing the key means losing the room, and every app (sym-swift,
MeloTune's room code, xmesh operators) must hold secrets it never held. A v2 layer, not the
v1 gate.

**B — Join grants on the existing precedence (recommended).** A room may declare an OWNER
(the identity that created it — for xmesh rooms, the tenant's operator; for the default room,
nobody: `default` stays open BY DESIGN, it is the public square). Joining an owned room means
presenting a **room-join grant**: a signed statement by the owner — v1 is OWNER-ONLY; the
draft's "or a member the owner authorized to invite" smuggled in delegation with no depth,
no attenuation and no bound, and the review struck it (delegation is its own future design,
and role-grant-store already shows the chain problems it must solve) — binding
`{room, grantee nodeId, grantee pubkey, expiry}`. Grants have a MAXIMUM lifetime of 24h:
that number IS the revocation exposure window for an offline peer (review F3 — revocation is
live gossip with no catch-up replay on reconnect, so an offline peer's stale binding survives
until expiry; B does not escape A's rekey cost, it RENAMES it into this bounded window, and
that is still the better trade). Expiry is evaluated AT JOIN ONLY, with ±5 min skew
tolerance: an admitted peer is never evicted mid-session by its grant lapsing (review F9 —
a phone's mood-room node must not strand mid-session; it re-presents a fresh grant on its
next join).

ONE enforcement point, receiver-side, direction-agnostic (review F1/F2): the HANDSHAKE. The
receiver compares the handshake's room claim (carried and transcript-bound today, compared
NOWHERE today — this check is new code on every path) and, for an owned room, verifies a
valid grant before the peer enters the room's peer set — regardless of who dialled whom
(loopback's lower-nodeId-dials tie-break means the stranger dials US in half of all
orderings; a scan-side skip alone is dead code for those pairs and survives only as a
dial-saving optimisation). The relay path runs the same check on first frame from an unseen
peer. No new crypto: grants and roster precedence exist; the invite URL becomes
`sym://room/{name}?grant=<base64url signed grant>` — sym-mesh-channel's `sym://room/` grammar
extended with one parameter; sym-swift parses a DIFFERENT grammar (`sym://invite/v1`,
`SymInviteURL.swift:73` — it would return nil on this shape) and needs the `grant` parameter
added to its own parser as part of the work, not as an afterthought (review F6).

**C — Stay at the product layer.** Today's state: xmesh fences writes (D), scopes names (C),
and the residual is accepted. Honest, already shipped, and the reason this document exists —
the design that ends at C is the one that keeps paying this week's cost on every new surface.

## Asymmetric error costs (the tie-breaker, stated)

False-REFUSE a legitimate joiner: visible immediately (their join fails), recoverable with a
fresh invite. False-ADMIT a stranger: silent for weeks, discovered by forensics — the exact
class the last week was spent on. The gate fails closed on owned rooms; rooms without owners
behave exactly as today, so nothing existing breaks on upgrade day. And the boundary's edge,
stated (review F11): B defends against misconfiguration and unauthorized REMOTE peers. A
same-uid process on the host is outside it and always was — the loopback registry, the
grant store and the node's key material all live under one `os.homedir()`, so a same-uid
adversary presents a real grant rather than forging one. What B stops is the class the week
of 2026-08-19..26 actually cost: accidents and cross-tenant misconfiguration.

## Compatibility constraints (each one load-bearing)

- `default` room: never owned, never gated — MMP §5.8's public mesh stays public. And
  `sym` is RESERVED and may not be owned (review F5): `roomServiceType('sym')` returns
  `_sym._tcp` and the inverse resolves to `default` — the mapping is not injective, so an
  "owned" room named `sym` would silently BE the public square. Refuse ownership on any name
  whose service type round-trips to a different name.
- Unowned named rooms: unchanged. Ownership is opt-in AT CREATION; existing rooms have no
  owner and no gate. sym-swift (v0.5.5; the relay ≥ 0.1.3 room-partition
  contract — MeloTune Core's m134, misattributed to sym-swift in the draft, review F7) and
  MeloTune's room code see zero behavior change until an app explicitly creates an owned
  room — verified by the review across every shared-named-room creator it could enumerate
  (its denominator and its pagination caveat are in the review's NOT CHECKED). One adjacent
  fact, not a conversion: MeloTune's mood-room names derive from uppercase UUIDs and are
  illegal under BOTH the current and widened kebab grammar — they work only because the app
  passes service types directly, same as xmesh. The grammar is advisory everywhere; another
  reason enforcement lives at the handshake, not in a regex.
- Mixed-version meshes: an old peer in an owned room cannot present a grant. The owner's
  invite can carry `legacy=1` marking the grant as pinned owner-side only (the owner and
  updated peers refuse strangers; the old peer joins as today). Partial enforcement stated
  honestly beats a flag-day nobody will run — and STATED means to the OPERATOR, not to this
  document's reader (review F8): the room's mode — `open` / `gated` / `gated-partial:<n>
  legacy peers` — prints from `sym room` and in the daemon's start line, and a room never
  transitions between modes silently. Today both surfaces print name and service type only;
  a legacy-partial room and a fully gated one are visually identical, which is the false
  sense of a closed boundary this line exists to prevent.
- The relay never vouches and never parses grants — verification stays at receiving nodes,
  exactly as roster-keys already rules for key bindings.

## Scope of the ruling requested

(1) Fix the room-name grammar inconsistency now — three sites, and a prerequisite for B's
invite path (yes/no). (2) Adopt B as the v1 join gate as folded above — owner-only grants
(delegation deliberately excluded from v1; the review flagged the draft's parenthetical as a
third decision smuggled into two questions, and it is withdrawn rather than asked), 24h max
grant lifetime as the stated revocation window, join-time-only expiry, handshake as the one
enforcement point — with A explicitly deferred and C explicitly rejected as an end state
(the recommendation). Implementation follows as ordinary mesh-reviewed work in the sym lane,
behind the two-stock-nodes gate like every sym change since 0.12.0.

## Review verdicts folded (2026-08-26, x-review cmb-3e58586f…, SHIP-WITH-FIXES, 12 findings)

All twelve applied in place above. The ones that reshaped the mechanism rather than the
prose: F1/F2 — enforcement moved to ONE receiver-side handshake check (new code, not an
extension; the loopback scan-skip demoted to optimisation; no room comparison exists at
handshake today); F3 — 24h max grant lifetime IS the stated offline-revocation window (B
renames A's lifecycle cost, not escapes it); F9 — expiry join-time-only, ±5 min skew, no
mid-session eviction; F5 — `sym` reserved (non-injective service-type mapping); F6 —
sym-swift's second invite grammar named as work; owner-only v1 (the delegation parenthetical
withdrawn). The review's NOT CHECKED list — notably the relay server's handling of room-less
auth, non-macOS mDNS truncation, and the paginated room-creator enumeration — carries into
implementation as measurements owed, not assumptions granted.
