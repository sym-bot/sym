# Room join authorization — membership by grant, not by knowledge of a string

**Date:** 2026-08-26 · **Author:** dev1 (sym runtime lane) · **Status:** DRAFT for mesh review
**Prior:** the C+D standing-rooms ruling (xmesh docs/DESIGN-tenancy-standing-rooms.md, founder
2026-08-26) names this as its residual: "sym resolves rooms by string … full closure needs
sym-side join authorization." This is that design.

## What a room IS today (measured, 2026-08-26, not recalled)

A room is a NAME. Three independent paths turn knowledge of the name into membership, and
none of them asks anyone's permission:

1. **LAN (mDNS).** `lib/rooms.js` maps name → service type; whoever advertises/browses the
   type is in the room. Probed today: a 43-byte tenant-suffixed type
   (`_probe-room--team-<24hex>._tcp`) registers, browses, and does NOT leak onto `_sym._tcp`
   — macOS does not enforce RFC 6763's 15-byte service name cap, so isolation-by-name works;
   nothing makes it isolation-by-right.
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
grammar becomes legal sym-wide (one regex change: `/^[a-z0-9]+(?:--?[a-z0-9]+)*$/`) or the
substrate and its flagship product disagree about what a room name is. Small, shippable
ahead of everything below, and blocking nothing.

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
presenting a **room-join grant**: a signed statement by the owner (or a member the owner
authorized to invite) binding `{room, grantee nodeId, grantee pubkey, expiry}`. Enforcement
is receiver-local and fail-closed per path:
  - loopback scan: skip endpoint files for owned rooms when no valid grant is pinned for that
    nodeId;
  - LAN: same check at handshake before the peer enters the room's peer set;
  - relay: same check on the first frame from an unseen peer in an owned room.
No new crypto (grants and roster precedence exist), no rekeying problem (revocation = the
owner publishes a signed revocation; peers drop the binding), and the invite URL becomes
`sym://room/{name}?grant=<base64url signed grant>` — the same paste-a-link flow that ships
today, now carrying a right instead of a hint.

**C — Stay at the product layer.** Today's state: xmesh fences writes (D), scopes names (C),
and the residual is accepted. Honest, already shipped, and the reason this document exists —
the design that ends at C is the one that keeps paying this week's cost on every new surface.

## Asymmetric error costs (the tie-breaker, stated)

False-REFUSE a legitimate joiner: visible immediately (their join fails), recoverable with a
fresh invite. False-ADMIT a stranger: silent for weeks, discovered by forensics — the exact
class the last week was spent on. The gate fails closed on owned rooms; rooms without owners
behave exactly as today, so nothing existing breaks on upgrade day.

## Compatibility constraints (each one load-bearing)

- `default` room: never owned, never gated — MMP §5.8's public mesh stays public.
- Unowned named rooms: unchanged. Ownership is opt-in AT CREATION; existing rooms have no
  owner and no gate. sym-swift (v0.5.5, m134 token+partition contract) and MeloTune's room
  code see zero behavior change until an app explicitly creates an owned room.
- Mixed-version meshes: an old peer in an owned room cannot present a grant. The owner's
  invite can carry `legacy=1` marking the grant as pinned owner-side only (the owner and
  updated peers refuse strangers; the old peer joins as today). Partial enforcement stated
  honestly beats a flag-day nobody will run.
- The relay never vouches and never parses grants — verification stays at receiving nodes,
  exactly as roster-keys already rules for key bindings.

## Scope of the ruling requested

(1) Fix the room-name grammar inconsistency now (yes/no). (2) Adopt B as the v1 join gate,
with A explicitly deferred and C explicitly rejected as an end state (the recommendation).
Implementation follows as ordinary mesh-reviewed work in the sym lane, behind the two-stock-
nodes gate like every sym change since 0.12.0.
