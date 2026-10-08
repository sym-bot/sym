# Authority in sym 0.14: an operator's guide

sym 0.14 implements MMP §6.6. Authority (who is an admin, a validator, an issuer) is a set of signed
statements (grants, revokes and endorses) rooted at an **anchor pin** you configure on every node. A
node computes what is in force from the statements it holds and from nothing else, so every node
holding the same statements under the same pin agrees. This guide covers configuring the pin,
changing it, and the one-time re-issue after upgrading from 0.13.

## 1. Configure the pin

The pin is a set of Ed25519 public keys and a threshold t: an anchor-level statement counts when t
distinct pinned keys have signed it. Configure the same pin on every node, out of band. It is never
learned from the network.

```js
// One founder key (the 1-of-1 case). The nodeId lets that node act as the anchor itself.
new SymNode({ name: 'founder', anchor: { threshold: 1, keys: [{ key: '<base64url key>', nodeId: '<uuid>' }] } });

// Three key holders, any two of whom act as the anchor.
new SymNode({ name: 'n', anchor: { threshold: 2, keys: [{ key: K1 }, { key: K2 }, { key: K3 }] } });
```

- `SYM_FOUNDER_ANCHOR="<nodeId>:<publicKey>"`, or the pin as JSON, does the same for a node built
  without the `anchor` option. A node's own key and nodeId are `node.publicKey` and `node.nodeId`.
- A pin that does not parse stops the node: it never runs without the root it was asked for.
- With no pin, nothing is in force. The node ignores authority frames, resolves everyone as a
  participant, and uses its configured `lifecycleRole` for its own validation (a closed development
  mode).
- `node.authorityStatus()` (and `status().coreSecure.authority`) shows the pin digest, the authority
  root, the in-force count and this node's roles. Two nodes with the same root hold the same
  authority.

## 2. Grant, revoke, endorse

Under a 1-of-1 pin the node holding the pinned key signs anchor-level statements by itself:

```js
node.grantRole(peerNodeId, 'validator');                  // the peer's key must be proven or pinned here
node.grant({ nodeId, key }, 'admin');                     // or name the key yourself
node.grant({ nodeId, key }, 'issuer', { scope: 'xmesh-world:w1' });
node.revokeRole(peerNodeId);                              // every in-force grant naming it that this node may remove
node.endorse([statementId]);                              // keep what a revoke cut off, where it should stand
```

Under a threshold above 1, one holder signs and the others co-sign, then any node submits it:

```js
const half = holder1.authorityStatement({ kind: 'grant', subject: { nodeId, key }, role: 'admin' }, { asAnchor: true });
const whole = holder2.cosignAuthority(half);              // add more holders until t have signed
anyNode.submitAuthority(whole);                           // then it spreads by gossip
```

An admin grants and revokes below itself the same way (`node.grant`, `node.revoke`). Delegation is
at most 4 links from the anchor; a scoped grant can only narrow its parent's scope.

## 3. Re-pin

Change the pin on every node and restart it. Nothing is deleted: statements are kept in one file
(`authority/statements.jsonl` in the node directory) whatever the pin, and at each start every
statement is judged again against the pin in force.

- **Dropping a compromised key, keeping a threshold of the old ones** (2 of 3 to 2 of 2, or 2 of 3
  to 2 of 3 with the bad key replaced): every anchor-level statement that the kept keys alone still
  sign t times keeps counting, and so does everything below it. A statement that needed the dropped
  key to reach t stops counting; re-sign it with the keys you keep.
- **Under a threshold of 1** every pinned key alone is the root, so removing a key removes what it
  alone signed.
- **A mistyped pin** destroys nothing: the node resolves nothing until you correct the pin and
  restart, and then finds everything again.
- **Compromise of t keys** is compromise of the root. Recover by pinning new keys everywhere, out of
  band, and re-issuing the grants that should stand.

## 4. Upgrading from 0.13: the flag day

sym 0.14 resolves no authority from the role grants 0.13 signed (MMP §6.6.11). After the upgrade
every node except the pinned anchor holder resolves as a participant until grants are re-issued
under the new rule. Re-issue at once, top down:

1. **The anchor's holder** lists the old grants and re-issues each it still regards as in effect,
   with the same subject and key; the 0.13 `anchor` role becomes `admin`:

   ```js
   for (const g of node.legacyRoleGrants()) {           // plain data: never verified, never resolved
     if (!stillStands(g)) continue;                      // your judgement, not the old store's
     if (g.granteeKey) node.grant({ nodeId: g.grantee, key: g.granteeKey }, g.role);
     else node.grantRole(g.grantee, g.role);             // a key proven by a session, or pinned, first
   }
   ```

2. **Each grantor**, once it holds its own new grant, re-issues the grants it signed under 0.13, if
   §6.6's role table permits them and they fit in 4 links. A link that does not fit (a validator
   that promoted a validator) does not carry over; that grantee needs a grant from the anchor or an
   admin.
3. A grant an old revoke had cleared is simply not re-issued.

Until a node is re-granted it is a participant everywhere. Nodes still running 0.13 ignore the new
frames and keep the old authority; the two kinds see only their own.
