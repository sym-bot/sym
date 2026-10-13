'use strict';

/**
 * A fake sym-relay for tests: relay-auth, relay-peers, relay-peer-joined/left, envelope routing
 * ({to, payload} → {from, fromName, payload}), the 0.5 token bucket per connection (close 4008),
 * duplicate-identity replacement with 4004 and no peer-left, and — when `fanout` is set — the
 * fan-out envelope of MMP spec draft PR #25 ({ fanout: [{ to, payload }, …] }, one message, counted
 * once), listed in relay-peers as `features: ['fanout']`; a fan-out naming a recipient twice is
 * refused whole with relay-error.
 *
 * `tap(env)` sees every routed payload ({ from, to, payload }) and may return:
 *   undefined → deliver as is;  false → drop;  an object → deliver that payload instead.
 */

const { WebSocketServer } = require('ws');

function fakeRelay({ ratePerSec = 25, burst = 300, fanout = false, maxFanout = 64, tap } = {}) {
  // maxFanout: what this relay accepts (the draft's floor is 64); a longer fan-out is refused whole.
  const wss = new WebSocketServer({ port: 0 });
  const conns = new Map(); // nodeId -> { ws, name }
  const stats = { framesIn: 0, rateLimited: 0, fanoutIn: 0, fanoutRefused: 0, routed: 0, replaced: 0 };
  const send = (ws, m) => { try { ws.send(JSON.stringify(m)); } catch { /* closed */ } };
  const route = (from, to, payload) => {
    let p = payload;
    if (tap) {
      const r = tap({ from: from.nodeId, to, payload });
      if (r === false) return;
      if (r && typeof r === 'object') p = r;
    }
    const target = conns.get(to);
    if (!target) return;
    stats.routed++;
    send(target.ws, { from: from.nodeId, fromName: from.name, payload: p });
  };
  wss.on('connection', (ws) => {
    let me = null;
    const bucket = { tokens: burst, last: Date.now() };
    ws.on('message', (data) => {
      const now = Date.now();
      stats.framesIn++;
      bucket.tokens = Math.min(burst, bucket.tokens + ((now - bucket.last) * ratePerSec) / 1000);
      bucket.last = now;
      if (--bucket.tokens < 0) { stats.rateLimited++; ws.close(4008, 'Rate limit exceeded'); return; }
      let msg;
      try { msg = JSON.parse(String(data)); } catch { return; }
      if (!me) {
        if (msg.type !== 'relay-auth') return;
        me = { nodeId: msg.nodeId, name: msg.name, ws };
        const prev = conns.get(me.nodeId);
        if (prev) { stats.replaced++; prev.replaced = true; try { prev.ws.close(4004, 'Replaced by new connection'); } catch { /* */ } }
        conns.set(me.nodeId, me);
        send(ws, {
          type: 'relay-peers',
          peers: [...conns.values()].filter((c) => c.nodeId !== me.nodeId).map((c) => ({ nodeId: c.nodeId, name: c.name, offline: false })),
          ...(fanout ? { features: ['some-future-token', 'fanout'] } : {}),
        });
        for (const c of conns.values()) if (c.nodeId !== me.nodeId) send(c.ws, { type: 'relay-peer-joined', nodeId: me.nodeId, name: me.name });
        return;
      }
      if (msg.type === 'relay-pong') return;
      if (fanout && Array.isArray(msg.fanout)) {
        const tos = msg.fanout.map((e) => e && e.to);
        if (msg.fanout.length > maxFanout || new Set(tos).size !== tos.length || tos.includes(me.nodeId) || tos.some((t) => typeof t !== 'string')) {
          stats.fanoutRefused++;
          send(ws, { type: 'relay-error', message: 'malformed fan-out' });
          return;
        }
        stats.fanoutIn++;
        for (const e of msg.fanout) route(me, e.to, e.payload);
        return;
      }
      if (msg.to) route(me, msg.to, msg.payload);
      else if (msg.payload) for (const c of conns.values()) if (c.nodeId !== me.nodeId) route(me, c.nodeId, msg.payload);
    });
    ws.on('close', () => {
      if (!me || conns.get(me.nodeId) !== me) return; // a replaced connection says no peer-left (§4.4.7)
      conns.delete(me.nodeId);
      for (const c of conns.values()) send(c.ws, { type: 'relay-peer-left', nodeId: me.nodeId, name: me.name });
    });
  });
  return {
    url: `ws://127.0.0.1:${wss.address().port}`,
    stats,
    conns,
    /** Drop a connection as the network would (the relay says peer-left). */
    kick(nodeId) { const c = conns.get(nodeId); if (c) c.ws.terminate(); },
    /** Send an envelope as if `from` had sent it (an injector holding a relay connection). */
    inject(from, to, payload) { const t = conns.get(to); if (t) send(t.ws, { from, fromName: 'injected', payload }); },
    close: () => new Promise((r) => { for (const c of conns.values()) { try { c.ws.terminate(); } catch { /* */ } } wss.close(() => r()); }),
  };
}

module.exports = { fakeRelay };
