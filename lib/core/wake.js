'use strict';

/**
 * @module sym/core/wake
 * @description WakeManager — manages wake channel persistence and peer wake notifications.
 *
 * Handles: load/save wake channels, setWakeToken, wakeSleepingPeers, APNs push.
 * Autonomous decision-making: checks transport state, coupling drift, and
 * cooldown before sending a wake notification.
 *
 * @copyright 2026 SYM.BOT Ltd.
 * @license Apache-2.0
 */

const fs = require('fs');
const path = require('path');
const { createSign } = require('crypto');

/**
 * Ensure a directory exists, creating it recursively if needed.
 * @param {string} dir - Directory path.
 * @private
 */
function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

/** A wake channel nobody has seen first-hand for this long is dropped (30 days). */
const WAKE_CHANNEL_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/** A newer sighting of the same channel is worth persisting once it moves lastSeen by this much. */
const REFRESH_GRANULARITY_MS = 60 * 60 * 1000;

/** How far each source of a wake channel is trusted, by how the nodeId it names was proven:
 *  - `direct` (3): the peer's own `wake-channel` frame over a session that proved it holds the key
 *    bound to that nodeId;
 *  - `relay` (2): the relay's peer list, the peer's own registration over its relay-auth session;
 *  - `legacy` (2): kept by a release before 0.14.0, which recorded no source;
 *  - `unproven` (1): a `wake-channel` frame over a session that proved nothing, so from whoever
 *    claimed that nodeId at handshake;
 *  - `gossip` (1): another peer's `peer-info`, which nothing authenticates.
 *  A source never replaces a stronger one's token, so nothing unproven can repoint a channel the peer
 *  announced over its own authenticated session. */
const SOURCE_RANK = Object.freeze({ gossip: 1, unproven: 1, legacy: 2, relay: 2, direct: 3 });
const RANKS = [1, 2, 3];
const rankOf = (source) => SOURCE_RANK[source] ?? 0;

/** At most this many wake channels are kept. Gossip names nodeIds nothing vouches for, so without a
 *  bound a peer could grow the map, its file and every peer-info this node sends. */
const WAKE_CHANNELS_MAX = 1024;

/** A `peer-info` frame carries, and is read for, at most this many entries: sender and receiver agree. */
const PEER_INFO_MAX = 256;

/** At most this many frames wait for one sleeping peer; the oldest go first. */
const PENDING_FRAMES_MAX = 64;

/** What a channel may hold: a nodeId, platform, token and environment are short strings, and the
 *  token goes into the push provider's request path, so it is one path segment. */
const NODE_ID_MAX = 128;
const TOKEN_RE = /^[A-Za-z0-9_:.-]{1,512}$/;
const PLATFORM_RE = /^[a-z0-9-]{1,32}$/;
const ENVIRONMENT_RE = /^[A-Za-z0-9_-]{1,32}$/;

/** A channel as stored, or null if it is not one: `platform: 'none'` (no channel) needs no token. */
function cleanChannel(nodeId, channel) {
  if (typeof nodeId !== 'string' || !nodeId || nodeId.length > NODE_ID_MAX) return null;
  if (!channel || typeof channel.platform !== 'string' || !PLATFORM_RE.test(channel.platform)) return null;
  if (channel.platform === 'none') return { platform: 'none' };
  if (typeof channel.token !== 'string' || !TOKEN_RE.test(channel.token)) return null;
  if (channel.environment !== undefined && channel.environment !== null
    && (typeof channel.environment !== 'string' || !ENVIRONMENT_RE.test(channel.environment))) return null;
  return { platform: channel.platform, token: channel.token, environment: channel.environment ?? undefined };
}

/**
 * Manages wake channel persistence and peer wake notifications.
 */
class WakeManager {

  /**
   * @param {object} opts
   * @param {string} opts.wakeChannelsFile - Path to wake-channels.json.
   * @param {Map} opts.peerWakeChannels - Shared Map nodeId -> { platform, token, environment }.
   * @param {Map} opts.peerLastWake - Shared Map nodeId -> timestamp.
   * @param {Map} opts.pendingFrames - Shared Map nodeId -> [frames].
   * @param {number} opts.wakeCooldownMs - Cooldown between wakes (ms).
   * @param {object} opts.wakeChannel - This node's wake channel config.
   * @param {function} opts.log - Logging function.
   * @param {function} opts.getPeers - () => peers Map.
   * @param {function} opts.getMeshNode - () => MeshNode instance.
   * @param {function} opts.getIdentity - () => identity object.
   * @param {string} opts.nodeName - This node's display name.
   */
  constructor(opts) {
    this._wakeChannelsFile = opts.wakeChannelsFile;
    this._peerWakeChannels = opts.peerWakeChannels;
    this._peerLastWake = opts.peerLastWake;
    this._pendingFrames = opts.pendingFrames;
    this._wakeCooldownMs = opts.wakeCooldownMs;
    this._wakeChannel = opts.wakeChannel;
    this._log = opts.log;
    this._getPeers = opts.getPeers;
    this._getMeshNode = opts.getMeshNode;
    this._getIdentity = opts.getIdentity;
    this._nodeName = opts.nodeName;
    this._ttlMs = opts.wakeChannelTtlMs ?? WAKE_CHANNEL_TTL_MS;
    this._maxChannels = opts.maxWakeChannels ?? WAKE_CHANNELS_MAX;
    this._maxPendingFrames = opts.maxPendingFrames ?? PENDING_FRAMES_MAX;
    this._now = opts.now || Date.now;
    // rank -> Map(nodeId -> true) in the order channels were last set: room is made by dropping the
    // head of the weakest rank, O(1), never by scanning the map. The map is written only through
    // _set and _delete, which keep this index.
    this._byRank = new Map(RANKS.map((r) => [r, new Map()]));

    this._apnsConfig = null;
    this._apnsKey = null;
  }

  /**
   * Load persisted peer wake channels from disk.
   *
   * A channel saved before records carried `lastSeen` gets one TTL of grace from now: it may belong
   * to a phone that is asleep and can only be reached through it, so it is not dropped on sight.
   *
   * @returns {void}
   */
  loadWakeChannels() {
    try {
      if (fs.existsSync(this._wakeChannelsFile)) {
        const data = JSON.parse(fs.readFileSync(this._wakeChannelsFile, 'utf8'));
        const now = this._now();
        // What is loaded is held to the same rules as what is learned: valid entries only, and at
        // most the cap. A file written before 0.14.0 could hold any number of gossiped ids.
        let dirty = false;
        for (const [id, ch] of Object.entries(data && typeof data === 'object' ? data : {})) {
          const clean = cleanChannel(id, ch);
          if (!clean || clean.platform === 'none') { dirty = true; continue; }
          // Stamped now, the first time only: written back below, so the grace is given once.
          if (!Number.isFinite(ch.lastSeen) || !ch.source) dirty = true;
          const lastSeen = Number.isFinite(ch.lastSeen) ? Math.min(ch.lastSeen, now) : now;
          const source = SOURCE_RANK[ch.source] ? ch.source : 'legacy';
          this._set(id, { ...clean, source, lastSeen });
        }
        const expired = this.pruneWakeChannels({ save: false });
        let over = 0;
        while (this._peerWakeChannels.size > this._maxChannels && this._evictFor('direct')) over++;
        if (dirty || expired > 0 || over > 0) this.saveWakeChannels();
        if (this._peerWakeChannels.size > 0) {
          const notes = [expired ? `${expired} expired` : '', over ? `${over} over the cap of ${this._maxChannels} dropped` : ''].filter(Boolean);
          this._log(`Loaded ${this._peerWakeChannels.size} wake channel(s) from disk${notes.length ? `, ${notes.join(', ')}` : ''}`);
        }
      }
    } catch (err) {
      this._log(`Failed to load wake channels: ${err.message}`);
    }
  }

  /** @private Set a channel, keeping the rank index: it moves to the end of its rank. */
  _set(nodeId, ch) {
    const prev = this._peerWakeChannels.get(nodeId);
    if (prev) this._byRank.get(rankOf(prev.source))?.delete(nodeId);
    this._peerWakeChannels.set(nodeId, ch);
    this._byRank.get(rankOf(ch.source))?.set(nodeId, true);
  }

  /** @private Drop a channel, and the frames waiting to reach that peer through it. */
  _delete(nodeId) {
    const prev = this._peerWakeChannels.get(nodeId);
    if (!prev) return;
    this._byRank.get(rankOf(prev.source))?.delete(nodeId);
    this._peerWakeChannels.delete(nodeId);
    this._pendingFrames?.delete(nodeId);
  }

  /**
   * Record a peer's wake channel, from one of the sources in SOURCE_RANK: `direct` or `unproven`
   * (the peer's own `wake-channel` frame, over a session that did or did not prove its key), `relay`
   * (the relay's peer list, after relay-auth) or `gossip` (another peer's `peer-info`).
   *
   * A weaker source never replaces a stronger one's token, so nothing unproven can repoint a channel
   * the peer announced over its own authenticated session. `lastSeen` is when someone last had
   * first-hand evidence of the channel, never the time a copy of it was forwarded, so a channel
   * nobody has seen ages out after the TTL however often it is gossiped.
   *
   * `platform: 'none'` is the peer turning its channel off: it removes the channel when it comes
   * from the peer's own frame or registration (not from gossip about it) at least as strong as the
   * channel held.
   *
   * @param {string} nodeId
   * @param {{platform:string, token?:string, environment?:string}} channel
   * @param {{source:'direct'|'unproven'|'relay'|'gossip', lastSeen?:number}} opts
   * @returns {'added'|'updated'|'refreshed'|'removed'|'unchanged'|'ignored'} what changed; only
   *   the first four need saving.
   */
  learnWakeChannel(nodeId, channel, { source, lastSeen } = {}) {
    const clean = cleanChannel(nodeId, channel);
    if (!clean || !rankOf(source)) return 'ignored';
    const prev = this._peerWakeChannels.get(nodeId);
    if (clean.platform === 'none') {
      if (source === 'gossip') return 'ignored';   // a peer turns off its own channel, nobody else's
      if (!prev) return 'unchanged';
      if (rankOf(source) < rankOf(prev.source)) return 'ignored';
      this._delete(nodeId);
      return 'removed';
    }
    const now = this._now();
    // The peer itself, or the relay that holds its registration, is first-hand evidence now; a
    // gossiped copy is only as fresh as the sighting it carries.
    const firstHand = source === 'direct' || source === 'unproven' || (source === 'relay' && !Number.isFinite(lastSeen));
    const seen = firstHand ? now : Math.min(Number.isFinite(lastSeen) ? lastSeen : 0, now);
    if (now - seen > this._ttlMs) return 'ignored';
    const next = { ...clean, source, lastSeen: seen };
    if (!prev) {
      if (this._peerWakeChannels.size >= this._maxChannels && !this._evictFor(source)) return 'ignored';
      this._set(nodeId, next);
      return 'added';
    }
    const sameToken = prev.platform === next.platform && prev.token === next.token && prev.environment === next.environment;
    if (sameToken) {
      // The same channel again: keep the stronger source and the later sighting.
      const keepSource = rankOf(source) > rankOf(prev.source) ? source : prev.source;
      const keepSeen = Math.max(seen, prev.lastSeen ?? 0);
      if (keepSource === prev.source && keepSeen === prev.lastSeen) return 'unchanged';
      this._set(nodeId, { ...prev, source: keepSource, lastSeen: keepSeen });
      // Against a 30-day TTL a sighting a few minutes newer changes nothing worth a write: the
      // record is updated in memory, and reported as needing a save only once it moves by an hour.
      if (keepSource === prev.source && keepSeen - (prev.lastSeen ?? 0) < REFRESH_GRANULARITY_MS) return 'unchanged';
      return 'refreshed';
    }
    // A different token: only a source at least as strong may replace it, and gossip must also be newer.
    if (rankOf(source) < rankOf(prev.source)) return 'ignored';
    if (source === 'gossip' && seen <= (prev.lastSeen ?? 0)) return 'ignored';
    this._set(nodeId, next);
    return 'updated';
  }

  /**
   * Make room for one channel from `source`: drop a channel of the weakest rank held, the one set
   * least recently among those, but never one from a stronger source than the newcomer's. So
   * fabricated gossip only ever displaces other gossip. O(1): the head of a rank's index.
   * @private
   * @returns {boolean} whether there is room now
   */
  _evictFor(source) {
    const rank = rankOf(source);
    for (const r of RANKS) {
      if (r > rank) return false;
      const ids = this._byRank.get(r);
      for (const id of ids.keys()) {
        // The head, unless the index has outlived the channel (it never should): then it goes too.
        if (rankOf(this._peerWakeChannels.get(id)?.source) === r) { this._delete(id); return true; }
        ids.delete(id);
      }
    }
    return false;
  }

  /**
   * Drop channels nobody has seen for longer than the TTL.
   * @param {{save?: boolean}} [opts]
   * @returns {number} how many were dropped
   */
  pruneWakeChannels({ save = true } = {}) {
    const now = this._now();
    let dropped = 0;
    for (const [id, ch] of this._peerWakeChannels) {
      if (now - (ch.lastSeen ?? 0) > this._ttlMs) { this._delete(id); dropped++; }
    }
    if (dropped > 0 && save) this.saveWakeChannels();
    return dropped;
  }

  /**
   * The entries a `peer-info` frame to `excludeId` should carry: live channels only, each with the
   * lastSeen this node holds rather than the time of sending, and at most `limit` of them, the most
   * recently seen, which is as many as a receiver reads.
   * @param {string} excludeId
   * @param {(id:string) => string|undefined} nameOf
   * @param {number} [limit=PEER_INFO_MAX]
   * @returns {Array<{nodeId:string, name:string, wakeChannel:object, lastSeen:number}>}
   */
  gossipEntries(excludeId, nameOf = () => undefined, limit = PEER_INFO_MAX) {
    this.pruneWakeChannels();
    let held = [];
    for (const [id, ch] of this._peerWakeChannels) if (id !== excludeId) held.push([id, ch]);
    if (held.length > limit) held = held.sort((a, b) => (b[1].lastSeen ?? 0) - (a[1].lastSeen ?? 0)).slice(0, limit);
    return held.map(([id, ch]) => ({
      nodeId: id,
      name: nameOf(id) || 'unknown',
      wakeChannel: { platform: ch.platform, token: ch.token, environment: ch.environment },
      lastSeen: ch.lastSeen,
    }));
  }

  /**
   * Persist peer wake channels to disk.
   *
   * @returns {void}
   */
  saveWakeChannels() {
    try {
      ensureDir(path.dirname(this._wakeChannelsFile));
      const data = Object.fromEntries(this._peerWakeChannels);
      fs.writeFileSync(this._wakeChannelsFile, JSON.stringify(data, null, 2));
    } catch (err) {
      this._log(`Failed to save wake channels: ${err.message}`);
    }
  }

  /**
   * Wake a sleeping peer via push notification.
   *
   * Autonomous decision: checks transport availability, coupling drift,
   * and cooldown before sending.
   *
   * @param {string} peerId - Target peer's node ID.
   * @param {string} [reason='message'] - Wake reason (e.g. 'mood', 'message', 'memory').
   * @returns {Promise<boolean>} True if wake was sent, false otherwise.
   */
  async wakeIfNeeded(peerId, reason = 'message') {
    const peers = this._getPeers();
    const peer = peers.get(peerId);
    if (peer?.transport) return false;

    const wakeChannel = this._peerWakeChannels.get(peerId);
    if (!wakeChannel || wakeChannel.platform === 'none') return false;

    const d = this._getMeshNode().couplingDecisions.get(peerId);
    if (d && d.decision === 'rejected') return false;

    const lastWake = this._peerLastWake.get(peerId) || 0;
    if (Date.now() - lastWake < this._wakeCooldownMs) return false;

    try {
      await this._sendWake(wakeChannel, reason);
      this._peerLastWake.set(peerId, Date.now());
      this._log(`Wake sent to ${peerId}: ${reason} via ${wakeChannel.platform}`);
      return true;
    } catch (err) {
      this._log(`Wake failed for ${peerId}: ${err.message}`);
      return false;
    }
  }

  /**
   * Wake all sleeping coupled peers.
   *
   * @param {string} [reason='message'] - Wake reason.
   * @returns {Promise<number>} Number of peers successfully woken.
   */
  async wakeAllPeers(reason = 'message') {
    const promises = [];
    for (const [peerId] of this._peerWakeChannels) {
      promises.push(this.wakeIfNeeded(peerId, reason));
    }
    const results = await Promise.allSettled(promises);
    return results.filter(r => r.status === 'fulfilled' && r.value).length;
  }

  /**
   * Wake all sleeping peers with wake channels but no active transport.
   * Queues the frame for delivery on reconnect.
   *
   * @param {string} reason - Wake reason.
   * @param {object} [pendingFrame] - Frame to queue for delivery on reconnect.
   * @returns {void}
   */
  wakeSleepingPeers(reason, pendingFrame) {
    const peers = this._getPeers();
    for (const [peerId] of this._peerWakeChannels) {
      if (!peers.has(peerId)) {
        if (pendingFrame) {
          // At most PENDING_FRAMES_MAX wait per peer (the oldest go), and only for a peer with a
          // channel: dropping the channel drops its queue (_delete).
          let queue = this._pendingFrames.get(peerId);
          if (!queue) { queue = []; this._pendingFrames.set(peerId, queue); }
          queue.push(pendingFrame);
          if (queue.length > this._maxPendingFrames) queue.splice(0, queue.length - this._maxPendingFrames);
        }

        this.wakeIfNeeded(peerId, reason).catch(err => {
          this._log(`Wake failed for ${peerId.slice(0, 8)}: ${err.message}`);
        });
      }
    }
  }

  /**
   * Route wake to the appropriate platform transport.
   *
   * @param {object} wakeChannel - { platform, token, environment }.
   * @param {string} reason - Wake reason.
   * @returns {Promise<void>}
   * @private
   */
  async _sendWake(wakeChannel, reason) {
    switch (wakeChannel.platform) {
      case 'apns':
        return this._sendAPNsWake(wakeChannel, reason);
      default:
        throw new Error(`Unsupported wake platform: ${wakeChannel.platform}`);
    }
  }

  /**
   * Send an APNs push notification to wake a sleeping iOS node.
   *
   * @param {object} wakeChannel - { platform, token, environment }.
   * @param {string} reason - Wake reason.
   * @returns {Promise<void>}
   * @private
   */
  async _sendAPNsWake(wakeChannel, reason) {
    const http2 = require('http2');
    const keysDir = require('./state-root').symPath('wake-keys');
    const configPath = path.join(keysDir, 'apns-config.json');
    const keyPath = path.join(keysDir, 'apns-key.p8');

    if (!this._apnsConfig) {
      if (!fs.existsSync(configPath) || !fs.existsSync(keyPath)) {
        throw new Error('APNs keys not found at ~/.sym/wake-keys/ (need apns-key.p8 + apns-config.json)');
      }
      this._apnsConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      this._apnsKey = fs.readFileSync(keyPath, 'utf8');

      if (!this._apnsConfig.teamId || !this._apnsConfig.keyId || !this._apnsConfig.bundleId) {
        this._apnsConfig = null;
        throw new Error('apns-config.json must have teamId, keyId, and bundleId');
      }
    }

    const { teamId, keyId, bundleId } = this._apnsConfig;
    const identity = this._getIdentity();

    const header = Buffer.from(JSON.stringify({ alg: 'ES256', kid: keyId })).toString('base64url');
    const iat = Math.floor(Date.now() / 1000);
    const claims = Buffer.from(JSON.stringify({ iss: teamId, iat })).toString('base64url');
    const signer = createSign('SHA256');
    signer.update(`${header}.${claims}`);
    const signature = signer.sign({ key: this._apnsKey, dsaEncoding: 'ieee-p1363' }, 'base64url');
    const jwt = `${header}.${claims}.${signature}`;

    const host = wakeChannel.environment === 'sandbox'
      ? 'api.sandbox.push.apple.com'
      : 'api.push.apple.com';

    const reasonText = {
      mood: 'shared a mood signal',
      message: 'sent a message',
      memory: 'shared a memory',
    }[reason] || 'wants to connect';

    const payload = JSON.stringify({
      aps: {
        alert: { title: 'SYM Mesh', body: `${this._nodeName}: ${reasonText}` },
        'content-available': 1,
        sound: 'default',
      },
      mmp: {
        type: 'wake',
        from: identity.nodeId,
        fromName: this._nodeName,
        reason,
      },
    });

    return new Promise((resolve, reject) => {
      const client = http2.connect(`https://${host}`);

      client.on('error', (err) => {
        client.close();
        reject(new Error(`APNs connection failed: ${err.message}`));
      });

      const req = client.request({
        ':method': 'POST',
        ':path': `/3/device/${wakeChannel.token}`,
        'authorization': `bearer ${jwt}`,
        'apns-topic': bundleId,
        'apns-push-type': 'alert',
        'apns-priority': '10',
      });

      let status;
      let body = '';

      req.on('response', (headers) => { status = headers[':status']; });
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => {
        client.close();
        if (status === 200) {
          resolve();
        } else {
          reject(new Error(`APNs responded ${status}: ${body}`));
        }
      });
      req.on('error', (err) => {
        client.close();
        reject(new Error(`APNs request failed: ${err.message}`));
      });

      req.write(payload);
      req.end();
    });
  }
}

module.exports = { WakeManager, WAKE_CHANNEL_TTL_MS, WAKE_CHANNELS_MAX, PEER_INFO_MAX, PENDING_FRAMES_MAX, SOURCE_RANK };
