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

/** At most this many wake channels are held (and written to wake-channels.json). */
const MAX_WAKE_CHANNELS = 1024;
/** No one peer may teach more than this many channels for nodes other than itself: half the table. */
const MAX_GOSSIPED_PER_ANNOUNCER = 512;
/** Frames queued for one sleeping peer; the oldest is dropped first. */
const MAX_PENDING_FRAMES_PER_PEER = 16;
/** A save asked for is written at most this long after (the writes of a burst coalesce into one). */
const WAKE_SAVE_DELAY_MS = 1000;
/** The source of a channel read back from wake-channels.json (who taught it is not written). */
const FROM_DISK = Symbol('wake-channel-from-disk');

/**
 * The wake channels a node holds — a Map (nodeId -> { platform, token, environment }) with a bound.
 * Every channel is fed by peers: a peer's own (`wake-channel`, or the relay's list of its peers'
 * registrations) or one a peer gossips for some other node (`peer-info`). Until 0.13.17 the table
 * had no bound, so twenty `peer-info` frames from one peer kept 5,120 channels, every one written
 * to disk and woken on every message. Now:
 *   - at most `max` channels are held (1024);
 *   - a peer may teach at most `maxPerAnnouncer` channels for nodes other than itself (512), so no
 *     one peer can fill the table with gossip;
 *   - a node's OWN channel always has room: when the table is full it displaces the oldest channel
 *     that was gossiped (or read back from disk), so gossip cannot lock a node out of being woken.
 *     A gossiped channel that finds the table full is not kept.
 * `set(nodeId, ch, announcer)` takes the announcing peer as a third argument (absent, or the
 * nodeId itself: the node's own channel); callers that need to know whether a channel was kept
 * check `get(nodeId) === ch` after. Replacing a held channel is not limited here (which source may
 * replace a phone's token is a separate question, open for 0.14.0). A channel dropped by `delete`,
 * displacement or `clear` is reported to `onDrop(nodeId)`.
 */
class WakeChannelTable extends Map {
  /**
   * @param {object} [opts]
   * @param {number} [opts.max=1024]
   * @param {number} [opts.maxPerAnnouncer=512]
   * @param {function(string): void} [opts.onDrop]
   */
  constructor(opts = {}) {
    super();
    this._max = opts.max || MAX_WAKE_CHANNELS;
    this._maxPerAnnouncer = opts.maxPerAnnouncer || MAX_GOSSIPED_PER_ANNOUNCER;
    this._onDrop = typeof opts.onDrop === 'function' ? opts.onDrop : null;
    this._from = new Map();        // nodeId -> announcer (a peer id or FROM_DISK); absent: the node's own
    this._perAnnouncer = new Map(); // announcer -> channels it taught that are held
  }

  set(nodeId, ch, announcer) {
    const own = announcer === undefined || announcer === nodeId;
    if (super.has(nodeId)) {
      super.set(nodeId, ch);
      if (own) this._unattribute(nodeId);
      return this;
    }
    if (!own && announcer !== FROM_DISK && (this._perAnnouncer.get(announcer) || 0) >= this._maxPerAnnouncer) return this;
    if (this.size >= this._max) {
      if (!own) return this;
      let displaced = null;
      for (const id of this._from.keys()) { displaced = id; break; } // oldest gossiped or read from disk
      if (displaced === null) return this;
      this.delete(displaced);
    }
    super.set(nodeId, ch);
    if (!own) {
      this._from.set(nodeId, announcer);
      if (announcer !== FROM_DISK) this._perAnnouncer.set(announcer, (this._perAnnouncer.get(announcer) || 0) + 1);
    }
    return this;
  }

  delete(nodeId) {
    const had = super.delete(nodeId);
    if (had) {
      this._unattribute(nodeId);
      if (this._onDrop) { try { this._onDrop(nodeId); } catch { /* never the failure */ } }
    }
    return had;
  }

  clear() {
    for (const id of [...this.keys()]) this.delete(id);
  }

  /** @private */
  _unattribute(nodeId) {
    if (!this._from.has(nodeId)) return;
    const a = this._from.get(nodeId);
    this._from.delete(nodeId);
    if (a === FROM_DISK) return;
    const n = (this._perAnnouncer.get(a) || 0) - 1;
    if (n > 0) this._perAnnouncer.set(a, n); else this._perAnnouncer.delete(a);
  }
}

/** A channel read back from disk, taken as text (the file has no integrity of its own), or null. */
function storedChannel(ch) {
  if (!ch || typeof ch !== 'object') return null;
  const { platform, token, environment } = ch;
  if (typeof platform !== 'string' || !platform || platform.length > 32) return null;
  if (typeof token !== 'string' || !token || token.length > 4096) return null;
  if (environment != null && (typeof environment !== 'string' || environment.length > 64)) return null;
  return { platform, token, environment: environment ?? undefined };
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

    this._apnsConfig = null;
    this._apnsKey = null;
    this._saveTimer = null;
  }

  /**
   * Load persisted peer wake channels from disk.
   *
   * @returns {void}
   */
  loadWakeChannels() {
    try {
      if (fs.existsSync(this._wakeChannelsFile)) {
        const data = JSON.parse(fs.readFileSync(this._wakeChannelsFile, 'utf8'));
        // Taken as a frame's channel is (0.13.16 wrote what peers sent, as sent), and held as
        // gossip: who taught a channel is not written, so one read back gives way to a node's own.
        for (const [id, raw] of Object.entries(data && typeof data === 'object' ? data : {})) {
          const ch = storedChannel(raw);
          if (id && id.length <= 256 && ch) this._peerWakeChannels.set(id, ch, FROM_DISK);
        }
        if (this._peerWakeChannels.size > 0) {
          this._log(`Loaded ${this._peerWakeChannels.size} wake channel(s) from disk`);
        }
      }
    } catch (err) {
      this._log(`Failed to load wake channels: ${err.message}`);
    }
  }

  /**
   * Ask for the peer wake channels to be persisted. Coalesced: the file is written once, at most
   * WAKE_SAVE_DELAY_MS later, however many saves a burst of frames asks for (each `peer-info` frame
   * rewrote the whole file before 0.13.17). `flushWakeChannels()` writes a pending save now.
   *
   * @returns {void}
   */
  saveWakeChannels() {
    if (this._saveTimer) return;
    this._saveTimer = setTimeout(() => this.flushWakeChannels(), WAKE_SAVE_DELAY_MS);
    if (this._saveTimer.unref) this._saveTimer.unref();
  }

  /**
   * Write the peer wake channels to disk now, if a save is pending (the node calls this on stop).
   *
   * @returns {void}
   */
  flushWakeChannels() {
    if (!this._saveTimer) return;
    clearTimeout(this._saveTimer);
    this._saveTimer = null;
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

    // The cooldown runs from the last ATTEMPT, not the last success: until 0.13.17 a wake that
    // failed (a node without APNs keys fails every one) was tried again on the very next message,
    // for every channel held, with a log line each time.
    const lastWake = this._peerLastWake.get(peerId) || 0;
    if (Date.now() - lastWake < this._wakeCooldownMs) return false;
    this._peerLastWake.set(peerId, Date.now());

    try {
      await this._sendWake(wakeChannel, reason);
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
   * Queues the frame for delivery on reconnect: at most MAX_PENDING_FRAMES_PER_PEER per peer, the
   * oldest dropped first (one frame object is shared by every queue it is in, so what is held is
   * bounded by that many frames, for at most as many peers as the wake-channel table holds).
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
          let queue = this._pendingFrames.get(peerId);
          if (!queue) { queue = []; this._pendingFrames.set(peerId, queue); }
          queue.push(pendingFrame);
          if (queue.length > MAX_PENDING_FRAMES_PER_PEER) queue.splice(0, queue.length - MAX_PENDING_FRAMES_PER_PEER);
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

module.exports = {
  WakeManager, WakeChannelTable, FROM_DISK,
  MAX_WAKE_CHANNELS, MAX_GOSSIPED_PER_ANNOUNCER, MAX_PENDING_FRAMES_PER_PEER, WAKE_SAVE_DELAY_MS,
};
