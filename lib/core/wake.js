'use strict';

/**
 * @module @sym-bot/core/wake
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
        for (const [id, ch] of Object.entries(data)) {
          if (ch?.platform && ch?.token) {
            this._peerWakeChannels.set(id, ch);
          }
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
          if (!this._pendingFrames.has(peerId)) {
            this._pendingFrames.set(peerId, []);
          }
          this._pendingFrames.get(peerId).push(pendingFrame);
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

module.exports = { WakeManager };
