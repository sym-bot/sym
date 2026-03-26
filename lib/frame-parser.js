'use strict';

const { EventEmitter } = require('events');

const MAX_FRAME_SIZE = 1024 * 1024;

class FrameParser extends EventEmitter {
  constructor() {
    super();
    this.buffer = Buffer.alloc(0);
    this.state = 'length';
    this.frameLength = 0;
  }

  feed(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    this._parse();
  }

  _parse() {
    while (true) {
      if (this.state === 'length') {
        if (this.buffer.length < 4) return;
        this.frameLength = this.buffer.readUInt32BE(0);
        this.buffer = this.buffer.subarray(4);
        if (this.frameLength === 0 || this.frameLength > MAX_FRAME_SIZE) {
          this.emit('error', new Error(`Invalid frame length: ${this.frameLength}`));
          return;
        }
        this.state = 'payload';
      }
      if (this.state === 'payload') {
        if (this.buffer.length < this.frameLength) return;
        const payload = this.buffer.subarray(0, this.frameLength);
        this.buffer = this.buffer.subarray(this.frameLength);
        this.state = 'length';
        this.frameLength = 0;
        try {
          this.emit('message', JSON.parse(payload.toString('utf8')));
        } catch (e) {
          this.emit('error', new Error(`Invalid JSON: ${e.message}`));
        }
      }
    }
  }
}

function sendFrame(socket, msg) {
  const payload = Buffer.from(JSON.stringify(msg), 'utf8');
  if (payload.length > MAX_FRAME_SIZE) return false;
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  try {
    socket.write(Buffer.concat([header, payload]));
    return true;
  } catch { return false; }
}

module.exports = { FrameParser, sendFrame };
