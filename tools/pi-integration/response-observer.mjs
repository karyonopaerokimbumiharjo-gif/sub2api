// Bounded, passive Responses observation. Only complete SSE frames are evidence.
export class ResponseObserver {
  constructor(contentType = 'text/event-stream', maxBytes = 256 * 1024) {
    if (!Number.isInteger(maxBytes) || maxBytes < 1) throw Error('Invalid frame limit');
    this.sse = contentType.split(';')[0].trim().toLowerCase() === 'text/event-stream';
    this.json = contentType.split(';')[0].trim().toLowerCase() === 'application/json';
    this.buffer = new Uint8Array(maxBytes);
    this.length = 0; this.lineLength = 0; this.afterCR = false; this.overflow = false;
    this.models = new Set(); this.terminals = new Set(); this.conflict = false;
    this.droppedFrames = 0; this.modelOverflow = false; this.finished = false;
  }
  append(byte) {
    if (this.overflow) return;
    if (this.length === this.buffer.length) { this.overflow = true; this.length = 0; return; }
    this.buffer[this.length++] = byte;
  }
  feed(bytes) {
    if (this.finished || (!this.sse && !this.json)) return;
    for (const byte of bytes) {
      if (!this.sse) { this.append(byte); continue; }
      if (this.afterCR && byte === 10) { this.afterCR = false; continue; }
      this.afterCR = byte === 13;
      if (byte === 10 || byte === 13) {
        if (this.lineLength === 0) {
          if (this.overflow) this.droppedFrames++;
          else this.frame(new TextDecoder().decode(this.buffer.subarray(0, this.length)));
          this.length = 0; this.overflow = false;
        } else this.append(10);
        this.lineLength = 0;
      } else { this.lineLength = 1; this.append(byte); }
    }
  }
  model(value) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_.-]{1,80}$/.test(value)) return;
    if (this.models.size < 16 || this.models.has(value)) this.models.add(value);
    else this.modelOverflow = true;
  }
  frame(raw) {
    let eventName = ''; const data = [];
    for (const line of raw.split('\n')) {
      if (line.startsWith(':')) continue;
      const colon = line.indexOf(':');
      const field = colon < 0 ? line : line.slice(0, colon);
      let value = colon < 0 ? '' : line.slice(colon + 1);
      if (value.startsWith(' ')) value = value.slice(1);
      if (field === 'data') data.push(value);
      if (field === 'event') eventName = value;
    }
    let obj;
    try { obj = JSON.parse(data.join('\n')); } catch { return; }
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return;
    const terminal = terminalType(obj.type);
    const namedTerminal = terminalType(eventName);
    if (terminal || namedTerminal) {
      if (eventName && eventName !== 'message' && eventName !== obj.type) this.conflict = true;
      if (terminal) {
        this.terminals.add(terminal);
        if (obj.response?.status !== undefined && obj.response.status !== terminal) this.conflict = true;
      }
    }
    if (['response.created', 'response.in_progress', 'response.completed', 'response.incomplete', 'response.failed'].includes(obj.type))
      this.model(obj.response?.model);
  }
  finish(interrupted = false) {
    if (this.finished) return this.result;
    this.finished = true;
    if (this.json && !interrupted && !this.overflow) {
      try {
        const obj = JSON.parse(new TextDecoder().decode(this.buffer.subarray(0, this.length)));
        if (obj?.object === 'response') {
          if (['completed', 'incomplete', 'failed'].includes(obj.status)) this.terminals.add(obj.status);
          this.model(obj.model);
        }
      } catch {}
    }
    if (this.overflow) this.droppedFrames++;
    // An unterminated SSE frame is deliberately discarded at EOF.
    this.result = {
      terminal_status: this.conflict || this.terminals.size > 1 ? 'conflicting' : [...this.terminals][0] ?? (interrupted ? null : 'missing_terminal'),
      stream_interrupted: interrupted,
      observedModels: [...this.models], droppedFrames: this.droppedFrames, modelOverflow: this.modelOverflow,
    };
    this.buffer = new Uint8Array(0); this.length = 0;
    return this.result;
  }
}
function terminalType(type) {
  return typeof type === 'string' && ['response.completed', 'response.incomplete', 'response.failed'].includes(type) ? type.slice(9) : null;
}

// Observe inline, with backpressure: no clone/tee, full-body buffering, or changed bytes.
export function observeResponse(response, onFinish) {
  const observer = new ResponseObserver(response.headers.get('content-type') || '');
  if (!response.body) { onFinish(observer.finish()); return response; }
  const reader = response.body.getReader();
  let reported = false;
  const finish = interrupted => {
    if (!reported) { reported = true; onFinish(observer.finish(interrupted)); }
  };
  const body = new ReadableStream({
    async pull(controller) {
      try {
        const {value, done} = await reader.read();
        if (done) { finish(false); controller.close(); }
        else { observer.feed(value); controller.enqueue(value); }
      } catch (error) { finish(true); controller.error(error); }
    },
    async cancel(reason) { finish(true); await reader.cancel(reason); },
  }, {highWaterMark: 0});
  return new Response(body, {status: response.status, statusText: response.statusText, headers: response.headers});
}
