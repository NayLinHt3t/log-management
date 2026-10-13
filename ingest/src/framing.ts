const MAX_FRAME = 64 * 1024;
const LT = 0x3c; // "<"
const LF = 0x0a;

/**
 * Syslog over TCP (RFC 6587) uses either octet counting ("57 <134>...") or one message per line.
 * This splitter accepts both, even mixed on one connection.
 */
export class SyslogFramer {
  private buf: Buffer = Buffer.alloc(0);

  push(chunk: Buffer): string[] {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    const out: string[] = [];
    while (this.buf.length) {
      // skip stray newlines between frames
      if (this.buf[0] === LF || this.buf[0] === 0x0d) {
        this.buf = this.buf.subarray(1);
        continue;
      }
      const head = /^(\d{1,6}) /.exec(this.buf.subarray(0, 8).toString("latin1"));
      if (head && this.buf[head[0].length] === LT) {
        const len = Number(head[1]);
        const start = head[0].length;
        if (this.buf.length < start + len) break; // wait for the rest of the frame
        out.push(this.buf.subarray(start, start + len).toString("utf8"));
        this.buf = this.buf.subarray(start + len);
        continue;
      }
      const nl = this.buf.indexOf(LF);
      if (nl < 0) {
        if (this.buf.length > MAX_FRAME) {
          out.push(this.buf.toString("utf8")); // oversized line: emit what we have
          this.buf = Buffer.alloc(0);
        }
        break;
      }
      out.push(this.buf.subarray(0, nl).toString("utf8"));
      this.buf = this.buf.subarray(nl + 1);
    }
    return out.map((l) => l.replace(/\r$/, "")).filter((l) => l.trim() !== "");
  }

  /** Remaining bytes when the connection closes (last line without a newline). */
  end(): string[] {
    const rest = this.buf.toString("utf8").trim();
    this.buf = Buffer.alloc(0);
    return rest ? [rest] : [];
  }
}
