import { describe, it, expect } from "vitest";
import { SyslogFramer } from "../../ingest/src/framing";
import { TenantResolver } from "../../ingest/src/config";

describe("TCP syslog framing (RFC 6587)", () => {
  it("handles octet counting split across reads, then newline framing", () => {
    const f = new SyslogFramer();
    const msg = "<134>Oct 12 10:00:00 fw01 action=deny src=10.0.0.1";
    const framed = `${Buffer.byteLength(msg)} ${msg}`;
    expect(f.push(Buffer.from(framed.slice(0, 20)))).toEqual([]);
    expect(f.push(Buffer.from(framed.slice(20) + "<13>Oct 12 10:00:01 h1 second\n<13>Oct 12"))).toEqual([
      msg,
      "<13>Oct 12 10:00:01 h1 second",
    ]);
    expect(f.end()).toEqual(["<13>Oct 12"]);
  });
});

describe("syslog tenant mapping", () => {
  it("maps senders by CIDR and falls back to the default tenant", () => {
    const r = new TenantResolver("10.20.0.0/16=demoB, 192.168.1.10=demoA", "demoA");
    expect(r.resolve("10.20.3.4")).toBe("demoB");
    expect(r.resolve("::ffff:10.20.3.4")).toBe("demoB"); // IPv4-mapped IPv6 from dual-stack sockets
    expect(r.resolve("192.168.1.10")).toBe("demoA");
    expect(r.resolve("172.16.0.1")).toBe("demoA");
  });

  it("rejects malformed mappings at startup", () => {
    expect(() => new TenantResolver("not-an-ip=demoB", "demoA")).toThrow();
  });
});
