import { describe, it, expect } from "vitest";
import { parseSyslog, parseSyslogLoose } from "../../packages/core/src/syslog/parser";
import { parseCef } from "../../packages/core/src/syslog/cef";
import { normalize } from "../../packages/core/src/normalizers";

const NOW = new Date("2026-10-12T00:00:00Z");
const FW =
  "<134>Aug 20 12:44:56 fw01 vendor=demo product=ngfw action=deny src=10.0.1.10 dst=8.8.8.8 spt=5353 dpt=53 proto=udp msg=DNS blocked policy=Block-DNS";
const RT =
  "<190>Aug 20 13:01:02 r1 if=ge-0/0/1 event=link-down mac=aa:bb:cc:dd:ee:ff reason=carrier-loss";

describe("syslog parser", () => {
  it("parses PRI, host, and key=value pairs, keeping 'msg' with spaces", () => {
    const p = parseSyslog(FW, "demoA", { now: NOW });
    expect(p.host).toBe("fw01");
    expect(p.syslog).toMatchObject({ facility: 16, severity: 6, format: "rfc3164" });
    expect(p.kv.msg).toBe("DNS blocked");
    expect(p.kv.policy).toBe("Block-DNS");
    expect(p["@timestamp"]).toBe("2026-08-20T12:44:56.000Z");
  });

  it("infers the previous year for a December log read in January", () => {
    const p = parseSyslog("<190>Dec 31 23:59:59 r1 event=x", "demoA", {
      now: new Date("2026-01-01T00:10:00Z"),
    });
    expect(p["@timestamp"]).toBe("2025-12-31T23:59:59.000Z");
  });

  it("can stamp with receive time", () => {
    const p = parseSyslog(FW, "demoA", { now: NOW, useReceiveTime: true });
    expect(p["@timestamp"]).toBe(NOW.toISOString());
  });

  it("rejects garbage", () => {
    expect(() => parseSyslog("hello world", "demoA")).toThrow();
  });
});

describe("syslog normalization", () => {
  it("firewall deny maps to the common schema", () => {
    const e = normalize(parseSyslog(FW, "demoA", { now: NOW }));
    expect(e.source).toBe("firewall");
    expect(e.action).toBe("deny");
    expect(e.src_ip).toBe("10.0.1.10");
    expect(e.dst_port).toBe(53);
    expect(e.protocol).toBe("udp");
    expect(e.rule_name).toBe("Block-DNS");
    expect(e.severity).toBe(4);
  });

  it("router syslog becomes a network event", () => {
    const e = normalize(parseSyslog(RT, "demoA", { now: NOW }));
    expect(e.source).toBe("network");
    expect(e.event_type).toBe("link-down");
    expect(e.tags).toContain("if:ge-0/0/1");
  });
});

describe("other syslog formats", () => {
  it("parses RFC 5424 as sent by `logger -n` (with structured data)", () => {
    const line =
      '<13>1 2026-10-12T21:50:00.123456+07:00 web01 ubuntu - - [timeQuality tzKnown="1" isSynced="1"] backup finished in 42s';
    const p = parseSyslog(line, "demoA", { now: NOW, timestampMode: "auto" });
    expect(p.syslog.format).toBe("rfc5424");
    expect(p.host).toBe("web01");
    expect(p.syslog.app).toBe("ubuntu");
    expect(p.syslog.sd?.timeQuality?.tzKnown).toBe("1");
    expect(p.message).toBe("backup finished in 42s");
    // RFC 5424 carries a year and zone, so "auto" trusts it
    expect(p["@timestamp"]).toBe("2026-10-12T14:50:00.123Z");
    const e = normalize(p);
    expect(e.source).toBe("network");
    expect(e.event_subtype).toBe("backup finished in 42s");
  });

  it("auto mode uses arrival time for RFC 3164 (no year, no zone)", () => {
    const p = parseSyslog(FW, "demoA", { now: NOW, timestampMode: "auto" });
    expect(p["@timestamp"]).toBe(NOW.toISOString());
    expect(p.syslog.timestamp).toBe("Aug 20 12:44:56");
  });

  it("parses CEF from a firewall", () => {
    const line =
      "<134>Oct 12 10:00:00 fw02 CEF:0|Acme|NGFW|9.1|1001|Port scan detected|7|src=198.51.100.9 dst=10.0.0.5 spt=40000 dpt=22 proto=TCP act=blocked cs1Label=Rule cs1=Scan-Protect msg=SSH sweep";
    const e = normalize(parseSyslog(line, "demoA", { now: NOW }));
    expect(e.source).toBe("firewall");
    expect(e.vendor).toBe("Acme");
    expect(e.action).toBe("deny");
    expect(e.severity).toBe(7);
    expect(e.src_ip).toBe("198.51.100.9");
    expect(e.dst_port).toBe(22);
    expect(e.rule_name).toBe("Scan-Protect");
    expect(e.rule_id).toBe("1001");
    expect(e.tags).toContain("format:cef");
  });

  it("understands Fortinet-style quoted key=value and numeric protocols", () => {
    const line =
      '<189>Oct 12 10:00:00 FGT60F devname="FGT60F" srcip=10.0.1.10 srcport=5353 dstip=8.8.8.8 dstport=53 proto=17 action="deny" policyid=12 policyname="Block DNS"';
    const e = normalize(parseSyslog(line, "demoA", { now: NOW }));
    expect(e.action).toBe("deny");
    expect(e.protocol).toBe("udp");
    expect(e.rule_name).toBe("Block DNS");
    expect(e.rule_id).toBe("12");
    expect(e.src_port).toBe(5353);
  });

  it("reads the verdict from UFW/iptables prefixes", () => {
    const line =
      "<4>Oct 12 10:00:00 gw kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.50 DST=10.0.0.2 PROTO=TCP SPT=51515 DPT=3389";
    const e = normalize(parseSyslog(line, "demoA", { now: NOW }));
    expect(e.source).toBe("firewall");
    expect(e.action).toBe("deny");
    expect(e.dst_port).toBe(3389);
    expect(e.tags).toContain("app:kernel");
  });

  it("keeps lines that are not syslog instead of dropping them", () => {
    const p = parseSyslogLoose("hello from netcat", "demoA", { now: NOW });
    expect(p.unparsed).toBe(true);
    const e = normalize(p);
    expect(e.event_type).toBe("syslog_unparsed");
    expect(e.tags).toContain("syslog_unparsed");
    expect(e.raw.message).toBe("hello from netcat");
  });
});

describe("CEF parser", () => {
  it("handles escaped pipes in the header and escaped = in extensions", () => {
    const c = parseCef("CEF:0|Ven\\|dor|Prod|1|42|Name|High|msg=a\\=b c src=10.0.0.1");
    expect(c?.vendor).toBe("Ven|dor");
    expect(c?.severity).toBe(8);
    expect(c?.ext.msg).toBe("a=b c");
    expect(c?.ext.src).toBe("10.0.0.1");
  });
});
