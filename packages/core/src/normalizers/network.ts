import { clampSeverity, compact, first, ip, num, SYSLOG_SEV } from "./util";
import { kvGet } from "../syslog/kv";
import { asKv } from "./shared";

// Router/switch syslog and any syslog line that is not a firewall traffic log.
export const normNetwork = (p: any) => {
  const k = asKv(p);
  const hasKv = Object.keys(p.kv ?? {}).length > 0;
  return {
    ts: p["@timestamp"],
    tenant: p.tenant,
    source: "network",
    vendor: first(k.vendor),
    product: first(k.product),
    event_type:
      first(k.event, k.event_type, p.event_type) ?? (p.unparsed ? "syslog_unparsed" : "syslog"),
    // keep a readable summary: the reason code, or the free text when there are no key=value pairs
    event_subtype: first(k.reason, !hasKv && p.message ? String(p.message).slice(0, 1000) : undefined),
    severity: p.syslog
      ? (SYSLOG_SEV[p.syslog.severity] ?? 1)
      : clampSeverity(num(p.severity) ?? 1),
    host: first(p.host, k.host),
    src_ip: ip(kvGet(k, "src") ?? k.ip),
    dst_ip: ip(kvGet(k, "dst")),
    username: kvGet(k, "user"),
    tags: compact([
      k.if && `if:${k.if}`,
      k.mac && `mac:${k.mac}`,
      p.syslog?.app && `app:${p.syslog.app}`,
      p.unparsed && "syslog_unparsed",
    ]),
    raw: p.syslog
      ? { message: p.raw, kv: p.kv ?? {}, syslog: p.syslog }
      : p,
  };
};
