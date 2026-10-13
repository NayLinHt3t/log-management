import { compact, first, ip, port, SYSLOG_SEV, clampSeverity, num } from "./util";
import { kvGet, protoName } from "../syslog/kv";
import { asKv, slug } from "./shared";

const ACTION: Record<string, "allow" | "deny"> = {
  allow: "allow",
  allowed: "allow",
  accept: "allow",
  accepted: "allow",
  permit: "allow",
  pass: "allow",
  deny: "deny",
  denied: "deny",
  drop: "deny",
  dropped: "deny",
  block: "deny",
  blocked: "deny",
  reject: "deny",
  rejected: "deny",
  "reset-both": "deny",
};

// Works for parsed syslog records ({ kv, syslog, cef, raw }) and for JSON posted to /ingest.
export const normFirewall = (p: any) => {
  const k = asKv(p);
  const action = ACTION[String(kvGet(k, "action") ?? "").toLowerCase()];
  const base = p.syslog
    ? (SYSLOG_SEV[p.syslog.severity] ?? 1)
    : (num(p.severity) ?? 1);
  const severity = p.cef
    ? p.cef.severity
    : clampSeverity(base + (action === "deny" ? 2 : 0));

  return {
    ts: p["@timestamp"],
    tenant: p.tenant,
    source: "firewall",
    vendor: first(kvGet(k, "vendor"), p.cef?.vendor),
    product: first(kvGet(k, "product"), p.cef?.product),
    event_type: action
      ? `traffic_${action}`
      : p.cef?.name
        ? slug(p.cef.name)
        : first(p.event_type) ?? "firewall_event",
    event_subtype: first(kvGet(k, "msg"), p.cef?.name),
    action,
    severity,
    src_ip: ip(kvGet(k, "src")),
    src_port: port(kvGet(k, "spt")),
    dst_ip: ip(kvGet(k, "dst")),
    dst_port: port(kvGet(k, "dpt")),
    protocol: protoName(kvGet(k, "proto")),
    username: kvGet(k, "user"),
    host: first(p.host, k.devname, k.dvchost),
    url: kvGet(k, "url"),
    http_method: kvGet(k, "method"),
    rule_name: kvGet(k, "policy"),
    rule_id: first(kvGet(k, "policy_id"), p.cef?.signatureId),
    tags: compact([
      p.cef && "format:cef",
      p.syslog?.app && `app:${p.syslog.app}`,
      p.unparsed && "syslog_unparsed",
    ]),
    raw: p.kv
      ? { message: p.raw, kv: k, syslog: p.syslog, ...(p.cef ? { cef: p.cef } : {}) }
      : p,
  };
};
