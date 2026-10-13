// key=value extraction shared by plain syslog payloads and CEF extensions.
// A value runs until the next " key=" or end of line, so "msg=DNS blocked" keeps its space.
// Quoted values (Fortinet style: devname="FG 100") are unquoted.
const KV_RE =
  /([A-Za-z_][\w.\-]*)=(?:"((?:[^"\\]|\\.)*)"|(.*?))(?=\s+[A-Za-z_][\w.\-]*=|\s*$)/g;

export function parseKv(text: string): Record<string, string> {
  const kv: Record<string, string> = {};
  for (const m of text.matchAll(KV_RE)) {
    const value = m[2] !== undefined ? m[2].replace(/\\"/g, '"') : (m[3] ?? "");
    kv[m[1]] = value.trim();
  }
  return kv;
}

// Different firewalls spell the same field differently (demo/CEF: src, Fortinet: srcip,
// iptables: SRC, ...). Normalizers read fields through these aliases.
export const KV_ALIASES = {
  src: ["src", "srcip", "src_ip", "SRC", "sip", "source_ip", "source_address"],
  dst: ["dst", "dstip", "dst_ip", "DST", "dip", "destination_ip", "destination_address"],
  spt: ["spt", "srcport", "src_port", "sport", "SPT", "source_port"],
  dpt: ["dpt", "dstport", "dst_port", "dport", "DPT", "destination_port"],
  proto: ["proto", "PROTO", "protocol"],
  action: ["action", "act", "ACTION", "disposition"],
  policy: ["policy", "policyname", "policy_name", "rule", "rulename", "rule_name"],
  policy_id: ["policyid", "policy_id", "ruleid", "rule_id"],
  user: ["user", "suser", "srcuser", "usrName", "username", "duser"],
  msg: ["msg", "message", "Message", "reason"],
  vendor: ["vendor"],
  product: ["product"],
  url: ["url", "request"],
  method: ["method", "requestMethod", "http_method"],
} as const;

export type KvField = keyof typeof KV_ALIASES;

export function kvGet(kv: Record<string, string>, field: KvField): string | undefined {
  for (const key of KV_ALIASES[field]) {
    const v = kv[key];
    if (v !== undefined && v !== "" && v !== "-") return v;
  }
  return undefined;
}

const IANA_PROTO: Record<string, string> = { "1": "icmp", "6": "tcp", "17": "udp", "58": "ipv6-icmp" };

export const protoName = (p?: string) =>
  p === undefined ? undefined : (IANA_PROTO[p] ?? p.toLowerCase());

/** Does this key=value set look like a traffic/firewall log? */
export const looksLikeFirewall = (kv: Record<string, string>) =>
  kvGet(kv, "src") !== undefined ||
  kvGet(kv, "dst") !== undefined ||
  kvGet(kv, "policy") !== undefined ||
  kvGet(kv, "policy_id") !== undefined;
