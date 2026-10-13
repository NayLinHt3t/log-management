import { isIP } from "node:net";

/**
 * A small search language shared by the search page, the dashboard and alert rules.
 *
 *   user:alice src_ip:10.0.0.0/8 -source:firewall severity:>=7 "DNS blocked"
 *
 *  - field:value         exact match (keyword fields are case-sensitive, like Kibana keywords)
 *  - field:val*          wildcard, case-insensitive
 *  - field:a,b           any of the values
 *  - -field:value        negation (events without the field are kept)
 *  - ip:1.2.3.4          source OR destination IP; CIDR works for every IP field
 *  - severity:>=7        numeric comparison (>, >=, <, <=, a..b) for severity, ports, status
 *  - tag:ts_restamped    events carrying a tag
 *  - raw.eventName:X     match a field of the original record (JSON containment, GIN indexed)
 *  - free text           substring match over the original record (trigram indexed)
 * Terms are combined with AND.
 */
export class QueryError extends Error {
  statusCode = 400;
}

type FieldType = "text" | "ip" | "int" | "tags" | "any_ip";
interface FieldDef {
  col: string;
  type: FieldType;
}
const F = (col: string, type: FieldType = "text"): FieldDef => ({ col, type });

export const QUERY_FIELDS: Record<string, FieldDef> = {
  tenant: F("tenant"),
  source: F("source"),
  vendor: F("vendor"),
  product: F("product"),
  event_type: F("event_type"),
  type: F("event_type"),
  event_subtype: F("event_subtype"),
  subtype: F("event_subtype"),
  severity: F("severity", "int"),
  action: F("action"),
  outcome: F("outcome"),
  src_ip: F("src_ip", "ip"),
  src: F("src_ip", "ip"),
  dst_ip: F("dst_ip", "ip"),
  dst: F("dst_ip", "ip"),
  ip: F("", "any_ip"),
  src_port: F("src_port", "int"),
  dst_port: F("dst_port", "int"),
  protocol: F("protocol"),
  user: F("username"),
  username: F("username"),
  host: F("host"),
  process: F("process"),
  url: F("url"),
  http_method: F("http_method"),
  method: F("http_method"),
  status_code: F("status_code", "int"),
  status: F("status_code", "int"),
  rule_name: F("rule_name"),
  rule: F("rule_name"),
  rule_id: F("rule_id"),
  cloud_account_id: F("cloud_account_id"),
  account: F("cloud_account_id"),
  cloud_region: F("cloud_region"),
  region: F("cloud_region"),
  cloud_service: F("cloud_service"),
  service: F("cloud_service"),
  tag: F("tags", "tags"),
  tags: F("tags", "tags"),
};

export interface Token {
  neg: boolean;
  field?: string;
  value: string;
  quoted: boolean;
  text: string; // the original token, used when the field is unknown
}

const TOKEN_RE = /(-?)(?:([A-Za-z_][\w.]*):)?(?:"((?:[^"\\]|\\.)*)"|(\S+))/g;

export function tokenize(q: string): Token[] {
  const tokens: Token[] = [];
  for (const m of q.matchAll(TOKEN_RE)) {
    const quoted = m[3] !== undefined;
    const value = quoted ? m[3].replace(/\\(["\\])/g, "$1") : m[4];
    if (value === undefined) continue;
    tokens.push({
      neg: m[1] === "-" && (m[2] !== undefined || value.length > 0),
      field: m[2],
      value,
      quoted,
      text: m[0].replace(/^-/, ""),
    });
  }
  return tokens;
}

class Params {
  values: unknown[] = [];
  constructor(private start: number) {}
  add(v: unknown) {
    this.values.push(v);
    return `$${this.start + this.values.length - 1}`;
  }
}

const likeEscape = (s: string) => s.replace(/[\\%_]/g, (c) => "\\" + c);
const wildcard = (s: string) => likeEscape(s).replace(/\\?\*/g, (m) => (m === "*" ? "%" : m));

function intCondition(col: string, raw: string, p: Params): string {
  const range = /^(-?\d+)\.\.(-?\d+)$/.exec(raw);
  if (range) return `${col} BETWEEN ${p.add(Number(range[1]))} AND ${p.add(Number(range[2]))}`;
  const cmp = /^(>=|<=|>|<|=)?(-?\d+)$/.exec(raw);
  if (!cmp) throw new QueryError(`"${raw}" is not a number (use e.g. 7, >=7 or 1..5)`);
  return `${col} ${cmp[1] ?? "="} ${p.add(Number(cmp[2]))}`;
}

function ipCondition(col: string, raw: string, p: Params): string {
  if (raw.includes("*")) return `host(${col}) LIKE ${p.add(wildcard(raw))}`;
  const cidr = /^([0-9a-fA-F:.]+)\/(\d{1,3})$/.exec(raw);
  if (cidr && isIP(cidr[1])) return `${col} <<= ${p.add(raw)}::inet`;
  if (isIP(raw)) return `${col} = ${p.add(raw)}::inet`;
  throw new QueryError(`"${raw}" is not an IP address or CIDR range`);
}

function textCondition(col: string, value: string, quoted: boolean, p: Params): string {
  if (!quoted && value.includes(",")) {
    const parts = value.split(",").filter(Boolean);
    if (parts.some((v) => v.includes("*")))
      return "(" + parts.map((v) => textCondition(col, v, true, p)).join(" OR ") + ")";
    return `${col} = ANY(${p.add(parts)}::text[])`;
  }
  if (value.includes("*")) return `${col} ILIKE ${p.add(wildcard(value))}`;
  return `${col} = ${p.add(value)}`;
}

function rawCondition(path: string[], value: string, p: Params): string {
  if (path.length === 0 || path.some((k) => k === "")) throw new QueryError("raw field path is empty");
  if (value.includes("*")) {
    return `(raw #>> ${p.add(path)}::text[]) ILIKE ${p.add(wildcard(value))}`;
  }
  const nest = (v: unknown) => path.reduceRight<unknown>((acc, key) => ({ [key]: acc }), v);
  const candidates: unknown[] = [value];
  if (/^-?\d+(\.\d+)?$/.test(value)) candidates.push(Number(value));
  if (value === "true" || value === "false") candidates.push(value === "true");
  return (
    "(" +
    candidates.map((c) => `raw @> ${p.add(JSON.stringify(nest(c)))}::jsonb`).join(" OR ") +
    ")"
  );
}

function tokenCondition(t: Token, p: Params): string {
  if (t.field?.startsWith("raw.")) return rawCondition(t.field.slice(4).split("."), t.value, p);
  const def = t.field ? QUERY_FIELDS[t.field.toLowerCase()] : undefined;
  if (!def) {
    // free text (also used for tokens like "http://x" whose prefix is not a field)
    const text = t.field && !t.quoted ? t.text : t.value;
    if (!text) return "TRUE";
    return `raw::text ILIKE ${p.add("%" + likeEscape(text) + "%")}`;
  }
  switch (def.type) {
    case "int":
      return intCondition(def.col, t.value, p);
    case "ip":
      return ipCondition(def.col, t.value, p);
    case "any_ip":
      return `(${ipCondition("src_ip", t.value, p)} OR ${ipCondition("dst_ip", t.value, p)})`;
    case "tags":
      if (t.value.includes("*"))
        return `EXISTS (SELECT 1 FROM unnest(tags) AS tg WHERE tg ILIKE ${p.add(wildcard(t.value))})`;
      return `tags @> ARRAY[${p.add(t.value)}]::text[]`;
    default:
      return textCondition(def.col, t.value, t.quoted, p);
  }
}

export interface EventFilter {
  /** undefined = every tenant the caller may see (enforced separately by RLS) */
  tenant?: string;
  from?: Date;
  to?: Date;
  sources?: string[];
  q?: string;
}

export interface WhereClause {
  where: string;
  params: unknown[];
}

export function buildEventWhere(f: EventFilter, firstParam = 1): WhereClause {
  const p = new Params(firstParam);
  const conds: string[] = [];
  if (f.tenant) conds.push(`tenant = ${p.add(f.tenant)}`);
  if (f.from) conds.push(`ts >= ${p.add(f.from.toISOString())}::timestamptz`);
  if (f.to) conds.push(`ts < ${p.add(f.to.toISOString())}::timestamptz`);
  if (f.sources?.length) conds.push(`source = ANY(${p.add(f.sources)}::text[])`);
  if (f.q && f.q.trim()) {
    if (f.q.length > 1000) throw new QueryError("query is too long");
    for (const t of tokenize(f.q)) {
      const c = tokenCondition(t, p);
      conds.push(t.neg ? `(${c}) IS NOT TRUE` : c);
    }
  }
  return { where: conds.length ? conds.join(" AND ") : "TRUE", params: p.values };
}
