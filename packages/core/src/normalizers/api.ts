import { ACTION, OUTCOME } from "../schema";
import { clampSeverity, compact, first, ip, num, outcomeFrom, port } from "./util";

const isAction = (v: unknown): v is (typeof ACTION)[number] =>
  typeof v === "string" && (ACTION as readonly string[]).includes(v);
const isOutcome = (v: unknown): v is (typeof OUTCOME)[number] =>
  typeof v === "string" && (OUTCOME as readonly string[]).includes(v);

// Generic application events posted to POST /api/ingest.
export const normApi = (p: any) => {
  const type = first(p.event_type, p.type, p.event) ?? "api_event";
  const lower = type.toLowerCase();
  const isLogin = /log_?in|logon|sign_?in|auth/.test(lower);
  const failed = /fail|denied|invalid|reject/.test(lower);
  const outcome = isOutcome(p.outcome)
    ? p.outcome
    : (outcomeFrom(p.status ?? p.result) ??
      (failed ? "failure" : /success|succeeded/.test(lower) ? "success" : undefined));

  return {
    ts: p["@timestamp"] ?? p.timestamp ?? p.time,
    tenant: p.tenant,
    source: "api",
    vendor: first(p.vendor),
    product: first(p.product, p.app, p.application),
    event_type: type,
    event_subtype: first(p.event_subtype, p.reason, p.message),
    severity:
      num(p.severity) !== undefined
        ? clampSeverity(num(p.severity)!)
        : failed
          ? 3
          : 1,
    action: isAction(p.action) ? p.action : isLogin ? "login" : undefined,
    outcome,
    username: first(p.user, p.username, p.user_name),
    // API clients get strict validation: an unparseable IP is passed through so the
    // schema rejects the record with a clear error instead of silently dropping the field.
    src_ip: ip(p.ip ?? p.src_ip ?? p.client_ip) ?? first(p.ip, p.src_ip, p.client_ip),
    src_port: port(p.src_port),
    dst_ip: ip(p.dst_ip) ?? first(p.dst_ip),
    dst_port: port(p.dst_port),
    host: first(p.host, p.hostname),
    url: first(p.url, p.path),
    http_method: first(p.http_method, p.method)?.toUpperCase(),
    status_code: num(p.status_code),
    tags: compact([
      p.reason && `reason:${p.reason}`,
      ...(Array.isArray(p.tags) ? p.tags.map(String) : []),
    ]),
    raw: p,
  };
};
