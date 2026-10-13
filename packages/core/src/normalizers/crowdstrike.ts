import { clampSeverity, compact, first, ip, num, toDate } from "./util";

// CrowdStrike Falcon severity is 1..5 (Informational..Critical); some feeds use 0..100.
const scaleSeverity = (v: unknown, fallback: number) => {
  const n = num(v);
  if (n === undefined) {
    const name = String(v ?? "").toLowerCase();
    const byName: Record<string, number> = {
      informational: 2,
      low: 4,
      medium: 6,
      high: 8,
      critical: 10,
    };
    return byName[name] ?? fallback;
  }
  return n <= 10 ? clampSeverity(n) : clampSeverity(n / 10);
};

// Accepts the abridged sample ({event_type, host, process, severity 0-10, sha256})
// and the Falcon streaming API shape ({ metadata: {...}, event: {...} }).
export const normCrowdstrike = (p: any) => {
  const e = p.event && typeof p.event === "object" ? p.event : p;
  const md = p.metadata ?? {};
  const nativeSeverity = e.Severity !== undefined && p.severity === undefined;
  const severity = nativeSeverity
    ? (() => {
        const n = num(e.Severity);
        return n !== undefined && n <= 5 ? clampSeverity(n * 2) : scaleSeverity(e.Severity, 5);
      })()
    : scaleSeverity(p.severity ?? e.SeverityName, 5);
  const sha256 = first(p.sha256, e.SHA256String, e.Sha256);

  return {
    ts:
      p["@timestamp"] ??
      toDate(md.eventCreationTime) ??
      toDate(e.ProcessStartTime) ??
      toDate(e.timestamp),
    tenant: p.tenant,
    source: "crowdstrike",
    vendor: "crowdstrike",
    product: "falcon",
    event_type: first(p.event_type, md.eventType) ?? "detection",
    event_subtype: first(e.DetectName, e.Technique, e.Tactic, e.Description),
    severity,
    action: "alert" as const, // original value ("quarantine", "kill process") stays in raw
    host: first(p.host, e.ComputerName, e.Hostname),
    username: first(p.user, e.UserName),
    process: first(p.process, e.FileName, e.ImageFileName),
    src_ip: ip(p.ip ?? e.LocalIP),
    url: first(e.FalconHostLink),
    rule_name: first(e.DetectName, e.PatternDispositionDescription),
    rule_id: first(e.DetectId, e.PatternId),
    tags: compact([
      sha256 && "sha256:" + sha256,
      e.Tactic && `tactic:${e.Tactic}`,
      e.Technique && `technique:${e.Technique}`,
      first(p.action) && `response:${p.action}`,
    ]),
    raw: p,
  };
};
