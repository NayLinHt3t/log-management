import { compact, first, getCI, ip, num, outcomeFrom, port } from "./util";

type Def = {
  type: string;
  action?: "login" | "logout" | "create" | "delete" | "alert";
  outcome?: "success" | "failure";
  severity: number;
};

// Windows Security event IDs most useful for AD monitoring.
const EVENTS: Record<number, Def> = {
  1102: { type: "AuditLogCleared", action: "delete", severity: 9 },
  4624: { type: "LogonSuccess", action: "login", outcome: "success", severity: 1 },
  4625: { type: "LogonFailed", action: "login", outcome: "failure", severity: 5 },
  4634: { type: "Logoff", action: "logout", severity: 0 },
  4647: { type: "Logoff", action: "logout", severity: 0 },
  4648: { type: "ExplicitCredentialLogon", action: "login", severity: 3 },
  4672: { type: "SpecialPrivilegesAssigned", severity: 3 },
  4688: { type: "ProcessCreated", severity: 1 },
  4720: { type: "UserAccountCreated", action: "create", severity: 5 },
  4722: { type: "UserAccountEnabled", severity: 3 },
  4725: { type: "UserAccountDisabled", severity: 3 },
  4726: { type: "UserAccountDeleted", action: "delete", severity: 5 },
  4728: { type: "MemberAddedToGlobalGroup", action: "create", severity: 6 },
  4732: { type: "MemberAddedToLocalGroup", action: "create", severity: 6 },
  4740: { type: "AccountLockedOut", action: "alert", severity: 7 },
  4756: { type: "MemberAddedToUniversalGroup", action: "create", severity: 6 },
  4768: { type: "KerberosTGTRequested", action: "login", severity: 1 },
  4771: { type: "KerberosPreAuthFailed", action: "login", outcome: "failure", severity: 5 },
  4776: { type: "CredentialValidation", action: "login", severity: 1 },
};

// Accepts the abridged sample ({event_id, event_type, user, host, ip, logon_type}),
// flat Windows exports (EventID, TargetUserName, IpAddress, Computer, TimeCreated - NXLog,
// PowerShell, CSV) and Winlogbeat ({winlog: {event_id, event_data: {...}}}).
export const normAd = (p: any) => {
  const w = p.winlog ?? {};
  const data = { ...(p.EventData ?? {}), ...(w.event_data ?? {}), ...p };
  const id = num(getCI(data, "event_id", "EventID", "EventId", "Id") ?? w.event_id) ?? 0;
  const def = EVENTS[id];

  const domain = first(getCI(data, "TargetDomainName"));
  const target = first(getCI(data, "TargetUserName", "SubjectUserName", "AccountName"));
  const user =
    first(p.user) ?? (target ? (domain && domain !== "-" ? `${domain}\\${target}` : target) : undefined);

  // 4768/4776 carry a status code: 0x0 = success, anything else = failure
  const statusOutcome = outcomeFrom(getCI(data, "Status", "Result"));
  // outcome only makes sense for authentication events (others keep it empty)
  const outcome = def?.outcome ?? (def?.action === "login" ? (statusOutcome ?? "success") : undefined);
  const severity =
    outcome === "failure" && def && def.severity < 5 ? 5 : (def?.severity ?? 2);
  const logonType = first(getCI(data, "logon_type", "LogonType"));

  return {
    ts: p["@timestamp"] ?? getCI(data, "TimeCreated", "EventTime", "TimeGenerated", "timestamp"),
    tenant: p.tenant,
    source: "ad",
    vendor: "microsoft",
    product: "windows-security",
    event_type: first(p.event_type) ?? def?.type ?? `Event${id}`,
    event_subtype: first(getCI(data, "SubStatus", "FailureReason")),
    action: def?.action,
    outcome,
    severity,
    username: user,
    host: first(
      typeof p.host === "string" ? p.host : p.host?.name,
      getCI(data, "Computer", "Hostname", "MachineName", "WorkstationName"),
      w.computer_name,
    ),
    src_ip: ip(p.ip ?? getCI(data, "IpAddress", "SourceAddress", "ClientAddress")),
    src_port: port(getCI(data, "IpPort", "SourcePort")),
    process: first(getCI(data, "NewProcessName", "ProcessName")),
    tags: compact([
      `event_id:${id}`,
      logonType && `logon_type:${logonType}`,
    ]),
    raw: p,
  };
};
