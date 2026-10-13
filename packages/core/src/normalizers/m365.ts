import { compact, first, ip, outcomeFrom } from "./util";

// Accepts the abridged sample ({event_type, user, ip, status, workload}) and native
// Unified Audit Log records ({CreationTime, Operation, UserId, ClientIP, ResultStatus, Workload}).
export const normM365 = (p: any) => {
  const operation: string = first(p.event_type, p.Operation) ?? "m365_event";
  const status = p.status ?? p.ResultStatus;
  const statusOutcome = outcomeFrom(status);
  const isLogin = operation === "UserLoggedIn" || operation === "UserLoginFailed";
  const failed =
    operation === "UserLoginFailed" ||
    (operation === "UserLoggedIn" && status !== undefined && statusOutcome !== "success");

  const action = isLogin
    ? "login"
    : operation === "UserLoggedOut"
      ? "logout"
      : /^(Add|New|Create)/i.test(operation)
        ? "create"
        : /^(Remove|Delete|HardDelete|SoftDelete)/i.test(operation)
          ? "delete"
          : undefined;

  const workload = first(p.workload, p.Workload);
  return {
    ts: p["@timestamp"] ?? p.CreationTime,
    tenant: p.tenant,
    source: "m365",
    vendor: "microsoft",
    product: "m365-unified-audit",
    // failed sign-ins get the native M365 operation name, whatever shape they arrived in
    event_type: failed ? "UserLoginFailed" : operation,
    event_subtype: first(p.LogonError, p.ErrorNumber, workload),
    action,
    outcome: failed ? "failure" : (statusOutcome ?? (isLogin ? "success" : undefined)),
    severity: failed ? 5 : /^(Add member to role|Set-Mailbox|New-InboxRule|Set-InboxRule)/.test(operation) ? 5 : 1,
    username: first(p.user, p.UserId),
    src_ip: ip(p.ip ?? p.ClientIP ?? p.ClientIPAddress),
    host: first(p.ClientInfoString?.slice?.(0, 100)),
    tags: compact([
      workload && "workload:" + workload,
      p.RecordType !== undefined && `record_type:${p.RecordType}`,
    ]),
    raw: p,
  };
};
