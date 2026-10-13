import { compact, first, ip } from "./util";

const actionFor = (name: string) =>
  name === "ConsoleLogin"
    ? "login"
    : /^(Create|Put|Run|Attach|Add|Register|Import)/.test(name)
      ? "create"
      : /^(Delete|Remove|Detach|Terminate|Deregister)/.test(name)
        ? "delete"
        : undefined;

// Calls worth a higher severity when they show up in CloudTrail.
const SENSITIVE = new Set([
  "CreateUser",
  "CreateAccessKey",
  "AttachUserPolicy",
  "AttachRolePolicy",
  "PutUserPolicy",
  "PutBucketPolicy",
  "DeleteTrail",
  "StopLogging",
  "UpdateTrail",
  "DeleteFlowLogs",
  "AuthorizeSecurityGroupIngress",
]);

// Accepts the abridged sample ({event_type, user, cloud:{...}}) and native CloudTrail
// records ({eventName, eventSource, awsRegion, userIdentity, sourceIPAddress, ...}).
export const normAws = (p: any) => {
  const r = p.eventName ? p : (p.raw ?? {}); // the sample nests the CloudTrail fragment under "raw"
  const name: string = first(p.event_type, r.eventName) ?? "aws_event";
  const uid = r.userIdentity ?? {};
  const user =
    first(
      p.user,
      uid.userName,
      uid.sessionContext?.sessionIssuer?.userName,
      typeof uid.arn === "string" ? uid.arn.split("/").pop() : undefined,
      uid.type === "Root" ? "root" : undefined,
      uid.principalId,
    ) ?? undefined;

  const loginResult = r.responseElements?.ConsoleLogin;
  const errorCode = first(r.errorCode);
  const outcome =
    errorCode || loginResult === "Failure"
      ? "failure"
      : loginResult === "Success" || r.eventName
        ? "success"
        : undefined;

  let severity = 2;
  if (SENSITIVE.has(name)) severity = 6;
  if (outcome === "failure") severity = Math.max(severity, 5);
  if (uid.type === "Root") severity = Math.max(severity, 7);

  const service = first(
    p.cloud?.service,
    typeof r.eventSource === "string" ? r.eventSource.replace(/\.amazonaws\.com$/, "") : undefined,
  );

  return {
    ts: p["@timestamp"] ?? r.eventTime,
    tenant: p.tenant,
    source: "aws",
    vendor: "amazon",
    product: "cloudtrail",
    event_type: name,
    event_subtype: first(errorCode, r.errorMessage),
    action: actionFor(name),
    outcome,
    severity,
    username: user,
    src_ip: ip(r.sourceIPAddress ?? p.ip),
    cloud_account_id: first(p.cloud?.account_id, r.recipientAccountId, uid.accountId),
    cloud_region: first(p.cloud?.region, r.awsRegion),
    cloud_service: service,
    tags: compact([
      uid.type && `identity:${uid.type}`,
      errorCode && `error:${errorCode}`,
      r.userAgent && typeof r.userAgent === "string" && `ua:${r.userAgent.slice(0, 60)}`,
    ]),
    raw: p,
  };
};
