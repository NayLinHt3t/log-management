import { z } from "zod";
import { isIP } from "node:net";

export const SOURCES = [
  "firewall",
  "crowdstrike",
  "aws",
  "m365",
  "ad",
  "api",
  "network",
] as const;
export type Source = (typeof SOURCES)[number];

export const ACTION = [
  "allow",
  "deny",
  "create",
  "delete",
  "login",
  "logout",
  "alert",
] as const;

// Not in the assignment's example schema, but it lets one alert rule
// ("action:login outcome:failure") cover AD 4625, M365 UserLoginFailed,
// AWS ConsoleLogin failures and API login failures alike.
export const OUTCOME = ["success", "failure", "unknown"] as const;

// Tenant ids become part of table names (events_<tenant>_<day>), so keep them short and safe.
export const TENANT_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/;
export const tenantId = z
  .string()
  .regex(TENANT_RE, "tenant must be 1-32 characters: letters, digits, '_' or '-'");

const ip = z.string().refine((value) => isIP(value) !== 0, {
  message: "Invalid IP address",
});

const port = z.number().int().min(0).max(65535);

export const EventSchema = z.object({
  ts: z.coerce.date(), // exposed as "@timestamp" by the API
  tenant: tenantId,
  source: z.enum(SOURCES),
  vendor: z.string().optional(),
  product: z.string().optional(),
  event_type: z.string().min(1).max(200),
  event_subtype: z.string().max(1000).optional(),
  severity: z.number().int().min(0).max(10).default(0),
  action: z.enum(ACTION).optional(),
  outcome: z.enum(OUTCOME).optional(),
  src_ip: ip.optional(),
  src_port: port.optional(),
  dst_ip: ip.optional(),
  dst_port: port.optional(),
  protocol: z.string().optional(),
  username: z.string().optional(), // "user" is reserved in SQL; the API maps it back to "user"
  host: z.string().optional(),
  process: z.string().optional(),
  url: z.string().optional(),
  http_method: z.string().optional(),
  status_code: z.number().int().optional(),
  rule_name: z.string().optional(),
  rule_id: z.string().optional(),
  cloud_account_id: z.string().optional(),
  cloud_region: z.string().optional(),
  cloud_service: z.string().optional(),
  tags: z.array(z.string()).default([]),
  raw: z.record(z.string(), z.unknown()).default({}),
});

export type NormalizedEvent = z.infer<typeof EventSchema>;
