import { z } from "zod";
import { SOURCES } from "@logs/core";
import { badRequest } from "../errors";

const isoDate = z
  .string()
  .refine((s) => !isNaN(new Date(s).getTime()), "must be an ISO-8601 date")
  .transform((s) => new Date(s));

/** Filters shared by search, dashboard stats and exports. */
export const FilterQuery = z.object({
  from: isoDate.optional(),
  to: isoDate.optional(),
  tenant: z.string().optional(),
  source: z
    .union([z.string(), z.array(z.string())])
    .optional()
    .transform((v) =>
      (Array.isArray(v) ? v : v ? v.split(",") : []).map((s) => s.trim()).filter(Boolean),
    )
    .refine((arr) => arr.every((s) => (SOURCES as readonly string[]).includes(s)), {
      message: `source must be one of ${SOURCES.join(", ")}`,
    }),
  q: z.string().max(1000).optional(),
});

/** Default window is the last 24 hours; ranges are capped at 400 days. */
export function timeRange(from?: Date, to?: Date) {
  const end = to ?? new Date();
  const start = from ?? new Date(end.getTime() - 24 * 3600_000);
  if (start >= end) throw badRequest("'from' must be before 'to'");
  if (end.getTime() - start.getTime() > 400 * 86_400_000) throw badRequest("time range too large");
  return { from: start, to: end };
}

/** Database row -> API event, using the field names of the assignment's common schema. */
export function serializeEvent(r: Record<string, any>) {
  const cloud =
    r.cloud_account_id || r.cloud_region || r.cloud_service
      ? { account_id: r.cloud_account_id, region: r.cloud_region, service: r.cloud_service }
      : undefined;
  return {
    id: String(r.id),
    "@timestamp": new Date(r.ts).toISOString(),
    ingested_at: r.ingested_at ? new Date(r.ingested_at).toISOString() : undefined,
    tenant: r.tenant,
    source: r.source,
    vendor: r.vendor ?? undefined,
    product: r.product ?? undefined,
    event_type: r.event_type,
    event_subtype: r.event_subtype ?? undefined,
    severity: r.severity,
    action: r.action ?? undefined,
    outcome: r.outcome ?? undefined,
    src_ip: r.src_ip ?? undefined,
    src_port: r.src_port ?? undefined,
    dst_ip: r.dst_ip ?? undefined,
    dst_port: r.dst_port ?? undefined,
    protocol: r.protocol ?? undefined,
    user: r.username ?? undefined,
    host: r.host ?? undefined,
    process: r.process ?? undefined,
    url: r.url ?? undefined,
    http_method: r.http_method ?? undefined,
    status_code: r.status_code ?? undefined,
    rule_name: r.rule_name ?? undefined,
    rule_id: r.rule_id ?? undefined,
    cloud,
    _tags: r.tags ?? [],
    raw: r.raw,
  };
}

export const EVENT_COLUMNS = `id, ts, ingested_at, tenant, source, vendor, product, event_type, event_subtype,
  severity, action, outcome, host(src_ip) AS src_ip, src_port, host(dst_ip) AS dst_ip, dst_port, protocol,
  username, host, process, url, http_method, status_code, rule_name, rule_id,
  cloud_account_id, cloud_region, cloud_service, tags, raw`;
