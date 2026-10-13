import type { Pool, PoolClient } from "pg";
import { buildEventWhere } from "./query";

export const GROUP_BY = ["src_ip", "dst_ip", "username", "host", "event_type"] as const;
export type GroupBy = (typeof GROUP_BY)[number];

export interface AlertRule {
  id: number;
  tenant: string | null; // null = every tenant
  name: string;
  description?: string | null;
  enabled: boolean;
  query: string;
  group_by: GroupBy | null;
  threshold: number;
  window_minutes: number;
  severity: number;
  webhook_url: string | null;
}

export interface RuleHit {
  tenant: string;
  group_key: string | null;
  count: number;
  first_seen: Date;
  last_seen: Date;
  sample: Record<string, unknown>[];
}

type Queryable = Pool | PoolClient;

const keyExpr = (g: GroupBy | null) =>
  g === null ? "NULL::text" : g.endsWith("_ip") ? `host(${g})` : g;

/**
 * "Which groups have >= threshold matching events in the last window_minutes?"
 * The rule's query uses the same language as the search box, compiled to parameterised SQL.
 */
export async function evaluateRule(
  db: Queryable,
  rule: Pick<AlertRule, "tenant" | "query" | "group_by" | "threshold" | "window_minutes">,
  now = new Date(),
): Promise<RuleHit[]> {
  if (rule.group_by !== null && !GROUP_BY.includes(rule.group_by)) {
    throw new Error(`invalid group_by: ${rule.group_by}`);
  }
  const from = new Date(now.getTime() - rule.window_minutes * 60_000);
  const { where, params } = buildEventWhere({
    tenant: rule.tenant ?? undefined,
    from,
    q: rule.query,
  });
  const key = keyExpr(rule.group_by);
  const notNull = rule.group_by ? ` AND ${rule.group_by} IS NOT NULL` : "";
  const sql = `
    SELECT tenant,
           ${key} AS group_key,
           count(*)::int AS count,
           min(ts) AS first_seen,
           max(ts) AS last_seen,
           (array_agg(jsonb_build_object(
              'id', id, 'ts', ts, 'event_type', event_type, 'source', source,
              'src_ip', host(src_ip), 'user', username, 'host', host)
            ORDER BY ts DESC))[1:5] AS sample
    FROM events
    WHERE ${where}${notNull}
    GROUP BY 1, 2
    HAVING count(*) >= $${params.length + 1}
    ORDER BY count DESC
    LIMIT 100`;
  const { rows } = await db.query(sql, [...params, rule.threshold]);
  return rows.map((r) => ({
    tenant: r.tenant,
    group_key: r.group_key,
    count: r.count,
    first_seen: new Date(r.first_seen),
    last_seen: new Date(r.last_seen),
    sample: r.sample ?? [],
  }));
}

/** The search that shows the events behind an alert (used for the "View events" link). */
export function alertSearchQuery(rule: Pick<AlertRule, "query" | "group_by">, groupKey: string | null) {
  if (!rule.group_by || groupKey === null) return rule.query;
  const field = rule.group_by === "username" ? "user" : rule.group_by;
  const value = /[\s"]/.test(groupKey) ? `"${groupKey.replace(/(["\\])/g, "\\$1")}"` : groupKey;
  return `${rule.query} ${field}:${value}`.trim();
}

export interface StoredAlert {
  id: number;
  rule_id: number | null;
  rule_name: string;
  tenant: string;
  group_by: string | null;
  group_key: string | null;
  severity: number;
  status: string;
  event_count: number;
  first_seen: Date;
  last_seen: Date;
  message: string;
  query: string | null;
}

/**
 * Turns hits into alerts. A hit that continues an active alert (same rule, tenant and key,
 * last seen within one window) only updates it; otherwise a new alert is created and returned
 * so the caller can send notifications exactly once per alert.
 */
export async function recordHits(
  db: Queryable,
  rule: AlertRule,
  hits: RuleHit[],
): Promise<StoredAlert[]> {
  const created: StoredAlert[] = [];
  for (const hit of hits) {
    const activeSince = new Date(hit.first_seen.getTime() - rule.window_minutes * 60_000);
    const existing = await db.query(
      `SELECT id FROM alerts
        WHERE rule_id = $1 AND tenant = $2 AND group_key IS NOT DISTINCT FROM $3
          AND status <> 'closed' AND last_seen >= $4
        ORDER BY id DESC LIMIT 1`,
      [rule.id, hit.tenant, hit.group_key, activeSince],
    );
    if (existing.rowCount) {
      await db.query(
        `UPDATE alerts SET event_count = GREATEST(event_count, $2),
                           last_seen = GREATEST(last_seen, $3),
                           sample = $4::jsonb, updated_at = now()
          WHERE id = $1`,
        [existing.rows[0].id, hit.count, hit.last_seen, JSON.stringify(hit.sample)],
      );
      continue;
    }
    const subject = rule.group_by ? ` from ${rule.group_by} ${hit.group_key}` : "";
    const message = `${rule.name}: ${hit.count} matching events${subject} in ${rule.window_minutes} min (threshold ${rule.threshold})`;
    const { rows } = await db.query(
      `INSERT INTO alerts (rule_id, rule_name, tenant, group_by, group_key, severity, event_count,
                           first_seen, last_seen, message, query, sample)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb)
       RETURNING id, rule_id, rule_name, tenant, group_by, group_key, severity, status,
                 event_count, first_seen, last_seen, message, query`,
      [
        rule.id,
        rule.name,
        hit.tenant,
        rule.group_by,
        hit.group_key,
        rule.severity,
        hit.count,
        hit.first_seen,
        hit.last_seen,
        message,
        alertSearchQuery(rule, hit.group_key),
        JSON.stringify(hit.sample),
      ],
    );
    created.push(rows[0]);
  }
  return created;
}
