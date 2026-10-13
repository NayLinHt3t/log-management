import type { FastifyInstance } from "fastify";
import { buildEventWhere, withTenantScope } from "@logs/core";
import { requestedTenant, requireUser, resolveScope } from "../auth";
import { FilterQuery, timeRange } from "./common";

// Bucket sizes for the timeline; the smallest one giving <= 120 buckets is used.
const BUCKETS: [string, number][] = [
  ["1 minute", 60],
  ["2 minutes", 120],
  ["5 minutes", 300],
  ["10 minutes", 600],
  ["15 minutes", 900],
  ["30 minutes", 1800],
  ["1 hour", 3600],
  ["2 hours", 7200],
  ["3 hours", 10800],
  ["6 hours", 21600],
  ["12 hours", 43200],
  ["1 day", 86400],
];

export function pickBucket(from: Date, to: Date): [string, number] {
  const span = (to.getTime() - from.getTime()) / 1000;
  return BUCKETS.find(([, s]) => span / s <= 120) ?? BUCKETS[BUCKETS.length - 1];
}

const ORIGIN = "2000-01-01T00:00:00Z";

export default async function statsRoutes(app: FastifyInstance) {
  const { pool } = app.ctx;

  // Everything the dashboard needs in one round trip: KPIs, timeline, Top-N lists.
  app.get("/stats/summary", { preHandler: requireUser }, async (req) => {
    const q = FilterQuery.parse(req.query);
    const scope = resolveScope(req.user, requestedTenant(req));
    const { from, to } = timeRange(q.from, q.to);
    const [bucketLabel, bucketSeconds] = pickBucket(from, to);
    const started = Date.now();
    const { where, params } = buildEventWhere({
      tenant: scope === "*" ? undefined : scope,
      from,
      to,
      sources: q.source,
      q: q.q,
    });
    const n = params.length;

    const top = (expr: string, notNull: string) =>
      `SELECT ${expr} AS key, count(*)::int AS count FROM events
        WHERE ${where} AND ${notNull} IS NOT NULL GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 10`;

    const result = await withTenantScope(pool, scope, async (db) => {
      const totals = await db.query(
        `SELECT count(*)::int AS total,
                count(*) FILTER (WHERE severity >= 7)::int AS high_severity,
                count(*) FILTER (WHERE action = 'login' AND outcome = 'failure')::int AS failed_logins,
                count(*) FILTER (WHERE action = 'deny')::int AS denied,
                count(DISTINCT src_ip)::int AS unique_src_ips,
                count(DISTINCT username)::int AS unique_users
           FROM events WHERE ${where}`,
        params,
      );
      const timeline = await db.query(
        `SELECT date_bin($${n + 1}::interval, ts, $${n + 2}::timestamptz) AS bucket, source, count(*)::int AS count
           FROM events WHERE ${where} GROUP BY 1, 2 ORDER BY 1`,
        [...params, bucketLabel, ORIGIN],
      );
      const topIps = await db.query(top("host(src_ip)", "src_ip"), params);
      const topUsers = await db.query(top("username", "username"), params);
      const topTypes = await db.query(
        `SELECT event_type AS key, min(source) AS source, count(*)::int AS count FROM events
          WHERE ${where} GROUP BY 1 ORDER BY 3 DESC, 1 LIMIT 10`,
        params,
      );
      const bySource = await db.query(
        `SELECT source AS key, count(*)::int AS count FROM events WHERE ${where} GROUP BY 1 ORDER BY 2 DESC`,
        params,
      );
      const bySeverity = await db.query(
        `SELECT CASE WHEN severity >= 9 THEN 'critical' WHEN severity >= 7 THEN 'high'
                     WHEN severity >= 4 THEN 'medium' ELSE 'low' END AS key, count(*)::int AS count
           FROM events WHERE ${where} GROUP BY 1`,
        params,
      );
      const openAlerts = await db.query(
        `SELECT count(*)::int AS n FROM alerts WHERE status = 'open'${scope === "*" ? "" : " AND tenant = $1"}`,
        scope === "*" ? [] : [scope],
      );
      return { totals, timeline, topIps, topUsers, topTypes, bySource, bySeverity, openAlerts };
    });

    // Pivot to [{t, firewall: n, aws: n, ...}] and fill empty buckets with zeros.
    const sources = new Set<string>();
    const byBucket = new Map<number, Record<string, number>>();
    for (const r of result.timeline.rows) {
      const t = new Date(r.bucket).getTime();
      sources.add(r.source);
      const row = byBucket.get(t) ?? {};
      row[r.source] = r.count;
      byBucket.set(t, row);
    }
    const step = bucketSeconds * 1000;
    const origin = new Date(ORIGIN).getTime();
    const first = origin + Math.floor((from.getTime() - origin) / step) * step;
    const timeline: Record<string, number | string>[] = [];
    for (let t = first; t < to.getTime(); t += step) {
      const counts = byBucket.get(t) ?? {};
      const row: Record<string, number | string> = { t: new Date(t).toISOString(), total: 0 };
      for (const s of sources) {
        row[s] = counts[s] ?? 0;
        (row.total as number) += counts[s] ?? 0;
      }
      timeline.push(row);
    }

    return {
      scope,
      from: from.toISOString(),
      to: to.toISOString(),
      bucket: bucketLabel,
      took_ms: Date.now() - started,
      totals: { ...result.totals.rows[0], open_alerts: result.openAlerts.rows[0].n },
      timeline,
      timeline_sources: [...sources].sort(),
      top_src_ips: result.topIps.rows,
      top_users: result.topUsers.rows,
      top_event_types: result.topTypes.rows,
      by_source: result.bySource.rows,
      by_severity: result.bySeverity.rows,
    };
  });
}
