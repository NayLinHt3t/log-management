import type { FastifyInstance } from "fastify";
import { GROUP_BY, OUTCOME, ACTION, QUERY_FIELDS, SOURCES } from "@logs/core";
import { requireUser } from "../auth";
import { forbidden, unauthorized } from "../errors";
import { gauge } from "../metrics";

const STALE_AFTER_S = 45;
const VERSION = process.env.APP_VERSION ?? "1.0.0";

export default async function systemRoutes(app: FastifyInstance) {
  const { pool, config, metrics } = app.ctx;

  // Liveness/readiness for Docker and load balancers (no auth, no data).
  app.get("/health", async (_req, reply) => {
    try {
      await pool.query("SELECT 1");
      return { status: "ok", db: "ok", version: VERSION, time: new Date().toISOString() };
    } catch {
      return reply.code(503).send({ status: "degraded", db: "unreachable", version: VERSION });
    }
  });

  // Field list and enums for the UI (query help, rule editor).
  app.get("/meta", { preHandler: requireUser }, async () => ({
    sources: SOURCES,
    actions: ACTION,
    outcomes: OUTCOME,
    group_by: GROUP_BY,
    query_fields: Object.keys(QUERY_FIELDS),
    retention_days: config.RETENTION_DAYS,
    late_event_policy: config.LATE_EVENT_POLICY,
  }));

  const heartbeats = async () => {
    const { rows } = await pool.query(
      `SELECT service, instance, started_at, last_seen, stats,
              extract(epoch FROM now() - last_seen)::float AS age_s
         FROM service_heartbeats ORDER BY service`,
    );
    return rows.map((r) => ({ ...r, healthy: r.age_s < STALE_AFTER_S }));
  };

  app.get("/system/status", { preHandler: requireUser }, async (req) => {
    const own = req.user.tenant;
    const partitions = await pool.query(
      `SELECT tenant, count(*)::int AS partitions, min(day) AS oldest_day, max(day) AS newest_day
         FROM event_partitions ${own ? "WHERE tenant = $1" : ""} GROUP BY tenant ORDER BY tenant`,
      own ? [own] : [],
    );
    return {
      version: VERSION,
      retention_days: config.RETENTION_DAYS,
      late_event_policy: config.LATE_EVENT_POLICY,
      services: await heartbeats(),
      partitions: partitions.rows,
    };
  });

  // Prometheus metrics. Admin JWT, or "Authorization: Bearer <METRICS_TOKEN>" for scrapers.
  app.get("/metrics", async (req, reply) => {
    const auth = req.headers.authorization ?? "";
    if (!(config.METRICS_TOKEN && auth === `Bearer ${config.METRICS_TOKEN}`)) {
      try {
        await req.jwtVerify();
      } catch {
        throw unauthorized();
      }
      if (req.user.role !== "admin" || req.user.tenant !== null) throw forbidden("global admin only");
    }
    const services = await heartbeats();
    const counters: [Record<string, string>, number][] = [];
    for (const s of services) {
      for (const [k, v] of Object.entries(s.stats ?? {})) {
        if (typeof v === "number") counters.push([{ service: s.service, stat: k }, v]);
      }
    }
    const open = await pool.query("SELECT tenant, count(*)::int AS n FROM alerts WHERE status = 'open' GROUP BY 1");
    const parts = await pool.query("SELECT tenant, count(*)::int AS n FROM event_partitions GROUP BY 1");
    const body = [
      metrics.render(),
      gauge("logmgmt_service_up", "1 if the service sent a heartbeat recently", services.map((s) => [{ service: s.service }, s.healthy ? 1 : 0])),
      gauge("logmgmt_service_stat", "Counters reported by each service heartbeat", counters),
      gauge("logmgmt_open_alerts", "Open alerts per tenant", open.rows.map((r) => [{ tenant: r.tenant }, r.n])),
      gauge("logmgmt_event_partitions", "Daily event partitions per tenant", parts.rows.map((r) => [{ tenant: r.tenant }, r.n])),
    ].join("\n");
    return reply.header("Content-Type", "text/plain; version=0.0.4").send(body + "\n");
  });
}
