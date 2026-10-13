import type { PoolClient } from "pg";
import {
  createPool,
  databaseUrl,
  describeError,
  evaluateRule,
  recordHits,
  startHeartbeat,
  waitForDb,
  type AlertRule,
} from "@logs/core";
import { buildPayload, sendWebhook } from "./notify";

const int = (v: string | undefined, d: number) => (v && /^\d+$/.test(v) ? Number(v) : d);
const cfg = {
  POSTGRES_URL: databaseUrl(),
  RETENTION_DAYS: Math.max(7, int(process.env.RETENTION_DAYS, 7)),
  ALERT_INTERVAL_SECONDS: Math.max(5, int(process.env.ALERT_INTERVAL_SECONDS, 15)),
  MAINTENANCE_INTERVAL_MINUTES: Math.max(1, int(process.env.MAINTENANCE_INTERVAL_MINUTES, 10)),
  ALERT_WEBHOOK_URL: process.env.ALERT_WEBHOOK_URL || undefined,
  PUBLIC_URL: process.env.PUBLIC_URL || undefined,
  ALERT_HISTORY_DAYS: int(process.env.ALERT_HISTORY_DAYS, 90),
};

const log = (msg: string) => console.log(`${new Date().toISOString()} ${msg}`);
const LEADER_LOCK = 727_002;

const stats = {
  is_leader: false,
  alert_evaluations: 0,
  alerts_created: 0,
  notifications_sent: 0,
  notifications_failed: 0,
  partitions_dropped: 0,
  last_alert_run: null as string | null,
  last_maintenance_run: null as string | null,
  last_error: null as string | null,
};

async function main() {
  const pool = createPool(cfg.POSTGRES_URL, "logmgmt-worker", 5);
  await waitForDb(pool);
  // wait until the backend has created the schema
  for (let i = 0; ; i++) {
    const { rows } = await pool.query("SELECT to_regclass('service_heartbeats') IS NOT NULL AS ready");
    if (rows[0].ready) break;
    if (i > 60) throw new Error("schema not found; is the backend running its migrations?");
    await new Promise((r) => setTimeout(r, 2000));
  }

  // Leader election: only one worker evaluates rules, even if several are started.
  // The session-level advisory lock is released automatically if this process dies.
  let leaderClient: PoolClient | undefined;
  const ensureLeader = async () => {
    if (stats.is_leader) return true;
    leaderClient ??= await pool.connect();
    const { rows } = await leaderClient.query("SELECT pg_try_advisory_lock($1) AS ok", [LEADER_LOCK]);
    stats.is_leader = rows[0].ok;
    if (stats.is_leader) log("[worker] acquired leader lock");
    return stats.is_leader;
  };

  // ---- alert rules ----------------------------------------------------------------------
  let alertBusy = false;
  const runAlerts = async () => {
    if (alertBusy) return;
    alertBusy = true;
    try {
      if (!(await ensureLeader())) return;
      const { rows: rules } = await pool.query<AlertRule>(
        `SELECT id, tenant, name, description, enabled, query, group_by, threshold, window_minutes,
                severity, webhook_url FROM alert_rules WHERE enabled ORDER BY id`,
      );
      for (const rule of rules) {
        try {
          const hits = await evaluateRule(pool, rule);
          const created = await recordHits(pool, rule, hits);
          stats.alert_evaluations++;
          for (const alert of created) {
            stats.alerts_created++;
            log(`[alert] #${alert.id} ${alert.message} [${alert.tenant}]`);
            const url = rule.webhook_url ?? cfg.ALERT_WEBHOOK_URL;
            const result = url
              ? await sendWebhook(url, buildPayload(alert, rule, cfg.PUBLIC_URL))
              : { ok: false, status: "no webhook configured (shown in UI only)" };
            if (url) result.ok ? stats.notifications_sent++ : stats.notifications_failed++;
            await pool.query(
              "UPDATE alerts SET notify_status = $2, notified_at = CASE WHEN $3 THEN now() END WHERE id = $1",
              [alert.id, result.status, result.ok],
            );
          }
        } catch (err) {
          stats.last_error = `rule ${rule.id}: ${(err as Error).message}`;
          log(`[alert] rule ${rule.id} "${rule.name}" failed: ${(err as Error).message}`);
        }
      }
      stats.last_alert_run = new Date().toISOString();
    } catch (err) {
      stats.last_error = (err as Error).message;
      log(`[alert] run failed: ${(err as Error).message}`);
      if (leaderClient) {
        leaderClient.release(true); // connection is suspect: drop it, the lock goes with it
        leaderClient = undefined;
        stats.is_leader = false;
      }
    } finally {
      alertBusy = false;
    }
  };

  // ---- partitions + retention -------------------------------------------------------------
  const runMaintenance = async () => {
    try {
      // pre-create today .. +2 days for every tenant, so inserts never wait on DDL at midnight
      await pool.query(
        `SELECT ensure_event_partition(t.id, ((now() AT TIME ZONE 'UTC')::date + d))
           FROM tenants t CROSS JOIN generate_series(0, 2) AS d`,
      );
      const dropped = await pool.query("SELECT dropped FROM drop_expired_partitions($1)", [cfg.RETENTION_DAYS]);
      stats.partitions_dropped += dropped.rowCount ?? 0;
      for (const r of dropped.rows) log(`[retention] dropped ${r.dropped}`);
      await pool.query("DELETE FROM alerts WHERE created_at < now() - make_interval(days => $1)", [cfg.ALERT_HISTORY_DAYS]);
      stats.last_maintenance_run = new Date().toISOString();
    } catch (err) {
      stats.last_error = (err as Error).message;
      log(`[maintenance] failed: ${(err as Error).message}`);
    }
  };

  await runMaintenance();
  await runAlerts();
  const t1 = setInterval(() => void runAlerts(), cfg.ALERT_INTERVAL_SECONDS * 1000);
  const t2 = setInterval(() => void runMaintenance(), cfg.MAINTENANCE_INTERVAL_MINUTES * 60_000);
  const stopHeartbeat = startHeartbeat(pool, "worker", () => ({
    ...stats,
    retention_days: cfg.RETENTION_DAYS,
    alert_interval_s: cfg.ALERT_INTERVAL_SECONDS,
    webhook_configured: Boolean(cfg.ALERT_WEBHOOK_URL),
  }));
  log(
    `[worker] alerts every ${cfg.ALERT_INTERVAL_SECONDS}s, maintenance every ${cfg.MAINTENANCE_INTERVAL_MINUTES}m, retention ${cfg.RETENTION_DAYS} days`,
  );

  const shutdown = async (signal: string) => {
    log(`[worker] ${signal}, shutting down`);
    clearInterval(t1);
    clearInterval(t2);
    await stopHeartbeat();
    leaderClient?.release();
    await pool.end();
    process.exit(0);
  };
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));
}

main().catch((err) => {
  console.error(describeError(err));
  process.exit(1);
});
