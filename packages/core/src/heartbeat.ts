import { hostname } from "node:os";
import type { Pool } from "pg";

/**
 * Every service upserts a heartbeat row with its counters. The System page and
 * /api/metrics read these rows, so one place shows the health of the whole pipeline.
 */
export function startHeartbeat(
  pool: Pool,
  service: string,
  getStats: () => Record<string, unknown>,
  intervalMs = 10_000,
): () => Promise<void> {
  const startedAt = new Date();
  const instance = `${hostname()}:${process.pid}`;
  const beat = () =>
    pool
      .query(
        `INSERT INTO service_heartbeats (service, instance, started_at, last_seen, stats)
         VALUES ($1, $2, $3, now(), $4::jsonb)
         ON CONFLICT (service) DO UPDATE
           SET instance = EXCLUDED.instance, started_at = EXCLUDED.started_at,
               last_seen = now(), stats = EXCLUDED.stats`,
        [service, instance, startedAt, JSON.stringify(getStats())],
      )
      .catch((err) => console.warn(`[heartbeat] ${service}: ${(err as Error).message}`));
  void beat();
  const timer = setInterval(() => void beat(), intervalMs);
  timer.unref();
  return async () => {
    clearInterval(timer);
    await beat();
  };
}
