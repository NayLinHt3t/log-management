import type { Pool, PoolClient } from "pg";

/** "*" = every tenant (global admin / background jobs); otherwise a single tenant id. */
export type TenantScope = string;
export const ALL_TENANTS: TenantScope = "*";

/**
 * Runs read queries as the restricted `logs_reader` role with `app.tenant` set for this
 * transaction only. Row-level security policies on events/alerts/alert_rules then filter
 * rows in Postgres itself, so a query that forgets `WHERE tenant = ...` still cannot read
 * another tenant's data. The transaction is READ ONLY as an extra guard.
 */
export async function withTenantScope<T>(
  pool: Pool,
  scope: TenantScope,
  fn: (client: PoolClient) => Promise<T>,
  statementTimeoutMs = 15_000,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN READ ONLY");
    await client.query("SET LOCAL ROLE logs_reader");
    await client.query("SELECT set_config('app.tenant', $1, true)", [scope]);
    await client.query(`SET LOCAL statement_timeout = ${Math.max(1000, Math.floor(statementTimeoutMs))}`);
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}
