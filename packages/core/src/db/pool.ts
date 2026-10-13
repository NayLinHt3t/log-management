import { Pool, types } from "pg";

// Return DATE columns as "YYYY-MM-DD" strings. The default turns them into a JS Date at
// local midnight, which shifts the day when the process runs in a non-UTC time zone.
types.setTypeParser(types.builtins.DATE, (v: string) => v);

let pool: Pool | undefined;

export function createPool(connectionString: string, applicationName = "logmgmt", max = 10): Pool {
  const p = new Pool({
    connectionString,
    max,
    application_name: applicationName,
    keepAlive: true,
    connectionTimeoutMillis: 10_000,
  });
  // An idle client can error when Postgres restarts; without a listener that crashes the process.
  p.on("error", (err) => console.error("[db] idle client error:", err.message));
  return p;
}

/**
 * POSTGRES_URL if set (docker-compose sets it), otherwise built from the same variables the
 * Postgres container uses, so local development only needs the values already in .env.
 */
export function databaseUrl(env: NodeJS.ProcessEnv = process.env): string {
  if (env.POSTGRES_URL) return env.POSTGRES_URL;
  const user = encodeURIComponent(env.POSTGRES_USER ?? "logs");
  const pass = encodeURIComponent(env.POSTGRES_PASSWORD ?? "logs");
  const host = env.POSTGRES_HOST ?? "localhost";
  const port = env.POSTGRES_PORT ?? env.DB_PORT ?? "5433";
  const db = encodeURIComponent(env.POSTGRES_DB ?? "logs");
  return `postgres://${user}:${pass}@${host}:${port}/${db}`;
}

export function getPool(applicationName?: string): Pool {
  if (!pool) pool = createPool(databaseUrl(), applicationName);
  return pool;
}

/**
 * A readable message for any thrown value. "localhost" resolves to both ::1 and 127.0.0.1 on
 * macOS; when both connection attempts fail, Node throws an AggregateError whose message is
 * empty, so list the individual attempts instead.
 */
export function describeError(err: unknown): string {
  if (err instanceof AggregateError && err.errors.length > 0) {
    return err.errors.map(describeError).join("; ");
  }
  if (err instanceof Error) return err.message || (err as NodeJS.ErrnoException).code || err.name;
  return String(err);
}

/** Waits for Postgres to accept connections (containers can start before the DB is ready). */
export async function waitForDb(p: Pool, attempts = 30, delayMs = 2000): Promise<void> {
  for (let i = 1; ; i++) {
    try {
      await p.query("SELECT 1");
      return;
    } catch (err) {
      if (i >= attempts) throw err;
      console.warn(`[db] not ready (${describeError(err)}), retry ${i}/${attempts}`);
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
}
