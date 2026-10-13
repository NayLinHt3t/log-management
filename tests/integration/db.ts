import { join } from "node:path";
import { Client, type Pool } from "pg";
import { createPool, databaseUrl, migrate } from "@logs/core";

/**
 * Integration tests run when TEST_POSTGRES_URL is set (CI), or with INTEGRATION=1, which uses
 * the database from .env with "_test" appended to its name. Otherwise they are skipped.
 */
export function integrationUrl(): string | undefined {
  if (process.env.TEST_POSTGRES_URL) return process.env.TEST_POSTGRES_URL;
  if (!process.env.INTEGRATION) return undefined;
  try {
    process.loadEnvFile(".env");
  } catch {
    /* no .env: defaults */
  }
  const u = new URL(databaseUrl());
  u.pathname = `/${u.pathname.slice(1) || "logs"}_test`;
  return u.toString();
}

/** Creates the test database if needed, wipes it and applies every migration. */
export async function freshDatabase(url: string): Promise<Pool> {
  const target = new URL(url);
  const name = decodeURIComponent(target.pathname.slice(1));
  if (!/^[A-Za-z0-9_]+$/.test(name)) throw new Error(`unsafe test database name: ${name}`);
  const admin = new URL(url);
  admin.pathname = "/postgres";
  const c = new Client({ connectionString: admin.toString() });
  await c.connect();
  const exists = await c.query("SELECT 1 FROM pg_database WHERE datname = $1", [name]);
  if (!exists.rowCount) await c.query(`CREATE DATABASE "${name}"`);
  await c.end();

  const pool = createPool(url, "logmgmt-tests", 5);
  await pool.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
  await migrate(pool, join(__dirname, "../../backend/migrations"), () => undefined);
  return pool;
}
