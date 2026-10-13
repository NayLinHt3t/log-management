import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Pool } from "pg";

const LOCK_ID = 727_001; // advisory lock so two services never migrate at the same time

export async function migrate(pool: Pool, dir: string, log: (msg: string) => void = console.log) {
  const client = await pool.connect();
  try {
    await client.query("SELECT pg_advisory_lock($1)", [LOCK_ID]);
    await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
      name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
    await client.query("ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum TEXT");
    const done = new Map<string, string | null>(
      (await client.query("SELECT name, checksum FROM schema_migrations")).rows.map((r) => [
        r.name,
        r.checksum,
      ]),
    );

    for (const file of readdirSync(dir)
      .filter((f) => f.endsWith(".sql"))
      .sort()) {
      const sql = readFileSync(join(dir, file), "utf8");
      const checksum = createHash("sha256").update(sql).digest("hex");
      if (done.has(file)) {
        const applied = done.get(file);
        if (applied && applied !== checksum) {
          throw new Error(
            `migration ${file} changed after it was applied. ` +
              "Add a new migration instead, or reset a dev database with `docker compose down -v`.",
          );
        }
        continue;
      }
      try {
        await client.query("BEGIN");
        await client.query(sql);
        await client.query("INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)", [
          file,
          checksum,
        ]);
        await client.query("COMMIT");
        log(`applied migration ${file}`);
      } catch (err) {
        await client.query("ROLLBACK");
        throw new Error(`migration ${file} failed: ${(err as Error).message}`);
      }
    }
  } finally {
    await client.query("SELECT pg_advisory_unlock($1)", [LOCK_ID]).catch(() => undefined);
    client.release();
  }
}
