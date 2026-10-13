import type { Pool } from "pg";
import type { Config } from "./config";
import { hashApiKey, hashPassword } from "./auth";

export const DEFAULT_RULES = [
  {
    name: "Brute-force login (5+ failures from one IP in 5 min)",
    description: "Failed logins from AD 4625, M365, AWS console and app APIs share action=login outcome=failure.",
    query: "action:login outcome:failure",
    group_by: "src_ip",
    threshold: 5,
    window_minutes: 5,
    severity: 8,
  },
  {
    name: "Malware detection (CrowdStrike severity >= 7)",
    description: "Any high-severity EDR detection, grouped per host.",
    query: "source:crowdstrike severity:>=7",
    group_by: "host",
    threshold: 1,
    window_minutes: 5,
    severity: 9,
  },
  {
    name: "Firewall deny burst (20+ denies from one IP in 5 min)",
    description: "Possible scanning: many blocked connections from the same source.",
    query: "source:firewall action:deny",
    group_by: "src_ip",
    threshold: 20,
    window_minutes: 5,
    severity: 6,
  },
];

/**
 * Idempotent demo data: two tenants, an admin, one viewer per tenant, default alert rules
 * and the ingest key from .env. Existing rows are never overwritten.
 */
export async function seed(pool: Pool, config: Config, log: (m: string) => void = console.log) {
  await pool.query(
    `INSERT INTO tenants (id, name) VALUES ('demoA', 'Demo Company A'), ('demoB', 'Demo Company B')
     ON CONFLICT (id) DO NOTHING`,
  );
  for (const t of ["demoA", "demoB"]) {
    await pool.query("SELECT ensure_event_partition($1, (now() AT TIME ZONE 'UTC')::date)", [t]);
  }

  const users: [string, string, "admin" | "viewer", string | null][] = [
    [config.ADMIN_USERNAME, config.ADMIN_PASSWORD, "admin", null],
    ["viewerA", config.VIEWER_PASSWORD, "viewer", "demoA"],
    ["viewerB", config.VIEWER_PASSWORD, "viewer", "demoB"],
  ];
  for (const [username, password, role, tenant] of users) {
    const exists = await pool.query("SELECT 1 FROM users WHERE lower(username) = lower($1)", [username]);
    if (exists.rowCount) continue;
    await pool.query("INSERT INTO users (username, password_hash, role, tenant) VALUES ($1, $2, $3, $4)", [
      username,
      await hashPassword(password),
      role,
      tenant,
    ]);
    log(`seed: created ${role} "${username}"${tenant ? ` for tenant ${tenant}` : " (all tenants)"}`);
  }

  const { rows } = await pool.query("SELECT count(*)::int AS n FROM alert_rules");
  if (rows[0].n === 0) {
    for (const r of DEFAULT_RULES) {
      await pool.query(
        `INSERT INTO alert_rules (tenant, name, description, query, group_by, threshold, window_minutes, severity, created_by)
         VALUES (NULL, $1, $2, $3, $4, $5, $6, $7, 'seed')`,
        [r.name, r.description, r.query, r.group_by, r.threshold, r.window_minutes, r.severity],
      );
    }
    log(`seed: created ${DEFAULT_RULES.length} default alert rules`);
  }

  if (config.INGEST_API_KEY) {
    const res = await pool.query(
      `INSERT INTO api_keys (name, tenant, key_hash, key_prefix, created_by)
       VALUES ('default ingest key (INGEST_API_KEY in .env)', NULL, $1, $2, 'seed')
       ON CONFLICT (key_hash) DO NOTHING`,
      [hashApiKey(config.INGEST_API_KEY), config.INGEST_API_KEY.slice(0, 10)],
    );
    if (res.rowCount) log("seed: registered INGEST_API_KEY as a global ingest key");
  }
}
