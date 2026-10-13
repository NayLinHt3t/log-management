// End-to-end check of the core pipeline against the database in .env, without the HTTP layer:
// the assignment's sample records -> normalize -> partitions -> insert -> read back per tenant.
//   npm run db:up && npm run smoke
import { join } from "node:path";
import {
  createPool,
  databaseUrl,
  EventWriter,
  migrate,
  processRecords,
  withTenantScope,
} from "@logs/core";

const SAMPLES: unknown[] = [
  "<134>Aug 20 12:44:56 fw01 vendor=demo product=ngfw action=deny src=10.0.1.10 dst=8.8.8.8 spt=5353 dpt=53 proto=udp msg=DNS blocked policy=Block-DNS",
  "<190>Aug 20 13:01:02 r1 if=ge-0/0/1 event=link-down mac=aa:bb:cc:dd:ee:ff reason=carrier-loss",
  { tenant: "demoA", source: "api", event_type: "app_login_failed", user: "alice", ip: "203.0.113.7", reason: "wrong_password", "@timestamp": "2025-08-20T07:20:00Z" },
  { tenant: "demoA", source: "crowdstrike", event_type: "malware_detected", host: "WIN10-01", process: "powershell.exe", severity: 8, sha256: "abc...", action: "quarantine", "@timestamp": "2025-08-20T08:00:00Z" },
  { tenant: "demoB", source: "aws", cloud: { service: "iam", account_id: "123456789012", region: "ap-southeast-1" }, event_type: "CreateUser", user: "admin", "@timestamp": "2025-08-20T09:10:00Z", raw: { eventName: "CreateUser", requestParameters: { userName: "temp-user" } } },
  { tenant: "demoB", source: "m365", event_type: "UserLoggedIn", user: "bob@demo.local", ip: "198.51.100.23", status: "Success", workload: "Exchange", "@timestamp": "2025-08-20T10:05:00Z" },
  { tenant: "demoA", source: "ad", event_id: 4625, event_type: "LogonFailed", user: "demo\\eve", host: "DC01", ip: "203.0.113.77", logon_type: 3, "@timestamp": "2025-08-20T11:11:11Z" },
];

(async () => {
  const pool = createPool(databaseUrl(), "logmgmt-smoke");
  await migrate(pool, join(__dirname, "../backend/migrations"));
  await pool.query(
    "INSERT INTO tenants (id, name) VALUES ('demoA','Demo Company A'),('demoB','Demo Company B') ON CONFLICT DO NOTHING",
  );

  const { events, errors } = processRecords(SAMPLES, {
    knownTenants: new Set(["demoA", "demoB"]),
    defaultTenant: "demoA", // syslog lines carry no tenant
  });
  if (errors.length) console.error("normalization errors:", errors);

  const writer = new EventWriter(pool);
  console.log("insert:", await writer.insertBatch(events));
  await writer.close();

  for (const tenant of ["demoA", "demoB"]) {
    // runs as the restricted logs_reader role: row-level security limits rows to this tenant
    const rows = await withTenantScope(pool, tenant, async (db) =>
      (await db.query(
        `SELECT ts, tenant, source, event_type, action, outcome, host(src_ip) AS src_ip, username
           FROM events ORDER BY id DESC LIMIT 10`,
      )).rows,
    );
    console.log(`\nvisible to tenant ${tenant}:`);
    console.table(rows);
  }
  await pool.end();
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
