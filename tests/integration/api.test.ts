import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import type { Pool } from "pg";
import { evaluateRule, recordHits, withTenantScope, type AlertRule } from "@logs/core";
import { buildApp } from "../../backend/src/app";
import { loadConfig } from "../../backend/src/config";
import { seed } from "../../backend/src/seed";
import { freshDatabase, integrationUrl } from "./db";

const url = integrationUrl();
const KEY = "test-ingest-key-0123456789";

describe.skipIf(!url)("API + PostgreSQL (integration)", () => {
  let app: FastifyInstance;
  let pool: Pool;
  const tokens: Record<string, string> = {};
  const as = (user: string) => ({ authorization: `Bearer ${tokens[user]}` });

  beforeAll(async () => {
    pool = await freshDatabase(url!);
    const config = loadConfig({
      NODE_ENV: "test",
      POSTGRES_URL: url,
      JWT_SECRET: "integration-test-secret-0123456789abcdef",
      ADMIN_PASSWORD: "Admin123!",
      VIEWER_PASSWORD: "Viewer123!",
      INGEST_API_KEY: KEY,
      LOG_LEVEL: "silent",
    });
    await seed(pool, config, () => undefined);
    app = await buildApp({ pool, config, logger: false });
    for (const [user, password] of [
      ["admin", "Admin123!"],
      ["viewerA", "Viewer123!"],
      ["viewerB", "Viewer123!"],
    ]) {
      const r = await app.inject({ method: "POST", url: "/api/auth/login", payload: { username: user, password } });
      expect(r.statusCode).toBe(200);
      tokens[user] = r.json().token;
    }
  });

  afterAll(async () => {
    await app?.close();
    await pool?.end();
  });

  it("rejects a wrong password and requests without a token", async () => {
    const bad = await app.inject({ method: "POST", url: "/api/auth/login", payload: { username: "admin", password: "nope" } });
    expect(bad.statusCode).toBe(401);
    expect((await app.inject({ url: "/api/events" })).statusCode).toBe(401);
  });

  it("POST /api/ingest stores the assignment's sample JSON and search finds it", async () => {
    const r = await app.inject({
      method: "POST",
      url: "/api/ingest",
      headers: { "x-api-key": KEY },
      payload: {
        tenant: "demoA",
        source: "api",
        event_type: "app_login_failed",
        user: "alice",
        ip: "203.0.113.7",
        reason: "wrong_password",
        "@timestamp": "2025-08-20T07:20:00Z",
      },
    });
    expect(r.statusCode).toBe(200);
    expect(r.json()).toMatchObject({ accepted: 1, rejected: 0, restamped: 1 });

    const s = await app.inject({ url: "/api/events?q=user:alice src_ip:203.0.113.0/24", headers: as("admin") });
    expect(s.statusCode).toBe(200);
    const [e] = s.json().events;
    expect(e).toMatchObject({ tenant: "demoA", source: "api", event_type: "app_login_failed", user: "alice", action: "login", outcome: "failure" });
    expect(e._tags).toContain("ts_restamped");
    expect(e.raw["@timestamp"]).toBe("2025-08-20T07:20:00Z");
  });

  it("ingests syslog lines sent as text/plain", async () => {
    const r = await app.inject({
      method: "POST",
      url: "/api/ingest?tenant=demoA",
      headers: { "x-api-key": KEY, "content-type": "text/plain" },
      payload:
        "<134>Aug 20 12:44:56 fw01 vendor=demo product=ngfw action=deny src=10.0.1.10 dst=8.8.8.8 spt=5353 dpt=53 proto=udp msg=DNS blocked policy=Block-DNS\n",
    });
    expect(r.json().accepted).toBe(1);
    const s = await app.inject({ url: '/api/events?q=rule:Block-DNS "DNS blocked"', headers: as("admin") });
    expect(s.json().events[0]).toMatchObject({ source: "firewall", action: "deny", dst_port: 53, rule_name: "Block-DNS" });
  });

  it("normalizes an uploaded CloudTrail file (multipart)", async () => {
    const file = JSON.stringify({
      Records: [
        { eventSource: "iam.amazonaws.com", eventName: "CreateUser", awsRegion: "ap-southeast-1", eventTime: new Date().toISOString(), userIdentity: { type: "IAMUser", userName: "admin", accountId: "123456789012" }, sourceIPAddress: "198.51.100.5" },
        { eventSource: "signin.amazonaws.com", eventName: "ConsoleLogin", awsRegion: "us-east-1", eventTime: new Date().toISOString(), userIdentity: { type: "Root", accountId: "123456789012" }, sourceIPAddress: "198.51.100.6", responseElements: { ConsoleLogin: "Failure" } },
      ],
    });
    const boundary = "----logmgmt-test";
    const body =
      `--${boundary}\r\nContent-Disposition: form-data; name="tenant"\r\n\r\ndemoB\r\n` +
      `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="aws_cloudtrail.json"\r\nContent-Type: application/json\r\n\r\n${file}\r\n` +
      `--${boundary}--\r\n`;
    const r = await app.inject({
      method: "POST",
      url: "/api/ingest/file",
      headers: { ...as("admin"), "content-type": `multipart/form-data; boundary=${boundary}` },
      payload: body,
    });
    expect(r.statusCode).toBe(200);
    expect(r.json()).toMatchObject({ format: "cloudtrail", accepted: 2, rejected: 0 });
    const s = await app.inject({ url: "/api/events?tenant=demoB&source=aws&q=outcome:failure", headers: as("admin") });
    expect(s.json().events[0]).toMatchObject({ event_type: "ConsoleLogin", user: "root", cloud: { region: "us-east-1", service: "signin" } });
  });

  it("RBAC: a viewer only ever sees their own tenant", async () => {
    const own = await app.inject({ url: "/api/events", headers: as("viewerB") });
    expect(own.statusCode).toBe(200);
    expect(new Set(own.json().events.map((e: { tenant: string }) => e.tenant))).toEqual(new Set(["demoB"]));

    const other = await app.inject({ url: "/api/events?tenant=demoA", headers: as("viewerB") });
    expect(other.statusCode).toBe(403);

    // trying to reach demoA through the query language still returns nothing
    const sneaky = await app.inject({ url: "/api/events?q=tenant:demoA", headers: as("viewerB") });
    expect(sneaky.json().total).toBe(0);

    const stats = await app.inject({ url: "/api/stats/summary", headers: as("viewerB") });
    expect(stats.json().scope).toBe("demoB");
  });

  it("RBAC: viewers cannot ingest, manage rules or users", async () => {
    const ingest = await app.inject({ method: "POST", url: "/api/ingest", headers: as("viewerA"), payload: { source: "api", event_type: "x" } });
    expect(ingest.statusCode).toBe(403);
    const rule = await app.inject({ method: "POST", url: "/api/alert-rules", headers: as("viewerA"), payload: { name: "x" } });
    expect(rule.statusCode).toBe(403);
    expect((await app.inject({ url: "/api/users", headers: as("viewerA") })).statusCode).toBe(403);
  });

  it("a tenant-bound API key cannot write into another tenant", async () => {
    const created = await app.inject({ method: "POST", url: "/api/api-keys", headers: as("admin"), payload: { name: "demoA app", tenant: "demoA" } });
    expect(created.statusCode).toBe(201);
    const key = created.json().key as string;
    const r = await app.inject({
      method: "POST",
      url: "/api/ingest",
      headers: { "x-api-key": key },
      payload: [
        { source: "api", event_type: "bound_ok" },
        { tenant: "demoB", source: "api", event_type: "cross_tenant" },
      ],
    });
    expect(r.json()).toMatchObject({ accepted: 1, rejected: 1 });
    expect(r.json().errors[0].error).toMatch(/not allowed/);
  });

  it("row-level security filters rows even for a query without a tenant condition", async () => {
    const tenants = await withTenantScope(pool, "demoB", async (db) =>
      (await db.query("SELECT DISTINCT tenant FROM events")).rows.map((r) => r.tenant),
    );
    expect(tenants).toEqual(["demoB"]);
    await expect(withTenantScope(pool, "demoB", (db) => db.query("DELETE FROM events"))).rejects.toThrow();
  });

  it("the brute-force rule raises one alert, updates it on re-evaluation, and stays in its tenant", async () => {
    const attempts = Array.from({ length: 6 }, () => ({
      tenant: "demoA",
      source: "ad",
      event_id: 4625,
      user: "demo\\eve",
      host: "DC01",
      ip: "203.0.113.99",
      logon_type: 3,
    }));
    const r = await app.inject({ method: "POST", url: "/api/ingest", headers: { "x-api-key": KEY }, payload: attempts });
    expect(r.json().accepted).toBe(6);

    const { rows } = await pool.query<AlertRule>("SELECT * FROM alert_rules WHERE query = 'action:login outcome:failure'");
    const rule = rows[0];
    const created = await recordHits(pool, rule, await evaluateRule(pool, rule));
    const mine = created.filter((a) => a.group_key === "203.0.113.99");
    expect(mine).toHaveLength(1);
    expect(mine[0]).toMatchObject({ tenant: "demoA", event_count: 6, severity: 8 });

    const again = await recordHits(pool, rule, await evaluateRule(pool, rule));
    expect(again.filter((a) => a.group_key === "203.0.113.99")).toHaveLength(0); // deduplicated

    const visibleToA = await app.inject({ url: "/api/alerts?status=open", headers: as("viewerA") });
    expect(visibleToA.json().alerts.some((a: { group_key: string }) => a.group_key === "203.0.113.99")).toBe(true);
    const visibleToB = await app.inject({ url: "/api/alerts?status=open", headers: as("viewerB") });
    expect(visibleToB.json().alerts.some((a: { group_key: string }) => a.group_key === "203.0.113.99")).toBe(false);

    const ack = await app.inject({ method: "POST", url: `/api/alerts/${mine[0].id}/ack`, headers: as("admin") });
    expect(ack.json()).toMatchObject({ status: "acknowledged", acknowledged_by: "admin" });
  });

  it("retention drops whole daily partitions older than the retention window", async () => {
    const { rows } = await pool.query(
      `SELECT ensure_event_partition('demoA', (now() AT TIME ZONE 'UTC')::date - 30) AS old,
              ensure_event_partition('demoA', (now() AT TIME ZONE 'UTC')::date) AS today`,
    );
    const dropped = (await pool.query("SELECT dropped FROM drop_expired_partitions(7)")).rows.map((r) => r.dropped);
    expect(dropped).toContain(rows[0].old);
    expect(dropped).not.toContain(rows[0].today);
    const left = await pool.query("SELECT to_regclass(format('%I', $1::text)) AS t", [rows[0].old]);
    expect(left.rows[0].t).toBeNull();
  });

  it("the dashboard summary returns totals, Top-N lists and a timeline", async () => {
    const r = await app.inject({ url: "/api/stats/summary?tenant=demoA", headers: as("admin") });
    expect(r.statusCode).toBe(200);
    const s = r.json();
    expect(s.totals.total).toBeGreaterThan(0);
    expect(s.totals.failed_logins).toBeGreaterThanOrEqual(7);
    expect(s.top_src_ips[0]).toEqual({ key: "203.0.113.99", count: 6 });
    expect(s.timeline.length).toBeGreaterThan(50);
    expect(s.by_source.map((b: { key: string }) => b.key)).toEqual(expect.arrayContaining(["ad", "api", "firewall"]));
  });

  it("reports query syntax errors as 400", async () => {
    const r = await app.inject({ url: "/api/events?q=src_ip:999.1.1.1", headers: as("admin") });
    expect(r.statusCode).toBe(400);
    expect(r.json().error).toMatch(/not an IP/);
  });
});
