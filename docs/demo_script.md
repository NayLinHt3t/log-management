# 30-minute demo: script and checklist

A plan for the demo video and the live interview: what to show, in what order, the exact
commands, and the points worth saying out loud. Timings add up to 30 minutes.

**Before recording**

* Appliance running (`./run.sh up`) with some history: `python3 samples/simulate.py --url https://localhost --insecure --backfill 24`
* SaaS deployment running at `https://<domain>`; a https://webhook.site tab open (copy its URL)
* Terminal in the project folder; browser logged out; `docs/architecture.md` diagram open
* Optional: `python3 samples/simulate.py --url https://localhost --insecure --minutes 30 --rate 3 --burst-every 0` in a second terminal for a live stream

---

### 1. Goal and scope (0:00-2:00)

* The task: a log management system with at least four real ingest sources, one schema,
  search, a dashboard, alerting, RBAC with tenant isolation, TLS, retention, and two
  deployment modes.
* What I built: show the README requirement table. Six source types work for real
  (syslog UDP, syslog TCP, HTTP JSON/NDJSON/text, file upload, inbox folder, simulator). All
  seven source formats are normalized, including native CloudTrail, M365 and Windows exports.

### 2. Architecture (2:00-8:00)

Open `docs/architecture.md`, section 1 diagram.

* Five containers: Caddy edge, backend API, ingest (syslog + inbox), worker (alerts,
  retention), PostgreSQL.
* **One pipeline for every source** (`processRecords`): parse, detect source, normalize,
  validate with zod, enforce tenant, apply the timestamp policy. Say why: the rules cannot
  drift between transports.
* **Why PostgreSQL** instead of OpenSearch/ClickHouse: one dependency that covers time-range
  search, JSON, free text (trigram) and, above all, **row-level security**. At this scale it
  is simpler and stronger on isolation. Name the next step at scale (a queue, then
  ClickHouse or OpenSearch).
* **Tenant isolation in four layers**: credential to tenant, API scoping from the JWT claim,
  RLS in Postgres (a query that forgets the tenant still cannot leak), and separate tables per
  tenant (list partition per tenant, range partition per day).
* **Retention** = `DROP TABLE` on daily partitions: cheap, and always at least 7 days kept.
* Schema addition: `outcome`, so one rule covers failed logins from AD, M365, AWS and apps.

### 3. Appliance deployment (8:00-10:00)

```bash
cat .env.example | head -30     # every setting documented; run.sh fills in secrets
./run.sh up                     # one command (already built, so it takes seconds)
./run.sh status                 # 5 containers healthy
```

Open `https://<appliance-ip>`: self-signed certificate, issued by Caddy for this IP. Log in as
admin.

### 4. Ingest, then search (10:00-17:00)

1. **Syslog**: `./samples/send_syslog.sh localhost 514 both`, then in Search
   `source:firewall`. Expand a row: normalized fields on the left, the original line on the
   right. Point at the CEF and Fortinet lines (different formats, same fields).
2. **HTTP API**: `python3 samples/post_logs.py --url https://localhost --insecure`, then
   search `user:alice`. Show the `ts_restamped` tag and explain the timestamp policy (the
   samples are from 2025, outside the 7-day retention).
3. **Files**: `cp samples/aws_cloudtrail.json samples/m365_audit.json data/inbox/demoB/`,
   then `ls data/inbox/processed/` and its `.result.json`. Search
   `source:aws outcome:failure` (failed root console login), and `raw.eventName:CreateUser`
   (query on the original record).
4. **Query language**: `src_ip:203.0.113.0/24 action:login`, `severity:>=7`, `host:WIN*`,
   `-source:firewall`. A bad query (`src_ip:999.1.1.1`) gives a clear 400 error.
5. Show the **Postman collection** briefly (Ingest folder).

### 5. Dashboard (17:00-21:00)

* Hero count plus timeline stacked by source. The tooltip lists every source; **Show as
  table** gives the same numbers as a table.
* Top source IPs, users and event types: click one to drill into Search with the filter
  added.
* Filters: time range (15m … 7d, custom), tenant, sources. Everything on the page updates
  from the same filters.
* Latest events, refreshed every 5 s. Severity mix. Recent alerts.

### 6. Alerting (21:00-25:00)

1. **Alerts → Rules → New rule**: `action:login outcome:failure`, 3+ events from the same
   source IP in 5 min, paste the webhook.site URL, then **Test rule**, then **Create rule**.
2. `python3 samples/simulate.py --url https://localhost --insecure --scenario bruteforce`
3. Within about 15 s: toast, Alerts badge, alert row with `Notification: sent (HTTP 200)`;
   switch to webhook.site and show the JSON payload.
4. Explain deduplication (the same IP keeps updating one alert) and **Acknowledge**.

### 7. Security (25:00-27:30)

* Log out, then log in as `viewerA`: fixed tenant demoA, no Admin page, only demoA alerts.
* `curl -k "https://localhost/api/events?tenant=demoB" -H "Authorization: Bearer <viewer token>"`
  returns 403.
* Show the RLS policy in `backend/migrations/001_events.sql` and the integration test that
  proves a query without a tenant filter is still isolated.
* API keys: hashed, revocable, can be bound to a tenant (Sources page). Login rate limit,
  argon2id, CSP and security headers (`curl -kI https://localhost`).

### 8. SaaS deployment (27:30-29:00)

* Open `https://<domain>`: a trusted Let's Encrypt certificate (click the lock).
* `docker-compose.saas.yml` differences: domain plus ACME, no database port.
* Send one event to the cloud: `python3 samples/post_logs.py --url https://<domain> --key <key>`

### 9. Quality and wrap-up (29:00-30:00)

* `npm test`: 50 unit tests plus 12 integration tests against PostgreSQL. GitHub Actions
  runs them, then boots the Docker appliance and checks syslog and HTTP ingest end to end.
* Pipeline health page and `/api/metrics` (Prometheus).
* Next steps: a queue in front of storage, syslog over TLS, OIDC SSO, GeoIP enrichment.

---

## Likely interview questions (short answers)

* **Why not Elasticsearch/OpenSearch?** Heavier to run (JVM heap, security plugin) and
  multi-tenancy needs its own index and role design. Postgres gives RLS and transactions with
  one dependency. OpenSearch becomes the better choice for large-scale relevance-ranked
  full-text search.
* **How do you stop tenant A seeing tenant B?** The JWT claim decides the scope; the API
  checks it; Postgres RLS enforces it again on every read; data is physically separate per
  tenant.
* **What happens if the database goes down?** HTTP ingest returns an error, so the sender
  retries. Syslog batches stay in the ingest buffer (up to 50k events) and are retried.
  Services reconnect automatically.
* **Why restamp old events?** They would be deleted at the next retention run; restamping
  keeps them searchable and is visible (tag + original time in raw). `LATE_EVENT_POLICY=reject`
  is available.
* **How would you scale?** Stateless ingest and API behind a load balancer; a queue (Kafka or
  NATS) between ingest and storage; the worker already uses leader election; events move to
  ClickHouse or OpenSearch while Postgres keeps metadata.
