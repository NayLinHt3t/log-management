# backend: REST API

Fastify 5 + TypeScript. It serves everything under `/api`: login and RBAC, HTTP ingest and
file upload, search, dashboard statistics, alert rules and alerts, tenant/user/key
administration, health and metrics. It also **owns the database schema**: on start it applies
`migrations/*.sql` (checksummed, under an advisory lock) and, with `SEED_DEMO=true`, creates
the demo tenants, users, alert rules and the ingest key from `.env`.

```
src/
  index.ts        start-up: config, wait for DB, migrate, seed, listen, heartbeat, graceful stop
  app.ts          buildApp(): plugins (jwt, multipart, cors), parsers, error handler, routes
  config.ts       environment validation (zod); refuses placeholder secrets in production
  auth.ts         argon2id, JWT claims, resolveScope() (tenant isolation), API keys, login limiter
  seed.ts         demo data and default alert rules
  routes/
    auth.ts       POST /auth/login, GET /auth/me
    ingest.ts     POST /ingest (JSON | array | NDJSON | text/plain), POST /ingest/file (multipart)
    events.ts     GET /events (search, keyset pagination), GET /events/export.csv
    stats.ts      GET /stats/summary (totals, timeline, Top-N, by source, by severity)
    alerts.ts     alerts (list, ack, close) and alert rules (CRUD, dry-run test)
    admin.ts      tenants, users, API keys
    system.ts     GET /health, /meta, /system/status, /metrics (Prometheus)
migrations/
  001_events.sql            events: partitioned by tenant then day; indexes; RLS role and policy
  002_tenants_auth.sql      tenants, users, api_keys, retention function
  003_alerts.sql            alert_rules, alerts (+ RLS)
  004_service_heartbeats.sql
```

**Tenant isolation on reads**: every read handler calls `resolveScope(user, ?tenant)` (a 403
for a different tenant) and runs its SQL through `withTenantScope()`. That runs the query as
the restricted `logs_reader` role with `app.tenant` set, so PostgreSQL row-level security
filters rows even if a query forgot the tenant condition.

Run on its own (needs PostgreSQL, see `npm run db:up`):

```bash
npm run dev -w @logs/backend        # tsx watch, reads ../.env
npm run build -w @logs/backend && node backend/dist/index.js
```

Main settings: `POSTGRES_URL` (or `POSTGRES_USER`/`PASSWORD`/`DB` + `DB_PORT`), `JWT_SECRET`,
`ADMIN_PASSWORD`, `VIEWER_PASSWORD`, `INGEST_API_KEY`, `RETENTION_DAYS`, `LATE_EVENT_POLICY`,
`PORT` (3000). See `../.env.example`.
