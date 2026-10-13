-- Each service (backend, ingest, worker) reports liveness and counters every few seconds.
-- Shown on the System page and exported as Prometheus metrics at /api/metrics.
CREATE TABLE service_heartbeats (
    service    TEXT PRIMARY KEY,
    instance   TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    stats      JSONB NOT NULL DEFAULT '{}'
);
