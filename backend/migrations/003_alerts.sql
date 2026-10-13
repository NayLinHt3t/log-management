-- Alert rules are written in the same query language as the search box, e.g.
--   query = 'action:login outcome:failure', group_by = 'src_ip', threshold = 5, window = 5 min
-- "fire when one source IP has >= 5 failed logins within 5 minutes".

CREATE TABLE alert_rules (
    id             SERIAL PRIMARY KEY,
    tenant         TEXT REFERENCES tenants (id) ON DELETE CASCADE, -- NULL = applies to every tenant
    name           TEXT NOT NULL,
    description    TEXT,
    enabled        BOOLEAN NOT NULL DEFAULT true,
    query          TEXT NOT NULL DEFAULT '',
    group_by       TEXT CHECK (group_by IN ('src_ip', 'dst_ip', 'username', 'host', 'event_type')),
    threshold      INT NOT NULL DEFAULT 1 CHECK (threshold BETWEEN 1 AND 100000),
    window_minutes INT NOT NULL DEFAULT 5 CHECK (window_minutes BETWEEN 1 AND 1440),
    severity       SMALLINT NOT NULL DEFAULT 5 CHECK (severity BETWEEN 0 AND 10),
    webhook_url    TEXT CHECK (webhook_url IS NULL OR webhook_url ~ '^https?://'),
    created_by     TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE alerts (
    id               BIGSERIAL PRIMARY KEY,
    rule_id          INT REFERENCES alert_rules (id) ON DELETE SET NULL,
    rule_name        TEXT NOT NULL,
    tenant           TEXT NOT NULL,
    group_by         TEXT,
    group_key        TEXT,               -- e.g. the offending source IP
    severity         SMALLINT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'closed')),
    event_count      INT NOT NULL,       -- highest number of matching events seen in one window
    first_seen       TIMESTAMPTZ NOT NULL,
    last_seen        TIMESTAMPTZ NOT NULL,
    message          TEXT NOT NULL,
    query            TEXT,               -- search that shows the matching events
    sample           JSONB NOT NULL DEFAULT '[]',
    notify_status    TEXT,               -- sent | failed: ... | no webhook configured
    notified_at      TIMESTAMPTZ,
    acknowledged_by  TEXT,
    acknowledged_at  TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX alerts_tenant_created ON alerts (tenant, created_at DESC);
CREATE INDEX alerts_active ON alerts (rule_id, tenant, group_key, last_seen DESC) WHERE status <> 'closed';

GRANT SELECT ON alert_rules, alerts TO logs_reader;

ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
CREATE POLICY alerts_tenant_isolation ON alerts FOR SELECT TO logs_reader
    USING (current_setting('app.tenant', true) = '*'
           OR tenant = current_setting('app.tenant', true));

ALTER TABLE alert_rules ENABLE ROW LEVEL SECURITY;
CREATE POLICY rules_tenant_isolation ON alert_rules FOR SELECT TO logs_reader
    USING (current_setting('app.tenant', true) = '*'
           OR tenant IS NULL
           OR tenant = current_setting('app.tenant', true));
