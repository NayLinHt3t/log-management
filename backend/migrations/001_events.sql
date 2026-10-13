-- Central event store.
-- Two-level partitioning gives every tenant its own physical tables and indexes:
--   events                       (partitioned by LIST tenant)
--     events_demoA               (partitioned by RANGE ts, one partition per UTC day)
--       events_demoA_20261012
--       events_demoA_20261013 ...
-- Queries filtered by tenant + time only touch the matching partitions, and retention is a
-- cheap DROP TABLE of whole days instead of a slow DELETE.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE events (
    id               BIGINT GENERATED ALWAYS AS IDENTITY,
    ts               TIMESTAMPTZ NOT NULL,              -- event time ("@timestamp")
    ingested_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    tenant           TEXT NOT NULL,
    source           TEXT NOT NULL,
    vendor           TEXT,
    product          TEXT,
    event_type       TEXT NOT NULL,
    event_subtype    TEXT,
    severity         SMALLINT NOT NULL DEFAULT 0 CHECK (severity BETWEEN 0 AND 10),
    action           TEXT,
    outcome          TEXT,
    src_ip           INET,
    src_port         INT,
    dst_ip           INET,
    dst_port         INT,
    protocol         TEXT,
    username         TEXT,                               -- "user" is a reserved word
    host             TEXT,
    process          TEXT,
    url              TEXT,
    http_method      TEXT,
    status_code      INT,
    rule_name        TEXT,
    rule_id          TEXT,
    cloud_account_id TEXT,
    cloud_region     TEXT,
    cloud_service    TEXT,
    tags             TEXT[] NOT NULL DEFAULT '{}',
    raw              JSONB NOT NULL DEFAULT '{}',        -- original record, untouched
    PRIMARY KEY (tenant, ts, id)                         -- must contain both partition keys
) PARTITION BY LIST (tenant);

-- Defined once on the parent, created automatically on every partition.
-- The primary key already serves "ORDER BY ts DESC" inside a tenant/day partition.
CREATE INDEX events_src_ip_idx  ON events (src_ip, ts DESC);
CREATE INDEX events_user_idx    ON events (username, ts DESC);
CREATE INDEX events_type_idx    ON events (event_type, ts DESC);
CREATE INDEX events_source_idx  ON events (source, ts DESC);
CREATE INDEX events_tags_idx    ON events USING GIN (tags);
CREATE INDEX events_raw_idx     ON events USING GIN (raw jsonb_path_ops);       -- raw.field:value
CREATE INDEX events_raw_trgm    ON events USING GIN ((raw::text) gin_trgm_ops); -- free text

-- Bookkeeping for retention: which daily tables exist.
CREATE TABLE event_partitions (
    tenant     TEXT NOT NULL,
    day        DATE NOT NULL,
    table_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, day)
);

CREATE FUNCTION ensure_tenant_partition(p_tenant TEXT) RETURNS TEXT AS $$
DECLARE
    tbl TEXT := 'events_' || p_tenant;
BEGIN
    IF p_tenant !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$' THEN
        RAISE EXCEPTION 'invalid tenant id: %', p_tenant;
    END IF;
    IF to_regclass(format('%I', tbl)) IS NULL THEN
        PERFORM pg_advisory_xact_lock(hashtext('events_partitions'));
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF events FOR VALUES IN (%L) PARTITION BY RANGE (ts)',
            tbl, p_tenant);
    END IF;
    RETURN tbl;
END $$ LANGUAGE plpgsql;

-- Creates (if needed) the partition holding one tenant's events for one UTC day.
CREATE FUNCTION ensure_event_partition(p_tenant TEXT, p_day DATE) RETURNS TEXT AS $$
DECLARE
    parent TEXT;
    tbl    TEXT;
BEGIN
    parent := ensure_tenant_partition(p_tenant);
    tbl := parent || '_' || to_char(p_day, 'YYYYMMDD');
    IF to_regclass(format('%I', tbl)) IS NULL THEN
        PERFORM pg_advisory_xact_lock(hashtext('events_partitions'));
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
            tbl, parent,
            p_day::timestamp AT TIME ZONE 'UTC',
            (p_day + 1)::timestamp AT TIME ZONE 'UTC');
        INSERT INTO event_partitions (tenant, day, table_name)
        VALUES (p_tenant, p_day, tbl)
        ON CONFLICT DO NOTHING;
    END IF;
    RETURN tbl;
END $$ LANGUAGE plpgsql;

-- Read path isolation: the API runs every read as this role (SET LOCAL ROLE) with
-- app.tenant set from the user's JWT. Postgres then filters rows itself.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'logs_reader') THEN
        CREATE ROLE logs_reader NOLOGIN;
    END IF;
END $$;
GRANT logs_reader TO CURRENT_USER;
GRANT USAGE ON SCHEMA public TO logs_reader;
GRANT SELECT ON events TO logs_reader;

ALTER TABLE events ENABLE ROW LEVEL SECURITY;
CREATE POLICY events_tenant_isolation ON events FOR SELECT TO logs_reader
    USING (current_setting('app.tenant', true) = '*'
           OR tenant = current_setting('app.tenant', true));
