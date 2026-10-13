-- Tenants, users (RBAC) and ingest API keys.

CREATE TABLE tenants (
    id             TEXT PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$'),
    name           TEXT NOT NULL,
    retention_days INT CHECK (retention_days BETWEEN 7 AND 3650), -- NULL = RETENTION_DAYS default
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- role admin  + tenant NULL  -> global admin (all tenants, manages tenants/users/keys)
-- role admin  + tenant X     -> tenant admin (manages rules/alerts/users of X only)
-- role viewer + tenant X     -> read-only, tenant X only
CREATE TABLE users (
    id            SERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE CHECK (username ~ '^[A-Za-z0-9._@-]{3,64}$'),
    password_hash TEXT NOT NULL,                       -- argon2id
    role          TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
    tenant        TEXT REFERENCES tenants (id) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ,
    CHECK (role = 'admin' OR tenant IS NOT NULL)
);

-- Machine credentials for POST /api/ingest. Only a SHA-256 of the key is stored.
CREATE TABLE api_keys (
    id           SERIAL PRIMARY KEY,
    name         TEXT NOT NULL,
    tenant       TEXT REFERENCES tenants (id) ON DELETE CASCADE, -- NULL = any tenant named in the payload
    key_hash     TEXT NOT NULL UNIQUE,
    key_prefix   TEXT NOT NULL,                                  -- shown in the UI to recognise a key
    created_by   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);

GRANT SELECT ON tenants TO logs_reader;

-- Retention: drop whole daily partitions that are older than the tenant's retention.
-- A day D is dropped once D+1 <= today - retention, so data is always kept >= retention days.
CREATE FUNCTION drop_expired_partitions(p_default_days INT)
RETURNS TABLE (dropped TEXT) AS $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT p.tenant, p.day, p.table_name
        FROM event_partitions p
        LEFT JOIN tenants t ON t.id = p.tenant
        WHERE p.day + 1 <= (now() AT TIME ZONE 'UTC')::date
                           - COALESCE(t.retention_days, GREATEST(p_default_days, 7))
        ORDER BY p.day
    LOOP
        EXECUTE format('DROP TABLE IF EXISTS %I', r.table_name);
        DELETE FROM event_partitions WHERE tenant = r.tenant AND day = r.day;
        dropped := r.table_name;
        RETURN NEXT;
    END LOOP;
END $$ LANGUAGE plpgsql;
