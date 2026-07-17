-- demo-blindspots schema: a small multi-tenant SaaS database, built purely with
-- generate_series so `docker compose up` needs no external data. The point of
-- this stack is not the schema but the *problematic query patterns* the load
-- drives against it (load.sh) — each one a blind spot of the usual in-database
-- tools that latkit sees anyway. Sizes are picked so init finishes in a handful
-- of seconds while the "export" and "runaway report" queries still do real work.
--
--   tenants    1k    rows   — the SaaS accounts
--   users     50k    rows   — email UNIQUE (feeds the unique-violation error)
--   api_keys  50k    rows   — token  UNIQUE (feeds a second unique violation)
--   events   1.5M    rows   — the fact table: big enough for a slow seq scan and
--                             a genuinely large (un-LIMITed) result set
--   ingest      -           — UNLOGGED scratch target for variable-size batch
--                             INSERT ... VALUES (the multi-row cardinality demo)

BEGIN;

DROP TABLE IF EXISTS events, api_keys, users, tenants, ingest CASCADE;

-- pg_stat_statements is what this demo contrasts latkit against, so make sure the
-- view exists. (shared_preload_libraries is set on the postgres command line in
-- docker-compose.yml — the extension is preloaded; here we just register it.)
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

CREATE TABLE tenants (
    tenant_id int PRIMARY KEY,
    name      text NOT NULL,
    plan      text NOT NULL
);
INSERT INTO tenants
SELECT g, 'tenant-' || g, (ARRAY['free','pro','enterprise'])[1 + (random() * 2)::int]
FROM generate_series(1, 1000) g;

CREATE TABLE users (
    user_id    int  PRIMARY KEY,
    tenant_id  int  NOT NULL REFERENCES tenants(tenant_id),
    email      text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL
);
INSERT INTO users
SELECT g,
       1 + (random() * 999)::int,
       'user' || g || '@example.com',
       now() - (random() * 400)::int * interval '1 day'
FROM generate_series(1, 50000) g;
CREATE INDEX ON users (tenant_id);

CREATE TABLE api_keys (
    key_id     int  PRIMARY KEY,
    user_id    int  NOT NULL REFERENCES users(user_id),
    token      text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO api_keys
SELECT g, g, 'tok_' || md5(g::text), now()
FROM generate_series(1, 50000) g;

-- The fact table. 1.5M rows, indexed on the columns the *healthy* queries use so
-- the point reads stay fast; the "problem" queries deliberately dodge the indexes.
CREATE TABLE events (
    event_id   bigint PRIMARY KEY,
    tenant_id  int  NOT NULL,
    user_id    int  NOT NULL,
    type       text NOT NULL,
    payload    text NOT NULL,
    created_at timestamptz NOT NULL
);
INSERT INTO events
SELECT g,
       1 + (random() * 999)::int,
       1 + (random() * 49999)::int,
       (ARRAY['login','click','purchase','logout','error','view'])[1 + (random() * 5)::int],
       'payload-' || md5(g::text),
       now() - (random() * 90)::int * interval '1 day'
FROM generate_series(1, 1500000) g;
CREATE INDEX ON events (tenant_id);
CREATE INDEX ON events (created_at);

-- UNLOGGED scratch table for the batch-INSERT cardinality demo (load.sh sends
-- INSERT ... VALUES with a *variable* number of rows). UNLOGGED + a periodic
-- TRUNCATE keeps it from growing without bounds.
CREATE UNLOGGED TABLE ingest (a int, b int);

COMMIT;

ANALYZE;
