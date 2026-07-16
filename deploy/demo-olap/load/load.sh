#!/usr/bin/env bash
# demo-olap load generator. Runs inside a postgres:17-alpine container against the
# server named by PGHOST over the compose network (never a published localhost
# port — docker-proxy would splice() the payload and defeat the socket capture,
# same rule as the base demo).
#
# Unlike the base demo (pgbench, tiny statements, high QPS), this one drives the
# nine heavyweight analytical queries in queries.sql: recursive CTEs, window
# functions, GROUPING SETS / CUBE, LATERAL, percentiles. The point is to show
# latkit under a *complex* workload — big multi-row results (rows/query and
# time-to-first-row panels), a fat p99 tail from the heavier queries, and a
# handful of distinct normalized shapes on "Top queries".
set -u

: "${PGHOST:=postgres}"
export PGUSER="${PGUSER:-latkit}" PGDATABASE="${PGDATABASE:-latkit}"

WORKERS="${WORKERS:-3}"      # parallel analytical sessions
HERE="$(dirname "$0")"

until pg_isready -q; do sleep 1; done

# Fresh volume on every `up` (down -v), so build the dataset unconditionally.
echo "load: building dataset (schema.sql) ..."
psql -qX -v ON_ERROR_STOP=1 -f "$HERE/schema.sql" || { echo "load: schema build failed"; exit 1; }
echo "load: dataset ready, starting $WORKERS analytical worker(s)"

# Each worker loops the whole query file over one reused connection. Results go to
# /dev/null (latkit still sees every row on the wire); \timing lines survive on
# stderr so `docker compose logs load` shows per-query latency.
for w in $(seq 1 "$WORKERS"); do
    while true; do
        psql -qX -f "$HERE/queries.sql" >/dev/null
        sleep 1
    done &
done

# Spice loop: a guaranteed slow query for the p99 tail plus three deliberate
# failures for the error-rate and SQLSTATE panels (22012 / 42P01 / 23505 — the
# last is a duplicate primary key in categories).
while true; do
    psql -qXtc "select pg_sleep(0.4)"                                    >/dev/null 2>&1
    psql -qXtc "select 1/0"                                              >/dev/null 2>&1
    psql -qXtc "select * from no_such_table"                             >/dev/null 2>&1
    psql -qXtc "insert into categories (category_id, name) values (1, 'dup')" >/dev/null 2>&1
    sleep 5
done
