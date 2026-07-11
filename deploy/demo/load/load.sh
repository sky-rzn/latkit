#!/usr/bin/env bash
# Demo load generator (Р43). Runs inside a postgres:17-alpine container against
# the server named by PGHOST (plaintext `postgres` or, in the tls profile,
# `pg-tls` with PGSSLMODE=require) — always over the compose network, never via
# a published localhost port (docker-proxy would splice() the payload and
# defeat the capture).
#
# The mix exists so every demo panel has data, not to benchmark anything:
#   - pgbench TPC-B + select-only     -> QPS, latency histograms, top queries;
#   - pg_sleep 0.2/0.6s               -> a visible p99 tail;
#   - division by zero, missing table,
#     unique violation                -> error rate + SQLSTATE breakdown
#                                        (22012 / 42P01 / 23505);
#   - a multi-row SELECT              -> rows/query, time-to-first-row.
set -u

: "${PGHOST:=postgres}"
export PGUSER="${PGUSER:-latkit}" PGDATABASE="${PGDATABASE:-latkit}"

until pg_isready -q; do sleep 1; done

# Fresh volume on every `up` (down -v), so initialise unconditionally; scale 10
# keeps init in seconds and the dataset bigger than shared_buffers defaults.
pgbench --initialize --scale=10

# pgbench exits after -T; the wrapper loops keep the load up for as long as the
# stack runs. -P prints progress into `docker compose logs load`.
while true; do pgbench -c 8 -j 2 -T 3600 -P 60 2>&1;               done &
while true; do pgbench -c 4 -j 2 -T 3600 --select-only >/dev/null; done &

while true; do
    psql -qXtc "select pg_sleep(0.2)" >/dev/null 2>&1
    psql -qXtc "select pg_sleep(0.6)" >/dev/null 2>&1
    psql -qXtc "select 1/0" >/dev/null 2>&1
    psql -qXtc "select * from no_such_table" >/dev/null 2>&1
    psql -qXtc "insert into pgbench_branches (bid, bbalance) values (1, 0)" >/dev/null 2>&1
    psql -qXtc "select aid, abalance from pgbench_accounts where aid <= 500" >/dev/null 2>&1
    sleep 3
done
