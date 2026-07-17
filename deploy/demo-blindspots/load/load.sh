#!/usr/bin/env bash
# demo-blindspots load generator. Runs inside a postgres:17-alpine container
# against the server named by PGHOST over the compose network (never a published
# localhost port — docker-proxy would splice() the payload and defeat the socket
# capture, same rule as the other demos).
#
# Unlike ../demo (pgbench) and ../demo-olap (heavy analytics), this load exists to
# reproduce four *problematic query patterns* that the usual in-database tools —
# pg_stat_statements above all — either can't see or mis-summarise, while latkit,
# reading the wire, catches every one. Each loop is one blind spot; the README
# maps them to what you check in Grafana vs. in pg_stat_statements:
#
#   baseline   healthy indexed traffic, so the problems stand out against it
#   errors     five queries that ALWAYS fail -> pg_stat_statements records NONE of
#              them (a canceled/errored statement is never counted); latkit's
#              SQLSTATE + error-rate panels light up (57014/23505/42P01/22P02/23503)
#   cardinality IN (...) lists and multi-row VALUES of VARYING length -> a distinct
#              pg_stat_statements row per length (table bloats and evicts); latkit
#              normalises `( ?, ?, ... )` -> `( ? )` to ONE stable row
#   bigresult  an un-LIMITed report returning ~300k rows -> latkit reports the true
#              rows/query and time-to-first-row for it; server-side wire truth,
#              with nothing installed in postgres
set -u

: "${PGHOST:=postgres}"
export PGUSER="${PGUSER:-latkit}" PGDATABASE="${PGDATABASE:-latkit}"

HERE="$(dirname "$0")"

until pg_isready -q; do sleep 1; done

# Fresh volume on every `up` (down -v), so build the dataset unconditionally.
echo "load: building dataset (schema.sql) ..."
psql -qX -v ON_ERROR_STOP=1 -f "$HERE/schema.sql" || { echo "load: schema build failed"; exit 1; }
echo "load: dataset ready, starting the blind-spot workloads"

# --- helpers: build variable-length literal lists in the client, so the SQL text
# --- differs on every run exactly the way a naive query builder / ORM emits it.
rand_id_list() {            # $1 = how many ids -> "3,7,12,..."
    local n="$1" out="" i
    for ((i = 0; i < n; i++)); do out+="$((RANDOM % 50000 + 1)),"; done
    printf '%s' "${out%,}"
}
rand_value_rows() {         # $1 = how many rows -> "(3,7),(1,9),..."
    local n="$1" out="" i
    for ((i = 0; i < n; i++)); do out+="($((RANDOM % 1000)),$((RANDOM % 1000))),"; done
    printf '%s' "${out%,}"
}

# --- 1) baseline: healthy, indexed, fast. Gives the dashboards a normal QPS floor
# ---    and p50 so the deliberate problems read as a tail / error spike, not noise.
while true; do
    uid=$((RANDOM % 50000 + 1)); tid=$((RANDOM % 1000 + 1))
    psql -qXtc "select user_id, email from users where user_id = $uid"                                  >/dev/null 2>&1
    psql -qXtc "select event_id, type, created_at from events where tenant_id = $tid order by created_at desc limit 20" >/dev/null 2>&1
    psql -qXtc "update tenants set plan = plan where tenant_id = $tid"                                   >/dev/null 2>&1
done &

# --- 2) errors: five statements that always fail. None of these ever lands in
# ---    pg_stat_statements; all of them land in latkit's SQLSTATE panel.
while true; do
    # 57014 query_canceled — a runaway ad-hoc report killed by statement_timeout.
    #        pg_sleep stands in for the long-running query so the cancellation is
    #        deterministic on any hardware (a real seq scan's time tracks CPU
    #        speed and could slip under the cap on a fast box).
    psql -qXtc "set statement_timeout='200ms'; select pg_sleep(3)" >/dev/null 2>&1
    # 23505 unique_violation — an API-key rotation that collides with an existing token.
    psql -qXtc "insert into api_keys (key_id, user_id, token) values (1, 1, 'tok_'||md5('1'))"          >/dev/null 2>&1
    # 42P01 undefined_table — app still queries a table dropped in a migration.
    psql -qXtc "select * from audit_log where tenant_id = 42"                                            >/dev/null 2>&1
    # 22P02 invalid_text_representation — unvalidated input concatenated into SQL.
    psql -qXtc "select user_id, email from users where user_id = 'admin'"                                >/dev/null 2>&1
    # 23503 foreign_key_violation — an orphaned write to a non-existent tenant.
    psql -qXtc "insert into users (user_id, tenant_id, email, created_at) values (999999, 999999, 'orphan@example.com', now())" >/dev/null 2>&1
    sleep 2
done &

# --- 3) cardinality: IN-lists and multi-row VALUES of *varying* length. To
# ---    pg_stat_statements each length is a different query (the table churns and
# ---    evicts under pg_stat_statements.max=100); latkit collapses them to one.
while true; do
    n=$((RANDOM % 89 + 2))          # IN-list of 2..90 ids
    psql -qXtc "select user_id, email from users where user_id in ($(rand_id_list $n))" >/dev/null 2>&1
    m=$((RANDOM % 39 + 2))          # batch INSERT of 2..40 rows
    psql -qXtc "insert into ingest (a, b) values $(rand_value_rows $m)"                  >/dev/null 2>&1
    psql -qXtc "truncate ingest"                                                          >/dev/null 2>&1
    sleep 1
done &

# --- 4) bigresult: an un-LIMITed export that returns ~300k joined rows. latkit
# ---    reports its true rows/query and time-to-first-row from the wire; results
# ---    go to /dev/null but every DataRow still crosses the socket latkit reads.
types=(login click purchase logout view)
while true; do
    typ=${types[RANDOM % ${#types[@]}]}
    psql -qXc "select e.event_id, e.type, e.created_at, u.email
               from events e join users u on u.user_id = e.user_id
               where e.type = '$typ'" >/dev/null 2>&1
    sleep 3
done &

wait
