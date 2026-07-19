#!/usr/bin/env bash
# Demo load generator (MYSQL.md М8). Runs inside a mysql:8.4 container against
# the server named by MYSQL_HOST (plaintext `mysql` or, in the tls profile,
# `mysql-tls` with MYSQL_SSL=REQUIRED) — always over the compose network, never
# via a published localhost port (docker-proxy would splice() the payload and
# defeat the socket capture).
#
# The mix exists so every demo panel has data, not to benchmark anything:
#   - persistent point-read/update sessions -> QPS, latency histograms, top queries;
#   - SELECT SLEEP(0.2/0.6)                  -> a visible p99 tail;
#   - a missing table, a duplicate key,
#     a syntax error                         -> error rate + SQLSTATE breakdown
#                                               (42S02 / 23000 / 42000);
#   - a multi-row SELECT                     -> rows/query, time-to-first-row.
#   - explicit START TRANSACTION..COMMIT
#     and ..ROLLBACK                         -> transaction duration (ok/aborted);
#                                               autocommit statements never set
#                                               SERVER_STATUS_IN_TRANS, so without
#                                               these the txn panel is dead.
set -u

HOST="${MYSQL_HOST:-mysql}"
# Plaintext link: opt out of the always-offered 8.4 TLS and let
# caching_sha2_password auth over it via RSA. TLS profile: force TLS instead.
if [ "${MYSQL_SSL:-DISABLED}" = "REQUIRED" ]; then
    SSL=(--ssl-mode=REQUIRED)
else
    SSL=(--ssl-mode=DISABLED --get-server-public-key)
fi
MY=(mysql "${SSL[@]}" -h "$HOST" -ulatkit latkit)

until "${MY[@]}" -e 'SELECT 1' >/dev/null 2>&1; do sleep 1; done

# Fresh volume on every `up` (down -v), so seed unconditionally. A 10k-row
# accounts table, small enough to build in a couple of seconds.
"${MY[@]}" <<'SQL'
CREATE TABLE IF NOT EXISTS accounts (
    id INT PRIMARY KEY, abalance INT NOT NULL, filler CHAR(84)
);
SET SESSION cte_max_recursion_depth = 10001;
INSERT INTO accounts (id, abalance, filler)
    SELECT n, 0, 'x' FROM (
        WITH RECURSIVE seq(n) AS (
            SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < 10000
        ) SELECT n FROM seq
    ) s
ON DUPLICATE KEY UPDATE abalance = accounts.abalance;
SQL

# Volume: several persistent sessions streaming point reads + writes as fast as
# the link allows. Persistent (not a fresh connection per statement) so the
# dashboards show steady query rate rather than a connection-churn artifact.
for _ in 1 2 3 4 5 6 7 8; do
    ( while :; do
        id=$(( RANDOM % 10000 + 1 ))
        printf 'SELECT abalance FROM accounts WHERE id = %d;\n' "$id"
        printf 'UPDATE accounts SET abalance = abalance + 1 WHERE id = %d;\n' "$id"
      done ) | "${MY[@]}" >/dev/null 2>&1 &
done

# A steadier read stream: an aggregate + a multi-row range scan (rows/query and
# time-to-first-row).
( while :; do
    printf 'SELECT count(*), avg(abalance) FROM accounts WHERE id < 100;\n'
    printf 'SELECT id, abalance FROM accounts WHERE id <= 500;\n'
  done ) | "${MY[@]}" >/dev/null 2>&1 &

# Explicit transactions: give latkit_txn_duration_seconds its IN_TRANS edge. A
# COMMIT (status 'ok') and a ROLLBACK (status 'aborted') per loop so both series
# of the "Transaction duration (p95 by status)" panel are populated.
( while :; do
    id1=$(( RANDOM % 10000 + 1 )); id2=$(( RANDOM % 10000 + 1 ))
    printf 'START TRANSACTION;\n'
    printf 'UPDATE accounts SET abalance = abalance + 1 WHERE id = %d;\n' "$id1"
    printf 'SELECT abalance FROM accounts WHERE id = %d;\n' "$id2"
    printf 'COMMIT;\n'
    printf 'START TRANSACTION;\n'
    printf 'UPDATE accounts SET abalance = abalance - 1 WHERE id = %d;\n' "$id1"
    printf 'ROLLBACK;\n'
  done ) | "${MY[@]}" >/dev/null 2>&1 &

# Spice: a visible tail and the three error classes, each on its own short-lived
# session so a failed statement does not poison the persistent streams.
while true; do
    "${MY[@]}" -e "SELECT SLEEP(0.2)"                                    >/dev/null 2>&1
    "${MY[@]}" -e "SELECT SLEEP(0.6)"                                    >/dev/null 2>&1
    "${MY[@]}" -e "SELECT * FROM no_such_table"                          >/dev/null 2>&1
    "${MY[@]}" -e "INSERT INTO accounts (id, abalance) VALUES (1, 0)"    >/dev/null 2>&1
    "${MY[@]}" -e "SELCT 1"                                              >/dev/null 2>&1
    sleep 3
done
