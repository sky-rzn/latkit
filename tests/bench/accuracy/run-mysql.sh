#!/usr/bin/env bash
#
# MySQL accuracy validation stand (MYSQL.md М7, РМ5 — the mysql analogue of
# run.sh / task 8.2, Р50).
#
# One controlled workload, two views of it:
#
#   - the agent's counters/histograms   (--dump-metrics at exit, proto=mysql);
#   - performance_schema.events_statements_summary_by_digest
#                                       (COUNT_STAR + latency per server digest).
#
# The join re-normalises each server DIGEST_TEXT through the agent's own
# lk_norm_sql (the `lknorm` CLI, MySQL dialect) so a digest lands on exactly the
# agent series that counted the same statements — the server digests on its
# parser, the agent on the РМ9 lexer, so their raw texts do not match and the
# re-normalisation is what makes the comparison honest (the same reason the PG
# stand keeps pg_stat_statements out of its join). The stand owns the exact
# ground truth: the workload runs each statement family a known number of times.
#
# Control-plane statements (seeding, the digest reset) go over the container's
# unix socket via `docker exec` — invisible to the capture by design, so both
# views see exactly the workload. The workload itself is driven at the container
# IP, never 127.0.0.1 (the docker-proxy relay would pollute the capture).
#
# A run is VALID only if the agent dump shows zero latkit_ringbuf_dropped_total
# and zero latkit_resync_total: `count matches exactly` and the РМ5 row bound
# (SELECT rows = row packets seen; a lossless run has no holes) are meaningful
# only on a clean capture.
#
# Usage:
#   tests/bench/accuracy/run-mysql.sh          # full run (~2 min)
#   tests/bench/accuracy/run-mysql.sh down     # remove a leftover container
#
# Knobs (env): SELECT_N=2000, AGG_N=500, UPD_N=500, TXN_N=300, SLEEP2_N=300,
#   SLEEP50_N=200, ROWS_N=200, ERR_N=200, TOL=5 (percent), MIN_MS=1,
#   AGENT_BIN=build/latkit, BUILD_DIR=build, OUT=tests/bench/accuracy/out/<ts>.
#
# Requirements: docker; passwordless sudo for the agent (BPF); an agent build
# and the lknorm tool (cmake --build build --target latkit lknorm); python3.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$HERE/../../.." && pwd)
BUILD_DIR=${BUILD_DIR:-$REPO_ROOT/build}
AGENT_BIN=${AGENT_BIN:-$BUILD_DIR/latkit}
LKNORM=${LKNORM:-$BUILD_DIR/lknorm}
IMAGE=mysql:8.4
MY=latkit-acc-mysql
DB_NAME=bench
DB_USER=root
DB_PW=pw
PROM=http://127.0.0.1:9752/metrics

SELECT_N=${SELECT_N:-2000}
AGG_N=${AGG_N:-500}
UPD_N=${UPD_N:-500}
TXN_N=${TXN_N:-300}
SLEEP2_N=${SLEEP2_N:-300}
SLEEP50_N=${SLEEP50_N:-200}
ROWS_N=${ROWS_N:-200}
ERR_N=${ERR_N:-200}
TOL=${TOL:-5}
MIN_MS=${MIN_MS:-1}
OUT=${OUT:-$HERE/out/$(date -u +%Y%m%dT%H%M%SZ)}

log()  { printf '\n=== %s ===\n' "$*"; }
note() { printf '  %s\n' "$*"; }
die()  { printf '  FATAL: %s\n' "$*" >&2; exit 1; }

myx() { docker exec -i "$MY" mysql -u"$DB_USER" -p"$DB_PW" "$@" 2>/dev/null; }
container_ip() {
    docker inspect "$MY" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
}
# Workload client: the mysql:8.4 image on the host network, talking to the
# container IP (never localhost — see the header). --ssl-mode=DISABLED keeps
# the wire plaintext so the socket capture sees the classic protocol;
# --get-server-public-key lets caching_sha2_password (the 8.4 default) do its
# RSA key exchange over that plaintext link, no TLS needed (plan risk 2).
myload() {
    docker run --rm -i --network host "$IMAGE" \
        mysql --ssl-mode=DISABLED --get-server-public-key \
        -h "$1" -u"$DB_USER" -p"$DB_PW" "$DB_NAME" 2>/dev/null
}

agent_pid() { pgrep -x latkit || true; }
AGENT_JOB=
agent_start() {
    [ -z "$(agent_pid)" ] || die "a latkit process is already running"
    sudo -n "$AGENT_BIN" -p 3306=mysql --dump-metrics="$OUT/agent.prom" \
        --prom-listen 127.0.0.1:9752 >>"$OUT/agent.log" 2>&1 &
    AGENT_JOB=$!
    for _ in $(seq 100); do
        curl -fsS -o /dev/null "$PROM" 2>/dev/null && return 0
        sleep 0.2
    done
    die "agent did not come up (see $OUT/agent.log)"
}
agent_stop() {
    local pid; pid=$(agent_pid)
    if [ -n "$pid" ]; then
        sudo -n kill -INT "$pid"
        for _ in $(seq 100); do [ -z "$(agent_pid)" ] && break; sleep 0.2; done
        [ -z "$(agent_pid)" ] || sudo -n kill -KILL "$(agent_pid)" 2>/dev/null || true
    fi
    [ -n "$AGENT_JOB" ] && { wait "$AGENT_JOB" 2>/dev/null || true; }
    AGENT_JOB=
}
cleanup() { agent_stop; docker rm -f "$MY" >/dev/null 2>&1 || true; }

if [ "${1:-}" = down ]; then docker rm -f "$MY" >/dev/null 2>&1 || true; exit 0; fi
trap cleanup EXIT
mkdir -p "$OUT"

command -v docker >/dev/null || die "docker not found"
[ -x "$AGENT_BIN" ] || die "agent not built: $AGENT_BIN (cmake --build $BUILD_DIR --target latkit)"
[ -x "$LKNORM" ] || die "lknorm not built: $LKNORM (cmake --build $BUILD_DIR --target lknorm)"

# --- 1. a fresh mysqld, performance_schema on, CPU-bound ---------------------
log "starting $IMAGE ($MY)"
docker rm -f "$MY" >/dev/null 2>&1 || true
# No --skip-ssl: MySQL 8.4 removed it as a server option. TLS is auto-offered
# but the workload clients opt out with --ssl-mode=DISABLED, so the wire stays
# plaintext for the socket capture (myload).
docker run -d --name "$MY" \
    -e MYSQL_ROOT_PASSWORD="$DB_PW" -e MYSQL_DATABASE="$DB_NAME" \
    "$IMAGE" mysqld \
    --performance_schema=ON \
    --performance-schema-consumer-statements-digest=ON \
    --innodb_flush_log_at_trx_commit=0 --sync_binlog=0 --skip-log-bin >/dev/null
for _ in $(seq 90); do
    myx -e 'SELECT 1' >/dev/null 2>&1 && break
    sleep 1
done
myx -e 'SELECT 1' >/dev/null 2>&1 || die "mysqld did not become ready"
IP=$(container_ip)
note "container IP: $IP"

# --- 2. seed (control plane, over the socket — invisible to the capture) -----
log "seeding the dataset (control plane, socket)"
myx "$DB_NAME" <<'SQL'
CREATE TABLE IF NOT EXISTS accounts (id INT PRIMARY KEY, abalance INT NOT NULL, filler CHAR(84));
CREATE TABLE IF NOT EXISTS uniq (id INT PRIMARY KEY);
SET SESSION cte_max_recursion_depth = 10001;
INSERT INTO accounts (id, abalance, filler)
    SELECT n, 0, 'x' FROM (
        WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n < 10000)
        SELECT n FROM seq) s
ON DUPLICATE KEY UPDATE abalance = accounts.abalance;
INSERT IGNORE INTO uniq VALUES (1);
SQL

# --- 3. attach the agent, then reset the digest table right before load ------
log "starting the agent (-p 3306=mysql)"
agent_start
note "resetting performance_schema digests (measured phase begins now)"
myx -e 'TRUNCATE performance_schema.events_statements_summary_by_digest;'

# --- 4. the workload: exact repetition counts, at the container IP ------------
log "running the workload"
gen_workload() {
    # Point SELECT on a rotating id: one digest, known count.
    for i in $(seq 1 "$SELECT_N"); do echo "SELECT abalance FROM accounts WHERE id = $((i % 10000 + 1));"; done
    for _ in $(seq 1 "$AGG_N"); do echo "SELECT count(*), avg(abalance) FROM accounts WHERE id < 100;"; done
    for i in $(seq 1 "$UPD_N"); do echo "UPDATE accounts SET abalance = abalance + 1 WHERE id = $((i % 10000 + 1));"; done
    for i in $(seq 1 "$TXN_N"); do
        echo "BEGIN;"; echo "SELECT abalance FROM accounts WHERE id = $((i % 10000 + 1)) FOR UPDATE;"; echo "COMMIT;"
    done
    for _ in $(seq 1 "$SLEEP2_N"); do echo "SELECT SLEEP(0.002);"; done
    for _ in $(seq 1 "$SLEEP50_N"); do echo "SELECT SLEEP(0.05);"; done
    # A known-row-count SELECT: 100 rows each (РМ5 — rows = row packets seen).
    for _ in $(seq 1 "$ROWS_N"); do echo "SELECT id FROM accounts WHERE id <= 100;"; done
    # Injected errors: missing table (1146 / 42S02) and duplicate key (1062 / 23000).
    for _ in $(seq 1 "$ERR_N"); do echo "SELECT * FROM this_table_does_not_exist;"; done
    for _ in $(seq 1 "$ERR_N"); do echo "INSERT INTO uniq VALUES (1);"; done
}
gen_workload | myload "$IP" || true
note "workload done; draining"
sleep 3

# --- 5. capture both views ---------------------------------------------------
log "capturing the digest table and the agent dump"
myx "$DB_NAME" -N -B -e "
  SELECT COUNT_STAR, ROUND(SUM_TIMER_WAIT/1e9,4), DIGEST_TEXT
    FROM performance_schema.events_statements_summary_by_digest
   WHERE DIGEST_TEXT IS NOT NULL
   ORDER BY COUNT_STAR DESC;" >"$OUT/digests.tsv"
agent_stop
[ -s "$OUT/agent.prom" ] || die "no agent dump ($OUT/agent.prom)"

# --- 6. the join + verdicts --------------------------------------------------
log "join + verdicts"
LKNORM="$LKNORM" TOL="$TOL" MIN_MS="$MIN_MS" python3 - "$OUT/digests.tsv" "$OUT/agent.prom" "$OUT/join.tsv" <<'PY'
import os, re, subprocess, sys

digests_path, prom_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
lknorm, tol, min_ms = os.environ["LKNORM"], float(os.environ["TOL"]), float(os.environ["MIN_MS"])

# --- server side: normalise each DIGEST_TEXT through the agent's lexer -------
rows = []          # (count, latency_ms, digest_text)
for line in open(digests_path):
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 3:
        continue
    cnt, lat, txt = parts[0], parts[1], "\t".join(parts[2:])
    rows.append((int(cnt), float(lat), txt))

# The server's DIGEST_TEXT backtick-quotes every identifier (`abalance`,
# `accounts`) even though the client's raw statement did not — so it is
# stripped before re-normalising, recovering the bare-identifier form the
# agent parsed off the wire. Values are already `?` in the digest, so no
# backtick can appear inside a literal.
texts = "\n".join(t.replace("`", "").replace("\n", " ") for _, _, t in rows) + "\n"
norm = subprocess.run([lknorm, "-m"], input=texts, capture_output=True, text=True).stdout.splitlines()

# Control-plane noise the mysql CLI / admin path issues, never the workload:
# the per-connection `@@version_comment` probe, session setup, the digest
# reset. It crosses the capture on TCP (unlike PG's [local] socket control
# plane), so it is filtered by shape, on both sides, before the comparison.
_CP = re.compile(r"^(select @@|set |show |use |truncate |flush |select database|select \$)")
def control_plane(label):
    return not label or bool(_CP.match(label))

server = {}        # normalised text -> [count, latency_ms]
for (cnt, lat, _), nline in zip(rows, norm):
    label = nline.split("\t", 1)[1] if "\t" in nline else ""
    if control_plane(label):
        continue
    e = server.setdefault(label, [0, 0.0])
    e[0] += cnt
    e[1] += lat

# --- agent side: the proto=mysql query series -------------------------------
def parse_labels(s):
    return dict(re.findall(r'(\w+)="([^"]*)"', s))

agent = {}         # normalised query label -> count
agent_ok = agent_err = 0
drops = resyncs = 0
for line in open(prom_path):
    line = line.rstrip("\n")
    if line.startswith("#") or not line:
        continue
    name, _, rest = line.partition("{")
    val = line.rsplit(None, 1)[-1]
    if name == "latkit_ringbuf_dropped_total": drops += float(val)
    elif name == "latkit_resync_total": resyncs += float(val)
    elif name == "latkit_query_duration_seconds_count":
        lab = parse_labels("{" + rest)
        if lab.get("proto") != "mysql":
            continue
        q = lab.get("query", "")
        if control_plane(q):
            continue
        agent[q] = agent.get(q, 0) + int(float(val))
        if lab.get("code") == "error": agent_err += int(float(val))
        else: agent_ok += int(float(val))

# --- compare -----------------------------------------------------------------
fails = 0
with open(out_path, "w") as out:
    out.write("# query\tserver_count\tagent_count\tdelta%\tserver_ms\tverdict\n")
    seen = set()
    for label in sorted(set(server) | set(agent)):
        s = server.get(label, [0, 0.0]); a = agent.get(label, 0)
        seen.add(label)
        # The server sees control-plane / internal digests the agent never
        # captured (SET, SHOW, the seeding CTE); only compare the workload
        # families that both sides recorded.
        if s[0] == 0 or a == 0:
            out.write("%s\t%d\t%d\t-\t%.2f\tSKIP(one-sided)\n" % (label, s[0], a, s[1]))
            continue
        d = 100.0 * (a - s[0]) / s[0]
        verdict = "PASS" if abs(d) <= tol else "FAIL"
        if verdict == "FAIL": fails += 1
        out.write("%s\t%d\t%d\t%+.1f\t%.2f\t%s\n" % (label, s[0], a, d, s[1], verdict))
    out.write("# drops=%d resyncs=%d agent_ok=%d agent_err=%d\n" % (drops, resyncs, agent_ok, agent_err))
    verdict = "PASS" if fails == 0 and drops == 0 and resyncs == 0 else "FAIL"
    out.write("# verdict: %s\n" % verdict)

print("  join written to", out_path)
print("  matched families:", sum(1 for l in (set(server) & set(agent))))
if drops or resyncs:
    print("  INVALID run: drops=%d resyncs=%d (РМ5: counts meaningful only lossless)" % (drops, resyncs))
sys.exit(1 if (fails or drops or resyncs) else 0)
PY
rc=$?

log "verdict"
sed -n 's/^# verdict: //p' "$OUT/join.tsv" | sed 's/^/  /'
note "full table: $OUT/join.tsv"
if [ "$rc" -eq 0 ]; then
    echo "  M7 mysql accuracy: PASS"
else
    echo "  M7 mysql accuracy: FAIL (see $OUT/join.tsv)"
fi
exit "$rc"
