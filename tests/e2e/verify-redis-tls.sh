#!/usr/bin/env bash
#
# Redis-over-TLS e2e check (PLAN-REDIS.md МR7, РR12): a TLS-only Redis, the same
# Redis in plaintext, one client driving an identical command sequence at both,
# and three agents — the plaintext control, the encrypted leg on `--tls auto`,
# and the encrypted leg watched through `--comm redis-server`.
#
# МR7 claims two things and this script tests both:
#
#   1. **The existing libssl channel carries Redis.** No new BPF was written for
#      this milestone (МR0 recon item 5: every image measured links libssl
#      dynamically), so the claim is that pointing the existing scan at
#      {redis-server, valkey-server, keydb-server} yields, on an encrypted port,
#      the observations a plaintext run of the same load yields. That is a
#      comparison, not a threshold, so the script drives both legs identically,
#      stops the load, and compares `latkit_redis_*` command by command.
#   2. **io-threads do not break the correlation, and the gate has to know
#      about them.** With `io-threads 4`, Redis makes the SSL_read and SSL_write
#      of one connection from threads named `io_thd_1…3`; the `{ssl, tgid}`
#      bridge is keyed on the process and should not care, and the uprobe gate
#      is keyed on the thread comm and very much does. The memtier phase drives
#      100 connections (Redis engages its io threads above `io-threads × 2`
#      clients) and asserts that the derived gate sees the whole load while the
#      `--comm redis-server` leg beside it does not.
#
# Plus the invariants that do not get weaker because the bytes arrived
# decrypted: no key and no password in either exposition, no unit lost, no
# parse error.
#
# Needs Docker, BPF privileges, and /proc of the servers (pid: host). Optional
# in CI like the other stands.
#
#   ./verify-redis-tls.sh                 # build, up, assert, down
#   KEEP=1 ./verify-redis-tls.sh          # leave the stand running afterwards
#   SOAK_SEC=86400 ./verify-redis-tls.sh  # + the МR7 soak: memtier through the
#                                         #   uprobes, and Redis has to survive it
set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT=$(cd ../.. && pwd)
COMPOSE="docker compose -p latkit-redis-tls -f docker-compose.redis-tls.yml"
PROM=http://localhost:19094
NET=latkit-redis-tls-net
MEMTIER_IMAGE=${MEMTIER_IMAGE:-redislabs/memtier_benchmark:latest}
SOAK_SEC=${SOAK_SEC:-0}
# 4 threads x 25 clients = 100 connections, which is what makes Redis hand the
# socket work to its io threads at all (above io-threads x 2 clients, МR0 recon
# item 4); 1000 requests each is 100 000 commands, enough for the difference
# between the two encrypted legs to be a fact rather than a fluctuation.
MEMTIER_THREADS=4
MEMTIER_CLIENTS=25
MEMTIER_REQUESTS=${MEMTIER_REQUESTS:-1000}
fails=0

tmp=$(mktemp -d)

log()  { printf '\n=== %s ===\n' "$*"; }
note() { printf '  %s\n' "$*"; }
pass() { printf '  ok   - %s\n' "$*"; }
fail() { printf '  FAIL - %s\n' "$*"; fails=$((fails + 1)); }

cleanup() {
    rm -rf "$tmp"
    if [ "${KEEP:-0}" = "1" ]; then
        log "KEEP=1 — leaving the stand up ('$COMPOSE down -v' to stop)"
        return
    fi
    log "tearing down"
    $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

promql()    { curl -sG "$PROM/api/v1/query" --data-urlencode "query=$1"; }
scalar_of() {
    promql "$1" | python3 -c '
import json, sys
r = json.load(sys.stdin).get("data", {}).get("result", [])
print(r[0]["value"][1] if r else "")
'
}
gt() { [ -n "$1" ] && python3 -c "import sys; sys.exit(0 if float('$1')>${2:-0} else 1)"; }

# --- 0. build and up --------------------------------------------------------
log "building the agent on the host"
cmake --build "$REPO_ROOT/build" --target latkit -j"$(nproc)" >/dev/null
note "built $REPO_ROOT/build/latkit"

log "bringing both legs up (plaintext :6479, TLS-only :6480, io-threads 4)"
$COMPOSE up -d --build
note "waiting for the uprobes to attach, the load to run and Prometheus to scrape"
sleep 40

for svc in latkit-plain latkit-tls latkit-tls-main; do
    if ! $COMPOSE ps $svc | grep -q ' Up\| running'; then
        fail "$svc is not running (BPF privileges? '$COMPOSE logs $svc')"
        $COMPOSE logs --tail=30 $svc || true
        exit 1
    fi
done

# Read the log into a file before grepping it: a `compose logs | grep -q`
# pipeline reports the writer's SIGPIPE under `set -o pipefail`, which reads as
# a failed match that sometimes passes.
$COMPOSE logs latkit-tls > "$tmp/latkit-tls.log" 2>&1 || true
grep -iE 'tls|libssl|uprobe|warn' "$tmp/latkit-tls.log" | tail -6 || true

for leg in plain tls tls-main; do
    [ "$(scalar_of "up{job=\"latkit-$leg\"}")" = "1" ] \
        || fail "Prometheus does not scrape latkit-$leg (up != 1)"
done
pass "Prometheus scrapes the three legs"

# --- 1. the derivation this milestone adds, in the agent's own words --------
log "what a redis port derives (РR12)"
cfg=$($COMPOSE run --rm --no-deps latkit-tls -p 6480=redis --tls auto --print-config 2>/dev/null \
      | grep -E '^tls_(scan|gate)_comm=' || true)
note "$(printf '%s' "$cfg" | tr '\n' ' ')"
case "$cfg" in
    *"tls_scan_comm=redis-server,valkey-server,keydb-server"*)
        pass "the scan set for a redis port is the three RESP servers" ;;
    *) fail "the redis port did not derive its scan set: $cfg" ;;
esac
case "$cfg" in
    *"io_thd_*"*) pass "the uprobe gate is widened by the io threads (io_thd_*)" ;;
    *) fail "the gate has no io-thread entry — the io threads' events will be dropped" ;;
esac

if grep -q "TLS uprobes attached on" "$tmp/latkit-tls.log"; then
    pass "libssl found and hooked in the running server: $(grep -m1 'TLS uprobes attached on' "$tmp/latkit-tls.log" | sed 's/.*attached on //')"
else
    fail "no libssl was attached — see the log:"
    grep -i 'libssl\|uprobe' "$tmp/latkit-tls.log" | head -3 | sed 's/^/      /'
fi

# --- 2. the TLS path is provably the data source ----------------------------
# The encrypted leg's port carries no plaintext at all (`--port 0` on that
# server), so anything observed there came through the uprobes by construction.
log "the decrypted channel"
attached=$(scalar_of 'latkit_tls_attached{job="latkit-tls",state="ok"}')
if [ "$attached" = "1" ]; then
    pass 'latkit_tls_attached{state="ok"} == 1'
else
    part=$(scalar_of 'latkit_tls_attached{job="latkit-tls",state="partial"}')
    [ "$part" = "1" ] && pass 'latkit_tls_attached{state="partial"} == 1' \
        || fail "the libssl uprobes are not attached (state is none)"
fi

gt "$(scalar_of 'latkit_tls_connections_total{job="latkit-tls"}')" \
    && pass "connections on :6480 were recognised as TLS at the socket" \
    || fail "no connection went TLS — is the encrypted leg really encrypted?"

uev=$(scalar_of 'latkit_tls_uprobe_events_total{job="latkit-tls"}')
note "latkit_tls_uprobe_events_total = ${uev:-<none>}"
gt "$uev" && pass "decrypted events flowed from the libssl probes" || fail "no decrypted events"

miss=$(scalar_of 'latkit_tls_correlation_misses_total{job="latkit-tls"}')
note "latkit_tls_correlation_misses_total = ${miss:-0}"
if python3 -c "import sys; m=float('${miss:-0}'); e=float('${uev:-0}'); sys.exit(0 if e>0 and m <= 0.05*e + 5 else 1)"; then
    pass "correlation misses negligible vs events (the {ssl,tgid} bridge holds)"
else
    fail "too many correlation misses ($miss) — the SSL*->connection bridge is failing"
fi

# --- 3. measure a window of load, then stop and compare ---------------------
# Two snapshots with the load stopped at both ends, for the reasons the S3 stand
# learned: the agents attach at slightly different moments (so the client's
# bootstrap lands on whichever was listening), and sampling while the loop runs
# measures the loop's phase, since it drives the legs one after the other.
snapshot() {
    for leg in plain tls; do
        curl -sG "$PROM/api/v1/query" \
             --data-urlencode "query=sum by (cmd,code) (latkit_redis_commands_total{job=\"latkit-$leg\"})" \
             > "$tmp/$1-$leg.json"
    done
    curl -sG "$PROM/api/v1/query" \
         --data-urlencode 'query=sum by (job,error) (latkit_redis_errors_total)' > "$tmp/$1-errors.json"
    curl -sG "$PROM/api/v1/query" \
         --data-urlencode 'query=sum by (job) (latkit_redis_bytes_total)' > "$tmp/$1-bytes.json"
    curl -sG "$PROM/api/v1/query" \
         --data-urlencode 'query=sum by (job) (latkit_redis_push_total)' > "$tmp/$1-push.json"
    for leg in plain tls; do
        curl -sG "$PROM/api/v1/query" \
             --data-urlencode "query=sum by (db,user) (latkit_redis_commands_total{job=\"latkit-$leg\"})" \
             > "$tmp/$1-$leg-labels.json"
    done
}

log "measuring a window of load, quiescent at both ends"
$COMPOSE stop load >/dev/null 2>&1 || true
sleep 12
snapshot a
note "running the load for 45 s with both legs up"
$COMPOSE start load >/dev/null 2>&1
sleep 45
$COMPOSE stop load >/dev/null 2>&1 || true
sleep 12
snapshot b

c_tls=$(scalar_of 'sum(latkit_redis_commands_total{job="latkit-tls"})')
c_pln=$(scalar_of 'sum(latkit_redis_commands_total{job="latkit-plain"})')
note "commands: tls=${c_tls:-0} plain=${c_pln:-0}"
gt "$c_tls" && pass "commands observed on a port that is ciphertext end to end" \
    || fail "nothing observed on the TLS leg"
gt "$c_pln" && pass "the plaintext control leg observed its own load" \
    || fail "the control leg saw nothing — the comparison below is meaningless"

p95=$(scalar_of 'histogram_quantile(0.95, sum(rate(latkit_redis_command_duration_seconds_bucket{job="latkit-tls"}[5m])) by (le))')
note "TLS leg p95 command duration = ${p95:-<none>} s"
if [ -n "$p95" ] && python3 -c "import sys; v=float('$p95'); sys.exit(0 if 0<=v<60 else 1)" 2>/dev/null; then
    pass "duration p95 is a plausible latency (0..60 s)"
else
    fail "p95 missing or out of range"
fi

log "TLS vs plaintext: the same load, observed both ways"
if python3 - "$tmp" <<'PY'
import json, os, sys

D = sys.argv[1]

def vec(path, keys):
    r = json.load(open(path))["data"]["result"]
    return {tuple(s["metric"].get(k, "") for k in keys): float(s["value"][1]) for s in r}

def window(name, keys):
    """What happened between the two snapshots: the counters are cumulative, so
    the difference is the window, and a key present only in b started at zero."""
    a = vec(os.path.join(D, "a-%s.json" % name), keys)
    b = vec(os.path.join(D, "b-%s.json" % name), keys)
    return {k: v - a.get(k, 0.0) for k, v in b.items() if v - a.get(k, 0.0) > 0}

plain  = window("plain", ("cmd", "code"))
tls    = window("tls", ("cmd", "code"))
errs   = window("errors", ("job", "error"))
byjob  = window("bytes", ("job",))
push   = window("push", ("job",))
lab_p  = window("plain-labels", ("db", "user"))
lab_t  = window("tls-labels", ("db", "user"))

ok = True
if not plain or not tls:
    print("    one of the legs observed nothing during the window")
    sys.exit(1)

# The load is a fixed sequence per iteration, so the *set* of (cmd, code) must
# match exactly: a command missing on the encrypted leg is a hole in the
# channel, not a rounding difference.
only_p, only_t = sorted(set(plain) - set(tls)), sorted(set(tls) - set(plain))
if only_p or only_t:
    ok = False
    print("    plaintext-only: %s" % (only_p or "-"))
    print("    TLS-only:       %s" % (only_t or "-"))

print("    %-26s %10s %10s %8s" % ("cmd/code", "plain", "tls", "delta"))
for k in sorted(set(plain) | set(tls)):
    a, b = plain.get(k, 0.0), tls.get(k, 0.0)
    print("    %-26s %10.0f %10.0f %7.1f%%"
          % ("/".join(k), a, b, 100 * abs(a - b) / max(a, b, 1.0)))
    # A few commands of skew are allowed (the window's edges fall inside an
    # iteration and the client stops mid-sequence); past that it is the channel
    # losing commands, which is what a half-working correlation looks like.
    if abs(a - b) > max(4.0, 0.10 * max(a, b)):
        ok = False
        print("      ^ beyond tolerance")

bp, bt = byjob.get(("latkit-plain",), 0.0), byjob.get(("latkit-tls",), 0.0)
print("    RESP bytes: plain=%.0f tls=%.0f (%.1f%%)"
      % (bp, bt, 100 * abs(bp - bt) / max(bp, bt, 1.0)))
if abs(bp - bt) > 0.15 * max(bp, bt, 1.0):
    ok = False
    print("      ^ the two legs did not carry the same volume")

ep = {k[1] for k in errs if k[0] == "latkit-plain"}
et = {k[1] for k in errs if k[0] == "latkit-tls"}
print("    symbolic errors: plain=%s tls=%s" % (sorted(ep) or "-", sorted(et) or "-"))
if not et or ep != et:
    ok = False
    print("      ^ the named failures differ between the legs")

# A push is not a reply (РR8), and a subscriber on each leg is publishing into
# both windows: the encrypted leg must have recognised them as pushes too, or
# its queue would have drifted and every latency after the first message on that
# connection would be someone else's.
pp, pt = push.get(("latkit-plain",), 0.0), push.get(("latkit-tls",), 0.0)
print("    pushes: plain=%.0f tls=%.0f" % (pp, pt))
if pt <= 0:
    ok = False
    print("      ^ no push seen through TLS — the subscriber's messages were counted as replies")

# The session labels are connection state parsed out of the decrypted stream
# (РR5/РR6): a `SELECT 3` and an ACL user seen on one leg must be seen on both.
sp, st = {k for k in lab_p}, {k for k in lab_t}
print("    (db,user) seen: plain=%s tls=%s" % (sorted(sp), sorted(st)))
if not {k for k in st if k[0] == "3"} or not {k for k in st if k[1] == "lkuser"}:
    ok = False
    print("      ^ the TLS leg lost a session label (SELECT / AUTH inside the encrypted stream)")

sys.exit(0 if ok else 1)
PY
then
    pass "the encrypted run yields the plaintext run's observations, within tolerance"
else
    fail "the two legs disagree — see the table above"
fi

# --- 4. io-threads: the revision РR12 asked for -----------------------------
# Redis hands the socket work to its io threads only above `io-threads x 2`
# clients, so this is where the milestone's second claim can be tested at all.
log "io-threads under TLS: 100 connections through memtier"
srv_pid=$($COMPOSE ps -q redis-tls | xargs docker inspect -f '{{.State.Pid}}')
note "server threads: $(cat /proc/"$srv_pid"/task/*/comm 2>/dev/null | sort | uniq -c | tr '\n' ' ')"
if cat /proc/"$srv_pid"/task/*/comm 2>/dev/null | grep -q '^io_thd_'; then
    pass "the server runs io threads named io_thd_* (not the io-thd-* РR12 guessed)"
else
    fail "no io_thd_* thread in the server — is io-threads really on?"
fi

before_full=$(scalar_of 'sum(latkit_redis_commands_total{job="latkit-tls"})')
before_main=$(scalar_of 'sum(latkit_redis_commands_total{job="latkit-tls-main"})')
docker run --rm --network "$NET" "$MEMTIER_IMAGE" \
    -s redis-tls -p 6480 --tls --tls-skip-verify \
    -t "$MEMTIER_THREADS" -c "$MEMTIER_CLIENTS" -n "$MEMTIER_REQUESTS" \
    --ratio=1:1 --pipeline=1 --key-prefix=lkm: --hide-histogram \
    > "$tmp/memtier.log" 2>&1 || true
tail -4 "$tmp/memtier.log" | sed 's/^/      /'
sleep 12

expected=$((MEMTIER_THREADS * MEMTIER_CLIENTS * MEMTIER_REQUESTS))
after_full=$(scalar_of 'sum(latkit_redis_commands_total{job="latkit-tls"})')
after_main=$(scalar_of 'sum(latkit_redis_commands_total{job="latkit-tls-main"})')
d_full=$(python3 -c "print(float('${after_full:-0}') - float('${before_full:-0}'))")
d_main=$(python3 -c "print(float('${after_main:-0}') - float('${before_main:-0}'))")
note "memtier drove ~$expected commands; --tls auto saw $d_full, --comm redis-server saw $d_main"

if python3 -c "import sys; sys.exit(0 if float('$d_full') >= 0.95*$expected else 1)"; then
    pass "the derived gate observed the whole load through the io threads (>= 95 %)"
else
    fail "the full leg lost commands ($d_full of ~$expected) — the io threads' events are being dropped"
fi
if python3 -c "import sys; sys.exit(0 if float('$d_main') < 0.9*float('$d_full') else 1)"; then
    pct=$(python3 -c "print('%.0f' % (100*float('$d_main')/max(float('$d_full'),1)))")
    pass "a comm filter naming only redis-server sees $pct % of it — the io-thread entry is load-bearing"
else
    fail "the two encrypted legs agree, so this run never engaged the io threads — the claim is untested"
fi

drop=$(scalar_of 'sum(latkit_queries_dropped_total{job="latkit-tls"})')
perr=$(scalar_of 'sum(latkit_parse_errors_total{job="latkit-tls",proto="redis"})')
perr_p=$(scalar_of 'sum(latkit_parse_errors_total{job="latkit-plain",proto="redis"})')
note "units dropped = ${drop:-0}, parse errors: tls=${perr:-0} plain=${perr_p:-0}"
if python3 -c "import sys; d=float('${drop:-0}'); c=float('${after_full:-0}'); sys.exit(0 if c>0 and d <= 0.01*c else 1)"; then
    pass "in-flight units lost stayed under 1 % of the commands observed"
else
    fail "too many in-flight units dropped ($drop) — replies are not reaching their commands"
fi
# The МR1 criterion, restated for the decrypted channel: clean traffic yields no
# parse error. It is not free here — the ciphertext of a TLS connection must
# never reach the framer, and a connection that was already open when the agent
# attached must be adopted rather than read as RESP for the rest of its life.
if [ "${perr:-0}" = "0" ]; then
    pass "no parse error on the decrypted stream (the plaintext leg has ${perr_p:-0})"
else
    fail "the TLS leg reports $perr parse errors — ciphertext is reaching the framer"
fi

# --- 5. the privacy invariant holds on decrypted bytes too ------------------
# Neither a key nor a password may appear anywhere in an exposition (РR4/РR6),
# and arriving through a uprobe rather than a socket changes nothing about that.
log "no key and no password in any exposition (РR4, РR6, РH12)"
for leg in plain:9757 tls:9758; do
    name=${leg%%:*}; port=${leg##*:}
    if curl -s "http://localhost:$port/metrics" > "$tmp/$name.txt"; then
        if grep -qE 'lkkey|lkpass|lkm:|lkcounter|lklist|lkchan' "$tmp/$name.txt"; then
            fail "a key or password reached the $name leg's metrics"
            grep -m2 -E 'lkkey|lkpass|lkm:|lkcounter|lklist|lkchan' "$tmp/$name.txt" | sed 's/^/      /'
        else
            pass "$name leg: no key, no password in $(wc -l < "$tmp/$name.txt") exposition lines"
        fi
    else
        fail "could not scrape the $name leg directly"
    fi
done

# --- 6. the diagnostic for a server the channel cannot reach ----------------
# The other half of "TLS is off and the dashboard is flat": a comm that is
# running and maps no libssl is a different problem from a comm that is not
# running, and only one of them can be fixed by waiting. Here the agent is
# pointed at a comm that exists (its own) and links no libssl.
log "diagnostics when the scan finds a server with no libssl"
out=$($COMPOSE run --rm --no-deps latkit-tls -p 6480=redis --tls auto \
        --tls-comm latkit --prom-listen none 2>&1 | head -20 || true)
if printf '%s' "$out" | grep -q 'map no libssl'; then
    pass "a running server with no shared libssl says so, in those words"
    printf '%s\n' "$out" | grep -A2 'map no libssl' | head -3 | sed 's/^/      /'
else
    fail "the no-libssl case is not distinguished from 'no such process':"
    printf '%s\n' "$out" | grep -i libssl | head -3 | sed 's/^/      /'
fi

# --- 7. optional soak -------------------------------------------------------
# МR7's last acceptance line: Redis survives a long memtier run *under the
# uprobes*. The default is off because it is a 24-hour claim (SOAK_SEC=86400);
# anything shorter is a smoke test of the same shape.
if [ "$SOAK_SEC" -gt 0 ]; then
    log "soak: memtier against the TLS leg for ${SOAK_SEC}s, under the uprobes"
    before_start=$($COMPOSE ps -q redis-tls | xargs docker inspect -f '{{.State.StartedAt}}')
    before_cmd=$(scalar_of 'sum(latkit_redis_commands_total{job="latkit-tls"})')
    docker run --rm --network "$NET" "$MEMTIER_IMAGE" \
        -s redis-tls -p 6480 --tls --tls-skip-verify \
        -t 4 -c 25 --test-time="$SOAK_SEC" --ratio=1:1 --pipeline=1 \
        --key-prefix=lksoak: --hide-histogram 2>&1 | tail -6 | sed 's/^/      /'
    sleep 12

    after_start=$($COMPOSE ps -q redis-tls | xargs docker inspect -f '{{.State.StartedAt}}')
    [ "$before_start" = "$after_start" ] \
        && pass "Redis was never restarted under the probes" \
        || fail "Redis restarted during the soak (started $before_start -> $after_start)"

    [ "$(scalar_of 'latkit_tls_attached{job="latkit-tls",state="ok"}')" = "1" ] \
        && pass "the libssl channel is still attached after the soak" \
        || fail "the attach state changed during the soak"

    after_cmd=$(scalar_of 'sum(latkit_redis_commands_total{job="latkit-tls"})')
    note "commands: ${before_cmd:-0} -> ${after_cmd:-0}"
    python3 -c "import sys; sys.exit(0 if float('${after_cmd:-0}') > float('${before_cmd:-0}') else 1)" \
        && pass "the agent kept observing throughout" || fail "observation stopped during the soak"

    drops=$(scalar_of 'sum(latkit_ringbuf_dropped_total{job="latkit-tls"})')
    evs=$(scalar_of 'sum(latkit_events_total{job="latkit-tls"})')
    note "ringbuf drops=${drops:-0} of events=${evs:-0}"
    if python3 -c "import sys; d=float('${drops:-0}'); e=float('${evs:-0}'); sys.exit(0 if e>0 and d <= 0.01*e else 1)"; then
        pass "drop rate under 1 % at memtier volume (the РR13 budget holds)"
    else
        fail "drop rate above 1 % — the per-port budget is not holding"
    fi
fi

# --- verdict -----------------------------------------------------------------
log "verdict"
if [ "$fails" -eq 0 ]; then
    echo "  Redis over TLS (libssl, io-threads 4) e2e: all checks passed"
    exit 0
fi
echo "  Redis over TLS (libssl, io-threads 4) e2e: $fails check(s) failed"
exit 1
