#!/usr/bin/env bash
#
# S3-over-TLS e2e check (PLAN-MINIO.md МS3, РS8): MinIO with certificates, the
# same MinIO without them, one `mc` client driving both, and one agent per leg —
# the encrypted one running `--tls auto --tls-go /srv/minio`.
#
# The exit criterion of МS3 is a *comparison*, not a threshold: "a TLS run gives
# the same observations a plaintext run of the same load gives". So the script
# drives both legs with an identical operation sequence, stops the load, waits
# for the last scrape, and then compares the two legs' `latkit_s3_*` families
# operation by operation. Everything else is support for that claim:
#
#   - the Go channel is provably the source (state="go", uprobe events, TLS
#     connections seen at the socket, correlation misses negligible) — on a
#     TLS-only port there is no other way for a request to be observed at all;
#   - the МS3 comm derivation works (`minio` for an s3 port). `--tls auto` is on
#     precisely so the derived set becomes the uprobe gate; a wrong derivation
#     drops every decrypted event in the kernel and shows up as a zero here;
#   - no object key reaches either exposition (РS2/РH12) — the invariant does not
#     get weaker because the bytes arrived decrypted;
#   - the diagnostics of a binary that cannot be hooked are the ones an operator
#     can act on (МS3: "a comprehensible diagnostic on a stripped binary").
#
# Needs Docker, BPF privileges, /proc of the servers (pid: host). Optional in CI
# like the other stands.
#
#   ./verify-s3-tls.sh              # extract, build, up, assert, down
#   KEEP=1 ./verify-s3-tls.sh       # leave the stand running afterwards
#   SOAK_SEC=86400 ./verify-s3-tls.sh   # + the МS3 soak: a warp run under the
#                                       #   uprobes, and MinIO has to survive it
set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT=$(cd ../.. && pwd)
COMPOSE="docker compose -p latkit-s3-tls -f docker-compose.s3-tls.yml"
PROM=http://localhost:19093
MINIO_IMAGE=${MINIO_IMAGE:-minio/minio:latest}
WARP_IMAGE=${WARP_IMAGE:-minio/warp:latest}
SOAK_SEC=${SOAK_SEC:-0}
fails=0

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

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

# --- 0. the binary the servers run and the agent hooks ----------------------
# One host file, bind-mounted into both MinIO containers and into the encrypted
# leg's agent. A uprobe is registered against an inode, so this is what makes
# "hooked" and "running" the same binary rather than two copies that happen to
# agree.
log "building the agent; extracting the MinIO binary from $MINIO_IMAGE"
cmake --build "$REPO_ROOT/build" --target latkit -j"$(nproc)" >/dev/null

if [ ! -f "$REPO_ROOT/build/minio" ]; then
    cid=$(docker create "$MINIO_IMAGE")
    for p in /usr/bin/minio /opt/bin/minio; do
        docker cp "$cid:$p" "$REPO_ROOT/build/minio" >/dev/null 2>&1 && break
    done
    docker rm "$cid" >/dev/null
fi
[ -f "$REPO_ROOT/build/minio" ] || { echo "  could not extract the minio binary"; exit 1; }
chmod 0755 "$REPO_ROOT/build/minio"
note "binary: $(file -b "$REPO_ROOT/build/minio" | cut -c1-72)"

# Which of the two tables it carries. Counted rather than grep -q'd: a quiet grep
# under `set -o pipefail` reports the writer's SIGPIPE instead of the match.
nsyms=$(nm "$REPO_ROOT/build/minio" 2>/dev/null | grep -c 'crypto/tls\.(\*Conn)\.Write' || true)
npcln=$(readelf -SW "$REPO_ROOT/build/minio" 2>/dev/null | grep -c '\.gopclntab' || true)
note "resolution tables: symtab entries=$nsyms, .gopclntab section=$npcln"
if [ "$nsyms" = "0" ] && [ "$npcln" = "0" ]; then
    fail "this MinIO build carries neither table — see the МS3 gate in PLAN-MINIO.md"
    exit 1
fi
[ "$nsyms" = "0" ] && note "stripped, as shipped (МS0 recon item 2): resolution goes through Go's function table"

# --- 1. up ------------------------------------------------------------------
log "bringing both legs up (plaintext :9401, TLS :9444)"
$COMPOSE up -d --build
note "waiting for the uprobes to attach, the load to run and Prometheus to scrape"
sleep 45

for svc in latkit-plain latkit-tls; do
    if ! $COMPOSE ps $svc | grep -q ' Up\| running'; then
        fail "$svc is not running (BPF privileges? '$COMPOSE logs $svc')"
        $COMPOSE logs --tail=30 $svc || true
        exit 1
    fi
done

# The agent's log is read once into a file and grepped from there. Piping
# `compose logs` straight into `grep -q` looks equivalent and is not: the quiet
# grep exits on the first match, the writer takes a SIGPIPE, and under
# `set -o pipefail` the pipeline reports *that* — a match that reads as a
# failure, and only sometimes, depending on how much of the log fit in the pipe.
$COMPOSE logs latkit-tls > "$tmp/latkit-tls.log" 2>&1 || true
grep -iE 'go tls|uprobe|libssl|warn' "$tmp/latkit-tls.log" | tail -6 || true
for fn in Write Read; do
    if grep -q "crypto/tls\.(\*Conn)\.$fn" "$tmp/latkit-tls.log"; then
        pass "crypto/tls.(*Conn).$fn hooked in the running MinIO binary"
    else
        fail "no uprobe on crypto/tls.(*Conn).$fn — resolution or bind-mount"
    fi
done

[ "$(scalar_of 'up{job="latkit-tls"}')" = "1" ] && [ "$(scalar_of 'up{job="latkit-plain"}')" = "1" ] \
    && pass "Prometheus scrapes both legs" || fail "a leg is not being scraped (up != 1)"

# The comm derivation of МS3, in the agent's own words: `--tls auto` on an s3
# port scans for `minio` and for nothing else, and reports the empty result as
# the expected shape of a Go server rather than as a blind zone.
if grep -q "no libssl found for comm 'minio'" "$tmp/latkit-tls.log"; then
    pass "the derived scan set for an s3 port is exactly 'minio'"
    if grep -q "as a Go server has none" "$tmp/latkit-tls.log"; then
        pass "the empty libssl scan is reported as expected, not as dropped traffic"
    else
        fail "the log still calls a Go server's missing libssl a loss of traffic"
    fi
else
    fail "the s3 port did not derive the 'minio' scan set:"
    grep -i 'libssl' "$tmp/latkit-tls.log" | head -2 | sed 's/^/      /'
fi

# --- 2. the Go channel is the source on the encrypted leg -------------------
log "the decrypted channel"
if [ "$(scalar_of 'latkit_tls_attached{job="latkit-tls",state="go"}')" = "1" ]; then
    pass 'latkit_tls_attached{state="go"} == 1 on the TLS leg'
else
    fail "the TLS leg's attach state is not \"go\" (state gauge: $(promql 'latkit_tls_attached{job="latkit-tls"}==1' | python3 -c 'import json,sys; r=json.load(sys.stdin)["data"]["result"]; print(r[0]["metric"]["state"] if r else "none")'))"
fi

gt "$(scalar_of 'latkit_tls_connections_total{job="latkit-tls"}')" \
    && pass "connections on :9444 were recognised as TLS at the socket" \
    || fail "no connection went TLS — is the TLS leg really encrypted?"

uev=$(scalar_of 'latkit_tls_uprobe_events_total{job="latkit-tls"}')
note "latkit_tls_uprobe_events_total = ${uev:-<none>}"
gt "$uev" && pass "decrypted events flowed from the Go probes" || fail "no decrypted events"

# The one assumption of РH13.3 (a goroutine's socket activity names its
# connection), measured. Allowed to be non-zero — a call whose entry predates the
# attach — but not a meaningful fraction.
miss=$(scalar_of 'latkit_tls_correlation_misses_total{job="latkit-tls"}')
note "latkit_tls_correlation_misses_total = ${miss:-0}"
if python3 -c "import sys; m=float('${miss:-0}'); e=float('${uev:-0}'); sys.exit(0 if e>0 and m <= 0.05*e + 5 else 1)"; then
    pass "correlation misses negligible vs events (TLS_CORR_MISS ≈ 0)"
else
    fail "too many correlation misses ($miss) — the goroutine-to-connection link is failing"
fi

# The comm derivation of МS3, observed from the outside: the uprobe gate is the
# derived set (`minio` for an s3 port) because `--tls auto` is on. Decrypted
# events arriving at all means MinIO's threads passed it.
if gt "$uev"; then
    pass "the derived TLS comm set admits MinIO's threads (--tls auto + s3 port)"
fi

# --- 3. measure a window of load, then stop and compare ---------------------
# The comparison is between two *snapshots*, not between two totals, and both
# reasons are real. The startup race is one: the two agents attach at slightly
# different moments, so the client's one-time bootstrap (CreateBucket and the
# probes around it) lands on whichever leg was already listening — a difference
# that says nothing about either channel. The other is that comparing while the
# load runs would measure the loop's phase, since the client alternates legs and
# one is always up to an iteration ahead. Between two snapshots taken with both
# agents up and the load stopped, every request counted was seen from the start
# by both.
snapshot() {
    for leg in plain tls; do
        curl -sG "$PROM/api/v1/query" \
             --data-urlencode "query=sum by (op,status) (latkit_s3_requests_total{job=\"latkit-$leg\"})" \
             > "$tmp/$1-$leg.json"
    done
    curl -sG "$PROM/api/v1/query" \
         --data-urlencode 'query=sum by (job) (latkit_s3_bytes_total)' > "$tmp/$1-bytes.json"
    curl -sG "$PROM/api/v1/query" \
         --data-urlencode 'query=sum by (job,s3code) (latkit_s3_errors_total)' > "$tmp/$1-errors.json"
}

# Both snapshots are taken with the load *stopped* and the last scrape landed.
# Sampling on the fly would make the two legs differ by the phase of Prometheus'
# two scrapes — up to one interval apart, which at this request rate is several
# per cent of the window and nothing to do with either channel.
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

log "S3 observations, encrypted leg"
r_tls=$(scalar_of 'sum(latkit_s3_requests_total{job="latkit-tls"})')
r_pln=$(scalar_of 'sum(latkit_s3_requests_total{job="latkit-plain"})')
note "requests: tls=${r_tls:-0} plain=${r_pln:-0}"
gt "$r_tls" && pass "S3 requests observed on a port that is ciphertext end to end" \
    || fail "nothing observed on the TLS leg"
gt "$r_pln" && pass "the plaintext control leg observed its own load" \
    || fail "the control leg saw nothing — the comparison below is meaningless"

p95=$(scalar_of 'histogram_quantile(0.95, sum(rate(latkit_s3_request_duration_seconds_bucket{job="latkit-tls"}[5m])) by (le))')
note "TLS leg p95 duration = ${p95:-<none>} s"
if [ -n "$p95" ] && python3 -c "import sys; v=float('$p95'); sys.exit(0 if 0<=v<60 else 1)" 2>/dev/null; then
    pass "duration p95 is a plausible latency (0..60 s)"
else
    fail "p95 missing or out of range"
fi

for q in 'latkit_s3_requests_total{job="latkit-tls",op="PutObject",bucket="lkbucket",user="lkroot"}' \
         'latkit_s3_requests_total{job="latkit-tls",op="GetObject",bucket="lkbucket",user="lkroot"}' \
         'latkit_s3_errors_total{job="latkit-tls",s3code="NoSuchKey"}'; do
    if gt "$(scalar_of "sum($q)")"; then
        pass "present through TLS: ${q#*\{}"
    else
        fail "missing on the TLS leg: $q"
    fi
done

blind=$(scalar_of 'sum(latkit_ignored_conns_total{job="latkit-tls",proto="s3"})')
note "blind connections on the TLS leg = ${blind:-0}"
python3 -c "import sys; sys.exit(0 if float('${blind:-0}') == 0 else 1)" \
    && pass "no connection fell into a blind zone (HTTP/1.1 throughout, МS0 item 1)" \
    || fail "a connection went blind ($blind) — h2 over ALPN?"

# --- 4. the comparison МS3 actually asks for --------------------------------
log "TLS vs plaintext: the same load, observed both ways"
if python3 - "$tmp" <<'PY'
import json, os, sys

D = sys.argv[1]

def vec(path, keys):
    r = json.load(open(path))["data"]["result"]
    return {tuple(s["metric"].get(k, "") for k in keys): float(s["value"][1]) for s in r}

def window(name, keys):
    """What happened between snapshot a and snapshot b — the counters are
    cumulative, so the difference is the window, and a key that only exists in
    b started at zero."""
    a = vec(os.path.join(D, "a-%s.json" % name), keys)
    b = vec(os.path.join(D, "b-%s.json" % name), keys)
    out = {k: v - a.get(k, 0.0) for k, v in b.items()}
    return {k: v for k, v in out.items() if v > 0}

plain = window("plain", ("op", "status"))
tls   = window("tls", ("op", "status"))
byjob = window("bytes", ("job",))
errs  = window("errors", ("job", "s3code"))

ok = True
if not plain or not tls:
    print("    one of the legs observed nothing during the window")
    sys.exit(1)

# The load is one fixed sequence per iteration, so the *set* of (op,status) must
# match exactly — a missing operation on the encrypted leg is a hole in the
# channel, not a rounding difference.
only_p, only_t = sorted(set(plain) - set(tls)), sorted(set(tls) - set(plain))
if only_p or only_t:
    ok = False
    print("    plaintext-only: %s" % (only_p or "-"))
    print("    TLS-only:       %s" % (only_t or "-"))

print("    %-26s %10s %10s %8s" % ("op/status", "plain", "tls", "delta"))
for k in sorted(set(plain) | set(tls)):
    a, b = plain.get(k, 0.0), tls.get(k, 0.0)
    d = abs(a - b) / max(a, b, 1.0)
    print("    %-26s %10.0f %10.0f %7.1f%%" % ("/".join(k), a, b, 100 * d))
    # A few requests of skew are allowed (the window's edges fall inside an
    # iteration, and the client stops mid-sequence), plus 10 % for the client's
    # own retries; anything past that is the channel losing requests, which is
    # what a partly-working correlation looks like.
    if abs(a - b) > max(4.0, 0.10 * max(a, b)):
        ok = False
        print("      ^ beyond tolerance")

# Volume, not just counts: the decrypted channel must carry the same bytes. The
# request bodies here are aws-chunked, so this also says the wire counters mean
# the same thing on both sides of the uprobe.
bp = byjob.get(("latkit-plain",), 0.0)
bt = byjob.get(("latkit-tls",), 0.0)
print("    body bytes: plain=%.0f tls=%.0f (%.1f%%)" % (bp, bt, 100 * abs(bp - bt) / max(bp, bt, 1.0)))
if abs(bp - bt) > 0.15 * max(bp, bt, 1.0):
    ok = False
    print("      ^ the two legs did not carry the same volume")

ep = {k[1] for k in errs if k[0] == "latkit-plain"}
et = {k[1] for k in errs if k[0] == "latkit-tls"}
print("    S3 error codes: plain=%s tls=%s" % (sorted(ep) or "-", sorted(et) or "-"))
if not et or ep != et:
    ok = False
    print("      ^ the named failures differ between the legs")

sys.exit(0 if ok else 1)
PY
then
    pass "the encrypted run yields the plaintext run's observations, within tolerance"
else
    fail "the two legs disagree — see the table above"
fi

# --- 5. the privacy invariant holds on decrypted bytes too ------------------
log "no object key in either exposition (РS2, РH12)"
for leg in plain:9755 tls:9756; do
    name=${leg%%:*}; port=${leg##*:}
    if curl -s "http://localhost:$port/metrics" > "$tmp/$name.txt"; then
        if grep -q 'obj-[0-9]' "$tmp/$name.txt"; then
            fail "an object key reached the $name leg's metrics"
            grep -m2 'obj-[0-9]' "$tmp/$name.txt" | sed 's/^/      /'
        else
            pass "$name leg: no object key in $(wc -l < "$tmp/$name.txt") exposition lines"
        fi
    else
        fail "could not scrape the $name leg directly"
    fi
done

# --- 6. what an operator sees when the binary cannot be hooked --------------
# The failure path is the one МS3 names explicitly: a binary latkit cannot hook
# must fail loudly, at startup, with a way forward — not start and stay silent.
log "diagnostics for a binary that cannot be hooked"
out=$($COMPOSE run --rm --no-deps latkit-tls -p 9444=s3 \
        --tls-go /proc/1/root/nonexistent/minio --prom-listen none 2>&1 || true)
if printf '%s' "$out" | grep -q 'nothing attached' && printf '%s' "$out" | grep -q '/proc/'; then
    pass "a missing binary names the container case and the /proc path to use"
else
    fail "the missing-binary diagnostic is not actionable:"; printf '%s\n' "$out" | sed 's/^/      /'
fi

out=$($COMPOSE run --rm --no-deps latkit-tls -p 9444=s3 \
        --tls-go /usr/local/bin/latkit --prom-listen none 2>&1 || true)
if printf '%s' "$out" | grep -q 'nothing attached'; then
    pass "a non-Go binary is refused at startup rather than silently unhooked"
    printf '%s\n' "$out" | grep -A2 'nothing attached' | head -4 | sed 's/^/      /'
else
    fail "a non-Go binary did not produce the startup refusal:"; printf '%s\n' "$out" | sed 's/^/      /'
fi

# --- 7. optional soak -------------------------------------------------------
# МS3's last acceptance line: MinIO survives a long warp run *under the uprobes*
# without degradation. The default is off because it is a 24-hour claim
# (SOAK_SEC=86400); anything shorter is a smoke test of the same shape.
if [ "$SOAK_SEC" -gt 0 ]; then
    log "soak: warp mixed against the TLS leg for ${SOAK_SEC}s, under the uprobes"
    before_start=$($COMPOSE ps -q minio-tls | xargs docker inspect -f '{{.State.StartedAt}}')
    before_req=$(scalar_of 'sum(latkit_s3_requests_total{job="latkit-tls"})')
    docker run --rm --network latkit-s3-tls-net "$WARP_IMAGE" mixed \
        --host minio-tls:9444 --tls --insecure \
        --access-key lkroot --secret-key lkrootpass123 --bucket lkwarp \
        --duration="${SOAK_SEC}s" --obj.size=1MiB --objects=200 --concurrent=4 \
        --noclear --no-color 2>&1 | tail -20 | sed 's/^/      /'
    sleep 12

    after_start=$($COMPOSE ps -q minio-tls | xargs docker inspect -f '{{.State.StartedAt}}')
    [ "$before_start" = "$after_start" ] \
        && pass "MinIO was never restarted under the probes" \
        || fail "MinIO restarted during the soak (started $before_start -> $after_start)"

    [ "$(scalar_of 'latkit_tls_attached{job="latkit-tls",state="go"}')" = "1" ] \
        && pass "the Go channel is still attached after the soak" \
        || fail "the attach state changed during the soak"

    after_req=$(scalar_of 'sum(latkit_s3_requests_total{job="latkit-tls"})')
    note "requests: ${before_req:-0} -> ${after_req:-0}"
    python3 -c "import sys; sys.exit(0 if float('${after_req:-0}') > float('${before_req:-0}') else 1)" \
        && pass "the agent kept observing throughout" || fail "observation stopped during the soak"

    drops=$(scalar_of 'sum(latkit_ringbuf_dropped_total{job="latkit-tls"})')
    evs=$(scalar_of 'sum(latkit_events_total{job="latkit-tls"})')
    note "ringbuf drops=${drops:-0} of events=${evs:-0}"
    if python3 -c "import sys; d=float('${drops:-0}'); e=float('${evs:-0}'); sys.exit(0 if e>0 and d <= 0.01*e else 1)"; then
        pass "drop rate under 1 % at warp volume"
    else
        fail "drop rate above 1 % — the per-port budget (РH14) is not holding"
    fi
fi

# --- verdict -----------------------------------------------------------------
log "verdict"
if [ "$fails" -eq 0 ]; then
    echo "  S3 over TLS (MinIO, Go crypto/tls) e2e: all checks passed"
    exit 0
fi
echo "  S3 over TLS (MinIO, Go crypto/tls) e2e: $fails check(s) failed"
exit 1
