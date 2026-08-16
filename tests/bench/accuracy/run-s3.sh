#!/usr/bin/env bash
#
# S3 accuracy validation stand (PLAN-MINIO.md МS4).
#
# One controlled workload, two views of it, joined **one request at a time**:
#
#   - the agent's observations   (--record, replayed through lkt_queries);
#   - MinIO's own per-request trace (`mc admin trace -v --json --call s3`),
#     keyed by the `X-Amz-Request-Id` the server answered with — which the agent
#     reports too, because МS1 reads it off the response head for exactly this.
#
# Per request rather than in aggregate, because that is the only way to catch a
# systematic error that cancels out in a percentile. And the reference is
# stronger than the HTTP bench's: nginx could only tell us how long a request
# took, MinIO also tells us *what request it was*, so the operation taxonomy of
# РS2 is checked against the authority on the subject rather than against our
# own table (s3_join.py, the operation column).
#
# The workload is a spread of the shapes РS5/РS6 are about, not a uniform flood:
# a small GET, a 1 MiB GET, an `aws-chunked` PUT of each size, a HEAD, a
# listing, a batched delete, a multipart upload, and two deliberate failures
# whose S3 codes differ behind one status.
#
# The second reference is MinIO's own Prometheus endpoint, compared in
# aggregate: it is the thing an operator would otherwise use instead of latkit,
# so "the two agree on how many requests there were" is worth stating (§2 of the
# plan is about what latkit adds *beyond* it, which presumes it does not
# disagree with it).
#
# Usage:
#   tests/bench/accuracy/run-s3.sh          # run the campaign
#   tests/bench/accuracy/run-s3.sh down     # remove a leftover stand
#
# Knobs (env): PASSES=25, TOL_MS=5, MIN_SAMPLES=50, AGENT_BIN=build-rel/latkit,
#   PORT=9403, OUT=tests/bench/accuracy/out/s3-<ts>
#
# Requirements: an optimised agent build (an -O0 agent can drop under burst and
# invalidate the run), docker, passwordless sudo.

set -euo pipefail

cd "$(dirname "$0")/../../.."       # repo root

CMD=${1:-run}
PASSES=${PASSES:-25}
TOL_MS=${TOL_MS:-5}
MIN_SAMPLES=${MIN_SAMPLES:-50}
AGENT_BIN=${AGENT_BIN:-build-rel/latkit}
PORT=${PORT:-9403}
OUT=${OUT:-tests/bench/accuracy/out/s3-$(date -u +%Y%m%dT%H%M%SZ)}
case "$OUT" in /*) ;; *) OUT=$PWD/$OUT ;; esac

MINIO_IMAGE=${MINIO_IMAGE:-minio/minio:latest}
MC_IMAGE=${MC_IMAGE:-minio/mc:latest}
NET=latkit-acc-s3-net
MINIO=latkit-acc-minio
TRACER=latkit-acc-tracer
AK=lkroot
SK=lkrootpass123

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

stack_down() {
    docker rm -f "$MINIO" "$TRACER" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}

agent_pid() { pgrep -x latkit || true; }

AGENT_JOB=
agent_start() {   # $1 = run dir
    [ -z "$(agent_pid)" ] || die "a latkit process is already running"
    # --record rather than --queries because the join wants the *replayed*
    # view, which is reproducible from the artefact this leaves behind.
    sudo -n "$AGENT_BIN" -p "$PORT=s3" \
        --record "$1/run.lkt" --dump-metrics="$1/agent.prom" \
        >>"$1/agent.log" 2>&1 &
    AGENT_JOB=$!
    sleep 3
    [ -n "$(agent_pid)" ] || die "agent did not come up (see $1/agent.log)"
}

agent_stop() {
    local pid; pid=$(agent_pid)
    if [ -n "$pid" ]; then
        sudo -n kill -INT "$pid"
        for _ in $(seq 100); do
            [ -z "$(agent_pid)" ] && break
            sleep 0.2
        done
        [ -z "$(agent_pid)" ] || sudo -n kill -KILL "$(agent_pid)" || true
    fi
    [ -n "$AGENT_JOB" ] && { wait "$AGENT_JOB" 2>/dev/null || true; }
    AGENT_JOB=
}

cleanup() { agent_stop; stack_down; }

stack_up() {
    stack_down
    docker network create "$NET" >/dev/null
    docker run -d --name "$MINIO" --network "$NET" --network-alias minio \
        -e MINIO_ROOT_USER="$AK" -e MINIO_ROOT_PASSWORD="$SK" \
        -e MINIO_UPDATE=off -e MINIO_PROMETHEUS_AUTH_TYPE=public \
        "$MINIO_IMAGE" server /data --address ":$PORT" >/dev/null
    for _ in $(seq 60); do
        docker exec "$MINIO" curl -fsS "http://127.0.0.1:$PORT/minio/health/live" \
            >/dev/null 2>&1 && break
        sleep 1
    done
    docker exec "$MINIO" curl -fsS "http://127.0.0.1:$PORT/minio/health/live" >/dev/null 2>&1 \
        || die "MinIO never became ready"
}

# mc, in a container on the stand's network. The alias is configured into a
# throwaway directory each time so the run leaves no credentials behind.
# --user: mc writes its configuration into the bind-mounted work directory, and
# a root-owned directory left in the tree is a directory the *next* thing to
# walk it cannot read (the release image's build context, for one).
mc() {
    docker run --rm --network "$NET" -u "$(id -u):$(id -g)" -v "$1:/w" "$MC_IMAGE" \
        --config-dir /w/mc --quiet --no-color "${@:2}"
}

# ... and a shell in the same image, for the workload loop. The image's
# entrypoint is `mc` itself, so a script needs the entrypoint overridden.
mc_sh() {
    docker run --rm --network "$NET" -u "$(id -u):$(id -g)" -v "$1:/w" \
        --entrypoint sh "$MC_IMAGE" -c "$2"
}

case $CMD in
    down) stack_down; exit 0 ;;
    run)  ;;
    *)    die "unknown command '$CMD' (run|down)" ;;
esac

[ -x "$AGENT_BIN" ] || die "no agent binary at $AGENT_BIN (build-rel recipe in tests/bench/run.sh)"
BUILD_DIR=$(dirname "$AGENT_BIN")
BUILD_TYPE=$(sed -n 's/^CMAKE_BUILD_TYPE:STRING=//p' "$BUILD_DIR/CMakeCache.txt" 2>/dev/null || echo unknown)
case "$BUILD_TYPE" in
    Release|RelWithDebInfo) ;;
    *) die "$AGENT_BIN is not an optimised build (CMAKE_BUILD_TYPE='$BUILD_TYPE')" ;;
esac
sudo -n true 2>/dev/null || die "passwordless sudo required"

log "building lkt_queries"
cmake --build build --target lkt_queries -j >/dev/null

mkdir -p "$OUT/w"
chmod 777 "$OUT/w"
trap cleanup EXIT INT TERM

log "bringing the stand up (MinIO on :$PORT)"
stack_up

# The objects the workload moves, written where the mc container can see them.
head -c 1048576 /dev/urandom > "$OUT/w/big.bin"
head -c 12582912 /dev/urandom > "$OUT/w/multi.bin"   # 12 MiB: multipart at 5 MiB parts
printf 'small object\n' > "$OUT/w/small.txt"

mc "$OUT/w" alias set lk "http://minio:$PORT" "$AK" "$SK" >/dev/null
mc "$OUT/w" mb --ignore-existing lk/lkbucket >/dev/null

# MinIO's own view, streamed to a file for the whole run. `-v` is what carries
# the response headers, and the request id with them; `--call s3` keeps the
# admin API (including this trace stream itself) out of the reference.
log "starting mc admin trace"
docker run -d --name "$TRACER" --network "$NET" -u "$(id -u):$(id -g)" \
    -v "$OUT/w:/w" "$MC_IMAGE" \
    --config-dir /w/mc --json admin trace -v --call s3 lk >/dev/null
sleep 3

agent_start "$OUT"

log "driving $PASSES passes"
mc_sh "$OUT/w" '
    mc() { /usr/bin/mc --config-dir /w/mc --quiet --no-color "$@"; }
    i=0
    while [ $i -lt '"$PASSES"' ]; do
        i=$((i + 1))
        mc cp /w/small.txt lk/lkbucket/small-$i       >/dev/null 2>&1 || true
        mc cp /w/big.bin   lk/lkbucket/big-$i         >/dev/null 2>&1 || true
        mc cat             lk/lkbucket/small-$i       >/dev/null 2>&1 || true
        mc cat             lk/lkbucket/big-$i         >/dev/null 2>&1 || true
        mc stat            lk/lkbucket/small-$i       >/dev/null 2>&1 || true
        mc ls              lk/lkbucket                >/dev/null 2>&1 || true
        mc cat             lk/lkbucket/no-such-object >/dev/null 2>&1 || true
        mc ls              lk/no-such-bucket-lk       >/dev/null 2>&1 || true
        mc rm              lk/lkbucket/small-$i       >/dev/null 2>&1 || true
        mc rm              lk/lkbucket/big-$i         >/dev/null 2>&1 || true
    done
    # One multipart upload: create + parts + complete, the operations that share
    # ?uploadId and are told apart by the method alone.
    mc cp /w/multi.bin lk/lkbucket/multi.bin          >/dev/null 2>&1 || true
' >"$OUT/mc.log" 2>&1 || true

sleep 2
agent_stop
docker logs "$TRACER" > "$OUT/trace.json" 2>/dev/null || true
docker rm -f "$TRACER" >/dev/null 2>&1 || true
curl -sf "http://$(docker inspect "$MINIO" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'):$PORT/minio/v2/metrics/cluster" \
    > "$OUT/minio.prom" 2>/dev/null || true

[ -s "$OUT/run.lkt" ] || die "the agent recorded nothing"
[ -s "$OUT/trace.json" ] || die "mc admin trace produced nothing (admin API reachable?)"
sudo -n chmod a+r "$OUT/run.lkt" "$OUT/agent.prom" 2>/dev/null || true

log "replaying the recording through the handler"
build/tests/replay/lkt_queries --proto s3 "$OUT/run.lkt" >"$OUT/queries.txt" 2>&1

log "joining by X-Amz-Request-Id"
RC=0
python3 tests/bench/accuracy/s3_join.py \
    --trace "$OUT/trace.json" --agent "$OUT/queries.txt" \
    --tol-ms "$TOL_MS" --min-samples "$MIN_SAMPLES" \
    >"$OUT/join.tsv" 2>"$OUT/join.summary" || RC=$?

# The aggregate second opinion: MinIO's own Prometheus endpoint against ours.
# Not gated — the two count over slightly different windows (the agent attaches
# after the server starts) — but printed, because a factor-of-two difference
# here would mean something is being counted twice or not at all.
python3 - "$OUT/minio.prom" "$OUT/agent.prom" >"$OUT/aggregate.txt" 2>&1 <<'PY' || true
import re, sys

def total(path, name):
    s = 0.0
    try:
        for line in open(path):
            if line.startswith("#") or not line.startswith(name):
                continue
            head = line.split()[0]
            if head == name or head.startswith(name + "{"):
                s += float(line.split()[-1])
    except OSError:
        return None
    return s

m = total(sys.argv[1], "minio_s3_requests_total")
a = total(sys.argv[2], "latkit_s3_requests_total")
i = total(sys.argv[2], "latkit_s3_internal_requests_total")
print("minio_s3_requests_total          = %s" % ("%.0f" % m if m is not None else "n/a"))
print("latkit_s3_requests_total         = %s" % ("%.0f" % a if a is not None else "n/a"))
print("latkit_s3_internal_requests_total= %s" % ("%.0f" % i if i is not None else "n/a"))
if m and a:
    print("ratio latkit/minio               = %.4f" % (a / m))
PY

REPORT=$OUT/report.txt
{
    echo "latkit S3 accuracy validation (PLAN-MINIO.md МS4)"
    echo "================================================="
    echo "date     : $(date -u '+%Y-%m-%d %H:%M UTC')"
    echo "commit   : $(git rev-parse --short HEAD)$(git diff --quiet || echo -dirty)"
    echo "agent    : $("$AGENT_BIN" --version) [$BUILD_TYPE, $AGENT_BIN]"
    echo "kernel   : $(uname -r)"
    echo "stand    : $MINIO_IMAGE on :$PORT, driven by $MC_IMAGE"
    echo "workload : $PASSES passes x {put small, put 1 MiB, get both, head, list,"
    echo "           404 NoSuchKey, 404 NoSuchBucket, batched delete} + 1 multipart"
    echo "reference: mc admin trace -v --json --call s3 — callStats.duration,"
    echo "           .timeToFirstByte, .tx and the api name, joined on X-Amz-Request-Id"
    echo "gates    : p90 duration and TTFB gaps <= ${TOL_MS} ms; response bytes exact;"
    echo "           status exact; >= 95% of traced requests observed;"
    echo "           >= 99% of operations agree with MinIO's own name"
    echo
    cat "$OUT/join.summary"
    echo
    echo "MinIO's own metrics, for scale:"
    sed 's/^/  /' "$OUT/aggregate.txt"
    echo
    echo "counters from the run:"
    grep -E '^latkit_(parse_errors_total|resync_total|ringbuf_dropped_total|ignored_conns_total)' \
        "$OUT/agent.prom" 2>/dev/null | sed 's/^/  /' || true
    echo
    echo "per-request table: $OUT/join.tsv"
} >"$REPORT"

# A run with drops or resyncs is not a valid measurement — the same rule the
# PostgreSQL and HTTP stands apply (Р49/Р50): "the count matches exactly" means
# nothing on a lossy capture.
drops=$(awk '$1 == "latkit_ringbuf_dropped_total" { print $2 }' "$OUT/agent.prom" 2>/dev/null)
resyncs=$(awk '$1 == "latkit_resync_total" { print $2 }' "$OUT/agent.prom" 2>/dev/null)
{
    printf 'validity : ringbuf_dropped=%s resync_total=%s -> ' "${drops:-?}" "${resyncs:-?}"
    if [ "${drops:-1}" = "0" ] && [ "${resyncs:-1}" = "0" ]; then
        echo "VALID"
    else
        echo "INVALID (the run is not lossless; the join numbers do not stand)"
        RC=1
    fi
} >>"$REPORT"

log "done; report: $REPORT"
cat "$REPORT"
exit "$RC"
