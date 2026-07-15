#!/usr/bin/env bash
#
# k8s smoke check (Р47): the DaemonSet path end-to-end on a throwaway kind
# cluster, asserting the same milestone criteria the deploy docs claim were
# verified by hand (docs/deploy.md "k8s DaemonSet"):
#
#   - the DaemonSet comes up Ready with green /healthz probes;
#   - a postgres workload driven over TCP lands in latkit_queries_total, and
#     the counter grows across a second load burst;
#   - the capture is clean: the exported error counters (parse_errors, resync,
#     ringbuf_dropped, queries_dropped) are all zero.
#
# Needs kind, kubectl, docker, and a host kernel with BTF (>= 5.15) — the agent
# loads/attaches BPF against the host kernel the kind node shares. Where the
# runner lacks any of these it is a manual check; CI marks it optional.
#
#   ./smoke.sh            # build image, up kind, assert, tear the cluster down
#   KEEP=1 ./smoke.sh     # leave the cluster up afterwards for inspection
#   SKIP_BUILD=1 ./smoke.sh   # reuse an already-built/loaded latkit:latest
#
# Two traps this script encodes so the manual run's mistakes don't recur:
#   - the release image is FROM scratch (docs/deploy.md) — no shell, no wget
#     inside; metrics are scraped from the host over `kubectl port-forward`,
#     never `kubectl exec`;
#   - pgbench WITHOUT `-h` connects over the postgres unix socket, which never
#     touches the TCP stack latkit hooks — capture would read zero and the test
#     would pass vacuously. Every pgbench invocation below forces TCP with
#     `-h 127.0.0.1`, and an explicit events_total>0 assert catches a regression
#     back to the socket path.
#
# Out of scope (manual, docs/deploy.md "cgroup filter in k8s"): the LATKIT_CGROUP
# multi-pod selector — it needs two postgres pods and node-specific globs.
set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT=$(cd ../.. && pwd)

CLUSTER=${CLUSTER:-latkit-smoke}
NS=${NS:-latkit-smoke}
IMAGE=${IMAGE:-latkit:latest}
PF_PORT=${PF_PORT:-19752}
MANIFEST="$REPO_ROOT/deploy/k8s/latkit-daemonset.yaml"
PF_PID=""
fails=0

log()  { printf '\n=== %s ===\n' "$*"; }
note() { printf '  %s\n' "$*"; }
pass() { printf '  ok   - %s\n' "$*"; }
fail() { printf '  FAIL - %s\n' "$*"; fails=$((fails + 1)); }

for tool in kind kubectl docker; do
    command -v "$tool" >/dev/null 2>&1 || { echo "smoke: '$tool' not found in PATH — this is a manual check" >&2; exit 2; }
done

cleanup() {
    [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null || true
    if [ "${KEEP:-0}" = "1" ]; then
        log "KEEP=1 — leaving cluster '$CLUSTER' up (kind delete cluster --name $CLUSTER to stop)"
        return
    fi
    log "tearing down"
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Scrape the agent from the host over the port-forward. The image is FROM
# scratch, so this is the only way in.
metrics() { curl -s "http://localhost:$PF_PORT/metrics"; }

# msum METRIC -> sum of every non-comment sample line for that exact metric
# name (labelled or bare). Absent series sum to 0, which is what the clean-
# capture asserts want.
msum() {
    metrics | awk -v m="$1" '$0 !~ /^#/ && $0 ~ "^"m"([{ ]|$)" { s += $NF } END { printf "%.0f", s+0 }'
}

# pgbench NAME EXTRA... — always over TCP (see the -h trap in the header).
pgb() { kubectl -n "$NS" exec pg -- pgbench -h 127.0.0.1 -U postgres "$@" postgres; }

# --- 0. build + load the release image --------------------------------------
if [ "${SKIP_BUILD:-0}" = "1" ]; then
    log "SKIP_BUILD=1 — reusing $IMAGE"
else
    log "building the release image ($IMAGE)"
    docker build -f "$REPO_ROOT/deploy/docker/Dockerfile" -t "$IMAGE" "$REPO_ROOT"
fi

# --- 1. bring up the cluster and load the image -----------------------------
log "creating kind cluster '$CLUSTER'"
kind create cluster --name "$CLUSTER" >/dev/null
note "kind does not pull local images — loading $IMAGE into the node"
kind load docker-image "$IMAGE" --name "$CLUSTER"

# --- 2. deploy the DaemonSet ------------------------------------------------
log "deploying the latkit DaemonSet"
kubectl create namespace "$NS" >/dev/null 2>&1 || true
# hostPID + added capabilities need a privileged PSA level (docs/deploy.md).
kubectl label ns "$NS" pod-security.kubernetes.io/enforce=privileged --overwrite >/dev/null
kubectl -n "$NS" apply -f "$MANIFEST" >/dev/null

log "waiting for the DaemonSet to become Ready (green /healthz)"
if kubectl -n "$NS" rollout status ds/latkit --timeout=120s; then
    # Readiness is the /healthz probe in the manifest — Ready == healthz green.
    pass "DaemonSet Ready, /healthz probes passing"
else
    fail "DaemonSet did not become Ready (BPF load/attach failed? kernel BTF?)"
    kubectl -n "$NS" logs -l app.kubernetes.io/name=latkit --tail=40 || true
    exit 1
fi

POD=$(kubectl -n "$NS" get pod -l app.kubernetes.io/name=latkit -o jsonpath='{.items[0].metadata.name}')
note "agent pod: $POD"

# --- 3. port-forward the agent from the host --------------------------------
log "port-forwarding the agent (:$PF_PORT -> 9752)"
kubectl -n "$NS" port-forward "$POD" "$PF_PORT:9752" >/dev/null 2>&1 &
PF_PID=$!
for _ in $(seq 1 30); do
    curl -sf "http://localhost:$PF_PORT/healthz" >/dev/null 2>&1 && break
    sleep 0.5
done
if curl -sf "http://localhost:$PF_PORT/healthz" >/dev/null 2>&1; then
    pass "/healthz reachable over the port-forward"
else
    fail "cannot reach the agent over the port-forward"
    exit 1
fi

# --- 4. postgres workload over TCP ------------------------------------------
log "deploying postgres and driving load over TCP"
kubectl -n "$NS" run pg --image=postgres:16 --env=POSTGRES_PASSWORD=pw --port=5432 >/dev/null
kubectl -n "$NS" wait --for=condition=Ready pod/pg --timeout=120s >/dev/null
# Ready != accepting connections; poll pg_isready before the first pgbench.
for _ in $(seq 1 30); do
    kubectl -n "$NS" exec pg -- pg_isready -q -U postgres >/dev/null 2>&1 && break
    sleep 1
done

ev0=$(msum latkit_events_total)
note "events_total before load = $ev0"
pgb -i -s 5 >/dev/null 2>&1
note "first load burst"
pgb -c 4 -T 8 2>&1 | grep -E 'tps|failed' | sed 's/^/  /'

# --- 5. assertions ----------------------------------------------------------
log "capture assertions"

ev1=$(msum latkit_events_total)
note "events_total after load = $ev1"
if [ "$ev1" -gt 0 ]; then
    pass "events_total > 0 (TCP traffic reached the fentry hooks)"
else
    fail "events_total is still 0 — no TCP seen (pgbench on the unix socket? wrong node?)"
fi

q1=$(msum latkit_queries_total)
note "sum(latkit_queries_total) = $q1"
if [ "$q1" -gt 0 ]; then
    pass "latkit_queries_total present and > 0"
else
    fail "latkit_queries_total missing or zero"
fi

note "second load burst — counter must grow"
pgb -c 4 -T 8 >/dev/null 2>&1
q2=$(msum latkit_queries_total)
note "sum(latkit_queries_total) after +burst = $q2"
if [ "$q2" -gt "$q1" ]; then
    pass "queries_total increased under load"
else
    fail "queries_total did not grow (pipeline stalled?)"
fi

log "clean-capture counters (must all be 0)"
# The exported subset of the kernel-smoke cleanliness criteria; iter_unsupported
# is a log-only stat (no Prometheus series), so it is not asserted here.
for m in latkit_parse_errors_total latkit_resync_total latkit_ringbuf_dropped_total latkit_queries_dropped_total; do
    v=$(msum "$m")
    if [ "$v" -eq 0 ]; then
        pass "$m == 0"
    else
        fail "$m == $v (expected 0)"
    fi
done

# --- verdict ----------------------------------------------------------------
log "verdict"
if [ "$fails" -eq 0 ]; then
    echo "  k8s smoke: all checks passed"
    exit 0
fi
echo "  k8s smoke: $fails check(s) failed"
exit 1
