#!/usr/bin/env bash
#
# МS0 (PLAN-MINIO.md): record the reference S3/MinIO trace corpus with the stock
# capture pipeline (`latkit --record`, LKT1 format). No S3 code exists yet — the
# capture layer is protocol-independent, so the agent runs with a plain
# `--port N` (the default pg framer finds nothing, which is fine) and only the
# raw ringbuf records are kept.
#
# Three stands, because the questions are different:
#
#   minio/  single node, plaintext, :9900  — the operation matrix
#   dist/   four nodes, plaintext, :9910   — the internal cluster traffic
#                                            (`/minio/storage/…`, the grid) that
#                                            a single node never produces
#   tls/    single node, TLS, :9902        — ciphertext, and the same load
#                                            decrypted through the Go uprobes
#
# Ports: the plan writes `--port 9000=s3`, and 9000 is what a MinIO deployment
# uses; the corpus is recorded on 9900/9902/9910 only because the recording host
# already had something on 9000. The port is the capture filter, not part of
# what a trace means.
#
# Clients: our own raw sockets (clients/raw.py — SigV4 signed, every shape an
# SDK will not make), aws-cli v2, boto3, MinIO's own mc, warp, and s3fs. The
# last three run as containers on the host network: published ports would put
# docker-proxy in the middle with the same local port and double every
# connection in the capture.
#
# Requirements: docker, passwordless sudo (BPF), python3 + boto3, aws-cli,
# curl, openssl; the agent binary from build-rel (or LATKIT=path).
#
#   ./record.sh              # ensure the stands, record everything
#   ./record.sh minio        # one stand only (minio | dist | tls)
#   KEEP=1 ./record.sh       # leave the stands running afterwards
set -uo pipefail

cd "$(dirname "$0")"
REPO_ROOT=$(cd ../../.. && pwd)
LATKIT=${LATKIT:-$REPO_ROOT/build-rel/latkit}
WORK=${WORK:-$PWD/.work}
ONLY=${1:-}

MINIO_IMAGE=${MINIO_IMAGE:-minio/minio:latest}
MC_IMAGE=${MC_IMAGE:-minio/mc:latest}
WARP_IMAGE=${WARP_IMAGE:-minio/warp:latest}
S3FS_IMAGE=${S3FS_IMAGE:-efrecon/s3fs:1.95}

PORT=${PORT:-9900}; PORT_CONSOLE=9901
PORT_TLS=${PORT_TLS:-9902}; PORT_TLS_CONSOLE=9903
PORT_DIST=${PORT_DIST:-9910}
AK=lkroot; SK=lkrootpass123; BUCKET=lkbucket
export S3_ENDPOINT="127.0.0.1:$PORT" S3_AK=$AK S3_SK=$SK S3_BUCKET=$BUCKET
export AWS_ACCESS_KEY_ID=$AK AWS_SECRET_ACCESS_KEY=$SK AWS_DEFAULT_REGION=us-east-1
export AWS_EC2_METADATA_DISABLED=true
AWS="aws --endpoint-url http://127.0.0.1:$PORT"

fails=0; recorded=0; skipped=0
log()  { printf '\n=== %s ===\n' "$*"; }
note() { printf '  %s\n' "$*"; }

# --- stands -----------------------------------------------------------------

ensure_fixtures() {
    mkdir -p "$WORK"
    [ -f "$WORK/small.bin" ]  || head -c 1024    /dev/urandom > "$WORK/small.bin"
    [ -f "$WORK/big8m.bin" ]  || head -c 8388608 /dev/urandom > "$WORK/big8m.bin"
    [ -f "$WORK/mp15m.bin" ]  || head -c 15728640 /dev/urandom > "$WORK/mp15m.bin"
}

ensure_certs() {
    [ -f "$WORK/tls/private.key" ] && return
    log "generating TLS certs (MinIO :$PORT_TLS)"
    mkdir -p "$WORK/tls"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj '/CN=lkt-s3' \
        -addext 'subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:lkt-s3' \
        -keyout "$WORK/tls/private.key" -out "$WORK/tls/public.crt" 2>/dev/null
    chmod 644 "$WORK/tls/private.key" "$WORK/tls/public.crt"
}

wait_health() { # wait_health URL
    for _ in $(seq 120); do
        curl -sSk -o /dev/null --max-time 2 "$1/minio/health/live" && return 0
        sleep 0.5
    done
    return 1
}

ensure_minio() {
    docker inspect lkt-s3-minio >/dev/null 2>&1 || {
        log "starting lkt-s3-minio ($MINIO_IMAGE) on :$PORT"
        mkdir -p "$WORK/data"
        # MINIO_DOMAIN is what turns on virtual-host-style addressing (РS3):
        # without it MinIO reads `bucket.localhost` as a bucket named "" and
        # answers NoSuchBucket, and the vhost trace would be a 404 trace.
        docker run -d --name lkt-s3-minio --network host \
            -e MINIO_ROOT_USER=$AK -e MINIO_ROOT_PASSWORD=$SK \
            -e MINIO_DOMAIN=localhost \
            -v "$WORK/data:/data" "$MINIO_IMAGE" server /data \
            --address ":$PORT" --console-address ":$PORT_CONSOLE" >/dev/null || return 1
    }
    wait_health "http://127.0.0.1:$PORT" || { note "FAIL: minio did not come up"; return 1; }
}

ensure_tls() {
    ensure_certs
    docker inspect lkt-s3-minio-tls >/dev/null 2>&1 || {
        log "starting lkt-s3-minio-tls on :$PORT_TLS"
        mkdir -p "$WORK/data-tls"
        docker run -d --name lkt-s3-minio-tls --network host \
            -e MINIO_ROOT_USER=$AK -e MINIO_ROOT_PASSWORD=$SK \
            -v "$WORK/data-tls:/data" -v "$WORK/tls:/root/.minio/certs:ro" \
            "$MINIO_IMAGE" server /data --address ":$PORT_TLS" \
            --console-address ":$PORT_TLS_CONSOLE" >/dev/null || return 1
    }
    wait_health "https://127.0.0.1:$PORT_TLS" || { note "FAIL: tls minio did not come up"; return 1; }
}

ensure_dist() {
    # A user-defined bridge, not the host network: MinIO refuses to form a
    # cluster out of 127.0.0.1 endpoints in a container, and nothing is
    # published, so no docker-proxy appears in the middle. The host reaches the
    # bridge addresses directly, and the kprobes see the containers' sockets —
    # they are in another netns, not another kernel.
    docker network inspect lkt-s3-net >/dev/null 2>&1 || \
        docker network create lkt-s3-net >/dev/null
    local args=""
    for i in 0 1 2 3; do args="$args http://d$i:$PORT_DIST/data"; done
    for i in 0 1 2 3; do
        docker inspect "lkt-s3-d$i" >/dev/null 2>&1 && continue
        log "starting lkt-s3-d$i (distributed pool)"
        mkdir -p "$WORK/dist/n$i"
        docker run -d --name "lkt-s3-d$i" --network lkt-s3-net --network-alias "d$i" \
            -e MINIO_ROOT_USER=$AK -e MINIO_ROOT_PASSWORD=$SK -e MINIO_DOMAIN=localhost \
            -v "$WORK/dist/n$i:/data" "$MINIO_IMAGE" server $args \
            --address ":$PORT_DIST" --console-address ":992$i" >/dev/null || return 1
    done
    DIST_IP=$(docker inspect -f \
        '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' lkt-s3-d0)
    wait_health "http://$DIST_IP:$PORT_DIST" || { note "FAIL: cluster did not form"; return 1; }
}

ensure_objects() { # ensure_objects ENDPOINT BUCKET
    local ep=$1 bkt=$2
    aws --endpoint-url "$ep" s3api create-bucket --bucket "$bkt" >/dev/null 2>&1
    aws --endpoint-url "$ep" s3api put-object --bucket "$bkt" --key small.bin \
        --body "$WORK/small.bin" >/dev/null 2>&1
    aws --endpoint-url "$ep" s3api put-object --bucket "$bkt" --key big8m.bin \
        --body "$WORK/big8m.bin" >/dev/null 2>&1
    # 400 tiny objects: a listing has to outgrow Go's 2 KB response buffer
    # before a gzipped one comes back chunked, and a two-object bucket never
    # does. Cheap, and it makes the listing traces look like a real bucket.
    if ! aws --endpoint-url "$ep" s3api head-object --bucket "$bkt" \
             --key fill/0399.bin >/dev/null 2>&1; then
        S3_ENDPOINT=${ep#http*://} S3_BUCKET=$bkt python3 clients/raw.py fill 400 >/dev/null
    fi
}

stop_stand() {
    docker rm -f lkt-s3-minio lkt-s3-minio-tls >/dev/null 2>&1
    for i in 0 1 2 3; do docker rm -f "lkt-s3-d$i" >/dev/null 2>&1; done
    docker network rm lkt-s3-net >/dev/null 2>&1
}

# --- recording --------------------------------------------------------------

# record DIR NAME "AGENT_FLAGS" -- client command…
record() {
    local dir=$1 name=$2 flags=$3; shift 3; shift   # swallow "--"
    local out=$PWD/$dir/$name.lkt alog=$WORK/agent-$dir-$name.log
    mkdir -p "$dir"
    sudo "$LATKIT" $flags --record "$out" --prom-listen none >"$alog" 2>&1 &
    local apid=$!
    for _ in $(seq 150); do grep -q 'capturing local port' "$alog" 2>/dev/null && break; sleep 0.1; done
    if ! grep -q 'capturing local port' "$alog" 2>/dev/null; then
        note "FAIL $dir/$name: agent did not attach (see $alog)"
        sudo kill "$apid" 2>/dev/null; wait "$apid" 2>/dev/null
        fails=$((fails+1)); return 1
    fi
    local rc=0
    "$@" >"$WORK/client-$dir-$name.log" 2>&1 || rc=$?
    sleep 0.8
    sudo kill -INT "$apid" 2>/dev/null; wait "$apid" 2>/dev/null
    sudo chown "$(id -u):$(id -g)" "$out" 2>/dev/null
    # Deliberately broken scenarios make the client exit nonzero — the trace is
    # the point, so only a missing or empty trace is a failure.
    if [ ! -s "$out" ]; then
        note "skip $dir/$name: no events captured (client rc=$rc)"
        rm -f "$out"; skipped=$((skipped+1)); return 1
    fi
    note "ok   $dir/$name ($(stat -c %s "$out") bytes, client rc=$rc)"
    recorded=$((recorded+1))
}

raw() { python3 clients/raw.py "$@"; }

mc_run() { # mc_run ENDPOINT script…
    local ep=$1; shift
    docker run --rm --network host -v "$WORK:/w" --entrypoint sh "$MC_IMAGE" -c \
        "mc alias set lk $ep $AK $SK >/dev/null 2>&1; $*"
}

# --- the single-node matrix -------------------------------------------------

record_minio() {
    log "recording minio (127.0.0.1:$PORT)"
    ensure_objects "http://127.0.0.1:$PORT" "$BUCKET"
    local p="--port $PORT"

    # The operation matrix, driven by our own signer.
    for s in get get-large put chunked-put continue keepalive pipelined vhost \
             anon badsig presigned presigned-expired errors multipart \
             multipart-abort delete-objects copy list subresources internal \
             encoded-keys bucket-names range garbage abort-midbody torn-body \
             slow-client select gzip-listing health; do
        record minio "$s" "$p" -- raw "$s"
    done
    # The whole operation taxonomy in one trace: 53 requests, one per row of
    # clients/ops.py, which is the table МS1 has to reproduce.
    record minio ops "$p" -- python3 clients/ops.py

    # A head over the per-call capture budget РH14 proposes, at both budgets:
    # 7000 bytes of padding is just under MinIO's own ~8 KB head limit.
    record minio huge-head "$p" -- raw huge-head small.bin 7000
    record minio huge-head-cap2048 "$p --capture-limit 2048" -- raw huge-head small.bin 7000
    # …and the ordinary matrix once more under that budget, to have a corpus of
    # truncated heads to develop against.
    record minio get-cap2048 "$p --capture-limit 2048" -- raw get
    record minio multipart-cap2048 "$p --capture-limit 2048" -- raw multipart

    # The five real clients.
    record minio awscli-basic "$p" -- sh -c "
        $AWS s3api put-object --bucket $BUCKET --key awscli.bin --body $WORK/small.bin
        $AWS s3api get-object --bucket $BUCKET --key awscli.bin /dev/null
        $AWS s3api head-object --bucket $BUCKET --key awscli.bin
        $AWS s3api list-objects-v2 --bucket $BUCKET --max-keys 20
        $AWS s3api delete-object --bucket $BUCKET --key awscli.bin
        $AWS s3api get-object --bucket $BUCKET --key nope.bin /dev/null"
    record minio awscli-multipart "$p" -- \
        $AWS s3 cp "$WORK/mp15m.bin" "s3://$BUCKET/awscli-mp.bin"
    record minio boto3-basic "$p" -- python3 clients/scenarios.py basic
    record minio boto3-multipart "$p" -- python3 clients/scenarios.py multipart
    record minio boto3-errors "$p" -- python3 clients/scenarios.py errors
    record minio mc-basic "$p" -- mc_run "http://127.0.0.1:$PORT" \
        'mc cp /w/small.bin lk/'"$BUCKET"'/mc.bin; mc ls lk/'"$BUCKET"' >/dev/null;
         mc cat lk/'"$BUCKET"'/mc.bin >/dev/null; mc rm lk/'"$BUCKET"'/mc.bin'
    # 5 MB, not 15: an `mc pipe` is a multipart upload of a stream of unknown
    # length, and one part is enough to show the shape without carrying 15 MB of
    # random bytes into the repository.
    record minio mc-pipe "$p" -- mc_run "http://127.0.0.1:$PORT" \
        'head -c 5242880 /w/mp15m.bin | mc pipe lk/'"$BUCKET"'/mc-piped.bin'
    # A realistic mixed load — GET/PUT/STAT/DELETE interleaved over pooled
    # keep-alive connections — under a 256-byte capture budget. The budget is
    # what makes it committable: a ringbuf record reserves a whole 4096-byte
    # payload slot unless the capture fits LK_CHUNK_SMALL (256), so at the
    # default budget one second of warp is 25 MB of trace and at 256 bytes it is
    # under two. Heads are therefore truncated here on purpose (`trunc` on most
    # records, `total_len` still honest) — the whole-head budget cases are
    # `get-cap2048` and `huge-head*`.
    record minio warp-mixed "$p --capture-limit 256" -- \
        docker run --rm --network host "$WARP_IMAGE" mixed \
        --host "127.0.0.1:$PORT" --access-key $AK --secret-key $SK --bucket lkwarp \
        --duration=1s --obj.size=64KiB --objects=20 --concurrent=2 --noclear --no-color
    record minio s3fs "$p" -- docker run --rm --network host --device /dev/fuse \
        --cap-add SYS_ADMIN --security-opt apparmor:unconfined --entrypoint sh \
        "$S3FS_IMAGE" -c "
            echo '$AK:$SK' > /pw && chmod 600 /pw && mkdir -p /mnt/s3
            s3fs $BUCKET /mnt/s3 -o passwd_file=/pw -o url=http://127.0.0.1:$PORT \
                 -o use_path_request_style -f &
            sleep 3; ls /mnt/s3 >/dev/null; cat /mnt/s3/small.bin >/dev/null
            echo hello-from-s3fs > /mnt/s3/s3fs.txt; sleep 1; umount /mnt/s3"
}

# --- the distributed cluster ------------------------------------------------

record_dist() {
    log "recording dist ($DIST_IP:$PORT_DIST, 4 nodes)"
    ensure_objects "http://$DIST_IP:$PORT_DIST" lkdist
    local p="--port $PORT_DIST"
    # Idle cluster: whatever the nodes say to each other with no S3 client at
    # all — the grid, the health chatter, the lock and storage RPCs.
    record dist grid-idle "$p" -- sleep 8
    # S3 traffic *and* the internal fan-out it causes, on the same port.
    record dist s3-and-grid "$p" -- env S3_ENDPOINT="$DIST_IP:$PORT_DIST" \
        S3_BUCKET=lkdist python3 clients/raw.py list
    record dist put-and-grid "$p" -- env S3_ENDPOINT="$DIST_IP:$PORT_DIST" \
        S3_BUCKET=lkdist python3 clients/raw.py put dist-put.bin 4194304
    # Fifty client operations on one connection while the cluster does its own
    # work: the client:internal ratio on the same port, in a trace small enough
    # to commit. (A warp run against the cluster is 6 MB of trace per second —
    # the volume question belongs to recon.sh item 6, not to the corpus.)
    record dist keepalive-and-grid "$p" -- env S3_ENDPOINT="$DIST_IP:$PORT_DIST" \
        S3_BUCKET=lkdist python3 clients/raw.py keepalive 50
}

# --- TLS --------------------------------------------------------------------

record_tls() {
    log "recording tls (127.0.0.1:$PORT_TLS)"
    ensure_objects "https://127.0.0.1:$PORT_TLS" "$BUCKET"
    local p="--port $PORT_TLS"
    record tls ciphertext "$p" -- env S3_ENDPOINT="127.0.0.1:$PORT_TLS" S3_TLS=1 \
        python3 clients/raw.py errors
    # The same load through the Go uprobes (РS8): MinIO ships a stripped binary,
    # so this is `go_pclntab.c` resolving crypto/tls.(*Conn).Read/Write in the
    # container's own copy of the executable.
    local pid bin
    pid=$(docker inspect -f '{{.State.Pid}}' lkt-s3-minio-tls 2>/dev/null)
    bin=$(sudo sh -c "ls /proc/$pid/root/usr/bin/minio /proc/$pid/root/opt/bin/minio \
                      2>/dev/null" | head -1)
    if [ -n "$bin" ]; then
        record tls decrypted "$p --tls-go $bin" -- env S3_ENDPOINT="127.0.0.1:$PORT_TLS" \
            S3_TLS=1 python3 clients/raw.py errors
        record tls decrypted-get "$p --tls-go $bin" -- env S3_ENDPOINT="127.0.0.1:$PORT_TLS" \
            S3_TLS=1 python3 clients/raw.py get
    else
        note "skip tls/decrypted: minio binary not found under /proc/$pid/root"
        skipped=$((skipped+2))
    fi
}

# --- main -------------------------------------------------------------------

[ -x "$LATKIT" ] || { echo "agent binary not found: $LATKIT (build it or set LATKIT=)"; exit 1; }
ensure_fixtures

for stand in minio dist tls; do
    [ -n "$ONLY" ] && [ "$ONLY" != "$stand" ] && continue
    case $stand in
        minio) ensure_minio && record_minio ;;
        dist)  ensure_dist  && record_dist  ;;
        tls)   ensure_tls   && record_tls   ;;
    esac
done

if [ "${KEEP:-0}" != "1" ]; then
    log "stopping the stands (KEEP=1 to keep)"
    stop_stand
fi

log "done: $recorded recorded, $skipped skipped, $fails failed"
[ "$fails" -eq 0 ]
