#!/usr/bin/env bash
#
# МS0 (PLAN-MINIO.md): the five reconnaissance questions, each answered on a
# live MinIO and each leaving its evidence in .work/recon/ so the numbers in
# README.md can be re-derived rather than believed:
#
#   1. does MinIO negotiate h2 over ALPN, and how is it turned off — the size of
#      the TLS blind zone (risk 1 of the plan; decides whether МS3 is worth it);
#   2. does the official MinIO binary keep the symbols the Go TLS module needs
#      (РS8) — and, the question that actually matters, does the agent resolve
#      them in the binary the container is running;
#   3. does MinIO serve objects with sendfile/splice — the weight of the РH4
#      degradation on an object store (risk 3);
#   4. what share of a typical load is framed chunked (response) and aws-chunked
#      (request) — how central the chunk paths and РS6 are;
#   5. what the MinIO threads are called — the входной parameter of the comm
#      filter, and of --tls-comm.
#
# Plus one the plan did not ask for and the stands made unavoidable:
#
#   6. on a distributed cluster, how much of the traffic on the S3 port is the
#      cluster talking to itself (РS2's op="internal", and risk 2's volume).
#
# Uses the same stands as record.sh (run that first, or STAND=1 here to bring
# them up and leave them running).
#
#   ./recon.sh            # all six items
#   ./recon.sh 2 4        # selected items
set -uo pipefail

cd "$(dirname "$0")"
REPO_ROOT=$(cd ../../.. && pwd)
LATKIT=${LATKIT:-$REPO_ROOT/build-rel/latkit}
WORK=${WORK:-$PWD/.work}
OUT=$WORK/recon
mkdir -p "$OUT"

PORT=${PORT:-9900}; PORT_TLS=${PORT_TLS:-9902}; PORT_DIST=${PORT_DIST:-9910}
AK=lkroot; SK=lkrootpass123; BUCKET=lkbucket
export S3_ENDPOINT="127.0.0.1:$PORT" S3_AK=$AK S3_SK=$SK S3_BUCKET=$BUCKET
SIGV4=(--aws-sigv4 "aws:amz:us-east-1:s3" -u "$AK:$SK")
ITEMS=${*:-1 2 3 4 5 6}

log()  { printf '\n=== %s ===\n' "$*"; }
want() { case " $ITEMS " in *" $1 "*) return 0;; *) return 1;; esac; }

[ "${STAND:-0}" = 1 ] && KEEP=1 ./record.sh none >/dev/null 2>&1

# --- 1. h2 over ALPN --------------------------------------------------------
# Go's TLS server picks the first entry of *its* NextProtos that the client also
# offers, so the answer is not "does MinIO support h2" but "what does it choose
# when a real client offers both" — which is what decides the blind zone.
if want 1; then
    log "item 1: does MinIO negotiate HTTP/2 over TLS?"
    {
        echo "--- what the server selects for each ALPN offer (openssl s_client) ---"
        for offer in h2,http/1.1 http/1.1,h2 h2 http/1.1; do
            printf '%-16s ' "offer=$offer"
            echo | openssl s_client -connect "127.0.0.1:$PORT_TLS" -alpn "$offer" 2>/dev/null \
                | grep -i '^ALPN protocol' || echo "(none)"
        done
        echo
        echo "--- what real clients end up speaking ---"
        printf '%-28s ' "curl (default)"
        curl -ksS -o /dev/null -w 'HTTP/%{http_version}\n' "https://127.0.0.1:$PORT_TLS/minio/health/live"
        printf '%-28s ' "curl --http2"
        curl -ksS --http2 -o /dev/null -w 'HTTP/%{http_version}\n' "https://127.0.0.1:$PORT_TLS/minio/health/live"
        if command -v go >/dev/null && [ -d ../http/clients/tlsprobe ]; then
            (cd ../http/clients/tlsprobe && go run . "https://127.0.0.1:$PORT_TLS/minio/health/live")
        fi
        printf '%-28s ' "python urllib (boto3 stack)"
        python3 - "https://127.0.0.1:$PORT_TLS/minio/health/live" <<'PY'
import ssl, sys, urllib.request
ctx = ssl.create_default_context(); ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
urllib.request.urlopen(sys.argv[1], context=ctx, timeout=10).read()
print("HTTP/1.1 (no ALPN offer)")
PY
        echo
        echo "--- cleartext prior-knowledge h2 on the plaintext port ---"
        curl -sS --http2-prior-knowledge -o /dev/null \
             -w 'prior-knowledge h2: HTTP/%{http_version}\n' \
             "http://127.0.0.1:$PORT/minio/health/live" 2>&1 | tail -1
    } 2>&1 | tee "$OUT/01-h2.txt"
fi

# --- 2. Go symbols in the official binary -----------------------------------
if want 2; then
    log "item 2: crypto/tls symbols in the MinIO binary (РS8)"
    {
        mkdir -p "$WORK/bin"
        if [ ! -f "$WORK/bin/minio" ]; then
            cid=$(docker create "${MINIO_IMAGE:-minio/minio:latest}" 2>/dev/null)
            for p in /usr/bin/minio /opt/bin/minio; do
                docker cp "$cid:$p" "$WORK/bin/minio" >/dev/null 2>&1 && break
            done
            docker rm "$cid" >/dev/null 2>&1
        fi
        bin=$WORK/bin/minio
        echo "# image binary: $(file -b "$bin" | cut -c1-80)"
        echo "# go version:   $(go version "$bin" 2>/dev/null | awk '{print $2}')"
        printf '# nm symtab:    '; nm -a "$bin" 2>&1 | head -1
        printf '# tls syms by nm: '
        nm -a "$bin" 2>/dev/null | grep -c 'crypto/tls\.(\*Conn)\.\(Write\|Read\)$'
        printf '# .gopclntab:   '; readelf -S "$bin" 2>/dev/null | grep -c '\.gopclntab'
        printf '# name string in file: '; grep -ac 'crypto/tls\.(\*Conn)\.Write' "$bin"
        echo
        echo "--- the question that matters: does the agent attach? ---"
        pid=$(docker inspect -f '{{.State.Pid}}' lkt-s3-minio-tls 2>/dev/null \
              || docker inspect -f '{{.State.Pid}}' lkt-s3-minio 2>/dev/null)
        runbin=$(sudo sh -c "ls /proc/$pid/root/usr/bin/minio /proc/$pid/root/opt/bin/minio \
                             2>/dev/null" | head -1)
        echo "# running binary: $runbin (pid $pid)"
        sudo timeout 8 "$LATKIT" --port "$PORT_TLS" --tls-go "$runbin" \
             --prom-listen none 2>&1 | grep -E 'Go TLS|capturing|error|failed'
    } 2>&1 | tee "$OUT/02-go-symbols.txt"
fi

# --- 3. sendfile ------------------------------------------------------------
if want 3; then
    log "item 3: does MinIO use sendfile/splice for object bodies?"
    {
        pid=$(docker inspect -f '{{.State.Pid}}' lkt-s3-minio 2>/dev/null)
        echo "# minio pid $pid, 20 x GET of an 8 MB object"
        sudo timeout 120 strace -f -qq -p "$pid" \
             -e trace=sendfile,splice,copy_file_range,write,writev,sendto,sendmsg,sendmmsg \
             -c -o "$OUT/03-strace.txt" &
        spid=$!
        sleep 1.5
        for _ in $(seq 20); do
            curl -sS "${SIGV4[@]}" -o /dev/null "http://127.0.0.1:$PORT/$BUCKET/big8m.bin"
        done
        sleep 1.5
        sudo kill -INT "$spid" 2>/dev/null; wait "$spid" 2>/dev/null
        cat "$OUT/03-strace.txt"
        echo
        echo "# what the agent saw for one of the same responses:"
        sudo timeout 12 "$LATKIT" --port "$PORT" --prom-listen none \
             > "$OUT/03-agent.log" 2>&1 &
        apid=$!
        for _ in $(seq 100); do grep -q 'capturing local port' "$OUT/03-agent.log" && break; sleep 0.1; done
        curl -sS "${SIGV4[@]}" -o /dev/null "http://127.0.0.1:$PORT/$BUCKET/big8m.bin"
        sleep 1; sudo kill -INT "$apid" 2>/dev/null; wait "$apid" 2>/dev/null
        grep -E 'stats events=' "$OUT/03-agent.log"
        echo "# kernel: $(uname -r)"
    } 2>&1 | tee "$OUT/03-sendfile.txt"
fi

# --- 4. chunked / aws-chunked -----------------------------------------------
if want 4; then
    log "item 4: response framing and aws-chunked share on a typical load"
    (python3 clients/tap.py 9990 127.0.0.1 "$PORT" --body 0 > "$OUT/04-tap.log" 2>&1 &)
    sleep 1
    docker run --rm --network host "${WARP_IMAGE:-minio/warp:latest}" mixed \
        --host 127.0.0.1:9990 --access-key $AK --secret-key $SK --bucket lkwarp \
        --duration=15s --obj.size=1MiB --objects=100 --concurrent=4 --noclear --no-color \
        >/dev/null 2>&1
    pkill -f 'tap.py 9990'
    sleep 0.5
    {
        echo "--- warp mixed, 4 concurrent, 1 MiB objects, through the tap ---"
        python3 clients/framing.py "$OUT/04-tap.log"
        echo
        echo "--- when MinIO *does* chunk: the Accept-Encoding A/B on a listing ---"
        python3 clients/raw.py fill 400 >/dev/null 2>&1
        for ae in identity gzip 'zstd,gzip'; do
            printf '  listing, Accept-Encoding: %-12s ' "$ae"
            curl -sS "${SIGV4[@]}" -o /dev/null -D - -H "Accept-Encoding: $ae" \
                 "http://127.0.0.1:$PORT/$BUCKET?list-type=2&max-keys=1000" 2>/dev/null \
                | grep -iE '^(content-length|transfer-encoding|content-encoding)' \
                | tr -d '\r' | paste -sd' '
        done
        printf '  object body, Accept-Encoding: gzip    '
        curl -sS "${SIGV4[@]}" -o /dev/null -D - -H 'Accept-Encoding: gzip' \
             "http://127.0.0.1:$PORT/$BUCKET/big8m.bin" 2>/dev/null \
            | grep -iE '^(content-length|transfer-encoding|content-encoding)' \
            | tr -d '\r' | paste -sd' '
        echo
        echo "--- and the two event-stream cases (both chunked, both bodies we never read) ---"
        python3 clients/raw.py select 2>&1 | tail -1
        printf '  admin trace: '
        timeout 3 curl -sS "${SIGV4[@]}" -D - -o /dev/null \
             "http://127.0.0.1:$PORT/minio/admin/v3/trace?s3=true" 2>/dev/null \
            | grep -iE '^(content-type|transfer-encoding)' | tr -d '\r' | paste -sd' '
    } 2>&1 | tee "$OUT/04-framing.txt"
fi

# --- 5. thread comms --------------------------------------------------------
if want 5; then
    log "item 5: what the MinIO threads are called"
    {
        for c in lkt-s3-minio lkt-s3-minio-tls lkt-s3-d0; do
            pid=$(docker inspect -f '{{.State.Pid}}' "$c" 2>/dev/null) || continue
            [ -n "$pid" ] || continue
            echo "--- $c (pid $pid) ---"
            ps -L -o comm= -p "$pid" | sort | uniq -c | sort -rn
        done
        echo
        echo "# and the executable name, which is what --comm matches:"
        pid=$(docker inspect -f '{{.State.Pid}}' lkt-s3-minio 2>/dev/null)
        sudo readlink "/proc/$pid/exe"
    } 2>&1 | tee "$OUT/05-comm.txt"
fi

# --- 6. how much of a cluster's port traffic is the cluster itself ----------
if want 6; then
    log "item 6: client vs internal traffic on a distributed cluster's port"
    {
        ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
             lkt-s3-d0 2>/dev/null)
        if [ -z "$ip" ]; then
            echo "distributed stand not running (./record.sh dist first)"
        else
            echo "# 4-node pool, one warp run; connections are counted by their peer:"
            echo "# a client is anything outside the pool's own addresses."
            sudo timeout 40 "$LATKIT" --port "$PORT_DIST" --prom-listen none --events \
                 > "$OUT/06-events.log" 2>&1 &
            apid=$!
            for _ in $(seq 100); do grep -q 'capturing local port' "$OUT/06-events.log" && break; sleep 0.1; done
            docker run --rm --network lkt-s3-net "${WARP_IMAGE:-minio/warp:latest}" mixed \
                --host "d0:$PORT_DIST" --access-key $AK --secret-key $SK --bucket lkwarpd \
                --duration=10s --obj.size=1MiB --objects=50 --concurrent=2 \
                --noclear --no-color >/dev/null 2>&1
            sleep 1; sudo kill -INT "$apid" 2>/dev/null; wait "$apid" 2>/dev/null
            pool=$(for i in 0 1 2 3; do
                     docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
                       "lkt-s3-d$i" 2>/dev/null; done | paste -sd'|')
            python3 - "$OUT/06-events.log" "$pool" <<'PY'
import re, sys
pool = set(sys.argv[2].split("|"))
opens, peers = {}, {}
ev = re.compile(r"^\d+ (\w+)\s+conn=(\w+)")
tup = re.compile(r"::ffff:([\d.]+):(\d+) -> ::ffff:([\d.]+):(\d+)")
n_int = n_cli = 0
data_int = data_cli = 0
for line in open(sys.argv[1], errors="replace"):
    m = ev.match(line)
    if not m:
        continue
    kind, conn = m.groups()
    if kind == "OPEN":
        t = tup.search(line)
        if t:
            peers[conn] = t.group(3)
            if t.group(3) in pool:
                n_int += 1
            else:
                n_cli += 1
    elif kind in ("SEND", "RECV"):
        p = peers.get(conn)
        if p is None:
            continue
        if p in pool:
            data_int += 1
        else:
            data_cli += 1
print("  pool addresses: %s" % ", ".join(sorted(pool)))
print("  connections : internal=%d client=%d (%.0f%% internal)"
      % (n_int, n_cli, 100.0 * n_int / max(1, n_int + n_cli)))
print("  data events : internal=%d client=%d (%.0f%% internal)"
      % (data_int, data_cli, 100.0 * data_int / max(1, data_int + data_cli)))
PY
        fi
    } 2>&1 | tee "$OUT/06-internal-share.txt"
fi

log "evidence in $OUT"
ls -l "$OUT"
