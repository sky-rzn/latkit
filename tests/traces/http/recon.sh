#!/usr/bin/env bash
#
# М0 (PLAN-HTTP.md): the five reconnaissance questions, each answered on a live
# stand and each leaving its evidence in .work/recon/ so the numbers in
# README.md can be re-derived rather than believed:
#
#   1. sendfile(2) — what share of nginx response bodies never passes
#      tcp_sendmsg (weight of degradation РH4);
#   2. chunked — how often typical backends frame responses chunked instead of
#      Content-Length (risk 4 of the plan);
#   3. Go symtab — do real Go binaries keep the symbols РH13.3 attaches to;
#   4. h2 — what share of TLS connections leaves HTTP/1.1 behind (§8);
#   5. header block sizes — percentiles, against the РH14 capture budget.
#
# Uses the same stand as record.sh (which brings it up; run that first, or
# STAND=1 here to bring it up and leave it running).
#
#   ./recon.sh            # all five items
#   ./recon.sh 3 4        # selected items
set -uo pipefail

cd "$(dirname "$0")"
LATKIT=${LATKIT:-$(cd ../../.. && pwd)/build-rel/latkit}
WORK=${WORK:-$PWD/.work}
OUT=$WORK/recon
mkdir -p "$OUT"

PORT_NGINX=8080; PORT_GO=8082; PORT_NODE=8083; PORT_GUNICORN=8084; PORT_TLS=8443
ITEMS=${*:-1 2 3 4 5}

log() { printf '\n=== %s ===\n' "$*"; }
want() { case " $ITEMS " in *" $1 "*) return 0;; *) return 1;; esac; }

[ "${STAND:-0}" = 1 ] && KEEP=1 ./record.sh none >/dev/null

# --- 1. sendfile ------------------------------------------------------------
# nginx worker syscall census while serving the same 8 MB file with sendfile on
# and off. The A/B is the proof: identical bytes on the wire, and with sendfile
# the body simply is not in any socket write.
if want 1; then
    log "item 1: sendfile(2) vs socket writes (nginx worker syscalls)"
    worker=$(pgrep -f 'nginx: worker process' | head -1)
    if [ -z "$worker" ]; then
        echo "  nginx worker not found — start the stand first" | tee "$OUT/01-sendfile.txt"
    else
        {
            echo "# nginx worker pid $worker, image ${NGINX_IMAGE:-nginx:1.29-alpine}"
            echo "# 20 x GET /huge (8 MB static, sendfile on)  vs  20 x GET /nosendfile/huge.bin"
            echo
            for mode in "sendfile-on:/huge" "sendfile-off:/nosendfile/huge.bin"; do
                name=${mode%%:*}; path=${mode#*:}
                sudo timeout 60 strace -f -qq -p "$worker" -e trace=sendfile,writev,write,sendto,send \
                     -c -o "$OUT/01-strace-$name.txt" &
                spid=$!
                sleep 1
                for _ in $(seq 20); do
                    curl -sS -o /dev/null "http://127.0.0.1:$PORT_NGINX$path"
                done
                sleep 1
                sudo kill -INT "$spid" 2>/dev/null; wait "$spid" 2>/dev/null
                echo "--- $name ($path) ---"
                cat "$OUT/01-strace-$name.txt"
                echo
            done
            echo "--- what the agent recorded for the same two responses ---"
            echo "# capture trace size, 8 MB response body each:"
            ls -l nginx/sendfile-static.lkt nginx/nosendfile-static.lkt 2>/dev/null
            echo
            echo "# and the agent's own stats for one /huge + one /nosendfile/huge.bin:"
            echo "# (bytes=captured/total and iter_unsupported are the whole story —"
            echo "#  on this kernel sendfile still *reaches* tcp_sendmsg, it just carries"
            echo "#  a splice-page iterator the probe cannot copy from)"
            sudo "${LATKIT:-../../../build-rel/latkit}" --port "$PORT_NGINX" \
                 --prom-listen none > "$OUT/01-agent-stats.log" 2>&1 &
            apid=$!
            for _ in $(seq 100); do
                grep -q 'capturing local port' "$OUT/01-agent-stats.log" && break; sleep 0.1
            done
            curl -sS -o /dev/null "http://127.0.0.1:$PORT_NGINX/huge"
            curl -sS -o /dev/null "http://127.0.0.1:$PORT_NGINX/nosendfile/huge.bin"
            sleep 1
            sudo kill -INT "$apid" 2>/dev/null; wait "$apid" 2>/dev/null
            grep -E 'stats events=' "$OUT/01-agent-stats.log"
            echo "# kernel: $(uname -r)"
        } | tee "$OUT/01-sendfile.txt"
    fi
fi

# --- 2. chunked -------------------------------------------------------------
if want 2; then
    log "item 2: response framing (chunked vs Content-Length) per backend"
    : > "$OUT/02-framing.tsv"
    python3 clients/probe.py sweep nginx    127.0.0.1 "$PORT_NGINX"    >> "$OUT/02-framing.tsv"
    python3 clients/probe.py sweep go       127.0.0.1 "$PORT_GO"       >> "$OUT/02-framing.tsv"
    python3 clients/probe.py sweep node     127.0.0.1 "$PORT_NODE"     >> "$OUT/02-framing.tsv"
    python3 clients/probe.py sweep gunicorn 127.0.0.1 "$PORT_GUNICORN" >> "$OUT/02-framing.tsv"
    python3 clients/probe.py summary "$OUT/02-framing.tsv" | tee "$OUT/02-framing.txt"
fi

# --- 3. Go symtab -----------------------------------------------------------
# РH13.3 attaches by symbol name; a stripped binary leaves only .gopclntab.
# The sample is deliberately mixed: our own build, our own -s -w build, vendor
# container images and the distribution's own Go binaries.
if want 3; then
    log "item 3: do real Go binaries keep crypto/tls symbols?"
    {
        probe_go() { # probe_go LABEL PATH
            local label=$1 path=$2
            [ -f "$path" ] || { printf '%-30s MISSING\n' "$label"; return; }
            local symtab syms pclntab namestr ver
            symtab=$(nm -a "$path" 2>/dev/null | wc -l)
            [ "$symtab" -gt 1 ] && symtab=yes || symtab=no
            syms=$(nm -a "$path" 2>/dev/null | grep -c 'crypto/tls\.(\*Conn)\.\(Write\|Read\)$')
            pclntab=$(readelf -S "$path" 2>/dev/null | grep -c '\.gopclntab')
            [ "$pclntab" -gt 0 ] && pclntab=section || pclntab=no-section
            # The function *name* lives in the pclntab name table, which -s -w
            # keeps: if the literal is in the file, РH13.3 can still find the
            # function by parsing pclntab — it just cannot use nm.
            namestr=$(grep -ac 'crypto/tls\.(\*Conn)\.Write' "$path" 2>/dev/null)
            ver=$(go version "$path" 2>/dev/null | awk '{print $2}')
            printf '%-30s symtab=%-3s tls_syms=%-2s pclntab=%-10s name_in_file=%-2s %s\n' \
                   "$label" "$symtab" "$syms" "$pclntab" "$namestr" "${ver:-not-go}"
        }
        echo "# symtab       = an ELF symbol table exists at all (nm)"
        echo "# tls_syms     = crypto/tls.(*Conn).Write/.Read found by nm (what РH13.3 attaches to)"
        echo "# pclntab      = .gopclntab section present (survives -s -w)"
        echo "# name_in_file = the function name string is somewhere in the binary,"
        echo "#                i.e. recoverable by parsing pclntab even without a symtab"
        echo
        (cd backends/go && go build -o "$WORK/bin/probe-plain" . \
                        && go build -ldflags="-s -w" -o "$WORK/bin/probe-stripped" .) 2>/dev/null
        probe_go "our build (default)"        "$WORK/bin/probe-plain"
        probe_go "our build (-ldflags -s -w)" "$WORK/bin/probe-stripped"

        for hostbin in /usr/bin/docker /usr/bin/containerd /usr/bin/runc \
                       /usr/bin/docker-proxy /usr/bin/ctr /snap/bin/kubectl; do
            probe_go "host: $hostbin" "$hostbin"
        done

        # Vendor images: the servers this plan actually promises (Caddy,
        # Traefik) plus MinIO, which PLAN-MINIO.md sits on top of.
        for img in caddy:2 traefik:v3.3 minio/minio:latest; do
            name=$(echo "$img" | tr '/:' '__')
            docker pull -q "$img" >/dev/null 2>&1 || { printf "%-30s PULL FAILED\n" "$img"; continue; }
            cid=$(docker create "$img" 2>/dev/null) || continue
            for p in /usr/bin/caddy /usr/local/bin/traefik /opt/bin/minio /usr/bin/minio; do
                docker cp "$cid:$p" "$WORK/bin/$name" >/dev/null 2>&1 && break
            done
            docker rm "$cid" >/dev/null 2>&1
            probe_go "image: $img" "$WORK/bin/$name"
        done
    } 2>&1 | tee "$OUT/03-go-symbols.txt"
fi

# --- 4. h2 over TLS ---------------------------------------------------------
# nginx logs $server_protocol and $ssl_alpn_protocol per request, so the answer
# is measured, not assumed: every client shape hits the same endpoint once.
if want 4; then
    log "item 4: what negotiates HTTP/2 on a TLS stand"
    docker exec lkt-http-nginx sh -c ': > /var/log/nginx/recon.log' 2>/dev/null
    url="https://127.0.0.1:$PORT_TLS/hello"
    {
        echo "--- clients ---"
        curl -ksS -o /dev/null -w 'curl-default   %{http_version}\n' "$url"
        curl -ksS --http1.1 -o /dev/null -w 'curl-http1.1   %{http_version}\n' "$url"
        python3 - "$url" <<'PY'
import ssl, sys, urllib.request
ctx = ssl.create_default_context(); ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
urllib.request.urlopen(sys.argv[1], context=ctx, timeout=10).read()
print("python-urllib  http/1.1 (no ALPN offer)")
PY
        NODE_TLS_REJECT_UNAUTHORIZED=0 node -e '
          fetch(process.argv[1]).then(r => console.log("node-fetch     http/" + "1.1 (undici)"))
            .catch(e => console.log("node-fetch     ERROR " + e.message))' "$url"
        (cd clients/tlsprobe && go run . "$url")
        java clients/TlsProbe.java "$url" 2>/dev/null || echo "java           SKIPPED"
        if command -v chromium >/dev/null; then
            # --dump-dom does not reliably exit on its own; by the time the
            # timeout fires the request is long since on the wire, and the wire
            # is all we measure.
            timeout 30 chromium --headless --no-sandbox --disable-gpu \
                    --ignore-certificate-errors --virtual-time-budget=3000 \
                    --dump-dom "$url" >/dev/null 2>&1
            echo "chromium       (real browser — see the access log below)"
        fi
        echo
        echo "--- openssl: what the server offers/selects for a browser-like ALPN list ---"
        echo | openssl s_client -connect "127.0.0.1:$PORT_TLS" -alpn h2,http/1.1 2>/dev/null \
            | grep -i 'ALPN'
        echo | openssl s_client -connect "127.0.0.1:$PORT_TLS" -alpn http/1.1 2>/dev/null \
            | grep -i 'ALPN'
        echo
        echo "--- nginx access log for the run (proto= is the truth) ---"
        docker exec lkt-http-nginx cat /var/log/nginx/recon.log 2>/dev/null \
            | grep -o 'proto=[^ ]* .*alpn=[^ ]*' | sed 's/ uri=/ /' | sort | uniq -c | sort -rn
        echo
        echo "--- tally ---"
        docker exec lkt-http-nginx cat /var/log/nginx/recon.log 2>/dev/null \
            | grep -o 'proto=[^ ]*' | sort | uniq -c
    } 2>&1 | tee "$OUT/04-h2.txt"
fi

# --- 5. header block sizes --------------------------------------------------
if want 5; then
    log "item 5: header block sizes vs the РH14 capture budget"
    [ -s "$OUT/02-framing.tsv" ] || {
        for s in "nginx $PORT_NGINX" "go $PORT_GO" "node $PORT_NODE" "gunicorn $PORT_GUNICORN"; do
            set -- $s; python3 clients/probe.py sweep "$1" 127.0.0.1 "$2"
        done > "$OUT/02-framing.tsv"
    }
    # Self-contained second opinion: drive a known load through nginx and let
    # nginx measure it ($request_length), so the numbers do not depend on what
    # the stand happened to see earlier.
    docker exec lkt-http-nginx sh -c ': > /var/log/nginx/recon.log' 2>/dev/null
    python3 clients/probe.py sweep nginx 127.0.0.1 "$PORT_NGINX" > /dev/null
    {
        python3 clients/probe.py summary "$OUT/02-framing.tsv" \
            | sed -n '/request header block/,$p'
        echo
        echo "--- nginx's own view (\$request_length of the same sweep) ---"
        docker exec lkt-http-nginx cat /var/log/nginx/recon.log 2>/dev/null \
            | grep -o 'req_len=[0-9]*' | cut -d= -f2 | sort -n | python3 -c '
import sys
v = sorted(int(x) for x in sys.stdin)
if not v: sys.exit("no access-log lines")
q = lambda p: v[min(len(v)-1, int(round(p/100*(len(v)-1))))]
print("n=%d min=%d p50=%d p90=%d p99=%d max=%d" % (len(v), v[0], q(50), q(90), q(99), v[-1]))
for cap in (1024, 2048, 4096, 8192):
    over = sum(1 for x in v if x > cap)
    print("  over a %5d-byte capture budget: %3d/%d (%.1f%%)"
          % (cap, over, len(v), 100.0 * over / len(v)))'
    } 2>&1 | tee "$OUT/05-head-sizes.txt"
fi

log "evidence in $OUT"
ls -l "$OUT"
