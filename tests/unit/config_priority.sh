#!/bin/sh
# Config-priority test (Р34, STAGE5.md task 5.4): asserts flag > LATKIT_* env >
# OTEL_* env > default over `latkit --print-config`. That path resolves CLI +
# environment and prints the effective config *before* touching BPF, so this
# needs no privileges and no kernel — it just execs the built agent.
#
# Usage: config_priority.sh /path/to/latkit   (wired from CMake as $<TARGET_FILE:latkit>)
set -eu

LATKIT="${1:?usage: config_priority.sh <path-to-latkit>}"
fails=0

# get KEY [env assignments...] [-- flags...]: print the value of KEY from
# --print-config, run with the given env and flags. Keeps env local to the run.
get() {
    key="$1"
    shift
    env_kv=""
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do
        env_kv="$env_kv $1"
        shift
    done
    [ "${1:-}" = "--" ] && shift
    # shellcheck disable=SC2086
    env $env_kv "$LATKIT" --print-config "$@" | sed -n "s/^$key=//p" | head -1
}

check() {
    what="$1"
    got="$2"
    want="$3"
    if [ "$got" = "$want" ]; then
        echo "ok   - $what ($got)"
    else
        echo "FAIL - $what: got '$got', want '$want'"
        fails=$((fails + 1))
    fi
}

# --- default (no flag, no env) ---
check "prom_listen default"   "$(get prom_listen)"       "127.0.0.1:9752"
check "otlp_interval default" "$(get otlp_interval)"      "15"
check "top_queries default"   "$(get top_queries)"        "500"
check "port default"          "$(get port)"               "5432"

# --- env overrides default ---
check "env sets prom_listen"  "$(get prom_listen LATKIT_PROM_LISTEN=0.0.0.0:9999)" "0.0.0.0:9999"
check "env sets interval"     "$(get otlp_interval LATKIT_OTLP_INTERVAL=42)"       "42"
check "env sets port"         "$(get port LATKIT_PORT=6000)"                        "6000"

# --- flag beats env ---
check "flag beats env (prom)" "$(get prom_listen LATKIT_PROM_LISTEN=0.0.0.0:9999 -- --prom-listen 127.0.0.1:1234)" "127.0.0.1:1234"
check "flag beats env (port)" "$(get port LATKIT_PORT=6000 -- -p 7777)"            "7777"

# --- boolean env: truthy on, falsey ignored ---
check "bool env on"           "$(get first_row_hist LATKIT_FIRST_ROW_HIST=1)"     "1"
check "bool env off (0)"      "$(get first_row_hist LATKIT_FIRST_ROW_HIST=0)"     "0"
check "bool env off (false)"  "$(get events LATKIT_EVENTS=false)"                  "0"

# --- OTEL_* honoured as a default; LATKIT_* beats OTEL_* ---
check "OTEL_ endpoint default"  "$(get otlp_endpoint OTEL_EXPORTER_OTLP_ENDPOINT=http://otel:4318)" "http://otel:4318"
check "LATKIT_ beats OTEL_"      "$(get otlp_endpoint LATKIT_OTLP_ENDPOINT=http://lk:4318 OTEL_EXPORTER_OTLP_ENDPOINT=http://otel:4318)" "http://lk:4318"
check "flag beats LATKIT_+OTEL_" "$(get otlp_endpoint LATKIT_OTLP_ENDPOINT=http://lk:4318 OTEL_EXPORTER_OTLP_ENDPOINT=http://otel:4318 -- --otlp-endpoint http://flag:4318)" "http://flag:4318"
check "OTEL_SERVICE_NAME"        "$(get otlp_service_name OTEL_SERVICE_NAME=svc)"  "svc"

# --- repeatable port via a comma-separated env list ---
check "env port list count"   "$(env LATKIT_PORT=6000,6001,6002 "$LATKIT" --print-config | grep -c '^port=')" "3"

# --- the per-port capture budget (РH14, PLAN-HTTP.md М7) ---
# `port_cap=PORT:BYTES` is the *resolved* budget — what the kernel data path
# will apply — so this is the one place the three-way precedence between the
# explicit `:BYTES`, the protocol's default and --capture-limit is pinned.
capof() { get_all="$("$LATKIT" --print-config "$@")"; printf '%s\n' "$get_all" | sed -n "s/^port_cap=$port://p"; }

port=5432
check "db port follows the global"  "$(capof -p 5432)"                        "8192"
check "db port follows --capture-limit" "$(capof -p 5432 --capture-limit 4096)" "4096"
port=8080
check "http port defaults to 2048"  "$(capof -p 8080=http)"                   "2048"
# A global budget is a ceiling: lowering it lowers the protocol default with it.
check "global caps the http default" "$(capof -p 8080=http --capture-limit 1024)" "1024"
# ... but a budget typed for this port was typed for a reason, and wins outright.
check "explicit port budget wins"   "$(capof -p 8080=http:4096 --capture-limit 1024)" "4096"
check "explicit budget over a db port" "$(capof -p 8080=pg:512)"              "512"

# --- the dimension limit follows the ports (РS4, PLAN-MINIO.md МS2) ---
# It has no flag of its own on purpose: the (bucket, access key) space of an S3
# port is much larger than the (schema, role) one of a database, so the limit is
# derived from what is being watched rather than from something an operator has
# to know to raise.
check "dims default"          "$(get max_session_dims)"                             "32"
check "dims raised by s3"     "$(get max_session_dims -- -p 9000=s3)"               "128"
check "dims raised in a mix"  "$(get max_session_dims -- -p 5432 -p 9000=s3)"       "128"
check "dims unchanged by http" "$(get max_session_dims -- -p 8080=http)"            "32"

# --- the Go TLS channel (РH13.3, М7) ---
check "tls_go default"        "$(get tls_go)"                                       ""
check "tls_go flag"           "$(get tls_go -- --tls-go /usr/bin/caddy)"            "/usr/bin/caddy"
check "tls_go env list"       "$(get tls_go LATKIT_TLS_GO=/a/caddy,/b/traefik)"     "/a/caddy,/b/traefik"
check "tls_go flag beats env" "$(get tls_go LATKIT_TLS_GO=/a/caddy -- --tls-go /b/x)" "/b/x"

# --- the HTTP route knobs (РH7, PLAN-HTTP.md М4) ---
# They have no LATKIT_* equivalent yet (the whole HTTP surface lands in the
# README at М9), so what is checked here is defaulting, parsing and the one
# place the agent reads a file at startup.
check "route depth default"   "$(get http_route_depth)"                             "8"
check "route depth flag"      "$(get http_route_depth -- --http-route-depth 3)"     "3"
check "query keys"            "$(get http_query_keys -- --http-query-keys action,op)" "action,op"
check "route header folded"   "$(get http_route_header -- --http-route-header X-Route)" "x-route"
check "no route map"          "$(get http_routes)"                                  "0"

routes="$(mktemp)"
printf '# a map\nGET /users/{id}\n* /health\nnonsense\n' > "$routes"
check "route map loaded"      "$(get http_routes -- --http-routes "$routes")"       "2"
rm -f "$routes"

# A route map that is entirely unusable is a config error, not a silent
# fallback to the heuristic: the operator asked for exact routes.
if "$LATKIT" --print-config --http-routes /nonexistent/routes.txt >/dev/null 2>&1; then
    echo "FAIL - a missing --http-routes file should exit non-zero"
    fails=$((fails + 1))
else
    echo "ok   - missing --http-routes file rejected"
fi

# --- a bad env value is a hard error (exit != 0) ---
if env LATKIT_PORT=99999 "$LATKIT" --print-config >/dev/null 2>&1; then
    echo "FAIL - bad env value should exit non-zero"
    fails=$((fails + 1))
else
    echo "ok   - bad env value rejected"
fi

echo "---"
if [ "$fails" -eq 0 ]; then
    echo "all config-priority checks passed"
    exit 0
fi
echo "$fails config-priority check(s) failed"
exit 1
