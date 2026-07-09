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
