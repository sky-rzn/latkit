#!/usr/bin/env bash
# Fuzzing campaign runner (task 8.3, Р51): the ≥24-CPU-hour local campaign and
# the corpus maintenance around it. CI does NOT run this — it runs the corpus
# regression (ctest) and short budgeted fuzzing directly (see ci.yml); this
# script is for the overnight stand run and for reproducing it.
#
#   tests/fuzz/campaign.sh [seconds-per-target] [workers]
#
# Defaults: 1800 s/target, nproc-1 workers => 6 * 1800 * 21 / 3600 = 63
# CPU-hours on the 22-core stand. Per target it:
#   1. seeds a working corpus from tests/fuzz/corpus/<t> + fresh gen_seeds;
#   2. fuzzes with -jobs=W -workers=W (W parallel processes, wall = budget);
#   3. minimises the result back into tests/fuzz/corpus/<t> with -merge=1 —
#      the committed corpus is the regression set, so every campaign leaves
#      its coverage behind in git.
# Any crash/timeout/OOM artifact fails the script (exit 1) and is left in
# <workdir>/findings/ with its fuzz-*.log for triage.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BUILD=${BUILD:-$ROOT/build-fuzz}
TIME=${1:-1800}
WORKERS=${2:-$(($(nproc) - 1))}
WORK=${WORK:-$BUILD/campaign-$(date +%Y%m%d-%H%M%S)}

# Per-target dictionary: MySQL has its own byte alphabet (command / lenenc /
# capability bytes), HTTP is text with its own token set (methods, framing
# headers, chunk shapes) and RESP is a third alphabet again (type bytes, lengths
# that must not parse, the verbs the handler acts on); pg.dict covers the pg
# framer, the norm SQL fragments and the pipe scenarios well enough. Two targets carry more than one input
# language behind a selector byte — fuzz_norm (SQL, HTTP routes since М4, S3
# classifier inputs since МS1) and fuzz_http (the base dialect and, since МS4,
# S3 behind 0xFD) — and libFuzzer takes a single -dict, so both get a
# concatenation, built once below.
dict_for() {
    case "$1" in
    my) echo "$ROOT/tests/fuzz/dict/my.dict" ;;
    redis) echo "$ROOT/tests/fuzz/dict/redis.dict" ;;
    http) echo "$WORK/http.dict" ;;
    norm) echo "$WORK/norm.dict" ;;
    *) echo "$ROOT/tests/fuzz/dict/pg.dict" ;;
    esac
}

# Stand trap: with DEBUGINFOD_URLS set, llvm-symbolizer stalls ~90 s per query
# on the network — every NEW_FUNC line would freeze a worker. Never useful here;
# crash artifacts can be symbolised offline.
export DEBUGINFOD_URLS=

if [ ! -x "$BUILD/tests/fuzz/fuzz_pg" ]; then
    cmake -B "$BUILD" -DCMAKE_C_COMPILER=clang -DLATKIT_FUZZ=ON
    cmake --build "$BUILD" --target fuzz_pg fuzz_my fuzz_http fuzz_redis fuzz_norm fuzz_pipe \
        gen_seeds -j"$(nproc)"
fi

mkdir -p "$WORK/findings" "$WORK/seed"/{pg,my,http,redis,norm,pipe}
cat "$ROOT/tests/fuzz/dict/pg.dict" "$ROOT/tests/fuzz/dict/route.dict" > "$WORK/norm.dict"
cat "$ROOT/tests/fuzz/dict/http.dict" "$ROOT/tests/fuzz/dict/s3.dict" > "$WORK/http.dict"
"$BUILD/tests/fuzz/gen_seeds" "$WORK/seed" >/dev/null

echo "campaign: $TIME s/target x $WORKERS workers x 6 targets" \
     "= $(((6 * TIME * WORKERS + 1800) / 3600)) CPU-hours; workdir $WORK"

fail=0
for t in pg my http redis norm pipe; do
    corp="$WORK/corpus-$t"
    mkdir -p "$corp"
    cp "$ROOT/tests/fuzz/corpus/$t"/* "$WORK/seed/$t"/* "$corp"/ 2>/dev/null || true
    # The .lkt traces double as raw framer seeds for their protocol.
    [ "$t" = pg ] && cp "$ROOT"/tests/fixtures/*.lkt "$corp"/
    [ "$t" = my ] && cp "$ROOT"/tests/traces/mysql/*/*.lkt "$corp"/ 2>/dev/null || true
    # ... and, for http, the S3 corpus too: same target, same framer, the
    # dialect chosen by a byte the mutator can flip (МS4).
    [ "$t" = http ] && cp "$ROOT"/tests/traces/http/*/*.lkt "$ROOT"/tests/traces/s3/*/*.lkt \
                          "$corp"/ 2>/dev/null || true
    # ... and the МR0 Redis corpus for the redis target: 93 recorded sessions
    # carrying shapes no seed writer invents — a 16.9 MB reply in 212 writes, a
    # 13-deep `COMMAND DOCS`, a client sending one byte per syscall.
    [ "$t" = redis ] && cp "$ROOT"/tests/traces/redis/*/*.lkt "$corp"/ 2>/dev/null || true

    echo "=== fuzz_$t: $TIME s, $WORKERS workers ==="
    mkdir -p "$WORK/run-$t"
    (cd "$WORK/run-$t" &&
     "$BUILD/tests/fuzz/fuzz_$t" "$corp" \
        -jobs="$WORKERS" -workers="$WORKERS" -max_total_time="$TIME" \
        -max_len=4096 -timeout=10 -rss_limit_mb=2048 -dict="$(dict_for "$t")" \
        -print_final_stats=1 \
        -artifact_prefix="$WORK/findings/$t-" >"$WORK/run-$t/driver.log" 2>&1) || true

    if ls "$WORK/findings/$t-"* >/dev/null 2>&1; then
        echo "!!! fuzz_$t produced artifacts:"
        ls -l "$WORK/findings/$t-"*
        fail=1
    else
        # Fold the campaign's coverage back into the committed regression set.
        "$BUILD/tests/fuzz/fuzz_$t" -merge=1 \
            "$ROOT/tests/fuzz/corpus/$t" "$corp" \
            >"$WORK/run-$t/merge.log" 2>&1
    fi
    grep -h "stat::number_of_executed_units\|cov:" "$WORK/run-$t"/fuzz-*.log 2>/dev/null |
        tail -3 || true
done

if [ "$fail" -ne 0 ]; then
    echo "campaign: FINDINGS in $WORK/findings — triage, fix, add regression inputs"
    exit 1
fi
echo "campaign: clean; corpus updated in tests/fuzz/corpus/ ($(date))"
