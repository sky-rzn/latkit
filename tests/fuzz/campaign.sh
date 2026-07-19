#!/usr/bin/env bash
# Fuzzing campaign runner (task 8.3, Р51): the ≥24-CPU-hour local campaign and
# the corpus maintenance around it. CI does NOT run this — it runs the corpus
# regression (ctest) and short budgeted fuzzing directly (see ci.yml); this
# script is for the overnight stand run and for reproducing it.
#
#   tests/fuzz/campaign.sh [seconds-per-target] [workers]
#
# Defaults: 1800 s/target, nproc-1 workers => 3 * 1800 * 21 / 3600 = 31.5
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
# capability bytes); pg.dict covers the pg framer, the norm SQL fragments and
# the pipe scenarios well enough.
dict_for() {
    case "$1" in
    my) echo "$ROOT/tests/fuzz/dict/my.dict" ;;
    *) echo "$ROOT/tests/fuzz/dict/pg.dict" ;;
    esac
}

# Stand trap: with DEBUGINFOD_URLS set, llvm-symbolizer stalls ~90 s per query
# on the network — every NEW_FUNC line would freeze a worker. Never useful here;
# crash artifacts can be symbolised offline.
export DEBUGINFOD_URLS=

if [ ! -x "$BUILD/tests/fuzz/fuzz_pg" ]; then
    cmake -B "$BUILD" -DCMAKE_C_COMPILER=clang -DLATKIT_FUZZ=ON
    cmake --build "$BUILD" --target fuzz_pg fuzz_my fuzz_norm fuzz_pipe gen_seeds -j"$(nproc)"
fi

mkdir -p "$WORK/findings" "$WORK/seed"/{pg,my,norm,pipe}
"$BUILD/tests/fuzz/gen_seeds" "$WORK/seed" >/dev/null

echo "campaign: $TIME s/target x $WORKERS workers x 4 targets" \
     "= $(((4 * TIME * WORKERS + 1800) / 3600)) CPU-hours; workdir $WORK"

fail=0
for t in pg my norm pipe; do
    corp="$WORK/corpus-$t"
    mkdir -p "$corp"
    cp "$ROOT/tests/fuzz/corpus/$t"/* "$WORK/seed/$t"/* "$corp"/ 2>/dev/null || true
    # The .lkt traces double as raw framer seeds for their protocol.
    [ "$t" = pg ] && cp "$ROOT"/tests/fixtures/*.lkt "$corp"/
    [ "$t" = my ] && cp "$ROOT"/tests/traces/mysql/*/*.lkt "$corp"/ 2>/dev/null || true

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
