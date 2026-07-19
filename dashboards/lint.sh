#!/usr/bin/env bash
# dashboards/lint.sh — structural + nomenclature lint for the four latkit
# dashboards (Р42). Runs in CI (job dashboards-lint) with only jq installed:
# no build, no root, no BPF.
#
# Checks, per dashboards/latkit-*.json:
#   1. valid JSON;
#   2. .uid equals the file basename (stable cross-links / provisioning);
#   3. no __inputs / __requires — dashboards ship as-is, not as "for sharing"
#      exports with datasource placeholders;
#   4. datasource is the $datasource template variable everywhere — a
#      datasource template var exists, and every panel/target/annotation that
#      names a datasource points at ${datasource} (no hardcoded uid);
#   5. every rate()/_bucket window is $__rate_interval, never a literal [30s];
#   6. no unbounded query fan-out: an expr that groups `by (... query ...)`
#      must be bounded by topk(...) or filtered to a single query=~"$query";
#   7. every metric named in any PromQL expr (targets, annotations, template
#      label_values) exists in the agent's metric nomenclature — the set of
#      metric-name string literals in src/. Rename a metric in the code and
#      this goes red until the dashboards are re-exported.
#
# Exit non-zero on the first category with findings (all findings printed).
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
fail=0
err() { printf '  FAIL: %s\n' "$*" >&2; fail=1; }

command -v jq >/dev/null || { echo "lint.sh needs jq" >&2; exit 2; }

# --- nomenclature: metric-name string literals emitted by the agent ---------
# (registry families, self-metric setters, LK_*_METRIC macro values, process_*).
nomen="$(grep -rhoE '"(latkit|process)_[a-z0-9_]+"' "$root/src" \
            --include='*.c' --include='*.h' | tr -d '"' | sort -u)"
if [ -z "$nomen" ]; then
    echo "lint.sh: empty metric nomenclature from $root/src — refusing to pass" >&2
    exit 2
fi
# Histogram/summary families gain _bucket/_sum/_count suffixes in exprs; fold
# them back to the base family before the membership test.
in_nomen() {
    local m="$1"
    m="${m%_bucket}"; m="${m%_sum}"; m="${m%_count}"
    grep -qxF "$m" <<<"$nomen"
}

# jq filter: emit every PromQL expr string in a dashboard (targets, annotations,
# and template label_values definitions), one per line.
JQ_EXPRS='
  [ (.. | objects | select(has("expr")) | .expr)
  , (.templating.list[]? | .definition // empty)
  ] | .[]'

# jq filter: emit every datasource reference (as compact JSON) anywhere.
JQ_DS='.. | objects | select(has("datasource")) | .datasource'

shopt -s nullglob
files=("$here"/latkit-*.json)
[ ${#files[@]} -eq 4 ] || err "expected 4 dashboards, found ${#files[@]}"

for f in "${files[@]}"; do
    base="$(basename "$f" .json)"
    echo "== $base"

    if ! jq empty "$f" 2>/dev/null; then
        err "$base: invalid JSON"; continue
    fi

    uid="$(jq -r '.uid // empty' "$f")"
    [ "$uid" = "$base" ] || err "$base: .uid='$uid' must equal file basename"

    if jq -e 'has("__inputs") or has("__requires")' "$f" >/dev/null; then
        err "$base: exported with __inputs/__requires (share-export) — provision as-is"
    fi

    # datasource template variable present?
    if ! jq -e '[.templating.list[]? | select(.type=="datasource" and .name=="datasource")] | length > 0' \
            "$f" >/dev/null; then
        err "$base: missing \$datasource template variable"
    fi
    # proto template variable present (РМ6/М6): every dashboard filters by
    # protocol so pg / mysql query spaces never blur together.
    if ! jq -e '[.templating.list[]? | select(.name=="proto")] | length > 0' \
            "$f" >/dev/null; then
        err "$base: missing \$proto template variable (РМ6)"
    fi
    # every datasource reference must be the variable (string form or {uid:${datasource}}),
    # or the built-in grafana datasource used by the default annotation.
    while IFS= read -r ds; do
        case "$ds" in
            *'${datasource}'*) : ;;                 # {"uid":"${datasource}", ...}
            '"${datasource}"') : ;;                 # bare string form
            *'"-- Grafana --"'*|*'"grafana"'*) : ;; # built-in annotation ds
            *) err "$base: hardcoded datasource $ds (must be \${datasource})" ;;
        esac
    done < <(jq -c "$JQ_DS" "$f")

    # exprs: rate window, cardinality, nomenclature
    while IFS= read -r expr; do
        [ -z "$expr" ] && continue

        # 5. no literal rate windows — always $__rate_interval
        if grep -qE '\[[0-9]+[smhdwy]' <<<"$expr"; then
            err "$base: literal rate window in: $expr"
        fi

        # 6. unbounded query fan-out
        if grep -qE 'by \([^)]*query' <<<"$expr"; then
            if ! grep -qE 'topk\(|query=~' <<<"$expr"; then
                err "$base: 'by (query)' not bounded by topk()/query=~: $expr"
            fi
        fi

        # 7. nomenclature
        while IFS= read -r m; do
            [ -z "$m" ] && continue
            in_nomen "$m" || err "$base: unknown metric '$m' in: $expr"
        done < <(grep -oE '(latkit|process)_[a-z0-9_]+' <<<"$expr" | sort -u)
    done < <(jq -r "$JQ_EXPRS" "$f")
done

if [ "$fail" -ne 0 ]; then
    echo "dashboards/lint.sh: FAILED" >&2
    exit 1
fi
echo "dashboards/lint.sh: OK (${#files[@]} dashboards)"
