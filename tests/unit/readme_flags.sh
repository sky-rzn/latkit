#!/bin/sh
# README ↔ binary consistency (Р44, STAGE7.md task 7.6): the README's
# configuration tables are a product surface and must not drift from the
# agent. Asserts two set equalities:
#
#   1. flags:  every long option `--help` advertises appears as a flag cell
#      in a README table, and no README table names a flag the binary lacks;
#   2. env:    the LATKIT_* variables named in main.c (the env layer, Р34)
#      and in the README are the same set.
#
# Needs no privileges — `--help` exits before any BPF work.
#
# Usage: readme_flags.sh /path/to/latkit /path/to/README.md /path/to/main.c
set -eu

LATKIT="${1:?usage: readme_flags.sh <latkit> <README.md> <main.c>}"
README="${2:?usage: readme_flags.sh <latkit> <README.md> <main.c>}"
MAIN_C="${3:?usage: readme_flags.sh <latkit> <README.md> <main.c>}"
fails=0

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Option lines in the usage text are indented 2 ("-p, --port") or 6 ("--tls")
# spaces; continuation lines are indented past that, so the anchor skips them.
"$LATKIT" --help \
    | grep -oE '^ {2,6}(-[a-zA-Z], )?--[a-z][a-z0-9-]*' \
    | grep -oE '\-\-[a-z][a-z0-9-]*' | sort -u > "$tmp/help"

# First cell of every README table row. Flag mentions elsewhere in a first
# cell (e.g. the capabilities table) only re-assert flags that must exist.
awk -F'|' '/^\|/ { print $2 }' "$README" \
    | grep -oE '\-\-[a-z][a-z0-9-]*' | sort -u > "$tmp/readme"

if cmp -s "$tmp/help" "$tmp/readme"; then
    echo "ok   - flag sets match ($(wc -l < "$tmp/help") flags)"
else
    echo "FAIL - README tables vs --help ('<' only in --help, '>' only in README):"
    diff "$tmp/help" "$tmp/readme" | grep '^[<>]' || true
    fails=$((fails + 1))
fi

# The env side. main.c is the single place every LATKIT_* variable is named
# (the env table, the OTLP fallbacks, LATKIT_DUMP_METRICS).
grep -oE 'LATKIT_[A-Z][A-Z0-9_]*' "$MAIN_C" | sort -u > "$tmp/env_src"
# `-DLATKIT_*` are CMake cache options, not the env layer — drop them first.
sed 's/-D[A-Z0-9_]*//g' "$README" \
    | grep -oE 'LATKIT_[A-Z][A-Z0-9_]*' | sort -u > "$tmp/env_readme"

if cmp -s "$tmp/env_src" "$tmp/env_readme"; then
    echo "ok   - LATKIT_* env sets match ($(wc -l < "$tmp/env_src") variables)"
else
    echo "FAIL - main.c vs README LATKIT_* ('<' only in main.c, '>' only in README):"
    diff "$tmp/env_src" "$tmp/env_readme" | grep '^[<>]' || true
    fails=$((fails + 1))
fi

echo "---"
if [ "$fails" -eq 0 ]; then
    echo "README is in sync with the binary"
    exit 0
fi
echo "$fails README consistency check(s) failed"
exit 1
