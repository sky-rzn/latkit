# report.awk — turn runs.tsv (tests/bench/run.sh) into the Р49 report:
# per-series medians over the ABAB pairs, baseline deltas, spread, cores
# per 50k qps, and the v1.0 gate verdicts (ΔTPS < 3% on C/D, < 1 core at
# 50k qps). Invalid X runs (capture degraded) are excluded from medians
# and reported; a series with no valid X runs gets no verdict at all.
#
# Usage: awk -f report.awk runs.tsv

BEGIN { FS = "\t" }

NR == 1 { next }                    # header

{
    wl = $1; cfg = $2; role = $4; valid = $5
    key = wl SUBSEP cfg
    if (!(key in seen)) { seen[key] = 1; order[++ngroups] = key }

    if (role == "X" && valid != 1) { nbad[key]++; badwhy[key] = $17; next }

    n = ++cnt[key, role]
    tps[key, role, n]   = $6
    p50[key, role, n]   = $8
    p95[key, role, n]   = $9
    acore[key, role, n] = $12
    pgc[key, role, n]   = $13
    # Queries/s as the agent counted them ($16 = queries delta, $10 = wall):
    # the 50k normalisation base. tps would be wrong for TPC-B, where one
    # transaction is ~7 wire queries.
    qps[key, role, n]   = $10 > 0 ? $16 / $10 : 0
}

function median(arr, key, role,    n, i, j, t, v) {
    n = cnt[key, role]
    if (!n) return 0
    for (i = 1; i <= n; i++) v[i] = arr[key, role, i] + 0
    for (i = 1; i < n; i++)
        for (j = i + 1; j <= n; j++)
            if (v[j] < v[i]) { t = v[i]; v[i] = v[j]; v[j] = t }
    return n % 2 ? v[(n + 1) / 2] : (v[n / 2] + v[n / 2 + 1]) / 2
}

# (max - min) / median, % — the recorded spread of a series
function spread(arr, key, role,    n, i, lo, hi, x, m) {
    n = cnt[key, role]
    if (n < 2) return 0
    lo = hi = arr[key, role, 1] + 0
    for (i = 2; i <= n; i++) {
        x = arr[key, role, i] + 0
        if (x < lo) lo = x
        if (x > hi) hi = x
    }
    m = median(arr, key, role)
    return m ? (hi - lo) / m * 100 : 0
}

function line(    i) { for (i = 0; i < 118; i++) printf "-"; print "" }

END {
    printf "%-8s %-3s %-5s %10s %10s %7s %8s %8s %9s %9s %8s %9s %7s\n", \
        "workload", "cfg", "runs", "tps A", "tps X", "dTPS%", \
        "sprA%", "sprX%", "p50 A>X", "p95 A>X", "agent", "cores/50k", "pgSCPU"
    line()

    for (g = 1; g <= ngroups; g++) {
        key = order[g]
        split(key, k, SUBSEP); wl = k[1]; cfg = k[2]

        nx = cnt[key, "X"]; na = cnt[key, "A"]
        if (!nx) {
            printf "%-8s %-3s  -- no valid agent runs (%d invalid: %s) --\n", \
                wl, cfg, nbad[key], badwhy[key]
            fail[++nfail] = wl "/" cfg ": no valid runs (" badwhy[key] ")"
            continue
        }

        ta = median(tps, key, "A"); tx = median(tps, key, "X")
        dt = ta ? (ta - tx) / ta * 100 : 0
        ac = median(acore, key, "X")
        # Normalise per 50k QUERIES/s on the agent's own query count (equals
        # tps for select-only, ~7x tps for TPC-B); fall back to tps when the
        # config observes nothing (B: filter miss).
        qx = median(qps, key, "X")
        c50 = qx > 0 ? ac * 50000 / qx : (tx ? ac * 50000 / tx : 0)
        note = nbad[key] ? sprintf("  [%d invalid: %s]", nbad[key], badwhy[key]) : ""

        printf "%-8s %-3s %2d+%-2d %10.0f %10.0f %+6.2f%% %7.1f%% %7.1f%% %4.2f>%-4.2f %4.2f>%-4.2f %8.3f %9.3f %+6.2f%s\n", \
            wl, cfg, na, nx, ta, tx, dt, \
            spread(tps, key, "A"), spread(tps, key, "X"), \
            median(p50, key, "A"), median(p50, key, "X"), \
            median(p95, key, "A"), median(p95, key, "X"), \
            ac, c50, \
            median(pgc, key, "X") - median(pgc, key, "A"), note

        # v1.0 gates (Р49): only C and D are gated; B/E are diagnostics.
        if (cfg == "C" || cfg == "D") {
            if (dt >= 3)
                fail[++nfail] = sprintf("%s/%s: dTPS %.2f%% >= 3%%", wl, cfg, dt)
            if (c50 >= 1)
                fail[++nfail] = sprintf("%s/%s: %.3f cores/50k qps >= 1", wl, cfg, c50)
        }
    }

    line()
    print "tps/p50/p95/cores: medians; p50/p95 in ms; dTPS% = (A-X)/A;"
    print "spr% = (max-min)/median of tps; cores/50k = agent cores normalised"
    print "to 50k queries/s on the agent-counted qps (= tps for select-only,"
    print "~7x tps for TPC-B); pgSCPU = postgres-cgroup cores, X minus A"
    print "medians (does the agent offload cost onto the observed process?)."
    print ""
    if (nfail) {
        printf "GATE: FAIL (%d)\n", nfail
        for (i = 1; i <= nfail; i++) print "  - " fail[i]
        exit 1
    }
    print "GATE: PASS — dTPS(C), dTPS(D) < 3%; agent < 1 core / 50k qps"
}
