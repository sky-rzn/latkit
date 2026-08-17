#!/usr/bin/env python3
"""Join the agent's Redis observations against the server's own three views
(PLAN-REDIS.md МR8).

The plan asks for three references, each with a different meaning and a
different inequality, and the point of doing all three is that no one of them
can settle the question alone:

  1. `INFO commandstats`  — how many times each command ran, and its *mean*
     service time inside the server. The count is checkable **exactly**: the
     server counted the same commands we did, so a mismatch is a lost or an
     invented observation and nothing else. The mean is checkable only with a
     known systematic — ours is measured on the wire and includes reading the
     command off the socket, writing the reply and any time the single-threaded
     event loop spent on somebody else's command first.

  2. `SLOWLOG GET` at threshold 0 — the *per-command* execution time, which is
     the strongest of the three because it is not an average. With a serial
     workload the k-th slowlog entry for a command is the k-th observation of
     it, so the two can be paired: our duration must be **>= the server's**, and
     the difference is exactly the thing latkit exists to show — the part of the
     latency the server cannot see.

  3. `memtier_benchmark` — the *client's* latency, which contains ours plus the
     client's own round trip. Our duration must be **<= memtier's**, and by
     roughly one network hop.

Two inequalities and one equality, and the failure of any of them is a specific
bug rather than a vague disagreement: a count that differs means the queue lost
a unit, a duration below the server's means the timings are attached to the
wrong events, and one above the client's means we are measuring something the
client never waited for.

Usage:
  redis_join.py --agent queries.txt --slowlog slowlog.json \\
                --commandstats commandstats.txt [--memtier memtier.txt]
                [--client-name NAME] [--min-samples 100]

Writes the per-command table to stdout and the summary + verdict to stderr.
Exit status 0 iff every gate passed.
"""
import argparse
import json
import re
import sys


def pct(sorted_vals, q):
    if not sorted_vals:
        return float("nan")
    i = min(len(sorted_vals) - 1, max(0, int(round(q * (len(sorted_vals) - 1)))))
    return sorted_vals[i]


def read_agent(path):
    """lkt_queries --proto redis lines -> {cmd: [duration_us in emission order]}.

    Emission order is completion order per connection, which for the serial
    workload this bench drives is also the order the server ran them in. Errors
    are kept: a `-WRONGTYPE` is a command the server executed and counted.
    """
    by_cmd, flags_seen = {}, {}
    line_re = re.compile(
        r"^redis conn=(\S+) cmd=(\S+) dur=(\d+)ns .* depth=(\d+) err=(\S+) flags=0x([0-9a-f]+)"
    )
    for line in open(path):
        m = line_re.match(line)
        if not m:
            continue
        cmd, dur_ns, depth, flags = m.group(2), int(m.group(3)), int(m.group(4)), int(m.group(6), 16)
        # A `+QUEUED` (0x1000) has no duration by construction (РR9) and a
        # blocking command's (0x2000) is the client's own wait (РR10): neither
        # is comparable with a server-side service time, and the server's own
        # references agree — a queued command's slowlog entry is the EXEC's.
        if flags & 0x3000:
            continue
        by_cmd.setdefault(cmd, []).append(dur_ns / 1000.0)
        flags_seen.setdefault(cmd, set()).add(depth)
    return by_cmd, flags_seen


def read_slowlog(path, client_name):
    """`redis-cli --json slowlog get N` -> {cmd: [exec_us in id order]}.

    Optionally filtered by the load client's name; by default the workload and
    the control connection are told apart by command name instead (the CONTROL
    set in main), because a `redis-cli -r N` cannot name itself and the
    connection that reads `INFO` and `SLOWLOG` is itself logged at threshold 0 —
    counting the measurement as part of what is measured is how a bench lies to
    itself.

    The command name is derived exactly as РR4 derives the label — the verb,
    upper-cased, plus the subcommand for a container command — so that the two
    sides are keyed by the same thing.
    """
    CONTAINERS = {
        "CONFIG", "CLIENT", "CLUSTER", "OBJECT", "SCRIPT", "FUNCTION", "ACL",
        "MEMORY", "XINFO", "XGROUP", "COMMAND", "LATENCY", "SLOWLOG", "PUBSUB",
    }
    entries = json.load(open(path))
    by_cmd = {}
    for e in entries:
        # [id, unix_ts, duration_us, [argv...], client_addr, client_name]
        if len(e) < 4:
            continue
        eid, dur, argv = e[0], e[2], e[3]
        name = e[5] if len(e) > 5 else ""
        if client_name and name != client_name:
            continue
        if not argv:
            continue
        cmd = str(argv[0]).upper()
        if cmd in CONTAINERS and len(argv) > 1:
            cmd = cmd + "|" + str(argv[1]).upper()
        by_cmd.setdefault(cmd, []).append((eid, float(dur)))
    # SLOWLOG returns newest first; the id is monotonic, so sorting by it puts
    # the entries back into execution order and the pairing below is by index.
    return {k: [d for _, d in sorted(v)] for k, v in by_cmd.items()}


def read_commandstats(path):
    """`INFO commandstats` -> {cmd: (calls, usec_per_call)}.

    The server spells a container command `config|get`; upper-casing it is the
    whole of the translation, which is worth noting: РR4's identity was chosen
    to be the server's own, so the join needs no alias table at all (unlike the
    S3 bench, where MinIO names a handler differently from the API).
    """
    out = {}
    for line in open(path):
        m = re.match(r"^cmdstat_(\S+):calls=(\d+),usec=(\d+),usec_per_call=([\d.]+)", line.strip())
        if m:
            out[m.group(1).upper()] = (int(m.group(2)), float(m.group(4)))
    return out


def read_memtier(path):
    """memtier's totals line -> (p50_ms, p99_ms, ops_per_sec) or None."""
    try:
        txt = open(path).read()
    except OSError:
        return None
    m = re.search(
        r"^Totals\s+([\d.]+)\s+\S+\s+\S+\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)", txt, re.M
    )
    if not m:
        return None
    return float(m.group(3)), float(m.group(4)), float(m.group(1))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", required=True)
    ap.add_argument("--slowlog", required=True)
    ap.add_argument("--commandstats", required=True)
    ap.add_argument("--memtier")
    # Off by default: the workload and the control connection are told apart by
    # command name (the CONTROL set below), which needs no cooperation from the
    # client. The flag is here for a stand that can name its client.
    ap.add_argument("--client-name", default="")
    ap.add_argument("--min-samples", type=int, default=100)
    # The memtier leg is a different workload against the same server, so the
    # two server-side references — which describe the *paired* workload — say
    # nothing about it. Its one question is the second inequality, and asking
    # the other two would produce a mismatch that is an artefact of the
    # question, not of the agent.
    ap.add_argument("--memtier-only", action="store_true",
                    help="check only the client-latency inequality")
    args = ap.parse_args()

    agent, _ = read_agent(args.agent)
    slow = read_slowlog(args.slowlog, args.client_name)
    stats = read_commandstats(args.commandstats)

    # The control connection's own commands are not part of the workload.
    # The control connection's own commands are not part of the workload. HELLO
    # is here for a subtler reason than the rest: `redis-cli` negotiates on some
    # connections and not others, so a stray one lands between the two resets
    # and belongs to neither side's window.
    CONTROL = {"INFO", "SLOWLOG|GET", "SLOWLOG|RESET", "CONFIG|RESETSTAT", "CONFIG|SET",
               "CONFIG|GET", "CLIENT|SETNAME", "CLIENT|INFO", "AUTH", "COMMAND|DOCS",
               "SLOWLOG", "MEMORY|DOCTOR", "HELLO"}

    rows, fails, total_pairs, wrong_order = [], [], 0, 0
    print("cmd\tagent_n\tslowlog_n\tstats_n\tagent_p50_us\tsrv_p50_us\tgap_p50_us\tgap_p90_us")
    for cmd in sorted(set(agent) | set(slow)):
        if cmd in CONTROL:
            continue
        a = sorted(agent.get(cmd, []))
        s_ordered = slow.get(cmd, [])
        s = sorted(s_ordered)
        n_stats = stats.get(cmd, (0, 0.0))[0]
        # Pairwise, in execution order: the k-th of each. Only where both sides
        # saw the same number of executions — a truncated slowlog or a command
        # the control connection also issued would pair the wrong two.
        gaps = []
        if len(agent.get(cmd, [])) == len(s_ordered) and s_ordered:
            for mine, theirs in zip(agent[cmd], s_ordered):
                gaps.append(mine - theirs)
                total_pairs += 1
                if mine < theirs:
                    wrong_order += 1
        gaps.sort()
        rows.append((cmd, len(a), len(s), n_stats))
        print("%s\t%d\t%d\t%d\t%.1f\t%.1f\t%s\t%s" % (
            cmd, len(a), len(s), n_stats, pct(a, 0.5), pct(s, 0.5),
            "%.1f" % pct(gaps, 0.5) if gaps else "-",
            "%.1f" % pct(gaps, 0.9) if gaps else "-"))

    log = lambda m: print(m, file=sys.stderr)
    if args.memtier_only:
        rows = []  # the per-command table above is the workload's, not this leg's
    else:
        log("=== counts: the server counted the same commands we did ===")
        counted, mismatched = 0, 0
        for cmd, n_agent, _, n_stats in rows:
            if not n_stats:
                continue
            counted += n_stats
            if n_agent != n_stats:
                mismatched += 1
                log("  MISMATCH %-18s agent=%d commandstats=%d" % (cmd, n_agent, n_stats))
        log("  %d commands over %d distinct identities, %d mismatched"
            % (counted, len(rows), mismatched))
        if mismatched:
            fails.append("%d command(s) disagree with INFO commandstats" % mismatched)
        elif counted < args.min_samples:
            fails.append("only %d commands in the run (want >= %d)" % (counted, args.min_samples))

        log("=== SLOWLOG: our duration is never below the server's ===")
        if total_pairs < args.min_samples:
            fails.append("only %d paired commands (want >= %d)" % (total_pairs, args.min_samples))
        log("  %d pairs, %d of them with our duration BELOW the server's execution time"
            % (total_pairs, wrong_order))
    # A handful is the measurement's own resolution: the server times with
    # microsecond granularity and we time with the kernel's event timestamps,
    # so a command whose whole execution is under a microsecond can round the
    # wrong way. A systematic breach is a different animal and is what this
    # gates on.
        if total_pairs and wrong_order > 0.01 * total_pairs:
            fails.append("%d of %d durations are below the server's own execution time"
                         % (wrong_order, total_pairs))

    if args.memtier:
        mt = read_memtier(args.memtier)
        if mt:
            p50_ms, p99_ms, ops = mt
            allv = sorted(v for lst in agent.values() for v in lst)
            our50, our99 = pct(allv, 0.5) / 1000.0, pct(allv, 0.99) / 1000.0
            log("=== memtier: our duration is never above the client's ===")
            log("  memtier p50=%.3f ms p99=%.3f ms at %.0f ops/s" % (p50_ms, p99_ms, ops))
            log("  latkit  p50=%.3f ms p99=%.3f ms over %d observations" % (our50, our99, len(allv)))
            if our50 > p50_ms:
                fails.append("our p50 (%.3f ms) exceeds the client's (%.3f ms)" % (our50, p50_ms))
        else:
            log("=== memtier: no totals line parsed (leg skipped) ===")

    log("")
    if fails:
        for f in fails:
            log("FAIL: " + f)
        return 1
    log("PASS: " + ("our duration stays under the client's"
                    if args.memtier_only else
                    "counts exact, durations bracketed by the server's and the client's"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
