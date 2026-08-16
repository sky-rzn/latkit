#!/usr/bin/env python3
"""`INFO commandstats` against the wire: the measurement §2 of the plan rests on.

Redis already counts every command and reports an average execution time. The
claim of the Redis track is that this average answers a different question than
the one an application asks — it measures the command *inside* the server, after
the event loop got to it. This script measures both numbers at once, twice:

  * idle:    nothing else is running, so the difference is the network path and
             the syscalls;
  * blocked: one `DEBUG SLEEP` occupies the single event loop while the GETs are
             issued, so the difference is the queueing that `commandstats`
             cannot see and the application feels.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from resp import Conn, enc  # noqa: E402

N = int(os.environ.get("N", "2000"))


def cmdstat(c, name="get"):
    c.send(enc("INFO", "commandstats"))
    info = c.read(1)[0][1].decode("latin1")
    for line in info.split("\r\n"):
        if line.startswith("cmdstat_" + name + ":"):
            return line
    return "(no cmdstat_%s)" % name


def run(c, n, key="lk:cs:k"):
    t0 = time.time()
    for _ in range(n):
        c.send(enc("GET", key))
        c.read(1)
    return (time.time() - t0) / n * 1e6


def main():
    c = Conn(log=False)
    c.send(enc("SET", "lk:cs:k", "v"))
    c.read(1)

    c.send(enc("CONFIG", "RESETSTAT"))
    c.read(1)
    wire = run(c, N)
    print("idle, %d GETs on one connection:" % N)
    print("  wire (first byte out → last byte in): %8.2f us/call" % wire)
    print("  server (INFO commandstats):           %s" % cmdstat(c))

    slow = Conn(log=False)
    c.send(enc("CONFIG", "RESETSTAT"))
    c.read(1)
    slow.send(enc("DEBUG", "SLEEP", "0.2"))
    blocked = run(c, 50)
    slow.read(1)
    print()
    print("with one DEBUG SLEEP 0.2 on another connection, 50 GETs:")
    print("  wire:                                 %8.2f us/call" % blocked)
    print("  server (INFO commandstats):           %s" % cmdstat(c))
    print()
    print("The server is not wrong — the GET really did take under a microsecond")
    print("to execute. It is just not the number anybody is paged about.")
    slow.close()
    c.close()


if __name__ == "__main__":
    main()
