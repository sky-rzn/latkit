#!/usr/bin/env python3
"""The МR0 scenario driver: RESP over raw sockets.

A client library is a bad instrument for a corpus. It hides the wire (it will
not send an inline command, a torn bulk, a pipeline of exactly three, or a
`HELLO 4`), it retries, and it decides on its own when to flush. This driver
sends bytes and reads bytes, so every trace is exactly the exchange its name
says it is.

  REDIS_HOST/REDIS_PORT select the stand (default 127.0.0.1:6399).

  python3 raw.py <scenario> [args…]
  python3 raw.py --list
"""
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from resp import Conn, Decoder, brief, enc, inline, say  # noqa: E402

SCENARIOS = {}


def scenario(fn):
    SCENARIOS[fn.__name__.replace("_", "-")] = fn
    return fn


def conn(**kw):
    return Conn(**kw)


def drain(c, wait=0.5, label="tail"):
    """Read whatever the server sends without expecting a count (pushes, MONITOR)."""
    c.sock.settimeout(wait)
    got = []
    try:
        while True:
            chunk = c.sock.recv(65536)
            if not chunk:
                break
            c.dec.feed(chunk)
            while True:
                v = c.dec.value()
                if v is None:
                    break
                got.append(v)
    except (socket.timeout, OSError):
        pass
    c.sock.settimeout(20.0)
    for v in got:
        say("  %-46s <- %s" % ("(" + label + ")", brief(v)))
    return got


# --- the shapes of the protocol ---------------------------------------------

@scenario
def basic():
    """The base case: the twenty commands every application actually runs."""
    c = conn()
    c.do("SET", "lk:k", "hello")
    c.do("GET", "lk:k")
    c.do("SET", "lk:k", "hello", "EX", "60")
    c.do("TTL", "lk:k")
    c.do("TYPE", "lk:k")
    c.do("INCR", "lk:n")
    c.do("INCRBY", "lk:n", "41")
    c.do("HSET", "lk:h", "a", "1", "b", "2")
    c.do("HGETALL", "lk:h")
    c.do("RPUSH", "lk:l", "a", "b", "c")
    c.do("LRANGE", "lk:l", "0", "-1")
    c.do("SADD", "lk:s", "x", "y")
    c.do("SMEMBERS", "lk:s")
    c.do("ZADD", "lk:z", "1.5", "one")
    c.do("ZSCORE", "lk:z", "one")
    c.do("GET", "lk:missing")
    c.do("EXISTS", "lk:k")
    c.do("DEL", "lk:k")
    c.do("PING")
    c.do("ECHO", "round trip")
    c.close()


@scenario
def types():
    """Every RESP2 reply type, from the one command that produces them on demand."""
    c = conn()
    for t in ("string", "integer", "double", "bignum", "null", "array", "set",
              "map", "attrib", "verbatim", "true", "false", "err"):
        c.do("DEBUG", "PROTOCOL", t)
    # …and the same types as real commands produce them.
    c.do("SET", "lk:t:s", "v")            # +OK        simple string
    c.do("GET", "lk:t:s")                 # $          bulk
    c.do("STRLEN", "lk:t:s")              # :          integer
    c.do("GET", "lk:t:missing")           # $-1        null bulk
    c.do("BLPOP", "lk:t:nolist", "0.05")  # *-1        null array
    c.do("HGETALL", "lk:t:missing")       # *0         empty array
    c.do("LPUSH", "lk:t:s", "x")          # -WRONGTYPE error
    c.close()


@scenario
def types3():
    """RESP3: the seven types RESP2 does not have, plus an attribute and a push."""
    c = conn()
    c.do("HELLO", "3")
    for t in ("string", "integer", "double", "bignum", "null", "array", "set",
              "map", "verbatim", "true", "false"):
        c.do("DEBUG", "PROTOCOL", t)
    # An attribute is a *prefix*, not a reply: two values arrive, and only the
    # second one answers the command (РR3 — an attribute must not close a unit).
    c.do("DEBUG", "PROTOCOL", "attrib", nreplies=2)
    # A push out of nowhere, on a connection that is not subscribed to anything.
    c.do("DEBUG", "PROTOCOL", "push", nreplies=2)
    c.do("GET", "lk:t:missing")           # _          RESP3 null
    c.do("HGETALL", "lk:t:missing")       # %0         empty map
    c.do("SMEMBERS", "lk:t:missing")      # ~0         empty set
    c.do("CONFIG", "GET", "maxmemory")    # %1         map
    c.do("HELLO", "2")                    # back down: the reply itself is RESP2
    c.do("GET", "lk:t:missing")           # $-1        null bulk again
    c.close()


@scenario
def bigvalue(size=1048576):
    """One megabyte through a bulk: the arithmetic body skip, both directions."""
    size = int(size)
    c = conn()
    c.send(enc("SET", "lk:big", b"x" * size))
    say("  SET lk:big (%d bytes) -> %s" % (size, brief(c.read(1)[0])))
    c.do("STRLEN", "lk:big")
    c.send(enc("GET", "lk:big"))
    v = c.read(1)[0]
    say("  GET lk:big -> $(%d)" % len(v[1]))
    c.do("DEL", "lk:big")
    c.close()


@scenario
def mget100():
    """A hundred keys in one command and a hundred bulks in one reply."""
    c = conn()
    keys = ["lk:m:%03d" % i for i in range(100)]
    c.send(enc("MSET", *sum(([k, "v" + k] for k in keys), [])))
    say("  MSET ×100 -> %s" % brief(c.read(1)[0]))
    c.send(enc("MGET", *keys))
    say("  MGET ×100 -> %s" % brief(c.read(1)[0]))
    c.send(enc("DEL", *keys))
    c.read(1)
    c.close()


@scenario
def pipeline100():
    """A hundred commands in one write(2): the normal mode of every pooled client."""
    c = conn()
    batch = b"".join(enc("SET", "lk:p:%03d" % i, "v%d" % i) for i in range(100))
    c.send(batch)
    vs = c.read(100)
    say("  100 SET in one write -> %d replies, first %s" % (len(vs), brief(vs[0])))
    batch = b"".join(enc("GET", "lk:p:%03d" % i) for i in range(100))
    c.send(batch)
    say("  100 GET in one write -> %d replies" % len(c.read(100)))
    c.close()


@scenario
def pipeline_depths():
    """Batches of 1, 2, 3, 10, 50 — the depth histogram's whole range in one trace."""
    c = conn()
    for depth in (1, 2, 3, 10, 50):
        c.send(b"".join(enc("GET", "lk:p:%03d" % i) for i in range(depth)))
        say("  batch of %-2d -> %d replies" % (depth, len(c.read(depth))))
        time.sleep(0.05)
    c.close()


@scenario
def multi():
    """MULTI/EXEC in every ending: commit, discard, abort, a runtime error,
    a nested MULTI, and a transaction abandoned by a closing connection."""
    c = conn()
    c.do("MULTI")
    c.do("SET", "lk:t:a", "1")            # +QUEUED in microseconds: not a latency
    c.do("INCR", "lk:t:n")
    c.do("GET", "lk:t:a")
    c.do("EXEC")                          # the only reply that means work
    say("  --- discard")
    c.do("MULTI")
    c.do("SET", "lk:t:b", "2")
    c.do("DISCARD")
    say("  --- abort: a queue-time error poisons the transaction")
    c.do("MULTI")
    c.do("NOSUCHCOMMAND")                 # -ERR at queue time
    c.do("SET", "lk:t:c", "3")
    c.do("EXEC")                          # -EXECABORT
    say("  --- runtime error inside EXEC: the transaction still commits")
    c.do("SET", "lk:t:str", "v")
    c.do("MULTI")
    c.do("LPUSH", "lk:t:str", "x")        # queues fine, fails at exec time
    c.do("SET", "lk:t:d", "4")
    c.do("EXEC")                          # *2 with an error inside
    say("  --- nested MULTI")
    c.do("MULTI")
    c.do("MULTI")                         # -ERR MULTI calls can not be nested
    c.do("EXEC")
    say("  --- WATCH/UNWATCH")
    c.do("WATCH", "lk:t:a")
    c.do("MULTI")
    c.do("GET", "lk:t:a")
    c.do("EXEC")
    say("  --- abandoned: MULTI and then the connection goes away")
    c.do("MULTI")
    c.do("SET", "lk:t:e", "5")
    c.close()


@scenario
def watch_abort():
    """A transaction the server refuses because a watched key moved: EXEC → nil."""
    c = conn()
    other = conn(log=False)
    c.do("SET", "lk:w", "1")
    c.do("WATCH", "lk:w")
    c.do("MULTI")
    c.do("INCR", "lk:w")
    other.do("SET", "lk:w", "99")         # somebody else touches the watched key
    c.do("EXEC")                          # *-1 / _ — aborted, and not an error
    other.close()
    c.close()


@scenario
def eval_scripts():
    """Scripts: EVAL, SCRIPT LOAD, an EVALSHA that hits and one that does not."""
    c = conn()
    script = "return redis.call('SET', KEYS[1], ARGV[1])"
    c.do("EVAL", script, "1", "lk:e:k", "v")
    sha = c.do("SCRIPT", "LOAD", script)[1].decode()
    c.do("EVALSHA", sha, "1", "lk:e:k", "v2")
    c.do("EVALSHA", "f" * 40, "0")        # -NOSCRIPT
    c.do("EVAL", "return {1,2,{3,'four'}}", "0")
    c.do("EVAL", "return redis.error_reply('CUSTOMERR something')", "0")
    c.do("SCRIPT", "EXISTS", sha, "f" * 40)
    c.do("FUNCTION", "LIST")
    c.close()


@scenario
def pubsub():
    """RESP2 subscription: the reply to SUBSCRIBE and a message are the same shape."""
    c = conn()
    c.do("SUBSCRIBE", "lk:chan", nreplies=1)   # one confirmation per channel
    c.do("SUBSCRIBE", "lk:chan2", "lk:chan3", nreplies=2)
    pub = conn(log=False)
    for i in range(3):
        pub.do("PUBLISH", "lk:chan", "message %d" % i)
    drain(c, 0.6, "push")
    # The four commands a subscribed RESP2 connection may still issue.
    c.do("PING")
    c.do("GET", "lk:k")                        # -ERR: not allowed in this context
    c.do("UNSUBSCRIBE", "lk:chan2", nreplies=1)
    c.do("SSUBSCRIBE", "lk:shard")             # RESP2 shard channels exist too
    pub.do("SPUBLISH", "lk:shard", "shard message")
    drain(c, 0.4, "push")
    c.do("RESET")
    c.do("GET", "lk:k")                        # allowed again
    pub.close()
    c.close()


@scenario
def pubsub3():
    """RESP3: a push is a type, not a shape — and ordinary commands keep working."""
    c = conn()
    c.do("HELLO", "3")
    c.do("SUBSCRIBE", "lk:chan", nreplies=1)
    # The distinguishing property of RESP3: while subscribed, the connection is
    # still a normal client.
    c.do("GET", "lk:k")
    c.do("SET", "lk:k", "while-subscribed")
    pub = conn(log=False)
    for i in range(3):
        pub.do("PUBLISH", "lk:chan", "message %d" % i)
    drain(c, 0.6, "push")
    c.do("PING")
    c.do("UNSUBSCRIBE", "lk:chan", nreplies=1)
    pub.close()
    c.close()


@scenario
def tracking():
    """RESP3 client-side caching: an invalidation push nobody asked for (РR8)."""
    c = conn()
    c.do("HELLO", "3")
    c.do("CLIENT", "TRACKING", "ON")
    c.do("SET", "lk:track", "1")
    c.do("GET", "lk:track")               # now the key is tracked
    other = conn(log=False)
    other.do("SET", "lk:track", "2")      # …and this invalidates it
    drain(c, 0.6, "invalidate")
    c.do("CLIENT", "TRACKING", "OFF")
    other.close()
    c.close()


@scenario
def blocking():
    """BLPOP by timeout, BLPOP by event, XREAD BLOCK: latency that is not the server's."""
    c = conn()
    t0 = time.time()
    c.do("BLPOP", "lk:bl", "1")           # *-1 after a whole second of nothing
    say("  (waited %.2fs — the client chose that, not the server)" % (time.time() - t0))

    def push_later():
        time.sleep(0.5)
        p = conn(log=False)
        p.do("RPUSH", "lk:bl", "woken")
        p.close()
    threading.Thread(target=push_later).start()
    t0 = time.time()
    c.do("BLPOP", "lk:bl", "5")
    say("  (waited %.2fs — the event decided)" % (time.time() - t0))
    c.do("XADD", "lk:stream", "*", "f", "v")
    c.do("XREAD", "COUNT", "10", "STREAMS", "lk:stream", "0")        # not blocking
    c.do("XREAD", "BLOCK", "300", "STREAMS", "lk:stream", "$")       # blocking
    c.do("BLMPOP", "0.3", "1", "lk:bl", "LEFT")
    c.do("WAIT", "0", "100")
    c.close()


@scenario
def scan():
    """A SCAN loop: N round trips, a cursor, and nothing blocking."""
    c = conn()
    c.send(enc("MSET", *sum(([("lk:sc:%03d" % i), "v"] for i in range(200)), [])))
    c.read(1)
    cursor, calls = "0", 0
    while True:
        v = c.do("SCAN", cursor, "MATCH", "lk:sc:*", "COUNT", "20")
        cursor = v[1][0][1].decode()
        calls += 1
        if cursor == "0" or calls > 50:
            break
    say("  SCAN loop finished in %d calls" % calls)
    c.do("HSET", "lk:sc:h", "f1", "1", "f2", "2")
    c.do("HSCAN", "lk:sc:h", "0")
    c.close()


@scenario
def keys_big(count=1000000):
    """KEYS * over a million keys: one command, one reply, tens of megabytes.

    The reason a Redis port needs a small capture budget (РR13) and the shape
    the plan's risk 1 is about: an aggregate whose length is a count, not bytes.
    """
    count = int(count)
    c = conn()
    c.do("SELECT", "9")
    c.do("FLUSHDB")
    c.do("DEBUG", "POPULATE", str(count))
    c.do("DBSIZE")
    t0 = time.time()
    c.send(enc("KEYS", "*"))
    v = c.read(1)[0]
    say("  KEYS * -> array of %d in %.2fs" % (len(v[1]), time.time() - t0))
    c.do("FLUSHDB")
    c.close()


@scenario
def errors():
    """The error dictionary, one symbol at a time (РR7)."""
    c = conn()
    c.do("SET", "lk:str", "v")
    c.do("LPUSH", "lk:str", "x")                     # WRONGTYPE
    c.do("NOSUCHCOMMAND", "a", "b")                  # ERR unknown command
    c.do("GET")                                      # ERR wrong number of arguments
    c.do("EVALSHA", "f" * 40, "0")                   # NOSCRIPT
    c.do("EXPIRE", "lk:str", "abc")                  # ERR not an integer
    c.do("SETRANGE", "lk:str", "-1", "x")            # ERR offset out of range
    c.do("XGROUP", "CREATE", "lk:nostream", "g", "$")  # ERR no such key
    c.do("XADD", "lk:str", "*", "f", "v")            # WRONGTYPE
    c.do("SUBSCRIBE")                                # ERR wrong number of arguments
    c.do("EXEC")                                     # ERR EXEC without MULTI
    c.do("HELLO", "4")                               # NOPROTO
    c.do("AUTH", "nobody", "nothing")                # WRONGPASS
    c.do("SELECT", "99")                             # ERR DB index is out of range
    c.do("LPOP", "lk:str", "-1")                     # ERR value is out of range
    c.do("GETRANGE")                                 # ERR arity
    c.do("INCR", "lk:str")                           # ERR not an integer
    c.close()


@scenario
def acl_errors():
    """NOPERM and NOAUTH: an ACL user who is allowed almost nothing."""
    admin = conn(log=False)
    admin.do("ACL", "SETUSER", "lkreader", "on", ">lkpass", "~lk:*", "+get", "+ping",
             "+auth", "+hello", "+reset")
    admin.close()
    c = conn()
    c.do("AUTH", "lkreader", "lkpass")
    c.do("GET", "lk:str")                            # allowed
    c.do("SET", "lk:str", "v")                       # NOPERM this user has no perms
    c.do("GET", "other:key")                         # NOPERM keys
    c.do("ACL", "WHOAMI")                            # NOPERM command
    c.do("RESET")
    c.close()
    # …and a server that requires a password at all: NOAUTH before anything.
    admin = conn(log=False)
    admin.do("CONFIG", "SET", "requirepass", "lkrootpass")
    admin.close()
    c = conn()
    c.do("GET", "lk:str")                            # NOAUTH
    c.do("AUTH", "wrong")                            # WRONGPASS
    c.do("AUTH", "lkrootpass")                       # +OK, one-argument form
    c.do("GET", "lk:str")
    c.do("CONFIG", "SET", "requirepass", "")
    c.close()


@scenario
def auth_forms():
    """Every way a user name reaches the server (РR6) — and the password never read."""
    c = conn()
    c.do("AUTH", "lkuser", "lkpass")                 # two-argument form: user first
    c.do("ACL", "WHOAMI")
    c.do("RESET")
    c.do("ACL", "WHOAMI")                            # back to default
    c.close()
    c = conn()
    c.do("HELLO", "3", "AUTH", "lkuser", "lkpass", "SETNAME", "lkapp")
    c.do("ACL", "WHOAMI")
    c.do("CLIENT", "GETNAME")
    c.close()
    c = conn()
    c.do("HELLO", "2", "AUTH", "lkuser", "wrongpass")  # WRONGPASS: user unchanged
    c.do("ACL", "WHOAMI")
    c.close()
    c = conn()
    c.do("AUTH", "lkuser", "wrongpass")
    c.do("ACL", "WHOAMI")
    c.close()


@scenario
def select_db():
    """The database number is connection state, and it moves (РR5)."""
    c = conn()
    c.do("SELECT", "3")
    c.do("SET", "lk:db3", "in-three")
    c.do("SELECT", "0")
    c.do("GET", "lk:db3")                            # nil: another database
    c.do("SELECT", "15")
    c.do("DBSIZE")
    c.do("SELECT", "16")                             # out of range: still in 15
    c.do("SELECT", "abc")
    c.do("SET", "lk:db15", "in-fifteen")
    c.do("SWAPDB", "3", "15")
    c.do("RESET")                                    # back to 0
    c.do("GET", "lk:db3")
    c.do("MOVE", "lk:k", "7")
    c.do("COPY", "lk:k", "lk:k-copy", "DB", "8")
    c.close()


@scenario
def inline_cmds():
    """Inline commands: what telnet, a healthcheck script and a load balancer send."""
    c = conn()
    c.send(inline("PING"))
    say("  inline PING            -> %s" % brief(c.read(1)[0]))
    c.send(inline("ECHO hello"))
    say("  inline ECHO hello      -> %s" % brief(c.read(1)[0]))
    c.send(inline('SET  "a b"  "c d"'))
    say("  inline quoted SET      -> %s" % brief(c.read(1)[0]))
    c.send(inline('GET "a b"'))
    say("  inline quoted GET      -> %s" % brief(c.read(1)[0]))
    c.send(b"\r\n\r\n" + inline("PING"))             # empty lines: no reply at all
    say("  two empty lines + PING -> %s" % brief(c.read(1)[0]))
    c.send(b"PING\n")                                # bare LF, no CR
    say("  bare-LF PING           -> %s" % brief(c.read(1)[0]))
    c.send(inline("INFO server") + enc("PING"))      # inline and RESP, one write
    say("  inline INFO + RESP PING-> %s | %s" % tuple(brief(v) for v in c.read(2)))
    c.close()


@scenario
def containers():
    """Container commands: the identity is `CMD|SUBCMD`, never the key (РR4)."""
    c = conn()
    c.do("CONFIG", "GET", "maxmemory")
    c.do("CONFIG", "SET", "maxmemory-policy", "noeviction")
    c.do("CONFIG", "RESETSTAT")
    c.do("CLIENT", "INFO")
    c.do("CLIENT", "SETNAME", "lkclient")
    c.do("CLIENT", "GETNAME")
    c.do("CLIENT", "NO-EVICT", "on")
    c.do("CLIENT", "ID")
    c.do("OBJECT", "ENCODING", "lk:str")
    c.do("OBJECT", "REFCOUNT", "lk:str")
    c.do("MEMORY", "USAGE", "lk:str")
    c.do("MEMORY", "DOCTOR")
    c.do("ACL", "WHOAMI")
    c.do("ACL", "CAT")
    c.do("COMMAND", "COUNT")
    c.do("COMMAND", "DOCS", "GET")
    c.do("LATENCY", "RESET")
    c.do("LATENCY", "HISTORY", "command")
    c.do("SLOWLOG", "GET", "2")
    c.do("SLOWLOG", "LEN")
    c.do("PUBSUB", "CHANNELS")
    c.do("PUBSUB", "NUMPAT")
    c.do("SCRIPT", "EXISTS", "f" * 40)
    c.do("FUNCTION", "STATS")
    c.do("XADD", "lk:xs", "*", "f", "v")
    c.do("XINFO", "STREAM", "lk:xs")
    c.do("XGROUP", "CREATE", "lk:xs", "g1", "0")
    c.do("XINFO", "GROUPS", "lk:xs")
    c.do("CLUSTER", "INFO")
    c.do("CLUSTER", "MYID")
    c.do("DEBUG", "JMAP")
    # A subcommand that does not exist, and a container called bare.
    c.do("CONFIG", "NOSUCHSUB")
    c.do("CONFIG")
    c.do("OBJECT", "HELP")
    c.close()


@scenario
def nested():
    """Aggregates inside aggregates: how deep a real reply actually goes (РR2)."""
    c = conn()
    c.do("DEL", "lk:n:z", "lk:n:xs")
    c.do("ZADD", "lk:n:z", "1", "a", "2", "b", "3", "c")
    c.do("ZRANGE", "lk:n:z", "0", "-1", "WITHSCORES")
    c.do("ZPOPMIN", "lk:n:z", "2")
    c.do("XADD", "lk:n:xs", "*", "f1", "v1", "f2", "v2")
    c.do("XADD", "lk:n:xs", "*", "f1", "v3")
    c.do("XRANGE", "lk:n:xs", "-", "+")               # array[ array[id, array[…]] ]
    c.do("XGROUP", "CREATE", "lk:n:xs", "g2", "0")
    c.do("XREADGROUP", "GROUP", "g2", "c1", "COUNT", "10", "STREAMS", "lk:n:xs", ">")
    c.do("XINFO", "STREAM", "lk:n:xs", "FULL")        # the deepest reply in Redis
    c.do("GEOADD", "lk:n:geo", "13.361389", "38.115556", "palermo")
    c.do("GEOPOS", "lk:n:geo", "palermo")
    c.do("CONFIG", "GET", "*max-*-entries*")
    c.do("COMMAND", "INFO", "GET")                    # array[array[…, array[…]]]
    c.close()


@scenario
def keepalive(n=1000):
    """A thousand exchanges on one connection: the normal life of a pooled socket."""
    n = int(n)
    c = conn(log=False)
    for i in range(n):
        c.send(enc("SET", "lk:ka:%d" % (i % 50), "v%d" % i))
        c.read(1)
        c.send(enc("GET", "lk:ka:%d" % (i % 50)))
        c.read(1)
    say("  %d round trips on one connection" % (2 * n))
    c.close()


@scenario
def torn_bulk():
    """A client that promises a megabyte, sends a hundred bytes and hangs up."""
    c = conn(log=False)
    c.send(b"*3\r\n$3\r\nSET\r\n$8\r\nlk:torn\r\n$1048576\r\n" + b"x" * 100)
    say("  declared $1048576, sent 100 bytes, closing")
    time.sleep(0.2)
    c.sock.close()
    # …and the same on a reply: ask for a big value, read a little, hang up.
    c2 = conn(log=False)
    c2.send(enc("SET", "lk:torn2", b"y" * 1048576))
    c2.read(1)
    c2.send(enc("GET", "lk:torn2"))
    say("  GET of 1 MB, read %d bytes, closing" % len(c2.sock.recv(4096)))
    c2.sock.close()


@scenario
def slow_client():
    """One byte at a time: the framer's stream mode, one syscall per byte."""
    c = conn(log=False)
    for b in enc("SET", "lk:slow", "value"):
        c.send(bytes([b]))
        time.sleep(0.002)
    say("  SET byte-by-byte -> %s" % brief(c.read(1)[0]))
    for b in enc("GET", "lk:slow"):
        c.send(bytes([b]))
        time.sleep(0.002)
    say("  GET byte-by-byte -> %s" % brief(c.read(1)[0]))
    c.close()


@scenario
def garbage():
    """Everything that is not RESP, and what the server does about it."""
    cases = [
        ("empty array",        b"*0\r\n" + enc("PING")),
        ("null array command", b"*-1\r\n" + enc("PING")),
        ("negative multibulk", b"*-5\r\n" + enc("PING")),
        ("bulk header not $",  b"*1\r\n+PING\r\n"),
        ("bulk over the limit", b"*2\r\n$3\r\nGET\r\n$536870913\r\n"),
        ("non-numeric length", b"*2\r\n$abc\r\n"),
        ("multibulk over INT_MAX", b"*2147483648\r\n"),
        ("unbalanced quotes",  b'SET "x\r\n'),
        ("binary junk",        bytes(range(256))),
        ("TLS ClientHello",    bytes.fromhex("160301009f010000")),
        ("HTTP request",       b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
    ]
    for name, payload in cases:
        c = conn(log=False)
        c.send(payload)
        time.sleep(0.15)
        c.sock.settimeout(0.4)
        try:
            out = c.sock.recv(4096)
            say("  %-24s -> %r%s" % (name, out[:80], "" if out else " (server closed)"))
        except socket.timeout:
            say("  %-24s -> (no reply, connection open)" % name)
        c.sock.close()


@scenario
def monitor():
    """MONITOR turns a connection into a stream of *other people's* commands (РR14)."""
    c = conn()
    c.do("MONITOR")

    def traffic():
        time.sleep(0.2)
        o = conn(log=False)
        o.do("SET", "lk:mon", "v")
        o.do("GET", "lk:mon")
        o.do("AUTH", "lkuser", "lkpass")   # Redis itself redacts this in the feed
        o.do("HSET", "lk:mon:h", "f", "v")
        o.close()
    t = threading.Thread(target=traffic)
    t.start()
    drain(c, 1.2, "monitor")
    t.join()
    c.close()


@scenario
def replica():
    """What a replica says on the port we capture: REPLCONF, PSYNC, and then RDB."""
    c = conn()
    c.do("PING")
    c.do("REPLCONF", "listening-port", "16399")
    c.do("REPLCONF", "capa", "eof", "capa", "psync2")
    c.send(enc("PSYNC", "?", "-1"))
    time.sleep(1.0)
    c.sock.settimeout(1.5)
    head = b""
    try:
        while len(head) < 512:
            chunk = c.sock.recv(65536)
            if not chunk:
                break
            head += chunk
    except socket.timeout:
        pass
    say("  PSYNC -> %r" % head[:120])
    # The write propagation stream: commands, but from the server side.
    o = conn(log=False)
    o.do("SET", "lk:repl", "v")
    o.do("INCR", "lk:repl:n")
    o.do("EXPIRE", "lk:repl", "60")
    o.close()
    time.sleep(0.6)
    try:
        say("  propagated -> %r" % c.sock.recv(65536)[:200])
    except socket.timeout:
        say("  propagated -> (nothing within the timeout)")
    c.close()


@scenario
def head_of_line():
    """One slow command, and everybody else's latency (§2 of the plan).

    `DEBUG SLEEP 0.2` occupies the single event loop; the four GETs issued on
    other connections meanwhile are fast commands with a slow round trip, and
    `INFO commandstats` will report them as fast. That difference is the whole
    argument for measuring on the wire.
    """
    slow = conn(log=False)
    fast = [conn(log=False) for _ in range(4)]
    for c in fast:
        c.do("SET", "lk:hol", "v")
    slow.send(enc("DEBUG", "SLEEP", "0.2"))
    t0 = time.time()
    for c in fast:
        c.send(enc("GET", "lk:hol"))
    for i, c in enumerate(fast):
        c.read(1)
        say("  GET #%d answered after %.3fs" % (i, time.time() - t0))
    slow.read(1)
    say("  DEBUG SLEEP answered after %.3fs" % (time.time() - t0))
    for c in fast + [slow]:
        c.close()


@scenario
def midstream(wait=4.0):
    """A connection that is already open when the agent attaches (LK_CONN_SYNTHETIC).

    record.sh starts this client *before* the agent: the SELECT and the AUTH
    happen unobserved, so everything the agent sees afterwards belongs to a
    database and a user it never saw named — which is exactly why РR5 says
    `db="?"` rather than `db="0"`.
    """
    c = conn(log=False)
    c.do("SELECT", "7")
    c.do("AUTH", "lkuser", "lkpass")
    c.do("SET", "lk:mid", "before the agent")
    say("  connected and SELECTed 7; waiting %.1fs for the agent" % float(wait))
    time.sleep(float(wait))
    c.log = True
    c.do("GET", "lk:mid")
    c.do("INCR", "lk:mid:n")
    c.do("PING")
    c.close()


@scenario
def unixsocket(path="/tmp/lkt-redis.sock"):
    """The blind zone, demonstrated: the same commands over AF_UNIX.

    Nothing appears in the capture — `tcp_sendmsg`/`tcp_recvmsg` are not on this
    path. The trace this produces is empty on purpose (record.sh keeps it out of
    the corpus and the README says why).
    """
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(path)
    dec = Decoder()
    for cmd in (("PING",), ("SET", "lk:unix", "v"), ("GET", "lk:unix")):
        s.sendall(enc(*cmd))
        while True:
            dec.feed(s.recv(65536))
            v = dec.value()
            if v is not None:
                break
        say("  unix %-20s -> %s" % (" ".join(cmd), brief(v)))
    s.close()


@scenario
def cluster():
    """A cluster client that guesses wrong: MOVED, ASK, CROSSSLOT (РR7)."""
    c = conn()
    c.do("CLUSTER", "MYID")
    c.do("CLUSTER", "INFO")
    c.do("CLUSTER", "SHARDS")
    c.do("SET", "foo", "v")                # this node or another — one of them MOVEs
    c.do("GET", "foo")
    c.do("SET", "bar", "v")
    c.do("MGET", "foo", "bar")             # CROSSSLOT
    c.do("MGET", "{tag}a", "{tag}b")       # same slot: fine, or one MOVED
    c.do("GET", "lk:cluster:missing")
    c.close()


@scenario
def ask():
    """ASK, which needs a slot in flight: MIGRATING here, IMPORTING there."""
    import subprocess

    def cli(port, *args):
        out = subprocess.run(
            ["docker", "run", "--rm", "--network", "host", "redis:7.4",
             "redis-cli", "-p", str(port)] + list(args),
            capture_output=True, text=True)
        return out.stdout.strip()

    # Both keys carry the same hash tag, so they live in the same slot: that is
    # the whole trick — ASK is only ever about a key that is *missing here* in a
    # slot that is *moving there*.
    present, absent = "{lkask}present", "{lkask}absent"
    ports = [6390, 6391, 6392]
    slot = int(cli(ports[0], "CLUSTER", "KEYSLOT", present))
    owner_port = None
    for p in ports:
        if cli(p, "SET", present, "v") == "OK":
            owner_port = p
            break
    other_port = [p for p in ports if p != owner_port][0]
    src_id = cli(owner_port, "CLUSTER", "MYID")
    dst_id = cli(other_port, "CLUSTER", "MYID")
    cli(other_port, "CLUSTER", "SETSLOT", str(slot), "IMPORTING", src_id)
    cli(owner_port, "CLUSTER", "SETSLOT", str(slot), "MIGRATING", dst_id)
    say("  slot %d migrating %d -> %d" % (slot, owner_port, other_port))
    c = Conn(port=owner_port)
    c.do("GET", present)                   # present: served normally
    c.do("GET", absent)                    # absent in a migrating slot: -ASK
    c.close()
    c = Conn(port=other_port)
    c.do("GET", absent)                    # importing without ASKING: -MOVED
    c.do("ASKING")
    c.do("GET", absent)                    # …with ASKING: served
    c.do("GET", present)                   # …but only for the one command
    c.close()
    cli(owner_port, "CLUSTER", "SETSLOT", str(slot), "STABLE")
    cli(other_port, "CLUSTER", "SETSLOT", str(slot), "STABLE")


@scenario
def hello_probe():
    """What the server offers each protocol version (the HELLO reply itself)."""
    c = conn()
    c.do("HELLO")                          # no argument: the current version
    c.do("HELLO", "3")
    c.do("HELLO", "2")
    c.do("HELLO", "4")                     # NOPROTO
    c.do("HELLO", "abc")
    c.close()


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("--list", "-l"):
        for name in sorted(SCENARIOS):
            doc = (SCENARIOS[name].__doc__ or "").strip().split("\n")[0]
            print("  %-20s %s" % (name, doc))
        return 0
    name, rest = args[0], args[1:]
    if name not in SCENARIOS:
        print("unknown scenario %r (--list to see them)" % name, file=sys.stderr)
        return 2
    say("=== %s (%s:%s)" % (name, os.environ.get("REDIS_HOST", "127.0.0.1"),
                            os.environ.get("REDIS_PORT", "6399")))
    SCENARIOS[name](*rest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
