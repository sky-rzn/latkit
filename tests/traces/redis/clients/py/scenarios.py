#!/usr/bin/env python3
"""redis-py scenarios: what the library does on the wire when nobody tells it to.

Run inside the clients/py image (record.sh does), one scenario per argv[1]:

  basic     connect, SET/GET/DEL/EXPIRE/INCR/HSET/HGETALL/LPUSH/LRANGE
  pipeline  the library's own pipeline of 100 commands
  multi     pipeline(transaction=True) — MULTI … EXEC
  pool      a connection pool under threads: what pooled reuse looks like
  resp3     protocol=3 — HELLO 3 and the RESP3 replies (recon item 2)
  pubsub    a subscriber and a publisher on two connections
  block     BLPOP with a timeout and BLPOP woken by a push
  auth      an ACL user, a wrong password, SELECT of another database
  err       WRONGTYPE, NOSCRIPT, unknown command
"""
import os
import sys
import threading
import time

import redis

HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
PORT = int(os.environ.get("REDIS_PORT", "6399"))


def conn(**kw):
    return redis.Redis(host=HOST, port=PORT, **kw)


def basic():
    r = conn()
    r.set("py:k", "v")
    print("get", r.get("py:k"))
    r.incr("py:n")
    r.expire("py:k", 60)
    r.hset("py:h", mapping={"a": "1", "b": "2"})
    print("hgetall", r.hgetall("py:h"))
    r.rpush("py:l", *[str(i) for i in range(10)])
    print("lrange", r.lrange("py:l", 0, -1))
    print("mget", r.mget(["py:k", "py:n", "py:missing"]))
    r.delete("py:k", "py:n", "py:h", "py:l")


def pipeline():
    r = conn()
    p = r.pipeline(transaction=False)
    for i in range(100):
        p.set("py:p:%d" % i, "v%d" % i)
    print("pipeline", len(p.execute()))
    p = r.pipeline(transaction=False)
    for i in range(100):
        p.get("py:p:%d" % i)
    print("pipeline get", len(p.execute()))


def multi():
    r = conn()
    p = r.pipeline(transaction=True)
    p.set("py:t:a", "1")
    p.incr("py:t:n")
    p.get("py:t:a")
    print("multi", p.execute())


def pool():
    r = redis.Redis(host=HOST, port=PORT, max_connections=4)
    def work(n):
        for i in range(25):
            r.set("py:pool:%d:%d" % (n, i), "x")
            r.get("py:pool:%d:%d" % (n, i))
    ts = [threading.Thread(target=work, args=(n,)) for n in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    print("pool done")


def resp3():
    r = conn(protocol=3)
    r.set("py:r3", "v")
    print("get", r.get("py:r3"))
    print("config", list(r.config_get("maxmemory").items())[:1])
    print("xinfo", r.client_info().get("resp"))
    print("hrandfield", r.hgetall("py:nope"))


def pubsub():
    sub = conn().pubsub()
    sub.subscribe("py:chan")
    got = []

    def reader():
        for msg in sub.listen():
            got.append(msg)
            if len(got) >= 4:
                break
    t = threading.Thread(target=reader)
    t.start()
    time.sleep(0.3)
    pub = conn()
    for i in range(3):
        pub.publish("py:chan", "msg%d" % i)
    t.join(5)
    print("received", len(got))
    sub.close()


def block():
    r = conn()
    print("blpop timeout", r.blpop(["py:bl"], timeout=1))
    def pusher():
        time.sleep(0.5)
        conn().rpush("py:bl", "woken")
    threading.Thread(target=pusher).start()
    print("blpop woken", r.blpop(["py:bl"], timeout=5))


def auth():
    r = conn(username="lkuser", password="lkpass", db=3)
    r.set("py:auth", "v")
    print("whoami", r.execute_command("ACL", "WHOAMI"))
    try:
        conn(username="lkuser", password="nope").ping()
    except redis.AuthenticationError as e:
        print("wrongpass", e)


def err():
    r = conn()
    r.set("py:str", "v")
    for fn in (lambda: r.lpush("py:str", "x"),
               lambda: r.evalsha("f" * 40, 0),
               lambda: r.execute_command("NOSUCHCOMMAND", "a")):
        try:
            fn()
        except redis.ResponseError as e:
            print("error:", e)


if __name__ == "__main__":
    globals()[sys.argv[1] if len(sys.argv) > 1 else "basic"]()
