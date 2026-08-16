# latkit with an existing MinIO

Monitoring-only stack — **latkit + Prometheus + Grafana**, pointed at a MinIO
(or Ceph RGW, SeaweedFS, Garage — anything speaking S3 over HTTP/1.x) you
already run on the host. Unlike [`../demo-minio`](../demo-minio) it brings **no**
object store and **no** load generator: the agent captures the real traffic.
Grafana and Prometheus reuse the postgres demo's provisioning and the bundled
dashboards from [`../../dashboards`](../../dashboards) — open **latkit — S3 /
MinIO**.

Nothing is asked of the server: no admin credentials, no `mc admin config set`,
no bucket-level metrics to enable, no reconfiguration, no restart.

## Requirements

- Linux kernel **≥ 5.15 with BTF** (`/sys/kernel/btf/vmlinux`). The agent checks
  at startup and says exactly what is missing.
- Docker + compose plugin.
- The traffic must be **S3 over HTTP/1.0 or HTTP/1.1 on TCP**. MinIO offers
  `http/1.1` to every real client's ALPN list, so unlike a browser-facing web
  server an S3 port does not quietly fall into the h2 blind zone — but read
  "What is not captured" below before concluding the agent is broken.

## Run

```sh
cd deploy/existing-minio
GF_ADMIN_PASSWORD='choose-one' docker compose up --build -d
```

Edit `LATKIT_PORT` in `docker-compose.yml` first — the default is `9000=s3`.
First build of the agent image is ~2 min. Grafana and Prometheus bind to
**127.0.0.1 only** — `/metrics` and this Grafana have no auth; reach them over
an SSH tunnel, never publish them:

```sh
ssh -L 3000:127.0.0.1:3000 -L 9090:127.0.0.1:9090 your-node
```

Then Grafana at <http://localhost:3000> (`admin` / your `GF_ADMIN_PASSWORD`) →
left nav **Dashboards** (click the word, not the arrow) → folder **latkit** →
**latkit — S3 / MinIO**.

## MinIO already exports metrics. Why this?

An honest answer, because MinIO's own Prometheus endpoint is good and does
include API latencies. latkit gives what is not there:

- **zero touch** — no admin credentials, no bucket-metric level to raise, no
  restart, and it works the same on a server whose metrics endpoint is off,
  locked down, or absent entirely (many S3-compatible servers have none);
- **the access key and the bucket in one series.** "Which tenant is driving the
  p99 on this bucket" is a question about a cut MinIO's own metrics do not
  offer, and the cardinality is bounded by construction (an operation table, a
  bucket-name validator, a top-K spill);
- **TTFB and body time kept apart** (РH5). On an object store those are two
  different stories — a slow `GetObject` that streams 5 MiB and a slow
  `GetObject` that thinks for 300 ms before the first byte are different
  incidents — and one histogram of the total blurs them together. The upload
  interval is a third family for the same reason: a client trickling a `PUT`
  over a slow link is not a slow server;
- **the request the metric came from**, as a sampled OTel span, joined to the
  caller's trace if it sent a `traceparent`;
- **one agent per host** for the databases, the web servers and the object
  store — one deployment, one nomenclature, one set of dashboards;
- **any S3-compatible server**, on the same labels, because the observation is
  made from the wire and not from the implementation.

What it is *not*: a replacement for MinIO's internal metrics (heal status,
drive health, capacity, replication lag). Run both.

## Which port to capture

The filter is on the **local (server) port** — the port MinIO accepts client
connections on:

```yaml
LATKIT_PORT: "9000=s3"
```

On a **distributed pool** that same port also carries the cluster's own traffic
— MinIO's nodes talk to each other on it — and the two are separated rather than
mixed:

- the **grid** multiplexer (`/minio/grid/…`) upgrades to a websocket carrying
  binary msgp. After an `Upgrade` the bytes are not HTTP any more and a
  websocket-framed binary stream is not something to guess at, so the connection
  is dropped whole and counted:
  `latkit_ignored_conns_total{reason="upgrade"}`;
- the ordinary HTTP requests to `/minio/…` — peer/storage/lock RPC, the health
  probes your orchestrator sends, the admin API, the metrics endpoint — are
  counted in `latkit_s3_internal_requests_total` and become **no observation**.
  They are on the dashboard as their own panel and in nothing that says
  "requests". This is not a rounding error: measured under a `warp` run on a
  four-node stand, **79 % of the data events and 90 % of the connections** on
  the S3 port were the cluster itself, and ~65 % of the *requests* the agent
  parsed were internal ones;
- the **Console/WebUI** (`--console-address`) is a separate port and is not
  captured unless you name it, which you should not: it is not the S3 API;
- run **one agent per node**. The observation is made where the request is
  served.

The per-port capture budget is 2048 bytes per send/recv call for an `s3` port
(`9000=s3:4096` to change it). That is heads-only on purpose — latkit parses
request and response heads plus a short prefix of an *error* body (that is where
the S3 code lives), never an object.

**Outgoing** requests — your application's calls to somebody else's S3 — are
**not** captured in v1: the filter is on the local port, and a client socket's
local port is ephemeral. This is a server-side observer.

## What is not captured — read this before troubleshooting

Each of these is *counted*, so the dashboard tells you which one you are in
rather than leaving you with an empty panel:

| What | Why | What you see |
|---|---|---|
| **The grid / inter-node protocol** | binary msgp inside a websocket; after `101` the bytes are not HTTP | `latkit_ignored_conns_total{reason="upgrade"}` |
| **HTTP/2** | HPACK's header table cannot survive a capture hole (README §"Known limitations") | `latkit_ignored_conns_total{reason="h2"}`. Rare on an S3 port — MinIO offers http/1.1 to real clients — but a proxy in front may negotiate it |
| **TLS with no `--tls-go`** | MinIO maps no libssl; there is exactly one channel and it must be named | `latkit_tls_attached{state="none"}` and a warning at startup |
| **`S3 Select` and event-framed responses** | the body is a frame stream, not an object | the unit closes at end of body; timings stay right, the payload is never parsed |
| **The admin API** (`/minio/admin/v3/*`) | not the S3 API | `latkit_s3_internal_requests_total` |
| **The Console/WebUI** | a different port, a different protocol | nothing — it is not in `LATKIT_PORT` |
| **`sendfile`-served bodies** | may not cross the capture point | `bytes_out` becomes a declared lower bound; the unit is flagged and left out of the size histogram. Since ~6.5 the kernel routes them through `sendmsg` and they are accounted normally |
| **Unix-domain sockets** | `tcp_*` hooks are not on that path | nothing at all |
| **`splice()`-relayed traffic** | e.g. docker-proxy on a published port, for connections originating on the same host | sends degrade to zero-payload events, receives are missed |

## TLS: one channel, and it must be named

MinIO terminates TLS inside Go's `crypto/tls` and maps no `libssl` at all, so
the `/proc` scan that serves postgres, MySQL and nginx has nothing to find here
(РS8). Name the binary:

```yaml
LATKIT_TLS: auto
LATKIT_TLS_GO: /host/usr/local/bin/minio
volumes:
  - /usr/local/bin/minio:/host/usr/local/bin/minio:ro
```

- the bind mount must be the **same file** MinIO runs: a uprobe binds to an
  inode, not to a path. For a MinIO in a container, seen from this one, the path
  form is `/proc/<pid>/root/usr/bin/minio` — that is what `pid: host` is for;
- **stripped binaries work.** That is how MinIO is shipped, and the official
  image resolves through Go's own function table (`.gopclntab`);
- `--tls auto` is still worth setting beside it: with an `s3` port configured
  the derived `/proc` scan set is `{minio}`, and that set is what gates the
  uprobe channel kernel-side. `latkit --print-config` prints it as
  `tls_scan_comm`;
- a binary that **cannot** be hooked is fatal at startup with the cause and a
  way forward — not a dashboard that is quietly flat. The alternatives are to
  terminate TLS in front of MinIO and capture the plaintext hop, or to accept
  the port as a named blind zone;
- x86-64 only.

Verify it is live:

```sh
docker compose logs latkit | grep -i 'Go TLS uprobes'
docker compose exec prometheus wget -qO- http://latkit:9752/metrics \
  | grep -E '^latkit_tls_(attached|connections|correlation_misses_total)'
# want: tls_attached{state="go"} 1, connections growing, misses 0
```

> **For a production install, prefer running the agent on the host as a systemd
> unit** ([`../systemd/latkit.service`](../systemd/latkit.service)): `/proc` is
> native, there is no container mount namespace to cross for the binary, and
> privileges are bounded by `CapabilityBoundingSet`. Set
> `LATKIT_PORT=9000=s3` and `LATKIT_TLS_GO=/usr/local/bin/minio` in
> `/etc/latkit/latkit.env`.

## Labels: what is bounded, and by what

| Label | Source | Bound |
|---|---|---|
| `op` | (method, path shape, query keys) → the operation table | the table itself, ~45 values; an unknown call is `op="other"` |
| `bucket` | path-style `/bucket/key`, or the Host with `LATKIT_S3_DOMAIN` | S3 naming rules — a name that does not pass them is `bucket="other"`, a request that names none is `bucket="-"` |
| `user` | the access key of the SigV4 signature, or `X-Amz-Credential` of a presigned URL | the (bucket,user) dimension limit, then `user="other"` |
| `s3code` | `<Code>` in the error body | the dictionary of known S3 codes, then `other` |

Two things to watch on a large deployment:

- **the `op="other"` share** is not a cardinality guard here — the operation
  label is bounded by a table, not by a heuristic — it is a **freshness**
  signal. The S3 API grows; a rising `other` share means the table in
  [docs/notes-s3proto.md](../../docs/notes-s3proto.md) has fallen behind your
  server, and it is worth an issue;
- **STS credentials are ephemeral.** A deployment handing out short-lived keys
  (Web Identity / AssumeRole) can invent access keys faster than any dictionary
  wants. The (bucket,user) dimension ceiling is therefore raised automatically
  for an `s3` port — `--print-config` prints `max_session_dims=128`, against 32
  for a database — and everything past it spills into `user="other"` rather than
  growing the series count. If that is still not the trade you want,
  `LATKIT_S3_USER=off` drops the label entirely.

## Privacy

An S3 request's most sensitive part is the object key — file names, e-mail
addresses, customer identifiers all end up in one. The rules are structural
rather than advisory (РS2, РH12):

- **the object key is never a label.** Not truncated, not hashed, not templated:
  the identity of a request is its *operation*, which comes from a table. Raw
  paths, query strings, headers and bodies never enter the metrics registry;
- **only the public half of a credential is read.** The access key becomes
  `user`; the signature, the per-chunk signatures and `X-Amz-Security-Token` are
  never touched, and `LATKIT_S3_USER=off` removes even that;
- **error bodies are read for the `<Code>` element and nothing else** — the only
  case in which any response body byte is looked at at all;
- **spans are off unless you configure an OTLP endpoint**, and a sampled span is
  the one path by which a `url.path` — object key included — leaves the host.

## Troubleshooting ladder

Isolate top-down; each step says which layer is at fault.

1. **Agent capturing?**

   ```sh
   docker compose exec prometheus wget -qO- http://latkit:9752/metrics | grep -E \
     '^latkit_(connections_active|events_total|s3_requests_total|s3_internal_requests_total|ignored_conns_total|udp_bytes_total)'
   ```

   - `connections_active > 0` comes from the `inet_sock_set_state` tracepoint,
     `events_total` from the `tcp_*` data path — their divergence localises the
     break;
   - `events_total` grows, `s3_requests_total` empty, **`s3_internal_requests_total`
     growing** → you are watching an idle server's health probes: the port is
     right and the clients are elsewhere;
   - `events_total` grows and nothing else does → the bytes are not readable
     HTTP/1.x. On a TLS port that means the uprobes did not attach (see above);
     otherwise check `ignored_conns_total{reason}`;
   - everything flat → the port filter does not match (wrong `LATKIT_PORT`), the
     traffic goes over a unix socket, `LATKIT_COMM` is set to something wrong,
     or `pid: host` is missing.

2. **Prometheus scraping?** <http://localhost:9090/targets> — job `latkit` UP.

3. **Grafana?** Datasource *Test* green; time range **Last 15 minutes**; check
   the host clock (`timedatectl`).

## Ports

Grafana `127.0.0.1:3000`, Prometheus `127.0.0.1:9090`; the agent's `9752` is not
published (Prometheus scrapes it over the compose network). Edit the `ports:`
mappings if any clash.
