# latkit HTTP demo stack

The HTTP twin of [`../demo`](../demo) (PostgreSQL) and
[`../demo-mysql`](../demo-mysql): nginx in front of a Go backend, a load
generator, the agent, Prometheus and Grafana with the bundled dashboards — one
`docker compose up` away from a live **latkit — HTTP** dashboard of a web
server that was neither instrumented nor reconfigured, and that has no access
log turned on.

## Requirements

- **Linux host** with kernel **≥ 5.15** and BTF at `/sys/kernel/btf/vmlinux`
  (any mainstream distro of the last few years qualifies; the agent checks on
  startup and says exactly what is missing). Docker Desktop on macOS/Windows
  runs a VM kernel — not tested, not promised.
- Docker with the compose plugin. The `latkit` container runs `privileged`
  with `pid: host` (demo simplicity; the minimal capability set is a comment
  in the compose file and a table in [docs/deploy.md](../../docs/deploy.md)).

## Run

```sh
git clone --recurse-submodules https://github.com/sky-rzn/latkit.git
cd latkit/deploy/demo-http
docker compose up --build -d
```

First run builds the agent image and the Go backend (~2 min) and pulls
nginx/curl/prometheus/grafana. From `git clone` to live panels is about 3–4
minutes on an average machine; image pulls on a slow network are the one thing
that can stretch it.

Then open:

| what | where |
|---|---|
| **Grafana** — anonymous, the bundled dashboards in the *latkit* folder | <http://localhost:3000/dashboards> |
| Prometheus | <http://localhost:19090> |
| raw agent metrics | `curl http://localhost:9752/metrics` |

Give it ~1 minute after `up`: Prometheus scrapes every 5 s and the load runs a
pass of ~30 requests per virtual host in a loop. Start at **latkit — HTTP**;
the other four dashboards are the database ones and stay empty here.

Tear down (containers, volumes and network — nothing survives):

```sh
docker compose --profile tls --profile trace down -v
```

(The profile flags make `down` cover the optional services too; they are
harmless otherwise.)

## What to look at, and why it is there

The load ([`load/load.sh`](load/load.sh)) invents **fresh random identifiers on
every pass** — a number, a UUID, a ULID, a 40-character hex digest, a date —
plus a junk query string. Each pass therefore visits a dozen URLs that have
never been seen before and will never be seen again. That is the point:

- **Top routes** shows a short, stable list (`/api/users/{id}`,
  `/api/orders/{id}`, `/api/reports/{id}`, …). The agent never saw the
  application's routing table; it templated the paths off the wire (РH7). The
  URLs it templated are in `docker compose logs load`-visible traffic and
  contain none of those `{id}`s;
- **route="other" share** is the honesty panel: it is the fraction of requests
  whose route did not fit in the top-K dictionary. On this stack it should sit
  at zero. If a heuristic ever fails on your API, this is the number that tells
  you — cardinality stays bounded either way, which is the guarantee;
- **`latkit_metric_series`** (Agent health) stays flat while the URL space
  grows without bound. That is the same claim from the other end;
- **Duration vs TTFB.** `/api/slow` sleeps before its first byte: its TTFB and
  its duration are the same, and both are far above everything else. The
  upload routes are the opposite case — see below;
- **Request upload time** is fed by `PUT /api/uploads/{id}`, whose client
  trickles a body over half a second. That half second is **not** in the
  duration panel: latkit starts the server's clock at the end of the request
  (РH5), so a slow client is not reported as a slow server. This is the number
  nginx's `$request_time` would blur;
- **Errors by status code** shows 500, 503, 429 and 404 as separate codes,
  while the **5xx share** panel counts only the first two. A 404 is the server
  correctly saying no;
- **Body throughput / Response size**: the 8 MB `/static/big.bin` is served
  with nginx's default `sendfile on`, and `/nosendfile/big.bin` is the same
  bytes written through the socket. Comparing them is comparing РH4's
  degradation against the ordinary path on your kernel;
- **Blind zones** should be all zeros: this stack is HTTP/1.1 throughout. Start
  the `tls` profile below and they stay zero — HTTPS is not a blind zone, h2
  is, and the profile keeps h2 off deliberately.

Two hosts (`shop.demo`, `api.demo`) are in the mix, so the `host` label — and
the "Top hosts" panel — has more than one value; a third, `127.0.0.1:8080`,
appears on its own because the container health check is real traffic on the
same port, and `host` is read per request rather than per connection.

**Both legs of the reverse proxy are observed** — 8080 (client → nginx) and 8081
(nginx → backend) — and on the dashboard they are `host="shop.demo"` /
`host="api.demo"` against `host="backend"`. Compare their p95 for the same
route: the front leg contains the upstream one, so the gap between them is
nginx's own overhead plus the hop. Note *why* `host` is what tells them apart:
the HTTP label set carries no port (a port is a deployment detail, and a label
of it would double every series), so two legs presenting the same `Host` would
land in one series. This nginx gives the upstream leg a Host of its own, which
is nginx's own default — see the comment in [`nginx.conf`](nginx.conf). In
spans the two are always distinct: `server.port` is an attribute.

### Route templating, by hand

```sh
curl -s http://localhost:9752/metrics | grep '^latkit_http_requests_total' \
  | sed 's/.*route="\([^"]*\)".*/\1/' | sort -u
```

Not one raw identifier appears. To pin the routes explicitly instead of letting
the templater guess, uncomment the `LATKIT_HTTP_ROUTES` line and the
`routes.map` volume in `docker-compose.yml` — [`routes.map`](routes.map)
explains the format and the trade.

### Privacy, by hand

The load sends `?token=<random>` on every search request (and the agent sees
every header of every request):

```sh
curl -s http://localhost:9752/metrics | grep -ci token   # 0
```

Query values whose key looks like a credential are replaced by `***` before the
target leaves the handler (`--http-redact`, on by default), and no raw URL,
header or body ever reaches a metric label at all (РH12).

## TLS profile

```sh
LATKIT_TLS=auto docker compose --profile tls up --build -d
```

adds a **second** nginx serving HTTPS on 8443 with a self-signed certificate,
and a load client that only talks to it, next to the plaintext pair. The socket
bytes of those sessions are ciphertext; the agent reads the plaintext from
nginx's libssl through uprobes and feeds the same pipeline, so the dashboards
show both kinds of traffic side by side and you cannot tell which observation
came from which. Proof it is really the TLS path:

```sh
curl -s http://localhost:9752/metrics | grep -E '^latkit_tls_(connections|attached)'
```

`latkit_tls_connections` grows and `latkit_tls_attached{state="ok"} 1` is the
attach gauge. No configuration was needed for it: with an `http` port
configured, the `--tls auto` scan set includes `nginx`, `httpd`, `apache2` and
`haproxy` (РH13.1). A **Go** server (Caddy, Traefik, any `net/http`) has no
libssl to find and is named instead: `LATKIT_TLS_GO=/usr/bin/caddy`, see
[docs/notes-tls.md](../../docs/notes-tls.md) §4b.

> **`LATKIT_TLS=auto` is opt-in here, and this is why.** That same scan set is
> also installed as the **kernel capture comm filter** — with TLS on, latkit
> captures send/recv only from processes whose comm is in it. That is what keeps
> a `psql` or a browser mapping the same shared `libssl` out of the uprobe
> channel, and on a database host it changes nothing, because the process you
> capture *is* the one being scanned. An HTTP deployment is not like that: the
> upstream leg of this stack is served by a **Go** process whose comm is
> `backend`, so with `--tls auto` the 8081 series stop and the "two legs" story
> above quietly becomes one. Turn the profile on and watch it happen — it is a
> deliberate demonstration. The ways out, in a real deployment: leave TLS
> capture off if the port you care about is plaintext, or give the app server
> its own agent (a second latkit with `--port 8081=http` and no `--tls`), or
> name it with `--tls-go` (which adds its comm to the filter). Same trap,
> in operator form: [`../existing-http/README.md`](../existing-http/README.md).

The HTTPS front is HTTP/1.1 only, on purpose: h2 is a declared blind zone
(README "Known limitations"), and a demo that quietly negotiated h2 would be
demonstrating the blind-zone counter instead of the TLS channel.

One artefact to expect on this profile: `latkit_parse_errors_total{proto="http"}`
grows by roughly **one per 70 HTTPS connections** (1.4 % here, where every curl
opens a new connection — the worst case for a per-connection artefact). The
observations themselves are unaffected. Cause: the TLS handshake is recognised
from the first event of a direction, and nginx's OpenSSL reads the client's
record header in two pieces, so the client side is recognised a moment late —
from the server's ServerHello instead — and the ciphertext seen in between is
framed as HTTP, fails, and says so. Root cause and the fix it needs:
[docs/notes-tls.md](../../docs/notes-tls.md) §6.

## Trace profile (`traceparent`)

```sh
LATKIT_OTLP_ENDPOINT=http://jaeger:4318 LATKIT_OTLP_SPANS=1 \
  docker compose --profile trace up --build -d
```

adds Jaeger (<http://localhost:16686>, service `latkit-demo-http`) and turns on
span export. Every request from the load carries a W3C `traceparent` with a
fresh trace id, and nginx passes it to the upstream leg, so each request
produces **two** server spans — the front leg and the upstream leg — carrying
the *caller's* trace id and pointing at the caller's span as their parent
(РH11). Search Jaeger by a trace id from `docker compose logs load`, or just
browse the service.

What you will see is a trace whose parent span is missing: the load generator
is `curl`, which mints a `traceparent` but never reports a span of its own. In
a real deployment that parent is your instrumented client, and latkit's
observation lands inside its trace without a line of code in the server. The
span attributes follow the OTel HTTP semantic conventions
(`http.request.method`, `http.route`, `http.response.status_code`,
`server.address`, `url.path`, `network.protocol.version`, …); `url.path` is
redacted (`--http-redact`).

## How it is wired

- **nginx** (1.27) publishes **no** port on purpose: the load reaches it by
  service name over the compose network. A published `localhost` port would
  route through docker-proxy, which `splice()`s the payload past the socket
  layer and defeats the capture (README "Known limitations"). Config:
  [`nginx.conf`](nginx.conf) — static files with `sendfile on`, plus a reverse
  proxy to the backend.
- **backend** — [`backend/main.go`](backend/main.go), Go `net/http`, built by
  the stack. Its routes exist to produce the shapes the agent has to get right;
  the file says which and why.
- **load** — [`load/load.sh`](load/load.sh) in a stock curl image.
- **latkit** — the release scratch image built from
  [`deploy/docker/Dockerfile`](../docker/Dockerfile) (musl static), configured
  only through `LATKIT_*` env: `LATKIT_PORT=8080=http,8081=http,8443=http` (the
  port form selects the wire protocol — a bare number would default to `pg`),
  `/metrics` on `0.0.0.0:9752`, `--tls auto`.
- **prometheus** (2.x) — scrapes `latkit:9752` every 5 s, 2 h retention.
- **grafana** (pinned 11.x) — anonymous Viewer; the datasource and the
  dashboards are provisioned from the postgres demo's
  [`../demo/grafana/provisioning`](../demo/grafana/provisioning) (same
  `prometheus` service name) plus [`../../dashboards`](../../dashboards),
  mounted read-only — the repo directory is the single source, no copies.

## Troubleshooting

- `latkit` exits immediately → `docker compose logs latkit`. The usual cause
  is missing BTF (`/sys/kernel/btf/vmlinux`) or an old kernel; the error
  message states the requirement.
- Panels show "No data" → wait for the first scrapes (~30–60 s after `up`),
  then check `docker compose logs load` and the Prometheus target page at
  <http://localhost:19090/targets>.
- Ports 3000/9752/19090 taken → edit the `ports:` mappings in
  `docker-compose.yml`; nothing inside the stack depends on the host port
  numbers.
- **`latkit_parse_errors_total{proto="http"}` ticks up very slowly** (order of
  1 per 1500 requests on this stack, all of them on the 8 MB routes). That is a
  known capture-layer limitation, not an HTTP one: a `tcp_sendmsg` the kernel
  refuses (`EAGAIN` on a full socket buffer) is counted at entry, before its
  return value exists, and the application re-sends the same bytes in the next
  call. The response body then appears longer than its `Content-Length`, the
  agent finishes the body early and rejects the leftover bytes as a start line
  — loudly, in the counter, which is the point. It needs a large response and a
  socket that fills; the database stands never produce it. Details in
  [docs/notes-iov.md](../../docs/notes-iov.md) "Known limitations".
