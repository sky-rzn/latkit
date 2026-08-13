# latkit with an existing web server

Monitoring-only stack — **latkit + Prometheus + Grafana**, pointed at an
nginx / Apache / HAProxy / Go service you already run on the host. Unlike
[`../demo-http`](../demo-http) it brings **no** server and **no** load
generator: the agent captures the real traffic. Grafana and Prometheus reuse
the postgres demo's provisioning and the bundled dashboards from
[`../../dashboards`](../../dashboards) — open **latkit — HTTP**.

Nothing is asked of the web server: no access log, no status module, no
reconfiguration, no restart.

## Requirements

- Linux kernel **≥ 5.15 with BTF** (`/sys/kernel/btf/vmlinux`). The agent checks
  at startup and says exactly what is missing.
- Docker + compose plugin.
- The traffic must be **HTTP/1.0 or HTTP/1.1 over TCP**. See "What is not
  captured" below before you conclude the agent is broken — h2 and h3 are the
  two answers to almost every "why is this dashboard empty".

## Run

```sh
cd deploy/existing-http
GF_ADMIN_PASSWORD='choose-one' docker compose up --build -d
```

Edit `LATKIT_PORT` in `docker-compose.yml` first — the default is `80=http`.
First build of the agent image is ~2 min. Grafana and Prometheus bind to
**127.0.0.1 only** — `/metrics` and this Grafana have no auth; reach them over
an SSH tunnel, never publish them:

```sh
ssh -L 3000:127.0.0.1:3000 -L 9090:127.0.0.1:9090 your-vps
```

Then Grafana at <http://localhost:3000> (`admin` / your `GF_ADMIN_PASSWORD`) →
left nav **Dashboards** (click the word, not the arrow) → folder **latkit** →
**latkit — HTTP**.

## Which port to capture

The filter is on the **local (server) port** — the port your server accepts on,
not the client's. A deployment usually has more than one worth watching:

```yaml
LATKIT_PORT: "443=http,8080=http"     # the edge, and the origin behind it
```

Two legs of a reverse proxy have genuinely different latencies (one includes the
upstream, the other is the upstream), and keeping them apart is the reason the
label set carries the port's traffic separately rather than averaging it. A
per-port capture budget can be given as `443=http:4096`; the default for an
`http` port is 2048 bytes per send/recv call, which is heads-only on purpose —
latkit never needs a response body, and copying one out of a gigabit stream
would buy nothing.

**Outgoing** requests (your application calling someone else's API) are **not**
captured in v1: the filter is on the local port, and a client socket's local
port is ephemeral (РH2). This is a server-side observer.

## What is not captured — read this before troubleshooting

Each of these is *counted*, so the dashboard tells you which one you are in
rather than leaving you with an empty panel:

| What | Why | What you see |
|---|---|---|
| **HTTP/2** | HPACK's header table cannot survive a capture hole, and per-stream state cannot be bounded (README §"Known limitations", plan §8). h2 is recognised by its preface and dropped as a whole connection | `latkit_ignored_conns_total{reason="h2"}` climbing. **This is the common case on a browser-facing TLS port**: ALPN picks h2 almost always |
| **gRPC** | is HTTP/2 | same counter |
| **HTTP/3** | QUIC is UDP; it never reaches `tcp_sendmsg`, so there is nothing to hook | `latkit_udp_bytes_total{port,dir}` non-zero, and a line in the agent's log naming the port |
| **WebSocket / any `Upgrade`** | after `101` the bytes are not HTTP any more | `latkit_ignored_conns_total{reason="upgrade"}` |
| **`CONNECT` tunnels** | a forward proxy's payload is somebody else's protocol | `latkit_ignored_conns_total{reason="connect"}` |
| **Unix-domain sockets** | `tcp_*` hooks are not on that path | nothing at all — check with `ss -xp` if a leg is missing |
| **`splice()`-relayed traffic** | e.g. docker-proxy on a published port, for connections originating on the same host | sends degrade to zero-payload events, receives are missed |

If the h2 counter is where all your traffic goes, the three honest options are:
capture the **origin** leg behind the TLS terminator (nginx talks HTTP/1.1
upstream by default), turn h2 off on the edge, or wait for an h2 track. Guessing
at HPACK state would be worse than counting.

## Plaintext vs TLS

- **A plaintext port** (an origin behind a TLS-terminating balancer, or a
  service mesh sidecar hop) needs nothing: set `LATKIT_TLS=off`,
  `cap_add: [BPF, PERFMON]`, and drop the `security_opt` block.
- **An OpenSSL server** (nginx, Apache/httpd, HAProxy) with `LATKIT_TLS=auto`
  is found by the `/proc` scan — with an `http` port configured the scan set is
  `{nginx, httpd, apache2, haproxy}` (РH13.1), so there is nothing to
  configure. In a container this needs `pid: host`,
  `cap_add: [BPF, PERFMON, SYS_PTRACE, SYS_ADMIN]` and
  **`security_opt: [apparmor=unconfined]`** (the `docker-default` profile
  blocks the cross-process `/proc/<pid>/root` read and the scan comes back
  empty *even with* `CAP_SYS_PTRACE` — see
  [docs/deploy.md](../../docs/deploy.md) "Minimal capabilities").
- **A Go server** (Caddy, Traefik, any `net/http`) has no `libssl` to find.
  Name the binary: `LATKIT_TLS_GO=/host/usr/bin/caddy`, bind-mounted read-only
  from the host at the *same file* (the uprobe binds to the inode, so both
  sides must see one inode). Stripped binaries — how Caddy, Traefik and MinIO
  are all shipped — are handled through Go's own function table. x86-64;
  [docs/notes-tls.md](../../docs/notes-tls.md) §4b.
- **A statically linked OpenSSL** (node, envoy): point `--libssl` /
  `LATKIT_LIBSSL` at the server binary itself.

> ### The trap: `LATKIT_TLS=auto` narrows what is captured at all
>
> With TLS capture on, the scan set is not only where latkit *looks for libssl*
> — it is also installed as the **kernel capture filter on the thread comm**.
> The reason is sound: a shared `libssl` uprobe fires for every process that
> maps the library, so something has to keep a `curl` or a `psql` on the same
> host out of the channel. The consequence is not obvious: with
> `LATKIT_TLS=auto` and no explicit `LATKIT_COMM`, **send/recv from a process
> whose comm is not in the set is dropped** — and the set is
> `{nginx, httpd, apache2, haproxy}` for an http port (plus the database three
> if you also capture a database port, plus `connection`).
>
> So an agent capturing `443=http,8080=http` with TLS on will report the nginx
> port and **silently see nothing on the 8080 leg** if that leg is served by a
> Go, Node, Python or Java process. The symptom is a port with connections but
> no observations, and it looks exactly like "the protocol is not HTTP".
>
> Three ways out, in order of preference:
> 1. **Is the port plaintext?** Then `LATKIT_TLS=off`. No filter is installed at
>    all, and every process on the captured ports is observed. An origin behind
>    a TLS-terminating balancer is this case.
> 2. **Name the Go binary** — `LATKIT_TLS_GO=/usr/bin/caddy` adds its comm to
>    the filter along with attaching its probes.
> 3. **One agent per role.** A second latkit with `LATKIT_PORT=8080=http` and
>    `LATKIT_TLS=off` next to the TLS one; the two capture disjoint ports, so
>    Prometheus scrapes both and nothing is counted twice.
>
> `LATKIT_COMM` is *not* a way out: it replaces the filter with exactly one
> comm, which is narrower still.

Verify TLS capture is live:

```sh
docker compose logs latkit | grep -i 'TLS uprobes'    # "attached on … (N probes)"
docker compose exec prometheus wget -qO- http://latkit:9752/metrics \
  | grep -E '^latkit_tls_(attached|connections|correlation_misses_total)'
# want: tls_attached{state="ok"|"go"} 1, connections growing, misses 0
```

> **For a production TLS install, prefer running the agent on the host as a
> systemd unit** ([`../systemd/latkit.service`](../systemd/latkit.service)):
> `/proc` is native, there is no container mount namespace or AppArmor barrier,
> and privileges are bounded by `CapabilityBoundingSet`. Set
> `LATKIT_PORT=443=http` and, if needed, `LATKIT_TLS_GO=/usr/bin/caddy` in
> `/etc/latkit/latkit.env`.

## Route labels: the one thing worth tuning

A URL space is unbounded by construction, so `route` is a **template**, and the
top-K dictionary bounds it whether or not the template is right. Two panels tell
you how it is going:

- **route="other" share** — requests whose route did not fit the dictionary. A
  large or growing share means either genuinely many routes (raise
  `LATKIT_TOP_QUERIES`) or a templater that is not recognising your ids;
- **Top routes** — read the list. If you see one route per customer slug, per
  filename or per e-mail address, the heuristic did not know those were
  identifiers. That is what `LATKIT_HTTP_ROUTES` is for: a file of
  `METHOD /path/{id}` patterns, first match wins, everything unmatched still
  falls through to the heuristic (format and trade-offs:
  [`../demo-http/routes.map`](../demo-http/routes.map)).

`LATKIT_HTTP_ROUTE_HEADER=X-Route` is the third option — trust a route the
application already computes and sends in a header. It is off by default because
that header is client-controllable input; only the top-K limit stands between it
and your series count.

## Privacy

URLs and headers are the most talkative data this agent has ever seen, so the
rules are structural rather than advisory (РH12):

- **only the template reaches a label.** Raw paths, query strings, headers and
  bodies never enter the metrics registry at all;
- **credential-looking query values are redacted** (`token`, `sig`,
  `password`, `key`, `code`, … → `***`) wherever a request target leaves the
  handler — spans included. `LATKIT_HTTP_REDACT=off` disables it, deliberately
  spelled as a value so it shows up in a config review;
- **`Authorization` is never decoded** beyond the user name, and only if you
  ask (`LATKIT_HTTP_USER=basic`). Bearer tokens are not touched at all;
- **spans are off unless you configure an OTLP endpoint**, and a sampled span
  is the only thing that carries a `url.path` off the host.

## Troubleshooting ladder

Isolate top-down; each step says which layer is at fault.

1. **Agent capturing?**

   ```sh
   docker compose exec prometheus wget -qO- http://latkit:9752/metrics | grep -E \
     '^latkit_(connections_active|events_total|http_requests_total|ignored_conns_total|udp_bytes_total)'
   ```

   - `connections_active > 0` comes from the `inet_sock_set_state` tracepoint;
     `events_total` from the `tcp_*` data path. Their divergence localises the
     break;
   - `events_total` grows, `http_requests_total` empty → the bytes are not
     readable HTTP/1.x: check `ignored_conns_total{reason}` (h2 / upgrade /
     connect) and, on an HTTPS port, whether the uprobes attached;
   - **one captured port reports and another does not** → almost always the
     comm-filter trap above: turn `LATKIT_TLS=off` and see whether the silent
     port comes to life;
   - everything flat, `udp_bytes_total` growing → HTTP/3;
   - everything flat and no UDP either → the port filter does not match (wrong
     `LATKIT_PORT`), the traffic is on a unix socket, or `pid: host` is missing.

2. **Prometheus scraping?** <http://localhost:9090/targets> — job `latkit` UP.

3. **Grafana?** Datasource *Test* green; time range **Last 15 minutes**; check
   the host clock (`timedatectl`).

## Ports

Grafana `127.0.0.1:3000`, Prometheus `127.0.0.1:9090`; the agent's `9752` is not
published (Prometheus scrapes it over the compose network). Edit the `ports:`
mappings if any clash.
