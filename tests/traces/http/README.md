# tests/traces/http — М0 reference trace corpus (HTTP/1.x)

Raw `--record` (LKT1) traces of real HTTP/1.x sessions, captured with the stock
agent **before any HTTP protocol code exists** — the capture layer is
protocol-independent (`--port 8080`, the default pg framer runs and finds
nothing, which is fine: `--record` writes the raw ringbuf records). This corpus
is the raw material for the М2/М3 replay fixtures and the fuzzer seed corpus,
and the ground truth [notes-httpproto](../../../docs/notes-httpproto.md) was
cross-checked against (PLAN-HTTP.md, этап М0).

Each trace is **one client session**: `CONN_OPEN` + data events (both
directions, capture budget 8192 bytes per syscall unless the name says
otherwise) + `CONN_CLOSE`. Traces are little-endian, recorded on x86-64,
kernel 7.0.0.

## Layout

```
nginx/      nginx 1.29-alpine: static (sendfile on), reverse proxy, h2c, TLS
go/         Go 1.26 net/http          (backends/go)
node/       node 22 + express 5       (backends/node)
gunicorn/   gunicorn + Flask 3, sync worker, 2 workers (backends/gunicorn)
```

All four serve the same route contract (`/hello`, `/json/<id>`, `/big`,
`/auto`, `/chunked`, `/echo`, `/slow`, `/boom`, `/redirect`, `/truncate`,
`/ws`), nginx statically where it can and by proxying to the Go backend where a
file server cannot — static and reverse proxy are nginx's two real modes and
the corpus needs both. File name = `<scenario>.lkt`.

## Scenarios

| Scenario | What it exercises |
|---|---|
| `get` | the base case: one request, one response, `Content-Length` |
| `get-large` | 1 MB response body — arithmetic skip (and, on nginx, `sendfile`) |
| `post` | 64 KB request body with `Content-Length` (РH5's upload interval) |
| `chunked-resp` | `Transfer-Encoding: chunked` response, several chunks |
| `chunked-req` | chunked *request* body with a trailer |
| `continue` | `Expect: 100-continue` → interim `100` then the final response (all four send it) |
| `keepalive-50` | 50 units on one connection |
| `pipelined` | four requests in one write: in-flight depth > 1 |
| `statuses` | 404 + 500 + 302 on one keep-alive connection |
| `head` | `HEAD`: a `Content-Length` describing a body that never comes |
| `options` | `OPTIONS` |
| `slow-response` | 250 ms before the first response byte (TTFB ≠ duration) |
| `huge-head` | 16 KB request header block |
| `huge-head-cap2048` | the same head under `--capture-limit 2048` (РH14 budget) |
| `slow-client` | the request head written one byte at a time |
| `abort-midbody` | client RSTs in the middle of a 1 MB response |
| `torn-body` | request promises 4096 body bytes, sends 100, hangs up |
| `truncated-resp` | response promises 64 KB, delivers 1 KB, connection dies |
| `absolute-form` | `GET http://host/path HTTP/1.1` (proxy-style target) — accepted by all four |
| `cl-te` | `Content-Length` **and** `Transfer-Encoding`: 400 from nginx/node/gunicorn, **200 from Go** |
| `lf-only` | bare LF line endings: 200 from nginx and Go, 400 from node, no answer at all from gunicorn |
| `bad-request` | binary garbage where a start line belongs |
| `traceparent` | W3C trace context, `X-Request-Id`, `Authorization`, `Cookie` |
| `h2c-upgrade` | `Upgrade: h2c` + `HTTP2-Settings` — all four ignore it and answer HTTP/1.1 200 |
| `h2-preface` | prior-knowledge HTTP/2 preface sent to an HTTP/1.1 server (400 everywhere) |
| `websocket` | `Upgrade: websocket` → `101` → opaque frames |
| `connect` (go) | `CONNECT` tunnel: opaque bytes after `200` |
| `chunked-default` (go) | Go's chunked-without-being-asked shape |
| `sendfile-static` (nginx) | 8 MB static file, `sendfile on` (the default) |
| `nosendfile-static` (nginx) | the same 8 MB through the socket — the control |
| `proxy-both-legs` (nginx) | front (8080) **and** upstream (8082) legs in one trace |
| `h2c-prior` (nginx) | cleartext h2 by prior knowledge, `http2 on` |
| `tls` (nginx) | TLS on the socket: ciphertext only. Since М7 the framer recognises the handshake record and marks the connection TLS, so this trace yields no observations *and* no parse errors |
| `tls-decrypted` (nginx) | the same load with libssl uprobes — plaintext, and curl's ALPN makes it **h2 inside TLS**, i.e. a blind zone inside a TLS connection |
| `tls-decrypted-h1` (nginx) | `--http1.1`: plaintext HTTP/1.1 through the uprobe channel — the М7 acceptance case, two ordinary observations |

113 traces total (nginx 33, go 28, node 26, gunicorn 26); 5.4 MB.

## Recording and validating

```
./record.sh              # brings up the stand, records everything
./record.sh go           # one server; KEEP=1 leaves the stand running
```

Requirements: docker, passwordless sudo (BPF), go, node+npm, python3, curl,
openssl; the agent binary from `build-rel` (or `LATKIT=path`). nginx runs as a
container **on the host network** and the other three servers are host
processes — published container ports would put docker-proxy in the middle with
the same local port and double every connection in the capture.

Validate / summarise (replays every record through `lk_replay_file` +
`lk_ev_decode`, fails on any malformed record):

```
cmake --build build --target lkt_info
build/tests/replay/lkt_info tests/traces/http/*/*.lkt
```

## Reconnaissance (М0), with the evidence

`./recon.sh` re-runs all five items and leaves the raw output in
`.work/recon/`. The findings below are from the run of 2026-08-08 on kernel
7.0.0-27-generic.

### 1. `sendfile` — the body bypasses the socket, but not the probe

`.work/recon/01-sendfile.txt`. Twenty 8 MB static responses, nginx worker
syscall census:

| `sendfile on` (default) | `sendfile off` |
|---|---|
| 273 `sendfile`, 20 `writev`, 20 `write` | 5120 `writev`, 20 `write` |

So yes: with the default config the body never appears in a socket write, only
the header block does (the 20 `writev`s). **But the agent still sees the body**
— since ~6.5 the kernel routes splice/sendfile through `sendmsg` with
`MSG_SPLICE_PAGES`, so `tcp_sendmsg` fires with an honest `total_len` and a
page iterator the probe cannot copy from. One `/huge` + one
`/nosendfile/huge.bin`:

```
latkit: stats events=659 drops=0 bytes=2097591/17232115 captured/total
        iter_unsupported=139 recv_miss=0
```

`bytes_out` and the arithmetic body skip both work off lengths, so on this
kernel `sendfile` costs us **payload we do not want anyway**, not accounting.
The trace pair shows the same thing: `sendfile-static.lkt` is 46 KB for an 8 MB
response, `nosendfile-static.lkt` is 2.1 MB.

**Consequence for РH4:** `LK_QO_BODY_UNSEEN` stays in the design as the
*old-kernel* case (before the splice→sendmsg conversion, `sendfile` used
`do_tcp_sendpages` and produced no event at all). The support matrix includes
5.15, so М7/М8 must measure both ends of the range, and the degradation needs a
synthetic replay fixture rather than the local kernel's behaviour.

### 2. chunked — a third to two thirds of real responses

`.work/recon/02-framing.txt`, 240 responses (4 servers × 15 routes × 4 client
profiles):

| server | Content-Length | chunked |
|---|---|---|
| gunicorn (Flask, sync worker) | 93.3 % | 6.7 % |
| Go net/http | 66.7 % | 33.3 % |
| nginx (static + proxying Go) | 66.7 % | 33.3 % |
| node + express | 40.0 % | **60.0 %** |

The `/auto?n=` sweep (one write, no explicit `Content-Length`, no flush) shows
where each stack gives up on computing a length:

```
server          64     512    1024    2048    4096    8192   16384   65536
go              CL      CL      CL      CL   chunk   chunk   chunk   chunk
gunicorn        CL      CL      CL      CL      CL      CL      CL      CL
nginx           CL      CL      CL      CL   chunk   chunk   chunk   chunk
node         chunk   chunk   chunk   chunk   chunk   chunk   chunk   chunk
```

- **node's core `http` never computes a length** — express's `res.send` does,
  which is why express routes show up as `Content-Length` and the raw
  `res.end()` route is chunked at every size.
- **Go switches at ~2 KB** (its response buffer): a handler that does not set
  `Content-Length` and writes more than that is chunked.
- **werkzeug/gunicorn always knows the length** for a str/bytes body and only
  goes chunked for generator responses.
- nginx mirrors its upstream: small chunked upstream responses come out with a
  `Content-Length` (it buffers them whole), larger ones stay chunked.

**Consequence for risk 4 of the plan:** well above the 10 % threshold the plan
set for "then implement real chunk parsing". М2 must parse chunk sizes properly
and fall back to anchor scanning only on holes — chunked is a main path.

### 3. Go symbols — the servers this plan names are all stripped

`.work/recon/03-go-symbols.txt`:

```
our build (default)            symtab=yes tls_syms=2  pclntab=section    name_in_file=2  go1.26.0
our build (-ldflags -s -w)     symtab=no  tls_syms=0  pclntab=section    name_in_file=1  go1.26.0
host: /usr/bin/docker          symtab=yes tls_syms=2  pclntab=section    name_in_file=2  go1.26.4
host: /usr/bin/containerd      symtab=no  tls_syms=0  pclntab=no-section name_in_file=1  go1.25.11
host: /usr/bin/runc            symtab=no  tls_syms=0  pclntab=no-section name_in_file=0  go1.25.11
host: /usr/bin/docker-proxy    symtab=yes tls_syms=0  pclntab=section    name_in_file=0  go1.26.4
host: /usr/bin/ctr             symtab=no  tls_syms=0  pclntab=no-section name_in_file=1  go1.25.11
host: /snap/bin/kubectl        symtab=no  tls_syms=0  pclntab=section    name_in_file=1  go1.26.0
image: caddy:2                 symtab=no  tls_syms=0  pclntab=section    name_in_file=1  go1.26.3
image: traefik:v3.3            symtab=no  tls_syms=0  pclntab=section    name_in_file=1  go1.23.8
image: minio/minio:latest      symtab=no  tls_syms=0  pclntab=section    name_in_file=1  go1.24.6
```

`tls_syms` is what `nm` finds; `name_in_file` is whether the literal
`crypto/tls.(*Conn).Write` exists anywhere in the file (it lives in pclntab's
name table, which `-s -w` keeps).

**Caddy, Traefik and MinIO — the three Go servers PLAN-HTTP.md and
PLAN-MINIO.md name by name — all ship `-s -w` binaries with no ELF symbol
table.** Only a `go build` with default flags (our own build, and Docker's CLI)
keeps one. The function *names* survive in every case, in `.gopclntab` for the
statically-linked binaries and, for the cgo/externally-linked ones
(containerd, runc, ctr), somewhere that is not even a `.gopclntab` section and
has to be found by scanning for the pclntab header.

**Consequence for РH13.3:** the plan's premise ("Go keeps its symtab by
default; with `-s -w` only `.gopclntab` remains — a possible extension") is
backwards for distributed binaries. Parsing `.gopclntab` is the **main path**,
not a fallback; `nm` covers only self-built services. `go tool nm` does not
help — it reads the same ELF symtab and returns nothing on these binaries. This
is a real scope increase for М7 and an argument for keeping М7 deferrable, as
the plan already allows.

**Resolved in М7:** `src/agent/go_pclntab.c` reads the function table, so
`--tls-go` resolves `crypto/tls.(*Conn).Read/Write` in exactly these stripped
binaries — verified against this Caddy image, whose two functions decode into 8
and 7 return sites. The symbol table is still tried first (it is what a
self-built server has) and gives byte-identical addresses on a binary carrying
both. The cgo-linked binaries in the table above (containerd, runc, ctr), whose
pclntab has no section of its own, remain out of scope — none of them is a
server this track observes.

### 4. HTTP/2 over TLS — 4 of 10 client shapes, and every browser

`.work/recon/04-h2.txt`. One request per client shape to the same
`https://…:8443/hello`, nginx logging `$server_protocol` and
`$ssl_alpn_protocol`:

| client | ALPN | protocol |
|---|---|---|
| curl (default) | h2 | **HTTP/2** |
| chromium 150 (headless, real browser) | h2 | **HTTP/2** |
| java.net.http (default `HttpClient`) | h2 | **HTTP/2** |
| Go `net/http` with `ForceAttemptHTTP2` (= `http.DefaultTransport`) | h2 | **HTTP/2** |
| curl `--http1.1` | http/1.1 | HTTP/1.1 |
| java.net.http pinned to `HTTP_1_1` | http/1.1 | HTTP/1.1 |
| Go with a custom `Transport{TLSClientConfig}` | — | HTTP/1.1 |
| Go with h2 explicitly disabled | — | HTTP/1.1 |
| python `urllib` (= what urllib3/requests do) | — | HTTP/1.1 |
| node `fetch` (undici) | — | HTTP/1.1 |

Tally for the run: 4 HTTP/2, 6 HTTP/1.1.

Two things worth carrying into the README of the release:

- **A browser over TLS is h2, always.** Any "put latkit in front of your web
  site" story is an h2 story, i.e. a blind zone.
- **Go's h2 is opt-in in practice.** `http.DefaultTransport` negotiates h2, but
  the moment a service sets its own `TLSClientConfig` on a custom `Transport`
  (the normal thing to do for custom CAs or timeouts) Go silently stops
  offering h2 and the connection is HTTP/1.1. Service-to-service Go traffic is
  therefore much more often HTTP/1.1 than the "Go clients speak h2" folklore
  suggests — which is good news for this plan's target audience.
- python and node clients do not offer ALPN at all.

### 5. Header block sizes vs the capture budget

`.work/recon/05-head-sizes.txt`. Request heads by client profile, response
heads by server (bytes):

```
request head    n    min    p50    p90    p99    max        response head    p50   max
browser        60    958    965    966    966    966        go               129   187
sdk            60    415    422    423    423    423        gunicorn         156   175
curl           60    100    107    108    108    108        nginx            151   255
minimal        60     63     70     71     71     71        node             129   221
```

nginx's own `$request_length` over the same sweep: `n=60 p50=415 p99=966
max=966`, **0 % above a 1024-byte budget**.

**Consequence for РH14:** a 2048-byte per-call budget is comfortable for
everything but browser traffic with a fat cookie jar, and the thing it has to
be measured against is not the header block but the **size of a single
`read`/`write` call** — servers read heads in 4–16 KB chunks, so a 16 KB head
arrives as several events and each is truncated independently. The corpus
proves it: `huge-head.lkt` (8 KB default budget) has `trunc=0` on Go and
`trunc=3` on nginx, while `huge-head-cap2048.lkt` truncates 1–4 events on every
server. Truncation is a flagged normal outcome, not a loss of the route: the
start line and the framing headers always arrive in the first event.

## Findings recorded while capturing (feed into М1/М2)

- **`--port N` without a protocol still records fine.** The pg framer runs over
  HTTP bytes and counts a couple of `dirty: badlen` per connection; it never
  touches capture (capture mode is BPF-side and only the TLS/CANCEL/replication
  policy changes it), so the corpus is the full-fidelity raw stream.
- **`total_len` is per *syscall*, and repeats on every chunk event of that
  call.** One 1 MB `writev` from node produces three events, all carrying
  `total=1048744` with `off` advancing (`cap=168`, `4096`, `3928`). Byte
  accounting in М3 must therefore take `total_len` once per call (`off == 0`),
  never sum it per event — and `lkt_info`'s `bytes=cap/total` column is a tally,
  not a capture ratio.
- **A pipelined burst arrives as one `recv` event**, not four — every
  `pipelined.lkt` in the corpus has `recv=1`. The framer's stream mode must be
  able to emit several request heads out of a single event.
- **How much of a head is truncated depends on the server's read buffer.**
  nginx (with `large_client_header_buffers 8 32k`) reads a 16 KB head in one
  call and loses the tail even at the 8 KB default budget (`trunc=3`), while Go
  and gunicorn read in ≤ 8 KB chunks and lose nothing (`trunc=0`).
- **Loopback plus `--network host` is the honest stand.** Publishing container
  ports inserts docker-proxy, whose own local port matches the filter, and
  every connection appears twice.
- The Go backend's `/truncate` route and the client-side `abort-midbody` are
  the two directions of a broken transfer; both leave the unit unterminated on
  the wire, and both must be closed by `CONN_CLOSE` rather than by a timeout.
