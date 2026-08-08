# notes-httpproto: HTTP/1.x on the wire — framing, units, body length, blind spots

Design notes backing the HTTP track ([PLAN-HTTP.md](../PLAN-HTTP.md), Russian,
decisions РH1–РH16). This is the wire-level conspectus the М2 framer and М3
handler will be written against — the same genre as
[notes-pgproto](notes-pgproto.md) and [notes-myproto](notes-myproto.md), and,
like the latter, written *before* the code: it fixes what we believe the
protocol does, which headers we read, how we decide where a body ends, and
where we stay blind on purpose. Primary sources are RFC 9110 (semantics) and
RFC 9112 (HTTP/1.1 message syntax); every claim that matters is cross-checked
against the recorded traces in `tests/traces/http/` (М0 corpus — four real
servers × the framing shapes that matter).

Scope guard: **HTTP/1.0 and HTTP/1.1, server side, plaintext or through the
existing TLS channel**. HTTP/2 is detected and treated as a named blind zone;
HTTP/3 is not even detectable at our capture point. The reasoning for both is
§8 of the plan and is not repeated here — this document only records what the
framer does when it meets them.

## Framing: a text protocol with no length prefix

```
 request                                  response
 ─────────────────────────────────────────────────────────────────────
 GET /orders/42?x=1 HTTP/1.1\r\n          HTTP/1.1 200 OK\r\n
 Host: shop.example\r\n                   Content-Type: text/html\r\n
 User-Agent: curl/8.5.0\r\n               Content-Length: 137\r\n
 \r\n                                     \r\n
 [ body, length decided by the headers ]  [ body, length decided by the headers ]
```

Everything the other two protocols get from a fixed header — where a message
starts, how long it is, what type it is — HTTP encodes in text that has to be
scanned for. Three consequences drive the design:

- **`hdr_size()`/`parse_hdr()` do not apply.** The `lk_proto_ops` contract
  hands the framer a fixed number of bytes to accumulate in `f->hdr[8]`; an
  HTTP head is 63 bytes at the low end and kilobytes at the high end (measured:
  §"Sizes" below). Hence the stream mode of РH1 — the protocol receives raw
  bytes and holes and does its own message assembly.
- **The head is scanned, the body is counted.** Only the head is parsed
  byte-by-byte, up to the `\r\n\r\n` terminator; the body is an arithmetic skip
  whenever its length is knowable in advance, which is the common case (§"Body
  length"). This keeps the cost per byte on large uploads and downloads at
  zero.
- **Resync is cheap and reliable.** After a hole, the text of the next start
  line is a strong anchor — much stronger than anything PG or MySQL offer
  (§"Resync").

### Start lines

```
 request-line = method SP request-target SP HTTP-version CRLF
 status-line  = HTTP-version SP status-code [ SP reason-phrase ] CRLF
```

- **method** is a case-sensitive token; we recognise `GET HEAD POST PUT DELETE
  CONNECT OPTIONS TRACE PATCH` by name (RFC 9110 §9 plus PATCH from RFC 5789)
  and accept any other token as `method="other"` for the counters — an unknown
  method must never desync the framer, only lose a label. The name list is also
  the resync anchor alphabet, so it stays short on purpose: WebDAV verbs
  (`PROPFIND`, `MKCOL`, …) parse fine but are not anchors.
- **request-target** has four forms, and all four appear in the corpus:
  | Form | Looks like | Used by | What we do |
  |---|---|---|---|
  | origin-form | `/orders/42?x=1` | every ordinary request | path + query → route (РH7) |
  | absolute-form | `http://shop.example/orders/42` | proxies, and any client that feels like it | authority overrides `Host` for the `host` label |
  | authority-form | `shop.example:443` | `CONNECT` only | blind zone, tunnel |
  | asterisk-form | `*` | `OPTIONS *` | route `*`, no templating |
- **HTTP-version** is `HTTP/1.0` or `HTTP/1.1` (`HTTP/0.9`, a bare `GET /path`
  with no version, is not supported: it is treated as a malformed head). The
  version goes into the `proto` label and changes two defaults: keep-alive and
  chunked (§"HTTP/1.0").
- **status-code** is exactly three digits; the reason phrase is ignored (it is
  optional in RFC 9112 and empty in real servers often enough — nginx's
  `HTTP/1.1 200 OK` vs a bare `HTTP/1.1 204` both parse).

### Header fields

```
 field-line = field-name ":" OWS field-value OWS CRLF
```

- **Names are case-insensitive** (`content-length` ≡ `Content-Length`) and must
  have no space before the colon — `Header : value` is malformed and rejected
  (it is a classic request-smuggling primitive, not a quirk to be forgiving
  about).
- **Values** are compared case-insensitively for tokens we act on
  (`chunked`, `close`, `100-continue`, `websocket`, `h2c`), byte-exactly for
  values we carry (`Host`, `traceparent`).
- **`obs-fold`** (a continuation line starting with SP/HTAB) is obsolete in RFC
  9112 §5.2 and must be rejected in requests. We reject it in both directions:
  it desynchronises header parsing between hops, which is exactly the class of
  bug that turns into smuggling.
- **Bare LF** as a line terminator: RFC 9112 §2.2 permits a recipient to accept
  it, and servers disagree in practice. Measured on the М0 corpus
  (`lf-only.lkt`): nginx and Go answer `200`, node answers `400`, gunicorn
  answers nothing at all and lets the connection die. The framer therefore
  accepts `LF` as well as `CRLF` for line ends *and counts it* — an observer
  that rejected LF-only would go blind exactly where the server did not, and
  knowing a client speaks LF-only is what explains a later disagreement with an
  access log.
- **The head ends** at the first empty line (`\r\n\r\n`, or `\n\n` in the
  LF-only case). The framer accumulates until then, capped at
  `LK_MSG_BODY_MAX`; a head longer than the cap is a parse error
  (`head_too_big`), the direction goes dirty and resyncs on the next start
  line. A head longer than the *capture budget* is an entirely different (and
  normal) situation — see §"Sizes".

### Headers of interest

Everything else is skipped without being copied anywhere. The list is short by
design: what is not read cannot leak (РH12).

| Header | Direction | Why |
|---|---|---|
| `Host` | request | the `host` label (db slot, РH10); absolute-form target wins over it |
| `Content-Length` | both | body length; duplicates/conflicts → reject (below) |
| `Transfer-Encoding` | both | `chunked` framing; anything else → treat as until-close |
| `Connection` | both | `close` ends the unit and the connection; `upgrade` is a blind-zone marker |
| `Upgrade` | both | `websocket`, `h2c`, anything → blind zone with a reason |
| `Expect` | request | `100-continue` predicts an interim response |
| `Content-Type` | response | first token only, span attribute |
| `User-Agent` | request | session label, span attribute |
| `traceparent`, `tracestate` | request | W3C trace context (РH11) |
| `X-Request-Id`, `X-Amzn-Trace-Id` | request | span attribute; the join key of the accuracy bench |
| `Authorization` | request | **only** with `--http-user basic`, and only the name before the colon (РH10); `Bearer` is never touched |
| `Cookie`, `Set-Cookie`, `Proxy-Authorization` | both | never read — masked in `--messages` output (РH3) |

## Body length: the decision list, in order

RFC 9112 §6.3 is a numbered list and the order is not negotiable — most
request-smuggling bugs are a hop that reordered it. Ours, adapted to a
passive observer:

1. **Responses that cannot have a body**, regardless of headers: any `1xx`,
   `204`, `304`, and *any* response to a `HEAD` request. The corpus has a
   `head` trace per server precisely because a `HEAD` response carries a
   `Content-Length` describing a body that will never arrive: reading it as a
   body length desynchronises the connection for every following request.
   This is why the framer must track the request method to parse the response
   — the two directions of a unit are not independent.
2. **A 2xx response to `CONNECT`**: everything after the head is tunnel
   payload. Blind zone, connection ignored from that point (РH4).
3. **`Transfer-Encoding` present.** If the final encoding is `chunked`, the
   body is chunked-framed; if it is anything else (`gzip` alone — legal, seen
   in the wild only from broken servers), we cannot know the length and fall
   back to until-close. **`Transfer-Encoding` together with `Content-Length` is
   rejected outright** (RFC 9112 §6.1: the message is unrecoverable), the
   direction goes dirty and resyncs — this is the CL+TE desync shape, and the
   corpus carries a `cl-te` trace per server for it. Servers do not agree here
   either: nginx, node and gunicorn answer `400`, **Go answers `200`** (it
   drops the `Content-Length` and reads the chunked body). Rejecting is still
   the right observer behaviour: when two hops disagree about where a message
   ends, any length we pick is a guess, and a dropped unit is honest where a
   guessed one is not.
4. **`Content-Length`**: one field, all digits, no duplicates with different
   values. Duplicate identical values are folded (RFC 9110 allows the
   comma-separated form `Content-Length: 5, 5`); conflicting values are
   rejected like CL+TE.
5. **Neither, in a request**: the body length is zero. A request body without a
   framing header is not readable by any server, so there is nothing to skip.
6. **Neither, in a response**: the body runs until the connection closes. The
   unit closes on `CONN_CLOSE`, and `Connection: close` in the head is the
   advance warning.

### chunked, and why a hole in it hurts

```
 1a\r\n                      chunk-size in hex, optional ";ext=value"
 chunk-0-xxxxxxxxxxxxx\r\n   chunk-data, exactly that many bytes
 …
 0\r\n                       last chunk
 X-Checksum: deadbeef\r\n    optional trailer fields
 \r\n
```

The sizes live *in the byte stream*, so unlike `Content-Length` the framer
cannot skip a chunked body arithmetically over a capture hole: one lost chunk
header and every subsequent byte is misread. The rule of РH4: while the body is
chunked and a hole arrives, the direction switches to "scan for the next start
line" and `chunked_scan` counts it. The unit is not silently mis-attributed —
it is dropped like any resync loss.

This matters more than it looks. Reconnaissance item 2 (`tests/traces/http`
README) measured the framing choice of four real servers across 240 responses:
**node's core `http` writes chunked at every body size, Go's `net/http`
switches to chunked above ~2 KB when the handler does not set a length, and
gunicorn/werkzeug never does**. Chunked is not a corner case, it is a third to
two thirds of the responses from a modern backend. Whatever М2 does with holes
in chunked bodies is a main-path decision, not an edge case.

Trailers are parsed only far enough to find the terminating empty line; their
contents are not read.

## Interim responses (1xx) and `Expect: 100-continue`

```
 client                                   server
 ──────────────────────────────────────────────────────────────
 POST /upload HTTP/1.1
 Content-Length: 4096
 Expect: 100-continue          ──▶
                               ◀──  HTTP/1.1 100 Continue\r\n\r\n     (interim)
 [ 4096 body bytes ]           ──▶
                               ◀──  HTTP/1.1 200 OK …                 (final)
```

- An interim response is any `1xx`: head only, never a body, **does not close
  the unit**. It is emitted as message type `'I'` (РH3) and its timestamp is
  kept — the gap between the request head and the `100 Continue` is the only
  server-side signal available before the upload starts.
- A server is free to skip the `100` and answer the final status immediately
  (an error, typically `417` or `404`); a client is free to send the body
  without waiting after a timeout. Both shapes must parse. The corpus records
  the well-behaved shape per server; all four (nginx, Go, node, gunicorn) do
  send the `100`.
- `103 Early Hints` is the same machinery and appears in front of `200` on
  real CDNs; nothing special is needed as long as "1xx does not close the unit"
  is honoured.

## Units, keep-alive, pipelining

A **unit** opens on a request head and closes at the end of the response body
(РH6). Between those points the FIFO of in-flight units is the PG handler's
existing ring:

- **keep-alive** is the HTTP/1.1 default: N units on one connection, strictly
  ordered. The corpus `keepalive-50` traces are 50 units on one socket.
- **pipelining** — several requests written before the first response arrives —
  makes the queue deeper than one; the responses come back in request order, so
  the FIFO is sufficient and `LK_QO_PIPELINED` marks the units. Real browsers
  do not pipeline; scripts and load generators do, and a `pipelined` trace per
  server is in the corpus.
- `Connection: close` (or HTTP/1.0 without `Connection: keep-alive`) means the
  unit is the last one; the body may be length-less (rule 6 above).
- A successful `Upgrade` (`101`) or `CONNECT` (`2xx`) ends the unit and turns
  the rest of the connection into a blind zone.
- A resync drops every in-flight unit into the existing `units_dropped_resync`
  counter. Nothing about HTTP changes that accounting.

## Timings (РH5)

```
  ts_start          ts_req_done        ts_first_row        ts_complete
     │                   │                   │                   │
     ├── request head ───┼── request body ───┤                   │
     │                   ├──── server work ──┼─ response body ───┤
     │                                       │                   │
     └──────────────── the span covers this whole interval ──────┘

   duration = ts_complete − ts_req_done      (server-side truth)
   ttfb     = ts_first_row − ts_req_done
   upload   = ts_req_done − ts_start         (client's upload, its own family)
```

For a `GET` the three models coincide because the request head arrives in one
event. For a `POST` of any size they do not, and the difference is the client's
upload time — a number that says nothing about the server. This is why the
plan spends a field on it rather than reporting one duration.

Reference points for the accuracy bench (М8): nginx's `$request_time` is *the
whole* interval (`ts_start … ts_complete`), `$upstream_response_time` is the
proxy leg only. Neither equals our `duration`; the mapping is
`$request_time ≈ ts_complete − ts_start`, and that identity is what the bench
checks.

## Resync: the strongest anchors of the three protocols

After a hole the framer scans for text, not for a byte pattern:

- **Request direction:** `METHOD SP <target> SP HTTP/1.[01]\r\n`, with METHOD
  from the known list. Matching requires the version token at the end of the
  line, which is what makes it strong: the three-part shape with a fixed tail
  is not something a body produces by accident.
- **Response direction:** `HTTP/1.[01] SP [1-5][0-9][0-9]` — even stronger,
  since it is anchored at the line start and the digits are constrained.
- The match slides across event boundaries (a torn anchor is remembered, like
  PG's `Z` anchor), and a syscall boundary (`off == 0`) raises confidence but
  is not required: unlike a database command, an HTTP request is not guaranteed
  to start its own `write`, because pipelining exists.
- False positives are possible in a body that contains HTTP text (a proxy
  logging its own traffic, an HTML page with a code sample). They cost one
  wrongly-framed unit and are corrected at the next real anchor; the counter
  `resync_scan` makes them visible. This is an accepted, documented cost, in
  the same spirit as the PG/MySQL resync notes.

## Blind spots (known, by design)

Every one of these gets its own `reason` in `latkit_conns_ignored_total`, and
each has a trace in the corpus so М2 can prove it detects them:

| Blind spot | How it is recognised | Cost |
|---|---|---|
| **HTTP/2** | the preface `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` as the first client bytes (prior knowledge, and the same bytes after ALPN inside TLS) | whole connection; **gRPC is HTTP/2, so gRPC is not supported** |
| **h2c upgrade** | `Upgrade: h2c` + `HTTP2-Settings` in a request; **only a `101` response makes it real** | whole connection past the `101`. Measured: none of nginx 1.29, Go, node or gunicorn accepts the upgrade — all four answer an ordinary HTTP/1.1 `200`, so the request alone must not be treated as a blind zone |
| **WebSocket** | `Upgrade: websocket` + a `101` response | connection after the `101`; the handshake unit itself is observed |
| **CONNECT tunnel** | `CONNECT` + a `2xx` response | connection after the response head |
| **TLS without an attached uprobe** | existing TLS detection | whole connection, existing counter |
| **HTTP/3 / QUIC** | *not detectable* — UDP never reaches `tcp_sendmsg` | invisible; РH16's UDP byte counter exists so this looks like QUIC rather than like a broken agent |

### `sendfile`, and a measurement that changes the story

nginx serves static files with `sendfile(2)` by default, and РH4 assumed that
means the response body never reaches `tcp_sendmsg`, leaving `bytes_out` a
lower bound and the unit closing only on the next request head
(`LK_QO_BODY_UNSEEN`).

Measured on the М0 stand (kernel 7.0, evidence in the corpus README, item 1):
nginx really does use `sendfile` for the body (273 `sendfile` calls vs 20
`writev` for 20 × 8 MB responses — the `writev`s are the header blocks), **but
the agent still sees the body events**. Since ~6.5 the kernel routes
splice/sendfile through `sendmsg` with `MSG_SPLICE_PAGES`, so `tcp_sendmsg`
fires with an honest `total_len` and a page iterator the probe cannot copy from
(`iter_unsupported=139` for one 8 MB response, `bytes=…/17232115`
captured/total). For this plan that is the good case: byte accounting and the
arithmetic body skip both work off lengths, and the payload of a body is
something we deliberately do not want.

The `LK_QO_BODY_UNSEEN` degradation therefore stays in the design, but as the
**old-kernel** case: before the splice-to-sendmsg conversion, `sendfile` used
`do_tcp_sendpages` and produced no `tcp_sendmsg` event at all. The support
matrix includes 5.15, so М7/М8 must measure both ends of the range and the
degradation must be exercised by a synthetic replay fixture rather than by
trusting the local kernel.

## HTTP/1.0 differences

- **No `Host` requirement.** A 1.0 request may have no `Host` at all → the
  `host` label falls back to `-` (РH10). Absolute-form targets are the other
  source.
- **No chunked.** `Transfer-Encoding: chunked` is a 1.1 feature; a 1.0 response
  without `Content-Length` runs until close, which is the normal shape for old
  CGI backends.
- **Keep-alive is opt-in** via `Connection: keep-alive` on both sides; the
  default is one unit per connection.
- nginx talks 1.0 to upstreams unless `proxy_http_version 1.1` is set — so the
  1.0 shapes show up on the *upstream* leg of a perfectly modern stack, which
  is exactly where the agent stands. The corpus records both legs of a reverse
  proxy in one trace (`nginx/proxy-both-legs.lkt`).

## `traceparent` (РH11)

```
 traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
              ^^ ^-------- trace-id, 32 hex -----^ ^-parent-id, 16-^ ^^ flags
```

- Accepted only in the exact W3C shape: version `00`, four dash-separated
  fields, lowercase hex of the right lengths, trace-id and parent-id not
  all-zero. Anything else is ignored — a malformed header must not produce a
  span attached to a made-up trace.
- `flags & 0x01` is `sampled`. A non-sampled request still may be exported by
  the slow-query threshold; that asymmetry is deliberate and documented.
- `tracestate` is carried through verbatim, unparsed, size-capped.
- Without a valid `traceparent` the span keeps today's behaviour: its own trace
  id, no parent.

## Sizes: what the capture budget actually meets

Reconnaissance item 5 measured header blocks on the stand:

- **Request heads**: 63 B minimal, ~107 B for curl, ~420 B for a typical SDK
  client (bearer token + trace context), **~966 B for a real browser profile
  with cookies**. Nothing in the sweep exceeded 1 KB — but a site with a fat
  cookie jar easily passes 4 KB, which is why the corpus carries an explicit
  16 KB head scenario per server.
- **Response heads**: 121–255 B across all four servers.

The number that matters for РH14 is not the size of the head but **the size of
a single `read` call**, since the capture budget is per call — and that is the
server's buffer size, not the client's. The corpus records the same 16 KB head
against each server at both budgets (`huge-head.lkt`, `huge-head-cap2048.lkt`):
Go and gunicorn read in ≤ 8 KB chunks and lose nothing at the 8 KB default,
nginx reads the whole head in one call (`large_client_header_buffers`) and
truncates three events even at 8 KB; at 2048 every server truncates. A
truncated head is a normal, flagged outcome (`LK_QO_TEXT_TRUNC`): the start
line and the first headers always arrive first, and those carry the route, the
method and the framing fields.

## What the corpus proves

`tests/traces/http/` (113 traces, four servers) is the material every claim
above was checked against, and the shapes М2/М3 will be regression-tested on:
the framing edge cases (`cl-te`, `lf-only`, `torn-body`, `truncated-resp`,
`abort-midbody`, `bad-request`), the blind zones (`h2-preface`, `h2c-upgrade`,
`websocket`, `connect`, `tls`), the degradations (`sendfile-static` vs
`nosendfile-static`, `huge-head-cap2048`) and the ordinary traffic they have to
be told apart from. Its README carries the recorded findings and the commands
that produced them.
