# notes-httpproto: HTTP/1.x on the wire — framing, units, body length, blind spots

Design notes backing the HTTP track ([PLAN-HTTP.md](../PLAN-HTTP.md), Russian,
decisions РH1–РH16). This is the wire-level conspectus the М2 framer and the М3
handler were written against — the same genre as
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
| the `--http-route-header` header | request | **only** when the flag names one: the app's own route, off by default (РH7, §"Route templating") |
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
- `tracestate` is carried through verbatim and unparsed; one longer than 256
  bytes is **dropped rather than clipped** — half a comma-separated list is not a
  shorter list, it is a malformed one.
- Without a valid `traceparent` the span keeps today's behaviour: its own trace
  id, no parent.

Since М6 this is wired: the observation carries the context (`struct
lk_http_obs`), the span adopts it, and the OTLP encoder emits a `SPAN_KIND_SERVER`
span with `parent_span_id` and `trace_state` set. The full attribute list and the
sampling rules live in docs/notes-export.md §"The HTTP span".

## What never leaves the agent (РH12)

Three rules, each enforced in one place rather than in every consumer:

1. **Labels carry only the template.** The raw path never becomes a metric label
   — that is the route templater's guarantee (РH7), not a policy applied at the
   sink.
2. **Credential-shaped query values are redacted where the target leaves the
   handler.** A key containing `token`, `sig`, `password`, `passwd`, `secret`,
   `key`, `code` or `auth` (case-insensitive substring, so `access_token` and
   `X-Amz-Signature` are covered) has its value replaced by `***` before the
   observation is published, so `--queries`, the span's `url.path` and anything
   added later all see the redacted form. `--http-redact off` turns it off.
   Over-redaction is the deliberate error direction: an unreadable value in one
   span costs a debugging session, a leaked credential costs an incident.
3. **Credential headers are never copied and never shown.** `Authorization`,
   `Proxy-Authorization`, `Cookie` and `Set-Cookie` travel past the parser
   untouched (the exception is `--http-user basic`, which extracts the name half
   and stops the base64 decode at the colon), and the `--messages --hexdump`
   view blanks their values — same length, so the framing stays readable.

`tests/replay/http_privacy.sh` is the test that makes this a property rather than
a comment: the corpus `*/traceparent.lkt` traces were recorded with a
`?token=s3cr3t`, a `Basic YWRtaW46aHVudGVyMg==` and a session cookie, and the
script greps every surface — `--queries`, `/metrics`, spans, hexdump — for all
three, asserting also that each surface produced output at all.

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

## What the М2 framer emits, and what it decided along the way

The framer is `src/proto/http/http_frame.c`, in the stream mode of РH1; the
text helpers it and the М3 handler read heads with are `http_wire.h`, the
`pg_wire.h` of this protocol. Everything it publishes is an ordinary `lk_msg`,
so `--messages`, the replay harness and the fuzzers are unchanged:

| Type | Meaning | `len` | `body` |
|---|---|---|---|
| `R` / `S` | request / response head | the header block's length | the block itself |
| `I` | interim `1xx` head — does not close the unit | likewise | likewise |
| `D` | body bytes accounted (captured **or** holed) | that count | none, ever |
| `E` | end of body | the message's total body size | none |
| `!` | framer note: a degradation or a blind zone | `enum lk_http_note` | none |

Four points where the implementation is sharper than the sketch above:

- **`D` never carries payload.** A body's *length* is observable and its
  content is not (РH12), so the count travels and the bytes do not. Holes
  report through `D` too — they were on the wire, `total_len` is honest — which
  is what keeps `bytes_in`/`bytes_out` exact under any capture budget. For a
  chunked body `D` counts *decoded* bytes, so chunked and `Content-Length`
  responses of the same size report the same number.
- **`LK_MSG_BODY_TRUNC` means something else here.** In the message mode it
  means "the captured prefix is shorter than the length the header declared".
  A head has no such declaration, so on `R`/`S` the flag reads "the block never
  terminated — a hole ate the rest, its real length is unknown and larger".
  `len == body_cap` always.
- **The notes are the framer's only channel.** A stream framer has no stats
  object of its own (it is a `const` vtable entry), so every degradation it
  recognises — a malformed start line, CL+TE, a conflicting `Content-Length`,
  an obs-fold, an oversized head, a hole on a head or in a chunked body, bare
  LF, pipelining past the ring, an unseen body, the three blind zones — becomes
  a `!` message. The handler turns the corrupt-input subset into
  `latkit_parse_errors_total` and the blind zones into the ignored-connection
  tally; capture losses are counted as holes and are deliberately *not* parse
  errors.
- **The request anchor is `METHOD SP`, not the whole request line.** The notes
  above describe the anchor as the three-part line with its version tail. As
  written that would resynchronise *after* the start line and lose the method
  and the route with it — the two fields the whole track exists to report. The
  framer instead matches the method token plus its space (a sliding match that
  survives event boundaries, like PG's `Z`), **keeps the matched bytes and
  feeds them back into the head assembler**, so framing resumes at the first
  byte of the start line. The version tail still has to be there: the head
  parser rejects anything that is not `… SP HTTP/1.[01]`, so a false anchor
  costs one head-parse and returns to the scan. Same guarantee, one recovered
  unit more.

Two limits worth stating plainly, because they are visible on the corpus:

- **The last call of a connection.** An under-captured call's tail becomes a
  hole only when the *next* call arrives (the generic lazy-tail rule, Р9), so a
  direction whose last call was cut short never learns those bytes existed.
  Two shapes in the corpus: `nginx/get.lkt`, where the 17-byte body goes out by
  `sendfile` with an uncopyable page iterator and the connection closes — no
  `E`, the unit is still open at `CONN_CLOSE` where М3 closes it; and
  `nginx/huge-head.lkt`, where nginx reads the whole 16 KB head in one call,
  the budget cuts it, nothing follows on that direction, and the request is
  never published at all. Making the close path flush the pending tail would
  fix both, but it is generic-layer surgery that would change PG and MySQL
  message counts, which РH15 forbids for this track.
- **TLS traces frame as garbage until М7.** PG and MySQL negotiate TLS in
  band, so the framer knows when a connection turns into ciphertext; HTTPS
  carries no such marker on the socket, and `LK_CONN_TLS` is set by the
  uprobe router, not by anything HTTP can see. Until the TLS stage the
  ciphertext of `tls-decrypted*.lkt` is fed to the framer alongside the
  plaintext channel and produces rejected heads. That is expected and is why
  those two traces are the only "clean" files with a nonzero `parse_errors`.

The boundary check that covers the whole corpus in one number: replay all 113
traces and count `R`/`S` against `E` per connection *and* per direction. Across
the 207 streams that produces, **175 balance exactly and 32 end with one open
head — never two, never a negative**. Every one of those 32 is a documented
tail: a body that runs until close (`Connection: close`, HTTP/1.0), a
deliberately truncated one (`torn-body`, `truncated-resp`, `abort-midbody`), a
head cut by the capture budget (`huge-head*`), or the last-call case above. A
desynchronised framer would show drift in the middle of a connection, not a
single unclosed unit at its end.

Measured over the same corpus (`lkt_queries --proto http`):
`parse_errors` is zero everywhere except the scenarios built to be rejected —
`bad-request` (binary garbage where a start line belongs), `cl-te` (the
desynchronisation shape, where the resync then finds the smuggled request),
`huge-head` on the two servers that accept a 16 KB block (over the message
ceiling), and the two TLS traces above.

## What the М3 handler makes of it

The framer says where messages begin and end; the handler
(`src/proto/http/http.c` + `http_req.c` / `http_resp.c`) says what an exchange
*was*. One `lk_query_obs` per request/response pair, and everything below is a
decision that shows up in the numbers.

**A unit is emitted exactly once, or dropped and counted.** It opens on a
request head, closes on the last byte of the response body, and waits in a FIFO
of at most 16 in between (`LK_HTTP_MAX_INFLIGHT`, the framer's own ring depth).
Every other exit is a counter: `units_dropped_resync` when the stream broke,
`units_dropped_close` when the connection died before an answer,
`units_dropped_overflow` when pipelining ran deeper than the ring. A message
that finds no unit at all — a response on a connection joined mid-stream — is
`orphan_msgs`, and *not* a parse error: nothing was wrong with the input.

**The four timings, and the one that is not the server's.** `ts_start` is the
first byte of the request head, `ts_req_done` the last byte of its body,
`ts_first_row` the first byte of the response head, `ts_complete` its last body
byte. `duration = ts_complete − ts_req_done` is the only one that is the
server's own; `upload = ts_req_done − ts_start` is the client's and gets its own
family (РH9). On the corpus the difference is exactly as predicted: every
`get.lkt` reports `upload=0` and all three models coincide, every `continue.lkt`
reports a ~50 ms upload against a sub-millisecond duration — the client waiting
for the interim `100`, which is time no server-side model should charge to the
server. When the answer arrives before the upload finishes (an early `413`)
there is no request-body end at all, and `ts_req_done` falls back to `ts_start`:
that unit leaves the upload family rather than reporting a negative interval.

**Three ways a status can land, not two.** `5xx` is `LK_QO_ERROR`, `4xx` is
`LK_QO_CLIENT_ERR`, everything else is neither, and `err_code` carries the
status on *every* observation because it is the response's identity rather than
its error code (РH10). Folding 4xx into ERROR is the easiest way to make a
404-heavy service read as broken, and once the metric is aggregated there is no
way back.

**Two directions, one unit.** The response side reads the request's method: a
`HEAD` answer's `Content-Length` describes a body that never arrives, and the
corpus `head.lkt` traces report `out=0` against a declared megabyte. Rule 6 is
recognised at the response head, not at the connection's end — a response with
no length and no chunked framing is *completed* by `CONN_CLOSE`, while one whose
declared length never finished is emitted with `LK_QO_BODY_UNSEEN` and a byte
count that is a lower bound. That second case is what makes `nginx/get.lkt` — a
single 200 with a 17-byte body the capture's last call never delivered —
produce an observation instead of nothing.

**A resync drops by direction.** A loss on the request side means a request may
have gone by unseen, so the queue no longer lines up with the responses still to
come and everything in flight is dropped (Р19). A loss on the *response* side
ruins the unit being answered and nothing else: the units behind it still have
honest request heads and the FIFO still puts their responses next. The
distinction is not cosmetic — a resync is reported late, when the framer finds
its anchor, by which time the next request has already opened its unit, so
dropping everything would discard the exchange the resync just recovered on
every connection the agent joins mid-stream.

**What the handler reads, and what it refuses to.** The header list is the one
in §"Headers of interest" and nothing else is copied anywhere. `Cookie` is never
read. `Authorization` is never read either unless `--http-user basic` asks for
it, and then only the name half — the base64 decode stops at the colon, so at
most two bytes of the password pass through a local variable and none reaches a
label. `Bearer` is untouched whatever the flag says. The request target travels
**raw** into `lk_query_obs.text`, query string included — redacting it for a span
is М6's job, and doing it here would move that rule somewhere it cannot be
tested. The *templated* identity travels beside it in `lk_query_obs.route`
(§"Route templating").

Per-connection cost: `struct http_conn` is the 16-unit ring plus a session, with
the two variable-length copies (the target, and `tracestate` when one arrives)
as owned buffers reused across the units of a slot — a keep-alive connection
serving 50 requests does one allocation per slot, not 50.

Measured over the corpus (`lkt_queries --proto http`, expectations pinned in
`tests/replay/http_queries_traces.sh`): **266 observations over the 113
traces**, `parse_errors` zero everywhere except the scenarios built to be
rejected, and every `orphan_msgs` accounted for by a trace that is degraded on
purpose. Three per-server disagreements are recorded rather than smoothed over,
because they are findings and not noise: gunicorn's sync worker answers exactly
one request per connection whatever arrives (its `keepalive-50` yields one
observation and 49 counted drops, where nginx, Go and node yield 50); nginx
answers `405` to `OPTIONS` on a static file; and only Go delivers the whole 1 MB
of `get-large` through the socket before the capture's last call is cut short.

## Route templating (РH7, М4)

The route is the one label in this track that cannot be read off the wire — it
has to be *reconstructed*, because a URL is unbounded by construction and a
metric label may not be. Three layers, and the guarantee comes from the third.

**Layer 1, the explicit map** (`--http-routes FILE`). Lines of
`METHOD /users/{id}/orders/{id}`, `*` for any method, `#` for comments. Matching
is segment by segment — `{...}` matches exactly one segment, everything else
matches byte for byte, segment counts must agree — and the first pattern that
matches wins. No regular expressions and no wildcards spanning segments, so the
cost of a lookup stays proportional to the path, which is what lets it run on
every observation. A pattern containing `?` or `#` is rejected at load with a
counted warning: it could never match, since the query is not part of matching.

**Layer 2, the heuristic** (the default). Each path segment is classified, and
one that looks like a *value* rather than a *name* becomes `{id}`:

| Rule | Templated | Not templated |
|---|---|---|
| all digits | `/42`, `/0` | — |
| UUID (8-4-4-4-12 hex, either case) | `3f2504e0-4f89-11d3-9a0c-0305e82c3301` | — |
| ULID (26 Crockford base32) | `01ARZ3NDEKTSV4RRFFQ69G5FAV` | a 26-letter word with `I`/`L`/`O`/`U` |
| hex, ≥ 8 chars | `a83bf2ef`, a git sha | `decade` |
| `YYYY-MM-DD` | `2024-01-02` | — (`2024/01/02` is three segments, each templated by the digit rule) |
| longer than 24 chars | any | — |
| base64-ish, ≥ 16 chars, mixed case + digits | `aGVsbG8gd29ybGQx` | a long lowercase word |
| more than 40 % digits **and ≥ 6 chars** | `2024q1`, `user1234` | **`v1`**, `2x` |
| any control byte | always | — |

The length floor on the digit-ratio rule is not decoration: `/api/v1/users` is
the most common route shape there is and `v1` is 50 % digits, so without a floor
the heuristic would report `/api/{id}/users` for half the internet. The
control-byte rule is a privacy rule wearing a classifier's clothes — it is what
guarantees no byte outside the printable range can reach a label through this
path, whatever arrives on the wire.

A file-shaped segment keeps its extension: `app.a83bf2ef.js` → `{file}.js`,
because a spike in `.js` next to a flat `.png` is a story that `{id}` would not
tell. The stem is judged component by component, which is what catches the
build-hash-in-the-middle convention every bundler uses; `index.html` and
`logo.2x.png` stay verbatim, and a version like `1.2.3` is not a file name at
all (an extension must contain a letter).

Depth is capped at `--http-route-depth` (default 8) with the tail folded into
`/...` rather than dropped, so `/a/b/...` and `/a/b` stay different routes.
The query string is dropped **whole** — the fuzzer checks this as a byte
property, not a formatting one — except for the keys `--http-query-keys` names,
for the RPC-over-GET APIs where `?action=…` *is* the handler; a promoted value
goes through the same classifiers, so `?id=42` templates instead of forking the
route per id.

**Layer 3, the top-K dictionary** (М5). Whatever the first two layers produce,
the registry keeps the busiest routes and folds the rest into `route="other"`.
That is what makes the cardinality bound structural rather than a hope about the
heuristic, and the *share* of `route="other"` is the quality signal on the
dashboard: a heuristic that reads someone's API wrong shows up as that share
climbing, which is diagnosable, rather than as a series explosion, which is not.

Two escapes above the heuristic, both off by default: `--http-routes` (layer 1)
and `--http-route-header X-Route`, which takes the application's own name for
its handler. The header is trusted for its *content* — a framework knows
`/posts/{slug}` is one route and no shape test on `why-we-left-the-cloud` ever
will — but not for its cardinality: it arrives from the network like any other
header, and layer 3 is the only thing bounding it.

The identity of a route is `XXH3-64(method NUL template)`. The method is in the
fingerprint because `GET /orders/{id}` and `DELETE /orders/{id}` are two routes;
it is not in the *text*, because the label set carries it in its own dimension.
A template that outgrows the 256-byte label is clipped while the hash keeps
consuming, so a clipped label never merges two identities — the norm_sql
property, for the same reason.

Measured. Over the whole М0 corpus the 266 observations collapse into **18
distinct routes**, and the only templating that fires is the `/json/<id>`
scenario (160 observations → `/json/{id}`); the one observation with no route at
all is the authority-form `CONNECT`, which has no path to template. Against a
generator of a million paths in the shape of real traffic — REST ids, UUIDs,
content-addressed assets, date partitions, session tokens, query strings —
the templater produces **224 distinct templates**, the number pinned in
`tests/unit/test_norm_route.c` so a leakier classifier is caught by a test rather
than by a Prometheus bill. One classification costs ~157 ns.

The documented miss stays documented: a slug (`/posts/why-we-left-the-cloud`) is
not templated by any shape rule, and never will be. That is what layer 1 and the
route header are for, and what layer 3 makes survivable in the meantime.

## What an exchange becomes: the metric families (РH9/РH10, М5)

The observation above is not itself a metric — it is what the aggregator reads.
Turning it into series is where the HTTP track stops looking like the database
one, and the design decision is that the *engine* does not change: the top-K
dictionary, the doorkeeper, the dimension limit and the `other` fold are the
same code (`registry.c`), while the family names and label keys come from a
**profile** table. `pg`/`mysql` use the `query` profile, `http` the `http` one,
and the numbers a PostgreSQL user sees are byte-for-byte what they were (РH15).

What an exchange lands in — the full table with the label sets is in
[notes-metrics.md](notes-metrics.md#http-metrics-рh9рh10):

| From the unit | Family |
|---|---|
| the exchange itself, by status class | `latkit_http_requests_total{…,status}` |
| `ts_complete − ts_req_done` | `latkit_http_request_duration_seconds{…,code}` |
| `ts_first_row − ts_req_done` | `latkit_http_ttfb_seconds` |
| `ts_req_done − ts_start` | `latkit_http_request_upload_seconds` |
| status ≥ 400, exact code | `latkit_http_errors_total{code,host,user,proto}` |
| `bytes_in` / `bytes_out` | `latkit_http_bytes_total{…,direction}` |
| `bytes_out` as a distribution | `latkit_http_response_size_bytes` |

Four things about that table are decisions rather than bookkeeping:

1. **the duration starts at the end of the request.** `ts_start … ts_complete`
   contains the client's upload, which the server neither spent nor controls; a
   1 GB POST would otherwise read as a slow server. The upload interval is its
   own family, and only for units where it means something — an `Expect:
   100-continue` request contains a server round trip and is excluded;
2. **the method is part of the route's identity.** The fingerprint is
   `XXH3(method NUL template)`, so `GET /orders/{id}` and `POST /orders/{id}`
   are two dictionary slots. `/hello` in the corpus produces separate `GET`,
   `HEAD` and `OPTIONS` series, which is the point — their latencies have
   nothing to do with each other;
3. **a 4xx is not an error.** `code="error"` means 5xx. A 404 is the server
   correctly saying no, and mixing the two would make every 404-heavy service
   look broken; both are still counted, by exact code, in
   `latkit_http_errors_total`;
4. **a body that never reached the socket is counted but not histogrammed.**
   `LK_QO_BODY_UNSEEN` (the `sendfile` case, and a connection that died
   mid-transfer) means `bytes_out` is a lower bound: honest as a total, actively
   misleading as a distribution.

The blind zones get the same treatment as the sizes — counted, named, visible:
`latkit_ignored_conns_total{reason}` splits into `h2`, `upgrade` and `connect`,
so "this dashboard is thin because half the traffic is HTTP/2" is a number
rather than a hypothesis.

One rename came with the families and is the track's only breaking change: the
agent's own exporter counter, which used to be called
`latkit_http_requests_total`, is now `latkit_exporter_requests_total` (РH9). The
old name now belongs to the traffic being observed.

## What the corpus proves

`tests/traces/http/` (113 traces, four servers) is the material every claim
above was checked against, and the shapes М2/М3 are regression-tested on:
the framing edge cases (`cl-te`, `lf-only`, `torn-body`, `truncated-resp`,
`abort-midbody`, `bad-request`), the blind zones (`h2-preface`, `h2c-upgrade`,
`websocket`, `connect`, `tls`), the degradations (`sendfile-static` vs
`nosendfile-static`, `huge-head-cap2048`) and the ordinary traffic they have to
be told apart from. Its README carries the recorded findings and the commands
that produced them.
