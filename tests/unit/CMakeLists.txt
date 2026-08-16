add_executable(test_smoke test_smoke.c)
target_include_directories(test_smoke PRIVATE ${CMAKE_SOURCE_DIR}/src/bpf)
add_test(NAME smoke COMMAND test_smoke)

add_executable(test_decode test_decode.c ${CMAKE_SOURCE_DIR}/src/agent/decode.c)
target_include_directories(test_decode PRIVATE
    ${CMAKE_SOURCE_DIR}/src/bpf ${CMAKE_SOURCE_DIR}/src/agent)
add_test(NAME decode COMMAND test_decode)

add_executable(test_conn_table test_conn_table.c ${CMAKE_SOURCE_DIR}/src/agent/conn_table.c)
target_include_directories(test_conn_table PRIVATE
    ${CMAKE_SOURCE_DIR}/src/bpf ${CMAKE_SOURCE_DIR}/src/agent)
add_test(NAME conn_table COMMAND test_conn_table)

# The framer's protocol knowledge lives behind the lk_proto_ops vtable (РМ1),
# so reassembly.c pulls in the proto lib for the PG entry (pg_frame.c).
add_executable(test_reassembly test_reassembly.c)
target_include_directories(test_reassembly PRIVATE
    ${CMAKE_SOURCE_DIR}/src/bpf ${CMAKE_SOURCE_DIR}/src/agent)
target_link_libraries(test_reassembly latkit_proto)
add_test(NAME reassembly COMMAND test_reassembly)

# TLS decrypted-channel routing (task 6.4): the shared pipeline over synthetic
# records — ciphertext drop, decrypted framing, framer reset, separate seq
# space. Libbpf-free, links the same agent modules as the replay harness.
add_executable(test_tls_route test_tls_route.c
    ${CMAKE_SOURCE_DIR}/src/agent/pipeline.c
    ${CMAKE_SOURCE_DIR}/src/agent/decode.c
    ${CMAKE_SOURCE_DIR}/src/agent/conn_table.c)
target_include_directories(test_tls_route PRIVATE
    ${CMAKE_SOURCE_DIR}/src/bpf ${CMAKE_SOURCE_DIR}/src/agent)
target_link_libraries(test_tls_route latkit_proto)
add_test(NAME tls_route COMMAND test_tls_route)

# x86-64 length decoder and return-site search (PLAN-HTTP.md М7, РH13.3): the
# module the Go TLS channel places its probes with, so its refusals matter as
# much as its answers. Pure — no libbpf, no ELF, no privileges.
add_executable(test_x86_len test_x86_len.c ${CMAKE_SOURCE_DIR}/src/agent/x86_len.c)
target_include_directories(test_x86_len PRIVATE ${CMAKE_SOURCE_DIR}/src/agent)
add_test(NAME x86_len COMMAND test_x86_len)

# ELF symbol reader (М7): looks its own function up in its own binary and
# compares the bytes at the file offset it computed with the mapped ones — the
# address arithmetic a Go uprobe depends on, checked against reality.
add_executable(test_elf_syms test_elf_syms.c ${CMAKE_SOURCE_DIR}/src/agent/elf_syms.c)
target_include_directories(test_elf_syms PRIVATE ${CMAKE_SOURCE_DIR}/src/agent)
add_test(NAME elf_syms COMMAND test_elf_syms)

# Go function-table reader (М7): the path that resolves crypto/tls in the
# stripped binaries every Go server actually ships (М0 recon item 3). Driven
# over a synthetic table, so no Go toolchain is needed to test the parser.
add_executable(test_go_pclntab test_go_pclntab.c ${CMAKE_SOURCE_DIR}/src/agent/go_pclntab.c)
target_include_directories(test_go_pclntab PRIVATE ${CMAKE_SOURCE_DIR}/src/agent)
add_test(NAME go_pclntab COMMAND test_go_pclntab)

# cgroup filter core (task 7.1, Р48): glob matcher, id-set diff and the cgroupfs
# resolver over a synthetic tree. Libbpf-free — links only the pure cgroup_match.c.
add_executable(test_cgroup test_cgroup.c ${CMAKE_SOURCE_DIR}/src/agent/cgroup_match.c)
target_include_directories(test_cgroup PRIVATE
    ${CMAKE_SOURCE_DIR}/src/bpf ${CMAKE_SOURCE_DIR}/src/agent)
add_test(NAME cgroup COMMAND test_cgroup)

# Bounded cursor (Р18): header-only, so the test just includes pg_wire.h.
add_executable(test_pg_wire test_pg_wire.c)
target_include_directories(test_pg_wire PRIVATE ${CMAKE_SOURCE_DIR}/src/proto/pg)
add_test(NAME pg_wire COMMAND test_pg_wire)

# MySQL bounded cursor (МYSQL.md М2): little-endian + lenenc twin of pg_wire.
add_executable(test_my_wire test_my_wire.c)
target_include_directories(test_my_wire PRIVATE ${CMAKE_SOURCE_DIR}/src/proto/my)
add_test(NAME my_wire COMMAND test_my_wire)

# MySQL framer (МYSQL.md М2): the reassembly matrix over lk_proto_my_ops plus
# continuation glue, connection phase, TLS/compress transitions and the РМ4
# anchors. Same shape as test_reassembly: reassembly.c + the proto lib.
add_executable(test_my_frame test_my_frame.c)
target_include_directories(test_my_frame PRIVATE
    ${CMAKE_SOURCE_DIR}/src/bpf ${CMAKE_SOURCE_DIR}/src/agent)
target_link_libraries(test_my_frame latkit_proto)
add_test(NAME my_frame COMMAND test_my_frame)

# Framer stream mode (PLAN-HTTP.md М1, РH1): the second framing mode of the
# vtable, driven over lk_reasm_data with the М1 HTTP stub — emit/resync
# accounting, hole handling, frame_state lifetime, and the РH15 invariant that
# a PG connection on the same framer is untouched.
add_executable(test_http_stream test_http_stream.c)
target_include_directories(test_http_stream PRIVATE
    ${CMAKE_SOURCE_DIR}/src/bpf ${CMAKE_SOURCE_DIR}/src/agent
    ${CMAKE_SOURCE_DIR}/src/proto ${CMAKE_SOURCE_DIR}/src/proto/http)
target_link_libraries(test_http_stream latkit_proto)
add_test(NAME http_stream COMMAND test_http_stream)

# HTTP/1.x framer (PLAN-HTTP.md М2): the reassembly matrix over lk_proto_http_ops
# — torn heads, holes on head/body/chunked, the body-length decision list, the
# blind zones, the textual resync anchors — plus the http_wire.h helpers.
add_executable(test_http_frame test_http_frame.c)
target_include_directories(test_http_frame PRIVATE
    ${CMAKE_SOURCE_DIR}/src/bpf ${CMAKE_SOURCE_DIR}/src/agent
    ${CMAKE_SOURCE_DIR}/src/proto ${CMAKE_SOURCE_DIR}/src/proto/http)
target_link_libraries(test_http_frame latkit_proto)
add_test(NAME http_frame COMMAND test_http_frame)

# HTTP handler (PLAN-HTTP.md М3): the header-value readers (test_http_wire), the
# two head parsers (test_http_req / test_http_resp) and the unit lifecycle with
# its four timings (test_http_unit). The last three drive the real chain —
# bytes -> framer -> lk_msg -> handler -> lk_query_obs — through http_obs.h.
add_executable(test_http_wire test_http_wire.c)
target_include_directories(test_http_wire PRIVATE ${CMAKE_SOURCE_DIR}/src/proto/http)
add_test(NAME http_wire COMMAND test_http_wire)

foreach(t http_req http_resp http_unit)
    add_executable(test_${t} test_${t}.c)
    target_include_directories(test_${t} PRIVATE
        ${CMAKE_SOURCE_DIR}/src/agent ${CMAKE_SOURCE_DIR}/src/bpf
        ${CMAKE_SOURCE_DIR}/src/proto ${CMAKE_SOURCE_DIR}/src/proto/http)
    target_link_libraries(test_${t} latkit_proto)
    add_test(NAME ${t} COMMAND test_${t})
endforeach()

# RESP wire helpers (PLAN-REDIS.md МR1, РR2): header-only, so the test just
# includes redis_wire.h — the type table, the strict length parse the server's
# own protocol errors define, the null forms and the two resync anchors.
add_executable(test_redis_wire test_redis_wire.c)
target_include_directories(test_redis_wire PRIVATE ${CMAKE_SOURCE_DIR}/src/proto/redis)
add_test(NAME redis_wire COMMAND test_redis_wire)

# RESP framer (МR1): the reassembly matrix over lk_proto_redis_ops — nesting and
# the element stack, inline commands, a bulk skipped through a capture hole and
# an aggregate that cannot be, corrupt lengths, and the call-boundary anchors.
# test_redis_stream is the acceptance invariant: the same bytes cut anywhere
# produce the same messages, which is the only honest way to state that the
# no-copy path and the slab path agree.
# Redis handler (МR2): the unit queue and the four timings over the real chain —
# bytes -> framer -> lk_msg -> handler -> lk_query_obs. Pipelining at depth
# 1/2/100, the ring overflowing, a reply that overtook its own command, the
# pub/sub rule in both protocol versions, and the three kinds of connection that
# are not a request/response stream at all.
# Redis labels (МR3): the session state machine on the same chain — the database
# of РR5 and the ACL user of РR6, both moving on the *reply* and not on the
# command, plus the privacy invariant asserted per observation (no key, no
# password, in any label).
foreach(t redis_frame redis_stream redis_unit redis_labels)
    add_executable(test_${t} test_${t}.c)
    target_include_directories(test_${t} PRIVATE
        ${CMAKE_SOURCE_DIR}/src/bpf ${CMAKE_SOURCE_DIR}/src/agent
        ${CMAKE_SOURCE_DIR}/src/proto ${CMAKE_SOURCE_DIR}/src/proto/redis)
    target_link_libraries(test_${t} latkit_proto)
    add_test(NAME ${t} COMMAND test_${t})
endforeach()

# Startup/auth/session (task 3.2): white-box over the PG handler (links the
# libbpf-free proto lib; includes the internal pg.h for state assertions).
add_executable(test_pg_session test_pg_session.c)
target_include_directories(test_pg_session PRIVATE
    ${CMAKE_SOURCE_DIR}/src/proto ${CMAKE_SOURCE_DIR}/src/proto/pg
    ${CMAKE_SOURCE_DIR}/src/agent ${CMAKE_SOURCE_DIR}/src/bpf)
target_link_libraries(test_pg_session latkit_proto)
add_test(NAME pg_session COMMAND test_pg_session)

# Simple query: units, rows, errors, transactions (task 3.3). Same white-box
# setup: synthetic lk_msg in, observations out.
add_executable(test_pg_query test_pg_query.c)
target_include_directories(test_pg_query PRIVATE
    ${CMAKE_SOURCE_DIR}/src/proto ${CMAKE_SOURCE_DIR}/src/proto/pg
    ${CMAKE_SOURCE_DIR}/src/agent ${CMAKE_SOURCE_DIR}/src/bpf)
target_link_libraries(test_pg_query latkit_proto)
add_test(NAME pg_query COMMAND test_pg_query)

# Prepared-statement cache: LRU, unnamed overwrite, Close, eviction rescue
# (task 3.4). Same white-box setup as the query test.
add_executable(test_pg_prep test_pg_prep.c)
target_include_directories(test_pg_prep PRIVATE
    ${CMAKE_SOURCE_DIR}/src/proto ${CMAKE_SOURCE_DIR}/src/proto/pg
    ${CMAKE_SOURCE_DIR}/src/agent ${CMAKE_SOURCE_DIR}/src/bpf)
target_link_libraries(test_pg_prep latkit_proto)
add_test(NAME pg_prep COMMAND test_pg_prep)

# MySQL connection phase (МYSQL.md М3): greeting/response/auth cycle, labels,
# promote/synthetic/compress paths. White-box over the my handler internals.
add_executable(test_my_session test_my_session.c)
target_include_directories(test_my_session PRIVATE
    ${CMAKE_SOURCE_DIR}/src/proto ${CMAKE_SOURCE_DIR}/src/proto/my
    ${CMAKE_SOURCE_DIR}/src/agent ${CMAKE_SOURCE_DIR}/src/bpf)
target_link_libraries(test_my_session latkit_proto)
add_test(NAME my_session COMMAND test_my_session)

# MySQL query phase machine (М3): resultset shapes, terminators, LOAD DATA,
# transactions, query attributes, cursors, honesty drops.
add_executable(test_my_query test_my_query.c)
target_include_directories(test_my_query PRIVATE
    ${CMAKE_SOURCE_DIR}/src/proto ${CMAKE_SOURCE_DIR}/src/proto/my
    ${CMAKE_SOURCE_DIR}/src/agent ${CMAKE_SOURCE_DIR}/src/bpf)
target_link_libraries(test_my_query latkit_proto)
add_test(NAME my_query COMMAND test_my_query)

# MySQL prepared-statement cache (М3): stmt_id binding, metadata skip, CLOSE
# without a reply, pipelined-close rescue, eviction, reset.
add_executable(test_my_prep test_my_prep.c)
target_include_directories(test_my_prep PRIVATE
    ${CMAKE_SOURCE_DIR}/src/proto ${CMAKE_SOURCE_DIR}/src/proto/my
    ${CMAKE_SOURCE_DIR}/src/agent ${CMAKE_SOURCE_DIR}/src/bpf)
target_link_libraries(test_my_prep latkit_proto)
add_test(NAME my_prep COMMAND test_my_prep)

# SQL normaliser + fingerprint (task 4.1): table-driven cases over the public
# lk_norm_sql API. Links the pure normaliser lib (no libbpf, no privileges).
add_executable(test_norm_sql test_norm_sql.c)
target_link_libraries(test_norm_sql latkit_norm)
add_test(NAME norm_sql COMMAND test_norm_sql)

# HTTP route templater (PLAN-HTTP.md М4, РH7): the segment classifiers, the
# explicit map, the query rules, and the cardinality invariant — a million
# generated paths must collapse into a bounded number of templates.
add_executable(test_norm_route test_norm_route.c)
target_link_libraries(test_norm_route latkit_norm)
add_test(NAME norm_route COMMAND test_norm_route)

# S3 classifier (PLAN-MINIO.md МS1, РS2/РS3): the operation table row for row,
# both addressing forms, the bucket-name rules the server enforces, and the
# closed-set invariant over a million generated paths — the check that makes the
# `op` label's cardinality a compile-time fact. Pure, links the normaliser lib.
add_executable(test_s3_op test_s3_op.c)
target_link_libraries(test_s3_op latkit_norm)
add_test(NAME s3_op COMMAND test_s3_op)

# S3 dialect over the real chain (PLAN-MINIO.md МS1): the labels of РS3/РS4, the
# two byte counts of РS6 and the error codes of РS5, asserted on observations —
# and, in every one of them, on the absence of any object key. Same harness as
# the HTTP handler tests, with lk_proto_s3_ops as the port's protocol.
foreach(t s3_labels s3_error)
    add_executable(test_${t} test_${t}.c)
    target_include_directories(test_${t} PRIVATE
        ${CMAKE_SOURCE_DIR}/src/agent ${CMAKE_SOURCE_DIR}/src/bpf
        ${CMAKE_SOURCE_DIR}/src/proto ${CMAKE_SOURCE_DIR}/src/proto/http
        ${CMAKE_SOURCE_DIR}/src/proto/s3)
    target_link_libraries(test_${t} latkit_proto)
    add_test(NAME ${t} COMMAND test_${t})
endforeach()

# Redis command table (PLAN-REDIS.md МR3, РR4-РR6): the closed identity table
# entry by entry, the container rule that is the only place a second element is
# read, the session parses of `SELECT`/`AUTH`/`HELLO`, the credential mask, and
# the closed-set invariant over a million random arrays — the check that makes
# the `cmd` label's cardinality a compile-time fact. Pure, links the normaliser.
add_executable(test_redis_cmd test_redis_cmd.c)
target_link_libraries(test_redis_cmd latkit_norm)
add_test(NAME redis_cmd COMMAND test_redis_cmd)

# ... and the same table against the notes it was generated from (МR3): the
# compiled entries, dumped by the test binary, must be exactly the table in
# docs/notes-redisproto.md §"The table" — which cmdtable.py generated from a live
# server. One source of truth, checked rather than asserted, so a hand-edit of
# either side turns CI red instead of quietly renaming a metric label.
add_test(NAME redis_table
         COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/redis_table.sh $<TARGET_FILE:test_redis_cmd>
                 ${CMAKE_SOURCE_DIR}/docs/notes-redisproto.md)

# Query-string redactor (PLAN-HTTP.md М6, РH12): the key table, the bounds, and
# the invariant the whole privacy claim rests on — no secret survives the copy.
add_executable(test_norm_redact test_norm_redact.c)
target_link_libraries(test_norm_redact latkit_norm)
add_test(NAME norm_redact COMMAND test_norm_redact)

# Exponential histogram (task 4.2): grid boundaries vs the ldexp reference,
# clamping, merge, classic-bucket text export. Links the pure metrics lib.
add_executable(test_hist test_hist.c)
target_link_libraries(test_hist latkit_metrics)
add_test(NAME hist COMMAND test_hist)

# Series registry (task 4.2): top-K LRU + doorkeeper + other-fold, dimension
# limit, dump format. Same pure metrics lib, driven white-box via registry.h.
add_executable(test_registry test_registry.c)
target_link_libraries(test_registry latkit_metrics)
add_test(NAME registry COMMAND test_registry)

# Aggregator (task 4.3): synthetic lk_query_obs through the lk_query_sink,
# asserting the resulting exposition. Uses the lk_query_obs contract (proto.h,
# types only) — hence the proto/agent/bpf header dirs — over the pure metrics lib.
add_executable(test_metrics test_metrics.c)
target_include_directories(test_metrics PRIVATE
    ${CMAKE_SOURCE_DIR}/src/proto ${CMAKE_SOURCE_DIR}/src/agent ${CMAKE_SOURCE_DIR}/src/bpf)
target_link_libraries(test_metrics latkit_metrics)
add_test(NAME metrics COMMAND test_metrics)

# Mini HTTP server (task 5.1): loopback state-machine tests over the export lib.
# Pulls in a bare loop.c (the loop lives with the agent, not the export lib) and
# needs no libbpf or privileges. See test_http.c for the covered cases.
add_executable(test_http test_http.c ${CMAKE_SOURCE_DIR}/src/agent/loop.c)
target_include_directories(test_http PRIVATE
    ${CMAKE_SOURCE_DIR}/src/export ${CMAKE_SOURCE_DIR}/src/agent)
target_link_libraries(test_http latkit_export)
add_test(NAME http COMMAND test_http)

# Protobuf writer golden bytes (task 5.2): varints, scalar fields, submessage
# length insertion via memmove. Pure, links the export lib for pbuf.c.
add_executable(test_pbuf test_pbuf.c)
target_include_directories(test_pbuf PRIVATE ${CMAKE_SOURCE_DIR}/src/export)
target_link_libraries(test_pbuf latkit_export)
add_test(NAME pbuf COMMAND test_pbuf)

# OTLP metric encoder (task 5.2): decodes the writer's output and asserts the
# OTLP structure + the Р24-grid -> ExponentialHistogram mapping. Needs the export
# lib (otlp/pbuf/timebase) and the metrics lib (hist, view types).
add_executable(test_otlp_enc test_otlp_enc.c ${CMAKE_SOURCE_DIR}/src/agent/loop.c)
target_include_directories(test_otlp_enc PRIVATE
    ${CMAKE_SOURCE_DIR}/src/export ${CMAKE_SOURCE_DIR}/src/metrics ${CMAKE_SOURCE_DIR}/src/agent)
target_link_libraries(test_otlp_enc latkit_export)
add_test(NAME otlp_enc COMMAND test_otlp_enc)

# Mono -> wall timebase (task 5.2): offset arithmetic and a sanity bound on a
# live sample. Pure, links the export lib for timebase.c.
add_executable(test_timebase test_timebase.c)
target_include_directories(test_timebase PRIVATE ${CMAKE_SOURCE_DIR}/src/export)
target_link_libraries(test_timebase latkit_export)
add_test(NAME timebase COMMAND test_timebase)

# Span collector (task 5.3): sampling predicates + ring over synthetic
# observations. Pure, links the export lib (spans.c) and reads the lk_query_obs
# contract (proto.h, types only) — hence the proto/agent/bpf header dirs.
add_executable(test_spans test_spans.c)
target_include_directories(test_spans PRIVATE
    ${CMAKE_SOURCE_DIR}/src/export ${CMAKE_SOURCE_DIR}/src/proto
    ${CMAKE_SOURCE_DIR}/src/agent ${CMAKE_SOURCE_DIR}/src/bpf)
target_link_libraries(test_spans latkit_export)
add_test(NAME spans COMMAND test_spans)

# Config priority (task 5.4, Р34): flag > LATKIT_* env > OTEL_* env > default,
# asserted over `latkit --print-config` (resolves config before touching BPF, so
# no privileges needed). Runs the built agent binary — hence the target dep.
add_test(NAME config_priority
         COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/config_priority.sh $<TARGET_FILE:latkit>)

# README ↔ --help ↔ env-layer consistency (task 7.6, Р44): the configuration
# tables in README.md are checked against the binary's usage text and the
# LATKIT_* names in main.c, so a flag or env rename turns CI red.
add_test(NAME readme_flags
         COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/readme_flags.sh $<TARGET_FILE:latkit>
                 ${CMAKE_SOURCE_DIR}/README.md ${CMAKE_SOURCE_DIR}/src/agent/main.c)

# OTLP client end-to-end on loopback (task 5.2): drives the real connect/write/
# read state machine in the loop against a bare TCP listener, no BPF. Pulls in
# loop.c like test_http and links the export + metrics libs.
add_executable(test_otlp_client test_otlp_client.c ${CMAKE_SOURCE_DIR}/src/agent/loop.c)
target_include_directories(test_otlp_client PRIVATE
    ${CMAKE_SOURCE_DIR}/src/export ${CMAKE_SOURCE_DIR}/src/metrics ${CMAKE_SOURCE_DIR}/src/agent
    ${CMAKE_SOURCE_DIR}/src/proto ${CMAKE_SOURCE_DIR}/src/bpf)
target_link_libraries(test_otlp_client latkit_export)
add_test(NAME otlp_client COMMAND test_otlp_client)
