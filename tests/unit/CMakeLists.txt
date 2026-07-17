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
add_executable(test_reassembly test_reassembly.c ${CMAKE_SOURCE_DIR}/src/agent/reassembly.c)
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
    ${CMAKE_SOURCE_DIR}/src/agent/conn_table.c
    ${CMAKE_SOURCE_DIR}/src/agent/reassembly.c)
target_include_directories(test_tls_route PRIVATE
    ${CMAKE_SOURCE_DIR}/src/bpf ${CMAKE_SOURCE_DIR}/src/agent)
target_link_libraries(test_tls_route latkit_proto)
add_test(NAME tls_route COMMAND test_tls_route)

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

# SQL normaliser + fingerprint (task 4.1): table-driven cases over the public
# lk_norm_sql API. Links the pure normaliser lib (no libbpf, no privileges).
add_executable(test_norm_sql test_norm_sql.c)
target_link_libraries(test_norm_sql latkit_norm)
add_test(NAME norm_sql COMMAND test_norm_sql)

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
