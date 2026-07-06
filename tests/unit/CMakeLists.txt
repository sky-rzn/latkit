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

add_executable(test_reassembly test_reassembly.c ${CMAKE_SOURCE_DIR}/src/agent/reassembly.c)
target_include_directories(test_reassembly PRIVATE
    ${CMAKE_SOURCE_DIR}/src/bpf ${CMAKE_SOURCE_DIR}/src/agent)
add_test(NAME reassembly COMMAND test_reassembly)

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
