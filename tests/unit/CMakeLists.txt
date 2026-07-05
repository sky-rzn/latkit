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
