# Replay harness (task 2.5): the full userspace pipeline over recorded traces,
# no BPF or privileges. Shares the libbpf-free agent modules; the fixture
# builders back both the generator and the reproducibility check.
set(REPLAY_SRC
    ${CMAKE_SOURCE_DIR}/src/agent/pipeline.c
    ${CMAKE_SOURCE_DIR}/src/agent/decode.c
    ${CMAKE_SOURCE_DIR}/src/agent/conn_table.c
    ${CMAKE_SOURCE_DIR}/src/agent/reassembly.c
    ${CMAKE_SOURCE_DIR}/src/agent/record.c
    fixtures_gen.c)

set(REPLAY_INC ${CMAKE_SOURCE_DIR}/src/bpf ${CMAKE_SOURCE_DIR}/src/agent)

# The protocol layer links libbpf-free into the offline harness too (Р15), so
# replay tests drive the PG parser over fixtures from task 3.2 on. Task 4.3 tees
# the observations into the metrics aggregator and asserts a deterministic dump.
add_executable(test_replay test_replay.c ${REPLAY_SRC})
target_include_directories(test_replay PRIVATE ${REPLAY_INC}
    ${CMAKE_SOURCE_DIR}/src/metrics ${CMAKE_SOURCE_DIR}/src/export)
target_link_libraries(test_replay latkit_proto latkit_metrics latkit_export)
target_compile_definitions(test_replay PRIVATE
    LK_FIXTURES_DIR="${CMAKE_SOURCE_DIR}/tests/fixtures")
add_test(NAME replay COMMAND test_replay)

# Dev tool: regenerate the committed fixtures (not run by ctest).
add_executable(gen_fixtures gen_fixtures.c ${REPLAY_SRC})
target_include_directories(gen_fixtures PRIVATE ${REPLAY_INC})
target_link_libraries(gen_fixtures latkit_proto)

# Dev tool: validate + summarise LKT1 traces (MySQL М0 trace-corpus check,
# tests/traces/mysql/README.md).
add_executable(lkt_info lkt_info.c
    ${CMAKE_SOURCE_DIR}/src/agent/decode.c
    ${CMAKE_SOURCE_DIR}/src/agent/record.c)
target_include_directories(lkt_info PRIVATE ${REPLAY_INC})

# Dev tool: the --messages view over LKT1 traces through the offline pipeline
# (МYSQL.md М2 acceptance — packet boundaries on the М0 corpus).
add_executable(lkt_messages lkt_messages.c ${REPLAY_SRC})
target_include_directories(lkt_messages PRIVATE ${REPLAY_INC})
target_link_libraries(lkt_messages latkit_proto)

# Dev tool: the --queries view — the real protocol handler over LKT1 traces
# (МYSQL.md М3 acceptance; the expectation table is queries_traces.sh).
add_executable(lkt_queries lkt_queries.c ${REPLAY_SRC})
target_include_directories(lkt_queries PRIVATE ${REPLAY_INC})
target_link_libraries(lkt_queries latkit_proto)

# М3 acceptance: expected observations per М0 trace scenario + parse_errors
# == 0 on clean traces, asserted over the committed corpus.
add_test(NAME my_queries_traces
         COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/queries_traces.sh
                 $<TARGET_FILE:lkt_queries> ${CMAKE_SOURCE_DIR}/tests/traces/mysql)
