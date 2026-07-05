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

add_executable(test_replay test_replay.c ${REPLAY_SRC})
target_include_directories(test_replay PRIVATE ${REPLAY_INC})
target_compile_definitions(test_replay PRIVATE
    LK_FIXTURES_DIR="${CMAKE_SOURCE_DIR}/tests/fixtures")
add_test(NAME replay COMMAND test_replay)

# Dev tool: regenerate the committed fixtures (not run by ctest).
add_executable(gen_fixtures gen_fixtures.c ${REPLAY_SRC})
target_include_directories(gen_fixtures PRIVATE ${REPLAY_INC})
