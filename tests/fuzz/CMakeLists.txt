# PG parser fuzz harness (task 3.6, stage-8 groundwork). Built only when
# LATKIT_FUZZ is ON so a normal build never pays for it. The harness is
# libbpf-free — it shares the framer (reassembly + conn_table) and the protocol
# layer, and runs with no privileges. Enable a sanitizer at configure time, e.g.
#   cmake -B build -DLATKIT_FUZZ=ON \
#         -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-sanitize-recover=all"
#
# LATKIT_FUZZER additionally builds the real libFuzzer target (needs clang and
# -fsanitize=fuzzer); the default build is the offline corpus runner CI uses.
set(FUZZ_SRC
    pg_fuzz.c
    ${CMAKE_SOURCE_DIR}/src/agent/conn_table.c
    ${CMAKE_SOURCE_DIR}/src/agent/reassembly.c)
set(FUZZ_INC
    ${CMAKE_SOURCE_DIR}/src/proto ${CMAKE_SOURCE_DIR}/src/proto/pg
    ${CMAKE_SOURCE_DIR}/src/agent ${CMAKE_SOURCE_DIR}/src/bpf)

add_executable(pg_fuzz ${FUZZ_SRC})
target_include_directories(pg_fuzz PRIVATE ${FUZZ_INC})
target_link_libraries(pg_fuzz latkit_proto)

# The corpus is the committed fixtures: arbitrary bytes into bytes -> lk_msg ->
# parser must never crash. Any sanitizer set in CMAKE_C_FLAGS applies here.
file(GLOB FUZZ_CORPUS ${CMAKE_SOURCE_DIR}/tests/fixtures/*.lkt)
add_test(NAME pg_fuzz COMMAND pg_fuzz ${FUZZ_CORPUS})

if(LATKIT_FUZZER)
    add_executable(pg_fuzz_libfuzzer pg_fuzz.c
                   ${CMAKE_SOURCE_DIR}/src/agent/conn_table.c
                   ${CMAKE_SOURCE_DIR}/src/agent/reassembly.c)
    target_include_directories(pg_fuzz_libfuzzer PRIVATE ${FUZZ_INC})
    target_link_libraries(pg_fuzz_libfuzzer latkit_proto)
    target_compile_definitions(pg_fuzz_libfuzzer PRIVATE LK_FUZZ_LIBFUZZER)
    target_compile_options(pg_fuzz_libfuzzer PRIVATE -fsanitize=fuzzer)
    target_link_options(pg_fuzz_libfuzzer PRIVATE -fsanitize=fuzzer)
endif()
