# Fuzzing profile (task 8.3, Р51). Three libFuzzer targets over the pure
# pipeline code, clang-only, with fuzzer+ASAN+UBSAN baked into the profile:
#
#   cmake -B build-fuzz -DCMAKE_C_COMPILER=clang -DLATKIT_FUZZ=ON
#
#   fuzz_pg    bytes -> framer -> lk_msg -> PG parser (harness from task 3.6)
#   fuzz_norm  bytes -> lk_norm_sql (harness from task 4.1)
#   fuzz_pipe  event scenario -> decode + conn_table + framer + parser + norm
#
# The dependency sources are compiled INTO each target rather than linked from
# latkit_proto/latkit_norm: the libraries are built without sanitizers, and an
# uninstrumented dependency is exactly where a fuzzer goes blind.
#
# Corpus lives in tests/fuzz/corpus/{pg,norm,pipe} (committed; minimised with
# -merge=1 by campaign.sh). The ctest entries below replay it with -runs=0 —
# the corpus-regression mode CI runs on every PR; fuzzing time budgets live in
# ci.yml, not here.

if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "LATKIT_FUZZ needs clang for libFuzzer; "
                        "configure with -DCMAKE_C_COMPILER=clang")
endif()

set(FUZZ_SAN -O2 -g -fno-omit-frame-pointer
    -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all)
set(FUZZ_INC
    ${CMAKE_SOURCE_DIR}/src/proto ${CMAKE_SOURCE_DIR}/src/proto/pg
    ${CMAKE_SOURCE_DIR}/src/agent ${CMAKE_SOURCE_DIR}/src/bpf
    ${CMAKE_SOURCE_DIR}/src/norm)
set(FUZZ_PROTO_SRC
    ${CMAKE_SOURCE_DIR}/src/proto/pg/pg.c ${CMAKE_SOURCE_DIR}/src/proto/pg/pg_session.c
    ${CMAKE_SOURCE_DIR}/src/proto/pg/pg_query.c ${CMAKE_SOURCE_DIR}/src/proto/pg/pg_prep.c)
set(FUZZ_CORE_SRC
    ${CMAKE_SOURCE_DIR}/src/agent/conn_table.c ${CMAKE_SOURCE_DIR}/src/agent/reassembly.c)
set(FUZZ_NORM_SRC ${CMAKE_SOURCE_DIR}/src/norm/norm_sql.c)

function(latkit_fuzzer name)
    add_executable(${name} ${ARGN})
    target_include_directories(${name} PRIVATE ${FUZZ_INC})
    target_include_directories(${name} SYSTEM PRIVATE ${CMAKE_SOURCE_DIR}/third_party/xxhash)
    target_compile_options(${name} PRIVATE ${FUZZ_SAN})
    target_link_options(${name} PRIVATE ${FUZZ_SAN})
endfunction()

latkit_fuzzer(fuzz_pg fuzz_pg.c ${FUZZ_CORE_SRC} ${FUZZ_PROTO_SRC})
latkit_fuzzer(fuzz_norm fuzz_norm.c ${FUZZ_NORM_SRC})
latkit_fuzzer(fuzz_pipe fuzz_pipe.c ${FUZZ_CORE_SRC} ${FUZZ_PROTO_SRC} ${FUZZ_NORM_SRC}
              ${CMAKE_SOURCE_DIR}/src/agent/decode.c ${CMAKE_SOURCE_DIR}/src/agent/pipeline.c)

# Seed writer (campaign.sh regenerates seeds with it): plain host tool, no
# fuzzer runtime, so it builds and runs anywhere the profile configures.
add_executable(gen_seeds gen_seeds.c)

# Corpus regression: every committed input replayed once, no fuzzing. The .lkt
# fixtures double as extra pg inputs — raw traces through the same entry point.
set(FUZZ_CORPUS ${CMAKE_SOURCE_DIR}/tests/fuzz/corpus)
add_test(NAME fuzz_pg_corpus
         COMMAND fuzz_pg -runs=0 ${FUZZ_CORPUS}/pg ${CMAKE_SOURCE_DIR}/tests/fixtures)
add_test(NAME fuzz_norm_corpus COMMAND fuzz_norm -runs=0 ${FUZZ_CORPUS}/norm)
add_test(NAME fuzz_pipe_corpus COMMAND fuzz_pipe -runs=0 ${FUZZ_CORPUS}/pipe)
