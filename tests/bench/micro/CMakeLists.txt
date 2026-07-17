# Hot-path micro-benchmarks (per-op heap churn). Built with the normal dev
# toolchain; each links the very module it measures plus the --wrap allocation
# shims (bench_wrap.c). Registered under the CTest label "bench" with a small
# smoke iteration count so `ctest` stays fast; run a binary directly with a
# larger N (argv[1]) for a stable figure. See bench_util.h for the rationale.

# span text malloc (Р32): links the export lib (spans.c + normaliser).
add_executable(bench_spans bench_spans.c bench_wrap.c)
target_include_directories(bench_spans PRIVATE
    ${CMAKE_SOURCE_DIR}/src/export ${CMAKE_SOURCE_DIR}/src/proto
    ${CMAKE_SOURCE_DIR}/src/agent ${CMAKE_SOURCE_DIR}/src/bpf)
target_link_libraries(bench_spans latkit_export)
target_link_options(bench_spans PRIVATE
    -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free)
add_test(NAME bench_spans COMMAND bench_spans 100000)
set_tests_properties(bench_spans PROPERTIES LABELS bench)

# reassembly body-prefix buffer (Р11): links reassembly.c directly (no libbpf,
# no conn_table calls), mirroring test_reassembly. The proto lib supplies the
# PG framer vtable entry (РМ1).
add_executable(bench_reasm bench_reasm.c bench_wrap.c ${CMAKE_SOURCE_DIR}/src/agent/reassembly.c)
target_include_directories(bench_reasm PRIVATE
    ${CMAKE_SOURCE_DIR}/src/bpf ${CMAKE_SOURCE_DIR}/src/agent)
target_link_libraries(bench_reasm latkit_proto)
target_link_options(bench_reasm PRIVATE
    -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free)
add_test(NAME bench_reasm COMMAND bench_reasm 100000)
set_tests_properties(bench_reasm PROPERTIES LABELS bench)
