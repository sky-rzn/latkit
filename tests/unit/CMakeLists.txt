add_executable(test_smoke test_smoke.c)
target_include_directories(test_smoke PRIVATE ${CMAKE_SOURCE_DIR}/src/bpf)
add_test(NAME smoke COMMAND test_smoke)

add_executable(test_decode test_decode.c ${CMAKE_SOURCE_DIR}/src/agent/decode.c)
target_include_directories(test_decode PRIVATE
    ${CMAKE_SOURCE_DIR}/src/bpf ${CMAKE_SOURCE_DIR}/src/agent)
add_test(NAME decode COMMAND test_decode)

add_executable(test_seqtrack test_seqtrack.c ${CMAKE_SOURCE_DIR}/src/agent/seqtrack.c)
target_include_directories(test_seqtrack PRIVATE ${CMAKE_SOURCE_DIR}/src/agent)
add_test(NAME seqtrack COMMAND test_seqtrack)
