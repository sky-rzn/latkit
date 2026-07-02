add_executable(test_smoke test_smoke.c)
target_include_directories(test_smoke PRIVATE ${CMAKE_SOURCE_DIR}/src/bpf)
add_test(NAME smoke COMMAND test_smoke)
