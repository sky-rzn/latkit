# Kernel-matrix smoke helpers (task 8.4, Р52): tiny loopback replayers of the
# fixture byte streams — pgstream over plain TCP, tlspipe through a real libssl
# session. No libbpf, no docker: they run identically inside a vmtest VM
# (kernels.yml) and on a live host (smoke.sh drives them plus the agent).
set(KERNEL_SRC
    ${CMAKE_SOURCE_DIR}/tests/replay/fixtures_gen.c
    ${CMAKE_SOURCE_DIR}/src/agent/record.c)
set(KERNEL_INC ${CMAKE_SOURCE_DIR}/src/bpf ${CMAKE_SOURCE_DIR}/src/agent
    ${CMAKE_SOURCE_DIR}/src/proto ${CMAKE_SOURCE_DIR}/src/proto/pg
    ${CMAKE_SOURCE_DIR}/tests/replay)

add_executable(pgstream pgstream.c ${KERNEL_SRC})
target_include_directories(pgstream PRIVATE ${KERNEL_INC})

# tlspipe needs libssl; skip (with a notice) where the dev package is absent —
# the plaintext half of the smoke still works, smoke.sh degrades gracefully.
find_package(OpenSSL)
if(OPENSSL_FOUND)
    find_package(Threads REQUIRED)
    add_executable(tlspipe tlspipe.c ${KERNEL_SRC})
    target_include_directories(tlspipe PRIVATE ${KERNEL_INC})
    target_link_libraries(tlspipe OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
else()
    message(STATUS "tests/kernel: OpenSSL dev headers not found — tlspipe skipped")
endif()
