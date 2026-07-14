cmake_minimum_required(VERSION 3.16)
project(latkit C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -Werror)

# --- version (Р45) ----------------------------------------------------------
# One source for --version, the --help header, the startup banner and the OTLP
# resource (service.version): git describe at configure time, overridable with
# -DLATKIT_VERSION= for builds without a .git (release tarballs). Configure-time
# capture means an incremental build after new commits keeps the old string
# until re-configure — acceptable for dev, and release builds always configure
# fresh.
set(LATKIT_VERSION "" CACHE STRING
    "Version string for --version and OTLP service.version (default: git describe)")
if(NOT LATKIT_VERSION)
    execute_process(COMMAND git describe --tags --always --dirty
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                    RESULT_VARIABLE _git_rc OUTPUT_VARIABLE _git_ver
                    OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
    if(_git_rc EQUAL 0)
        set(LATKIT_VERSION ${_git_ver})
    else()
        set(LATKIT_VERSION "unknown")
    endif()
endif()
message(STATUS "latkit version: ${LATKIT_VERSION}")
# Only the two consumers of version.h get the define, so a version bump does
# not rebuild the world.
set_property(SOURCE src/agent/main.c src/export/otlp.c APPEND PROPERTY
             COMPILE_DEFINITIONS LATKIT_VERSION="${LATKIT_VERSION}")

option(LATKIT_SYSTEM_LIBBPF "Link against system libbpf instead of the bundled submodule" OFF)
set(LATKIT_BPFTOOL "" CACHE FILEPATH "Path to bpftool (auto-detected when empty)")
set(LATKIT_VMLINUX_H "" CACHE FILEPATH
    "Pre-generated vmlinux.h (default: dumped from host BTF at build time)")

# --- bpftool ---------------------------------------------------------------
# Ubuntu's /usr/sbin/bpftool is a wrapper that fails when linux-tools for the
# running kernel is absent (typical on CI), so probe candidates by running them.
set(_bpftool_candidates ${LATKIT_BPFTOOL})
find_program(_bpftool_in_path bpftool HINTS /usr/sbin /usr/local/sbin)
if(_bpftool_in_path)
    list(APPEND _bpftool_candidates ${_bpftool_in_path})
endif()
file(GLOB _bpftool_versioned /usr/lib/linux-tools/*/bpftool)
list(APPEND _bpftool_candidates ${_bpftool_versioned})
set(BPFTOOL "")
foreach(_cand IN LISTS _bpftool_candidates)
    execute_process(COMMAND ${_cand} version RESULT_VARIABLE _rc
                    OUTPUT_QUIET ERROR_QUIET)
    if(_rc EQUAL 0)
        set(BPFTOOL ${_cand})
        break()
    endif()
endforeach()
if(NOT BPFTOOL)
    message(FATAL_ERROR "working bpftool not found; install linux-tools or set -DLATKIT_BPFTOOL=")
endif()
message(STATUS "bpftool: ${BPFTOOL}")

# --- BPF target arch -------------------------------------------------------
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64")
    set(BPF_ARCH x86)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(BPF_ARCH arm64)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "riscv64")
    set(BPF_ARCH riscv)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "s390x")
    set(BPF_ARCH s390)
else()
    message(FATAL_ERROR "unsupported architecture for BPF: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

find_program(CLANG_BPF clang REQUIRED)

# --- libbpf ----------------------------------------------------------------
if(LATKIT_SYSTEM_LIBBPF)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBBPF REQUIRED libbpf>=1.0)
    set(LIBBPF_INCLUDE_DIR ${LIBBPF_INCLUDE_DIRS})
    set(LATKIT_LIBBPF_LIBS ${LIBBPF_LIBRARIES})
    set(LIBBPF_BUILD_DEP "")
else()
    include(ExternalProject)
    set(LIBBPF_SRC ${CMAKE_CURRENT_SOURCE_DIR}/third_party/libbpf/src)
    if(NOT EXISTS ${LIBBPF_SRC}/Makefile)
        message(FATAL_ERROR "libbpf submodule is empty; run: git submodule update --init")
    endif()
    set(LIBBPF_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/libbpf)
    ExternalProject_Add(libbpf_ext
        PREFIX ${LIBBPF_PREFIX}
        SOURCE_DIR ${LIBBPF_SRC}
        CONFIGURE_COMMAND ""
        BUILD_COMMAND make -C ${LIBBPF_SRC} BUILD_STATIC_ONLY=1
                      OBJDIR=${LIBBPF_PREFIX}/obj DESTDIR=${LIBBPF_PREFIX}
                      INCLUDEDIR= LIBDIR= UAPIDIR= install install_uapi_headers
        INSTALL_COMMAND ""
        BUILD_BYPRODUCTS ${LIBBPF_PREFIX}/libbpf.a
        LOG_BUILD ON)
    add_library(libbpf_static STATIC IMPORTED GLOBAL)
    set_target_properties(libbpf_static PROPERTIES
                          IMPORTED_LOCATION ${LIBBPF_PREFIX}/libbpf.a)
    add_dependencies(libbpf_static libbpf_ext)
    set(LIBBPF_INCLUDE_DIR ${LIBBPF_PREFIX})
    set(LATKIT_LIBBPF_LIBS libbpf_static elf z)
    set(LIBBPF_BUILD_DEP libbpf_ext)
endif()

# --- vmlinux.h -------------------------------------------------------------
set(VMLINUX_DIR ${CMAKE_CURRENT_BINARY_DIR}/vmlinux)
if(LATKIT_VMLINUX_H)
    get_filename_component(VMLINUX_INCLUDE_DIR ${LATKIT_VMLINUX_H} DIRECTORY)
    set(VMLINUX_H ${LATKIT_VMLINUX_H})
elseif(EXISTS /sys/kernel/btf/vmlinux)
    set(VMLINUX_INCLUDE_DIR ${VMLINUX_DIR})
    set(VMLINUX_H ${VMLINUX_DIR}/vmlinux.h)
    add_custom_command(OUTPUT ${VMLINUX_H}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${VMLINUX_DIR}
        COMMAND sh -c "${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX_H}"
        COMMENT "Generating vmlinux.h from host BTF"
        VERBATIM)
else()
    # BTF-less hosts (btfhub snapshots etc.) are a stage 8 concern.
    message(FATAL_ERROR "no /sys/kernel/btf/vmlinux on this host; "
                        "pass -DLATKIT_VMLINUX_H=<pre-generated vmlinux.h>")
endif()

# --- latkit.bpf.o + skeleton ------------------------------------------------
set(BPF_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/bpf/latkit.bpf.c)
set(BPF_OBJ ${CMAKE_CURRENT_BINARY_DIR}/latkit.bpf.o)
set(SKEL_H ${CMAKE_CURRENT_BINARY_DIR}/latkit.skel.h)

add_custom_command(OUTPUT ${BPF_OBJ}
    # -mcpu=v3: atomic fetch-add (per-conn seq) needs BPF_ATOMIC ops, kernel >= 5.12.
    # -fms-extensions + -Wno-microsoft-anon-tag: kernels built with GCC's Plan 9
    # anonymous tagged members (e.g. `struct aes_enckey;` inside struct aes_key)
    # dump into vmlinux.h as tagged anonymous members; -fms-extensions is clang's
    # equivalent that keeps them as real embedded members (correct layout), the
    # -Wno silences the "Microsoft extension" note that -Werror would fail on.
    COMMAND ${CLANG_BPF} -g -O2 -target bpf -mcpu=v3 -D__TARGET_ARCH_${BPF_ARCH}
            -Wall -Werror -fms-extensions -Wno-microsoft-anon-tag
            -I${VMLINUX_INCLUDE_DIR} -I${CMAKE_CURRENT_SOURCE_DIR}/src/bpf
            -I${LIBBPF_INCLUDE_DIR}
            -c ${BPF_SRC} -o ${BPF_OBJ}
    DEPENDS ${BPF_SRC} ${CMAKE_CURRENT_SOURCE_DIR}/src/bpf/latkit.h ${VMLINUX_H}
            ${LIBBPF_BUILD_DEP}
    COMMENT "Compiling BPF object ${BPF_OBJ}"
    VERBATIM)

add_custom_command(OUTPUT ${SKEL_H}
    COMMAND sh -c "${BPFTOOL} gen skeleton ${BPF_OBJ} > ${SKEL_H}"
    DEPENDS ${BPF_OBJ}
    COMMENT "Generating BPF skeleton ${SKEL_H}"
    VERBATIM)

add_custom_target(latkit_skel DEPENDS ${SKEL_H})

# --- protocol handlers (stage 3) -------------------------------------------
# src/proto/** is the "core <-> protocol" layer (Р15): pure state machines, no
# libbpf and no I/O, so it links unchanged into both the agent and the offline
# unit/replay harnesses. It speaks to the core through the contract headers
# only (proto.h re-exports conn_table.h / reassembly.h).
set(PROTO_SRC src/proto/pg/pg.c src/proto/pg/pg_session.c src/proto/pg/pg_query.c
              src/proto/pg/pg_prep.c)
set(PROTO_INC ${CMAKE_CURRENT_SOURCE_DIR}/src/proto
              ${CMAKE_CURRENT_SOURCE_DIR}/src/proto/pg
              ${CMAKE_CURRENT_SOURCE_DIR}/src/agent
              ${CMAKE_CURRENT_SOURCE_DIR}/src/bpf)
add_library(latkit_proto STATIC ${PROTO_SRC})
target_include_directories(latkit_proto PUBLIC ${PROTO_INC})

# --- SQL normaliser (stage 4) ----------------------------------------------
# src/norm/** is pure like src/proto/**: no libbpf, no I/O beyond the caller's
# buffer, so it links into the agent and the offline harnesses alike. It depends
# on nothing but libc and the vendored xxhash (XXH3-64, header-only, BSD) — kept
# as a SYSTEM include so -Werror does not police third-party code.
add_library(latkit_norm STATIC src/norm/norm_sql.c)
target_include_directories(latkit_norm PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/norm)
target_include_directories(latkit_norm SYSTEM PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/xxhash)

# --- metrics registry (stage 4) --------------------------------------------
# src/metrics/** is pure like src/norm/**: histograms, the top-K series registry
# and the text-format dump, no libbpf and no I/O beyond the caller's FILE. The
# aggregator (task 4.3) links the normaliser and reads the lk_query_obs contract
# (proto.h, types only) — hence the proto/agent/bpf header dirs — but still no
# libbpf. selfstats.c (task 4.4) is the one impure member: it reads getrusage /
# procfs for the process_* series, still with no libbpf. The histogram needs
# libm (frexp/ldexp).
add_library(latkit_metrics STATIC
    src/metrics/hist.c src/metrics/registry.c src/metrics/metrics.c src/metrics/selfstats.c)
target_include_directories(latkit_metrics PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/metrics)
target_include_directories(latkit_metrics PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/proto ${CMAKE_CURRENT_SOURCE_DIR}/src/agent
    ${CMAKE_CURRENT_SOURCE_DIR}/src/bpf)
target_link_libraries(latkit_metrics PUBLIC m latkit_norm)

# --- exporters (stage 5) ---------------------------------------------------
# src/export/** is the pull/push export layer (Р29-Р31): it depends only on
# src/metrics/ and the shared epoll loop (loop.h from src/agent), never on
# libbpf or the rest of src/agent. That keeps it testable on loopback without
# BPF (test_http links it against a bare loop.c). loop.c itself stays with the
# agent; whoever links latkit_export also provides loop.o.
add_library(latkit_export STATIC src/export/http.c src/export/prom.c src/export/pbuf.c
            src/export/timebase.c src/export/otlp.c src/export/spans.c)
target_include_directories(latkit_export PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/export)
target_include_directories(latkit_export PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/agent ${CMAKE_CURRENT_SOURCE_DIR}/src/metrics
    ${CMAKE_CURRENT_SOURCE_DIR}/src/common ${CMAKE_CURRENT_SOURCE_DIR}/src/proto
    ${CMAKE_CURRENT_SOURCE_DIR}/src/bpf)
# spans.c reads the lk_query_obs contract (proto.h) and normalises the span name
# (latkit_norm) — still no libbpf, so the export lib stays BPF-free.
target_link_libraries(latkit_export PUBLIC latkit_metrics latkit_norm)

# --- agent -----------------------------------------------------------------
add_executable(latkit src/agent/main.c src/agent/loop.c src/agent/events.c
               src/agent/decode.c src/agent/conn_table.c src/agent/reassembly.c
               src/agent/pipeline.c src/agent/record.c src/agent/tls_attach.c
               src/agent/cgroup_filter.c src/agent/cgroup_match.c
               src/common/otel_env.c)
add_dependencies(latkit latkit_skel)
set_source_files_properties(src/agent/main.c PROPERTIES OBJECT_DEPENDS ${SKEL_H})
target_include_directories(latkit PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/src/bpf
    ${CMAKE_CURRENT_SOURCE_DIR}/src/proto ${CMAKE_CURRENT_SOURCE_DIR}/src/metrics
    ${CMAKE_CURRENT_SOURCE_DIR}/src/export ${CMAKE_CURRENT_SOURCE_DIR}/src/common
    ${LIBBPF_INCLUDE_DIR})
target_link_libraries(latkit latkit_proto latkit_metrics latkit_export ${LATKIT_LIBBPF_LIBS})

# Release builds (Р45): fully static musl binary, built in the Alpine builder
# stage of deploy/docker/Dockerfile. Only the agent goes static; tests and dev
# builds stay dynamic (sanitizers do not mix with musl -static).
option(LATKIT_STATIC "Link the agent fully static (musl toolchain; release builds)" OFF)
if(LATKIT_STATIC)
    target_link_options(latkit PRIVATE -static)
    # Alpine's static libelf is built with zstd support for compressed sections.
    target_link_libraries(latkit zstd)
endif()

# Install (Р47): just the binary, /usr/local/bin by default. The systemd unit
# and env file are copied by hand from deploy/systemd/ (see the header of
# latkit.service) — no deb/rpm in v1, so no point pretending CMake owns /etc.
include(GNUInstallDirs)
install(TARGETS latkit RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# --- tests -----------------------------------------------------------------
enable_testing()
add_subdirectory(tests/unit)
add_subdirectory(tests/replay)
add_subdirectory(tests/kernel)
add_subdirectory(tests/bench/micro)

# Accuracy cross-check (task 8.2, Р50): csvlog -> lk_norm_sql -> join with the
# --dump-metrics exposition. Links the very normaliser/histogram code the agent
# runs — that identity is the point of the tool (see its header). Built by
# tests/bench/accuracy/run.sh; no libbpf, so it builds anywhere.
add_executable(logjoin tests/bench/accuracy/logjoin.c)
target_link_libraries(logjoin latkit_metrics)

# Fuzzing profile (task 8.3, Р51): three libFuzzer targets (fuzz_pg, fuzz_norm,
# fuzz_pipe) with fuzzer+ASAN+UBSAN baked in, clang only. Off by default — a
# normal build never pays for it. See tests/fuzz/CMakeLists.txt.
option(LATKIT_FUZZ "Build the libFuzzer targets (clang; fuzzer,address,undefined)" OFF)
if(LATKIT_FUZZ)
    add_subdirectory(tests/fuzz)
endif()
