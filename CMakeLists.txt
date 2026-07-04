cmake_minimum_required(VERSION 3.16)
project(latkit C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -Werror)

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
    COMMAND ${CLANG_BPF} -g -O2 -target bpf -mcpu=v3 -D__TARGET_ARCH_${BPF_ARCH}
            -Wall -Werror
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

# --- agent -----------------------------------------------------------------
add_executable(latkit src/agent/main.c src/agent/loop.c src/agent/events.c
               src/agent/decode.c src/agent/conn_table.c src/agent/reassembly.c)
add_dependencies(latkit latkit_skel)
set_source_files_properties(src/agent/main.c PROPERTIES OBJECT_DEPENDS ${SKEL_H})
target_include_directories(latkit PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/src/bpf ${LIBBPF_INCLUDE_DIR})
target_link_libraries(latkit ${LATKIT_LIBBPF_LIBS})

# --- tests -----------------------------------------------------------------
enable_testing()
add_subdirectory(tests/unit)
