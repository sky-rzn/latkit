# Release image (Р45/Р46): builder = fully static musl binary on Alpine,
# final stage = scratch with exactly /latkit inside. musl over glibc because a
# truly static glibc binary is a trap (getaddrinfo/NSS dlopen libnss_* at
# runtime, and the OTLP client resolves its endpoint); musl carries its own
# resolver, so -static means what it says.
#
# Build from the repository root (the context must be the repo, .git included
# for the version stamp):
#
#   docker build -f deploy/docker/Dockerfile -t latkit .
#
# vmlinux.h is generated from the *build host's* BTF (/sys/kernel/btf/vmlinux
# is visible inside `docker build` steps), so building requires a Linux host
# with a BTF-enabled kernel — the same requirement running the agent has.
# The result is CO-RE, not tied to the build kernel.
#
# Run (Р46; hostPID is required for the TLS libssl autodetect, Р39):
#
#   docker run --pid=host \
#       --cap-add BPF --cap-add PERFMON \
#       -p 9752:9752 -e LATKIT_PROM_LISTEN=0.0.0.0:9752 latkit
#
# TLS capture (LATKIT_TLS=auto) additionally needs --cap-add SYS_PTRACE
# (reading /proc/<pid> of the postgres processes) and --cap-add SYS_ADMIN
# (the kernel requires it for uprobe creation); kernels < 5.11 also want
# --cap-add SYS_RESOURCE for the memlock rlimit. The measured matrix, the
# failure signatures and the --privileged fallback: docs/deploy.md.

FROM alpine:3.22 AS builder

# clang both compiles the BPF object and (CC=clang) the agent: no gcc needed.
# elfutils-dev ships the static libelf.a on Alpine; libbpf comes from the
# third_party submodule (stage 0), already BUILD_STATIC_ONLY.
RUN apk add --no-cache clang cmake make musl-dev linux-headers git \
        elfutils-dev zlib-static zstd-static bpftool

COPY . /src

RUN test -r /sys/kernel/btf/vmlinux || { \
        echo >&2 "error: /sys/kernel/btf/vmlinux is not visible in the build" \
                 " container; build on a Linux host with a BTF-enabled kernel" \
                 " (5.15+ recommended)"; exit 1; }

# Overrides the version stamp when the context has no usable .git (e.g. a
# source tarball); empty means CMake runs `git describe --tags` itself.
ARG LATKIT_VERSION=

# CC=clang reaches the libbpf ExternalProject make, which defaults to `cc`
# (not installed). Only the agent target is built: tests stay out of the image.
RUN CC=clang cmake -B /build -S /src \
        -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Release \
        -DLATKIT_STATIC=ON -DLATKIT_VERSION="${LATKIT_VERSION}" && \
    CC=clang cmake --build /build --target latkit -j"$(nproc)" && \
    /build/latkit --version

FROM scratch
COPY --from=builder /build/latkit /latkit
# No HEALTHCHECK on purpose: scratch has no curl, and compose/k8s probe
# /healthz from outside (kubelet httpGet needs nothing in the image).
ENTRYPOINT ["/latkit"]
