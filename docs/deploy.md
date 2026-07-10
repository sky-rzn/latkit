# Deployment notes

Operator-facing detail that does not belong in the README: the release
binary, the Docker image, and the **measured** minimal capability set with
its kernel/LSM caveats. Design decisions are Р45–Р47 in
[STAGE7.md](../STAGE7.md).

## The release binary

The release artifact is a **fully static musl binary** (Р45), built in the
Alpine builder stage of [`deploy/docker/Dockerfile`](../deploy/docker/Dockerfile):

```
docker build -f deploy/docker/Dockerfile -t latkit .
docker create --name lk latkit && docker cp lk:/latkit . && docker rm lk
```

`file latkit` reports `statically linked`; there is no libc, no NSS, no
dynamic loader involved at run time. musl was chosen over a "fully static"
glibc build deliberately: glibc's `getaddrinfo` dlopens `libnss_*` even from
a `-static` binary (and the OTLP exporter resolves its endpoint), while musl
carries its own resolver. The glibc/debian:11 fallback contemplated in Р45
was **not needed** — Alpine's static `libelf.a`/`libz.a`/`libzstd.a` link
cleanly against libbpf from `third_party/`.

The binary was verified on foreign userspaces (alpine 3.22, debian 12,
fedora 42 rootfs): `--version`, `--print-config`, the `LATKIT_*` env layer
and full capture behave identically — the only host dependency is the
kernel (≥ 5.15 with BTF; CO-RE, not tied to the build machine's kernel).

Version stamping: `git describe --tags --always --dirty` is captured by
CMake at configure time (override with `-DLATKIT_VERSION=` or the
`LATKIT_VERSION` build arg of the Dockerfile) and surfaces in `--version`,
the `--help` header, the startup banner, and the OTLP resource
(`service.version`).

Dev builds (`cmake --build build`) stay dynamic glibc — sanitizers do not
mix with musl `-static`.

## Docker image

`FROM scratch` + `/latkit`, ≈4.4 MB. Configuration is `LATKIT_*` env only
(Р34). No HEALTHCHECK in the image (nothing but the binary is inside);
probe `/healthz` from outside. `--network` is only needed to *scrape* the
agent — capture itself is fentry on the host kernel and sees every netns
regardless.

Plaintext capture:

```
docker run -d --pid=host \
    --cap-add BPF --cap-add PERFMON \
    -e LATKIT_PROM_LISTEN=0.0.0.0:9752 -p 9752:9752 latkit
```

With TLS capture (`LATKIT_TLS=auto`):

```
docker run -d --pid=host \
    --cap-add BPF --cap-add PERFMON --cap-add SYS_PTRACE --cap-add SYS_ADMIN \
    -e LATKIT_TLS=auto -e LATKIT_PROM_LISTEN=0.0.0.0:9752 -p 9752:9752 latkit
```

`--pid=host` is required for TLS: the libssl autodetect walks `/proc/<pid>`
of the postgres processes. Plaintext capture works without it, but keeping
it unconditionally is simpler and costs nothing.

## Minimal capabilities (measured)

Measured on the dev stand: kernel 7.0 (Ubuntu), Docker 29, default seccomp
profile, AppArmor `docker-default`. The container runs as root; the sets
below are `--cap-add` on top of Docker's default cap set.

| Feature | Capabilities | Why |
|---|---|---|
| Plaintext capture (fentry `tcp_*`, ringbuf) | `CAP_BPF` + `CAP_PERFMON` | `CAP_BPF` — bpf() (programs, maps); `CAP_PERFMON` — tracing program load |
| … on kernels < 5.11 | + `CAP_SYS_RESOURCE` | memlock rlimit for BPF memory (≥ 5.11 accounts via memcg; without it the agent logs a harmless `setrlimit(MEMLOCK)` warning) |
| TLS capture (libssl uprobes, Р39) | + `CAP_SYS_PTRACE` + `CAP_SYS_ADMIN` | `CAP_SYS_PTRACE` — `PTRACE_MODE_READ` for `/proc/<pid>/maps` and opening `/proc/<pid>/root/...` of foreign processes; `CAP_SYS_ADMIN` — the kernel's `perf_uprobe_init()` demands full `capable(CAP_SYS_ADMIN)` for **u**probes (`CAP_PERFMON` is enough for fentry/kprobes but *not* for uprobes — this is a kernel rule, not a Docker one) |

Failure signatures when a capability is missing — useful for triage:

| Missing | What you see |
|---|---|
| `CAP_PERFMON` | `prog 'lk_inet_sock_set_state': BPF program load failed: -EPERM` (libbpf then suggests raising `ulimit -l` — red herring) |
| `CAP_BPF` | `failed to load BPF skeleton: -EPERM` at map creation |
| `CAP_SYS_PTRACE` (TLS) | soft degradation: `TLS uprobes: no libssl found for comm 'postgres', TLS connections will be dropped` — the /proc scan comes back empty |
| `CAP_SYS_ADMIN` (TLS) | `failed to create uprobe '/proc/<pid>/root/...libssl.so.3:0x...' perf event: -EACCES` |

Notes:

- `CAP_SYS_ADMIN` subsumes `CAP_BPF`/`CAP_PERFMON` (the kernel's
  `bpf_capable()`/`perfmon_capable()` accept either), so the TLS set can be
  written as just `SYS_PTRACE + SYS_ADMIN`. The explicit four-cap list is
  kept in the documentation because it states intent and survives a future
  kernel relaxing the uprobe rule.
- **AppArmor** (`docker-default`, Ubuntu): no interference observed — the
  uprobe `-EACCES` above is the kernel capability check, not AppArmor
  (verified identical with `--security-opt apparmor=unconfined`).
- **seccomp**: Docker's default profile gates `bpf(2)`/`perf_event_open(2)`
  on the corresponding capabilities (Docker ≥ 20.10.10) — no custom profile
  needed. Much older Docker requires `--security-opt seccomp=unconfined` or
  a custom profile.
- **SELinux hosts** (Fedora/RHEL): untested; expect to need
  `--security-opt label=disable` or a policy that permits bpf/perf. Kernel
  and LSM combinations differ — when in doubt, fall back below.
- `--privileged` is the documented **fallback**, not the default: it
  short-circuits every check above (caps, seccomp, LSM) at the cost of
  granting everything. Use it to *diagnose* (if privileged works and the
  cap set does not, an LSM is in the way), or on runtimes that cannot
  express fine-grained caps.

## systemd unit and k8s DaemonSet

Shipped under `deploy/systemd/` and `deploy/k8s/` (task 7.5). The
capability findings above apply as-is:
`CapabilityBoundingSet`/`securityContext.capabilities.add` need
`SYS_ADMIN` whenever TLS capture is on, and `hostPID: true` is mandatory
for the libssl autodetect (Р39).
