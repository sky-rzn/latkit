# Deployment notes

Operator-facing detail that does not belong in the README: the release
binary, the Docker image, the **measured** minimal capability set with its
kernel/LSM caveats, the systemd unit and the k8s DaemonSet (with the cgroup
filter's kubepods globs). Design decisions are Р45–Р48 in
[STAGE7.md](../STAGE7.md).

## Kernel support

The floor is **Linux 5.15 with BTF** (`CONFIG_DEBUG_INFO_BTF=y`, i.e.
`/sys/kernel/btf/vmlinux` present). Every program is CO-RE, so one binary
relocates across kernels — but only the versions the CI kernel matrix
(`kernels.yml`, Р52) actually boots are supported. Each is booted under
[vmtest](https://github.com/danobi/vmtest) with prebuilt
[cilium/ci-kernels](https://github.com/cilium/ci-kernels) images and run
through `tests/kernel/smoke.sh` — the fixture byte streams replayed over a
real loopback socket (`pgstream`) and a real libssl session (`tlspipe`),
asserting OPEN/CLOSE, exact query/error counts, and zero parse-errors /
resyncs / ringbuf-drops / `iter_unsupported`, in both plaintext and TLS.

| Kernel | Status | Notes |
|---|---|---|
| < 5.15 | **unsupported** | ringbuf exists from 5.8, but not tested and not promised; the agent still tries to load and will fail loudly if a relocation is missing |
| 5.15 LTS | ✅ matrix | IOVEC path (no `ITER_UBUF` yet); `tcp_recvmsg` has the pre-5.19 `nonblock` arg — a dedicated fexit variant is autoloaded |
| 6.1 LTS | ✅ matrix | |
| 6.8 | ✅ matrix | |
| current stable | ✅ matrix | latest stable at CI time (7.x); `tcp_recvmsg` dropped `addr_len` — a third fexit variant covers it |
| no BTF (any version) | **refused** | startup check fails with `kernel 5.15+ with BTF is required`; a `kernels.yml` negative test asserts the message and a clean exit (no segfault) |

CO-RE handles the version drift internally (`src/bpf/latkit.bpf.c`,
[notes-iov.md](notes-iov.md)): the `iov_iter` shape and field spellings
(`ubuf`/`__iov`/`iov`), the `iter_type` enum renumbering across the
`ITER_UBUF` addition, and the changing arity of `tcp_recvmsg` are all
resolved at load time — the event format never changes. **arm64** is a v1.1
target (CO-RE does not stand in the way; it is untested hardware).

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
- **AppArmor** (`docker-default`, Ubuntu): no interference with *plaintext*
  capture, and the uprobe `-EACCES` above is the kernel capability check, not
  AppArmor (verified identical with `--security-opt apparmor=unconfined`).
  **But `docker-default` DOES break the `LATKIT_TLS=auto` libssl scan in a
  container**: the scan reads `/proc/<host-pid>/root/.../libssl.so` of the
  postgres backends, and the profile mediates that cross-process `/proc`
  access — the scan comes back empty and the agent logs `TLS uprobes: no
  libssl found for comm 'postgres'` *even with `CAP_SYS_PTRACE` granted*
  (isolated on a VPS: `--privileged` worked, the four-cap set did not,
  `cap_add:[…] + --security-opt apparmor=unconfined` with the same caps
  fixed it — so AppArmor, not a missing cap). For containerised TLS capture
  add `apparmor=unconfined` (keeps seccomp + the minimal caps) or ship a
  custom profile that permits the `/proc/<pid>/root` traversal. The host
  **systemd** unit is not under `docker-default` and needs none of this — the
  scan resolves natively; prefer it for TLS installs.
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

## systemd unit

[`deploy/systemd/latkit.service`](../deploy/systemd/latkit.service) +
[`latkit.env.example`](../deploy/systemd/latkit.env.example); install steps in
the unit header. The env file is the **only** configuration surface (Р34/Р47) —
every `LATKIT_*` variable is documented in the example, and the resolved
config can be checked without touching BPF:

```
sudo env $(grep -v '^#' /etc/latkit/latkit.env | xargs) latkit --print-config
```

Verified on the dev host (kernel 7.0, systemd 257):

- the sandbox (`ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
  `NoNewPrivileges=yes`) does **not** interfere with capture, including TLS:
  uprobe attach opens `/proc/<pid>/root/...libssl.so.3` of a foreign
  container's mount namespace, and those procfs magic links resolve in the
  *target's* namespace, outside the unit's mount sandbox. Confirmed by
  attaching to an alpine container's libssl from the sandboxed unit;
- the capability findings above apply as-is: the shipped
  `CapabilityBoundingSet` carries the TLS set including `CAP_SYS_ADMIN`
  (uprobes); running plaintext-only, delete `CAP_SYS_PTRACE CAP_SYS_ADMIN`
  from it for a tighter unit;
- `Restart=on-failure` verified with `kill -9`: a fresh agent is up after
  `RestartSec=5`, re-attaches, capture continues (counters restart from zero —
  they are process-local; `rate()` in Grafana absorbs the reset);
- `systemctl restart` is clean — BPF links are kernel-side per-fd objects and
  die with the process, nothing leaks between generations;
- `--record` under `ProtectSystem=strict` needs its target directory
  whitelisted via `ReadWritePaths=` (comment in the unit).

Non-root + `AmbientCapabilities` stays a v1.1 experiment (Р47):
`/proc/<pid>/root` of other uids' processes from non-root needs its own
verification round.

## k8s DaemonSet

[`deploy/k8s/latkit-daemonset.yaml`](../deploy/k8s/latkit-daemonset.yaml) —
one file, no Helm (v1 scope). `hostPID: true` (mandatory for the libssl
autodetect, Р39), the measured capability set from the table above,
`hostNetwork` deliberately absent (fentry sees every netns of the node;
`/metrics` is a normal pod port). Verified end-to-end on kind v0.29
(kubernetes 1.33, containerd, cgroup v2): DaemonSet Ready with green
`/healthz` probes, pgbench Job traffic lands in `latkit_queries_total`,
in-cluster scrape by pod IP works, and the fine-grained capability set is
sufficient — no `privileged: true` needed on kind/containerd.

kind/k8s specifics that came out of the run:

- **Pod Security Admission**: hostPID + added capabilities require the
  namespace to be labelled
  `pod-security.kubernetes.io/enforce=privileged` on PSA-enforced clusters;
- **BTF**: `/sys/kernel/btf/vmlinux` is visible inside the kind node (and any
  normal container) without an extra hostPath — sysfs is mounted by default;
- **image**: kind does not pull local images — `kind load docker-image
  latkit:latest --name <cluster>`.

### cgroup filter in k8s (Р48)

The scenario the filter exists for: several postgres pods on one node, all on
port 5432 — the port and comm filters cannot tell them apart. Confirmed on
kind with two postgres pods (different QoS classes) and a guaranteed-only
glob: only the target pod's queries are counted, the other pod produces no
series at all; `latkit_cgroup_filter_paths` reports the matched-path count
(0 = misconfigured glob, warn-logged).

Where pods live under `/sys/fs/cgroup` depends on the cgroup driver and the
kubelet's cgroup root — **check the node, then write the glob**:

| Node flavour | Pod cgroup path (relative to /sys/fs/cgroup) |
|---|---|
| systemd driver (kubeadm default) | `kubepods.slice/kubepods-<qos>.slice/kubepods-<qos>-pod<uid>.slice/cri-containerd-<cid>.scope` |
| … guaranteed QoS pods | `kubepods.slice/kubepods-pod<uid>.slice/…` (no qos sub-slice) |
| kind (kubelet cgroup root `/kubelet`) | `kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-pod<uid>.slice/…` |
| cgroupfs driver | `kubepods/<qos>/pod<uid>/<cid>` |

Pod uid dashes become underscores in the systemd slice names
(`pod6187d742_9023_…`).

Glob rules that matter here:

- the predicate compares `bpf_get_current_cgroup_id()` — the **leaf** cgroup
  of the postgres process — against exact matched directories, so patterns
  must reach the leaves: end them with `/**` (matches the directory itself
  and everything below);
- a glob pinned to a pod **uid** goes stale when the pod is recreated — the
  replacement gets a new uid. The 30 s re-resolve handles churn only if the
  *pattern* still matches the new path: select structurally (all of
  `kubepods.slice/**`, a QoS class, `kubelet-kubepods-pod*.slice/**`) rather
  than by uid. Verified: pod delete + recreate under a structural glob is
  picked up by the next re-resolve tick (old ids removed, new added, capture
  resumes; the first seconds before the tick are lost — documented Р48 gap);
- combine with the port/comm filters (AND semantics) to narrow *what* within
  the matched cgroups is captured.

`resources` in the manifest (100m/64Mi requests, 500m/256Mi limits) are a
working hypothesis until the stage-8 load budget; RSS scales with connection
count and `LATKIT_TOP_QUERIES`.
