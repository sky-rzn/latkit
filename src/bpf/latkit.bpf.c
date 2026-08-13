// SPDX-License-Identifier: GPL-2.0
/* Stage 1 capture layer: TCP traffic of sockets whose LOCAL port is in the
 * `ports` map — the server side only (design decision Р7) — in both
 * directions, keyed by connection.
 *
 * SEND is observed on entry to tcp_sendmsg; RECV uses the paired fentry/fexit
 * scheme on tcp_recvmsg (buffer known only on exit, once ret bytes have been
 * copied). Payload bytes are read out of the userspace iov_iter for both
 * directions — multi-segment iovecs included, via a segment snapshot taken
 * while the iterator is still unadvanced; see iter_snapshot() and
 * docs/notes-iov.md. One call becomes a chain of chunked data events sharing
 * total_len (emit_data_chunks).
 *
 * Connections are identified by the socket cookie (design decision Р1) and
 * registered in the `conns` LRU map (Р2). The lifecycle path is
 * tp_btf/inet_sock_set_state (Р3): TCP_ESTABLISHED registers the connection
 * and emits CONN_OPEN, TCP_CLOSE emits CONN_CLOSE and drops the entry.
 * Connections first seen on the data path (opened before the agent started,
 * or whose lifecycle event was lost) get a lazily created entry plus a
 * synthetic CONN_OPEN. */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "latkit.h"

char LICENSE[] SEC("license") = "GPL";

/* Not exposed as macros by vmlinux.h. */
#define AF_INET  2
#define AF_INET6 10

/* Force a real load/store, no clang store-to-load forwarding. The chunk loop
 * depends on its cursor values actually round-tripping through map memory —
 * see the lk_cursor comment. */
#define ONCE(x) (*(volatile typeof(x) *)&(x))

/* Capture budget in bytes per send/recv call (design decision Р6). Affects
 * cap_len only — total_len always reports the real call size, so the stage 2
 * reassembler knows the exact size of the hole. The per-connection
 * capture_mode in `conns` can tighten it further (LK_CAP_HEADERS). */
const volatile __u32 cfg_capture_limit = LK_CAPTURE_LIMIT;

/* Optional comm filter (task 1.3), off when the first entry is empty; entries
 * are packed from index 0. A short list, not a single name (РМ10): the match is
 * against the *thread* comm, and one server may need several — MySQL 8.x names
 * its per-session threads `connection` while the process stays `mysqld`.
 * Checked on the send/recv path and in the uprobe channels — everywhere the
 * program runs in the calling task's context. Never from the lifecycle
 * tracepoint, which may fire in softirq where comm is garbage.
 *
 * This one carries **only what the operator asked for** (`--comm`): it is a
 * capture filter, and its whole meaning is "capture nothing else". */
const volatile char cfg_comm_filter[LK_COMM_FILTER_MAX][LK_COMM_LEN];

/* The second filter, and the reason there are two: the comm set the agent
 * *derives* for TLS (the libssl scan set, a `--tls-comm`, the basenames of
 * `--tls-go` binaries, plus `connection`) gates the **uprobe channels only**.
 *
 * A uprobe on a shared libssl attaches at pid=-1, so it fires for every process
 * on the host that maps that file — a psql or a curl included. Something has to
 * say which of them is the server we mean, and a comm is what we have.
 *
 * The socket path needs no such gate: it is already scoped to the configured
 * local ports (Р7), i.e. to the server side of exactly the traffic that was
 * asked for. Gating it on the same derived set (as v1 did until PLAN-HTTP.md
 * М9) silently narrowed *plaintext* capture to the servers the TLS scanner
 * happens to know: with `--tls auto`, a `--port 8081=http` served by a Go, Node
 * or Python process — the ordinary shape of an application behind nginx —
 * produced no observations at all, while the nginx port looked fine. Harmless
 * where the captured process is the scanned one (a database host), a silent
 * blind spot anywhere else. */
const volatile char cfg_tls_comm_filter[LK_COMM_FILTER_MAX][LK_COMM_LEN];

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, LK_RINGBUF_SZ);
} events SEC(".maps");

/* Connection registry, key = socket cookie. LRU so that entries whose
 * CONN_CLOSE was missed (lost event, agent restart) age out on their own;
 * sized ~x10 over a typical max_connections. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct lk_conn_state);
} conns SEC(".maps");

/* Per-connection capture-budget override (Р21), key = socket cookie, value =
 * __u8 enum lk_cap_mode. Written only by userspace (the stage-3 policy and the
 * --cap-headers hook), read here on the data path. Split out of `conns` so the
 * userspace writer never read-modify-writes lk_conn_state and thus cannot race
 * the kernel's seq/dropped updates. LRU so a missed CONN_CLOSE ages out; a miss
 * means FULL. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u8);
} capmode SEC(".maps");

/* Snapshot of the userspace segments of one send/recv call: up to LK_MAX_SEGS
 * {base, len} pairs in call order. Filled by iter_snapshot(), consumed by
 * emit_data_chunks(). nr == 0 means nothing capturable (unsupported iterator
 * type) — the data path still emits one empty event to keep total_len honest. */
struct lk_segs {
    __u64 base[LK_MAX_SEGS];
    __u32 len[LK_MAX_SEGS];
    __u32 nr;
};

/* Per-in-flight-recv segment snapshot saved on fentry(tcp_recvmsg) and
 * consumed on fexit (by then the iterator has been advanced past the copied
 * bytes). Keyed by pid_tgid: tcp_recvmsg does not switch task between entry
 * and exit, so the caller's pid_tgid uniquely identifies the pending call. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct lk_segs);
} recv_state SEC(".maps");

/* Loop cursor of emit_data_chunks. Lives in a per-CPU map, not on the stack,
 * on purpose: the verifier does not track map-value memory, so the
 * loop-carried values reloaded from here each iteration come back as
 * bounds-checked unknowns and the chunk-loop states converge and prune. Kept
 * on the stack they stay precise per path, and the 8-chunk loop blows the
 * 1M-insn verification budget (measured, not theoretical). `busy` guards
 * against a preempting send/recv on the same CPU (CONFIG_PREEMPT) clobbering
 * the cursor mid-chain.
 *
 * A small pool of slots per CPU, not a single cursor: chains DO interleave on
 * one CPU under load — a preempting task runs its own send/recv (or SSL_*)
 * chain before the first one resumes. With one slot the preemptor had to
 * degrade to a single empty TRUNC event, i.e. an artificial capture hole that
 * dirtied the framer and cost a resync (measured on the TLS benchmark: a
 * handful per minute at 50k qps, gone with the pool). Claiming scans for a
 * free slot; only when all of them are mid-chain does the old degrade path
 * kick in. */
#define LK_CURSOR_SLOTS 4

struct lk_cursor {
    __u32 busy;
    __u32 si;     /* current segment index */
    __u32 soff;   /* bytes of segs->len[si] already consumed */
    __u32 pos;    /* stream offset within the call = sum of emitted cap_len */
    __u32 budget; /* capture bytes still allowed for this call */
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, LK_CURSOR_SLOTS);
    __type(key, __u32);
    __type(value, struct lk_cursor);
} cursor SEC(".maps");

/* First free cursor slot on this CPU, marked busy; NULL when all are taken by
 * preempted chains (the caller then degrades to a single empty event). The
 * test_and_set is atomic against a preemptor scanning the same slots. */
static __always_inline struct lk_cursor *cursor_claim(void)
{
    for (__u32 i = 0; i < LK_CURSOR_SLOTS; i++) {
        __u32 key = i;
        struct lk_cursor *cur = bpf_map_lookup_elem(&cursor, &key);

        if (!cur)
            return NULL;
        if (!__sync_lock_test_and_set(&cur->busy, 1))
            return cur;
    }
    return NULL;
}

/* Global loss/volume statistics (design decision Р5), indexed by enum
 * lk_stat_id; the agent sums across CPUs and reports periodically. Per-CPU,
 * so a plain += suffices: a preempting BPF program on the same CPU can in
 * theory lose one increment, which is acceptable for statistics. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, LK_ST_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void stat_add(__u32 id, __u64 n)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &id);

    if (v)
        *v += n;
}

/* Account one lost event of this connection (Р5): the seq number was already
 * consumed by the caller, so userspace sees a hole; gap_pending additionally
 * makes the next successful event carry LK_F_GAP. A plain store is enough —
 * against a concurrent gap_take() either order leaves the loss flagged. */
static __always_inline void conn_mark_loss(struct lk_conn_state *st, __u32 stat_id)
{
    __sync_fetch_and_add(&st->dropped, 1);
    st->gap_pending = 1;
    stat_add(stat_id, 1);
}

/* Atomically claim the pending-gap marker: exactly one of the events racing
 * past a loss gets LK_F_GAP. */
static __always_inline __u16 gap_take(struct lk_conn_state *st)
{
    return __sync_lock_test_and_set(&st->gap_pending, 0) ? LK_F_GAP : 0;
}

/* Port filter, filled by the agent from --port after load, before attach.
 * Keys are host-order local ports; the value carries the port's capture budget
 * (РH14) — presence in the map is still the whole filter, the value only tunes
 * how much of each call is copied. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, LK_MAX_PORTS);
    __type(key, __u16);
    __type(value, struct lk_port_cfg);
} ports SEC(".maps");

/* UDP volume counters (РH16), key = {port, dir}. Per-CPU so the QUIC fast path
 * costs one uncontended add; userspace sums across CPUs. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, LK_MAX_UDP_KEYS);
    __type(key, struct lk_udp_key);
    __type(value, struct lk_udp_stat);
} udp_stats SEC(".maps");

/* cgroup filter (task 7.1, Р48): keys are cgroup ids
 * (bpf_get_current_cgroup_id), value unused. Filled and diffed by the agent's
 * resolver from --cgroup glob patterns; an empty map means the filter is off,
 * exactly like `ports`. cgroup ids are only meaningful on a cgroup v2 unified
 * hierarchy — the agent refuses --cgroup on a v1 host at startup. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, LK_MAX_CGROUPS);
    __type(key, __u64);
    __type(value, __u8);
} cgroups SEC(".maps");

/* Single flag mirroring "the `cgroups` map is non-empty", maintained by the
 * agent after every re-resolve. HASH maps have no O(1) emptiness test in BPF,
 * so this array carries it: index 0 is 1 while the filter is active, 0 when the
 * map is empty (no --cgroup, or a glob that matched nothing — filter off). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} cgroup_on SEC(".maps");

/* Capture predicate (design decision Р7): the LOCAL port must be in `ports`,
 * i.e. only the server-side socket is captured. This dedups loopback traffic
 * (client SEND + server RECV of the same payload) for free and pins direction
 * semantics: RECV = frontend->backend, SEND = backend->frontend. skc_num is
 * already host order. */
static __always_inline struct lk_port_cfg *sk_port_cfg(struct sock *sk)
{
    __u16 lport = BPF_CORE_READ(sk, __sk_common.skc_num);

    return bpf_map_lookup_elem(&ports, &lport);
}

static __always_inline int sk_port_match(struct sock *sk)
{
    return sk_port_cfg(sk) != NULL;
}

/* Capture budget for this call (Р6 + РH14): the port's own limit when it has
 * one, otherwise the global --capture-limit. Nothing else about the value is
 * interpreted here — the precedence between the flag, the protocol default and
 * the explicit `:BYTES` was resolved in userspace. */
static __always_inline __u32 port_budget(const struct lk_port_cfg *pc)
{
    __u32 cap = pc ? pc->cap_limit : 0;

    return cap ? cap : cfg_capture_limit;
}

/* Same, by port number: the uprobe channels have no struct sock, only the tuple
 * snapshot taken when the connection was correlated. */
static __always_inline __u32 port_cfg_budget(__u16 lport)
{
    return port_budget(bpf_map_lookup_elem(&ports, &lport));
}

/* cgroup filter (task 7.1, Р48): the calling task's cgroup id must be in the
 * `cgroups` map. A no-op unless the map is non-empty (cgroup_on[0] != 0). Like
 * comm_allowed(), only valid on the send/recv path: fentry(tcp_sendmsg) and
 * fexit(tcp_recvmsg) run in the postgres backend's task context, so `current`
 * is that backend and its cgroup id is the one we filter on. Never called from
 * the lifecycle tracepoint, which can fire in softirq. */
static __always_inline int cgroup_allowed(void)
{
    __u32 zero = 0;
    __u32 *on = bpf_map_lookup_elem(&cgroup_on, &zero);
    __u64 id;

    if (!on || !*on)
        return 1; /* map empty: filter off */
    id = bpf_get_current_cgroup_id();
    return bpf_map_lookup_elem(&cgroups, &id) != NULL;
}

/* Exact-match against one comm list: the current thread's comm must equal one of
 * the configured entries; a no-op (allow) unless the list is set. Both callers
 * run in the calling task's context — see the two cfg_*_comm_filter comments. */
static __always_inline int comm_match(const volatile char (*flt)[LK_COMM_LEN])
{
    char comm[LK_COMM_LEN];

    if (!flt[0][0])
        return 1;
    if (bpf_get_current_comm(comm, sizeof(comm)))
        return 0;
    for (unsigned f = 0; f < LK_COMM_FILTER_MAX; f++) {
        unsigned i;

        if (!flt[f][0])
            break; /* packed from 0: first empty entry ends the list */
        for (i = 0; i < LK_COMM_LEN; i++) {
            if (comm[i] != flt[f][i])
                break;
            if (!comm[i])
                return 1; /* equal up to and including the NUL */
        }
        if (i == LK_COMM_LEN)
            return 1; /* both unterminated at 16 bytes: full-buffer match */
    }
    return 0;
}

/* The operator's `--comm`: every path, socket and uprobe alike. */
static __always_inline int comm_allowed(void)
{
    return comm_match(cfg_comm_filter);
}

/* The uprobe gate: `--comm` (if any) *and* the agent-derived TLS set. Both, not
 * either — the derived set says which server the uprobes are for, `--comm` says
 * what the operator wants captured at all, and neither implies the other. */
static __always_inline int tls_comm_allowed(void)
{
    return comm_match(cfg_comm_filter) && comm_match(cfg_tls_comm_filter);
}

/* Fill *t (must be zeroed by the caller) from the socket. tcp_sendmsg and
 * tcp_recvmsg are shared between tcp_prot and tcpv6_prot, so both families
 * arrive here; v6 addresses are read only when the kernel has the fields. */
static __always_inline void fill_tuple(struct lk_tuple *t, struct sock *sk)
{
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

    t->family = family;
    t->netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
    t->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    t->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    if (family == AF_INET6 && bpf_core_field_exists(sk->__sk_common.skc_v6_rcv_saddr)) {
        BPF_CORE_READ_INTO(&t->saddr, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&t->daddr, sk, __sk_common.skc_v6_daddr);
    } else {
        __u32 s4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __u32 d4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);

        __builtin_memcpy(t->saddr, &s4, sizeof(s4));
        __builtin_memcpy(t->daddr, &d4, sizeof(d4));
    }
}

static __always_inline void emit_conn_event(__u8 type, __u64 cookie, struct lk_conn_state *st,
                                            __u16 flags, __u32 pid)
{
    struct lk_ev_conn *ev;
    /* seq is consumed before reserve so that a failed reserve leaves a hole
     * in the sequence — one of the two loss signals of Р5. */
    __u32 seq = __sync_fetch_and_add(&st->seq, 1);

    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        conn_mark_loss(st, type == LK_EV_CONN_OPEN ? LK_ST_RESERVE_FAIL_OPEN
                                                   : LK_ST_RESERVE_FAIL_CLOSE);
        return;
    }
    flags |= gap_take(st);

    __builtin_memset(ev, 0, sizeof(*ev)); /* ringbuf memory is not zeroed */
    ev->hdr.conn_id = cookie;
    ev->hdr.ts_ns = bpf_ktime_get_ns();
    ev->hdr.seq = seq;
    ev->hdr.type = type;
    ev->hdr.flags = flags;
    ev->tuple = st->tuple;
    ev->pid = pid;
    ev->conn_dropped = st->dropped;
    bpf_ringbuf_submit(ev, 0);
    stat_add(LK_ST_EVENTS, 1);
}

/* Look the connection up in `conns`, lazily registering it when absent:
 * a miss on the data path means the connection was opened before the agent
 * started (or its OPEN was lost / the entry was LRU-evicted), so the parser
 * never saw the startup phase — hence the synthetic CONN_OPEN. BPF_NOEXIST
 * makes the first CPU to insert win, so the race emits a single OPEN. */
static __always_inline struct lk_conn_state *conn_get(struct sock *sk, __u64 cookie)
{
    struct lk_conn_state *st = bpf_map_lookup_elem(&conns, &cookie);
    struct lk_conn_state init = {};
    int created;

    if (st)
        return st;

    fill_tuple(&init.tuple, sk);
    init.flags = LK_CS_OPEN_SENT;
    created = bpf_map_update_elem(&conns, &cookie, &init, BPF_NOEXIST) == 0;

    st = bpf_map_lookup_elem(&conns, &cookie);
    if (st && created)
        emit_conn_event(LK_EV_CONN_OPEN, cookie, st, LK_F_SYNTHETIC,
                        bpf_get_current_pid_tgid() >> 32);
    return st;
}

/* Lifecycle path (task 1.2, design decision Р3). inet_sock_set_state fires on
 * every TCP state transition host-wide, possibly in softirq context, where
 * pid/comm belong to whatever task was interrupted — never read them here;
 * lk_ev_conn.pid stays 0 on this path. The tracepoint is shared with DCCP and
 * others, hence the protocol check. */
SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(lk_inet_sock_set_state, struct sock *sk, int oldstate, int newstate)
{
    struct lk_conn_state *st;
    __u64 cookie;

    if (BPF_CORE_READ(sk, sk_protocol) != IPPROTO_TCP)
        return 0;

    if (newstate == TCP_ESTABLISHED) {
        struct lk_conn_state init = {};

        if (!sk_port_match(sk))
            return 0;
        cookie = bpf_get_socket_cookie(sk);

        /* BPF_NOEXIST: if the data path won the race and already emitted a
         * synthetic OPEN (LK_CS_OPEN_SENT), do not emit a second one. */
        fill_tuple(&init.tuple, sk);
        init.flags = LK_CS_OPEN_SENT;
        if (bpf_map_update_elem(&conns, &cookie, &init, BPF_NOEXIST))
            return 0;

        st = bpf_map_lookup_elem(&conns, &cookie);
        if (st)
            emit_conn_event(LK_EV_CONN_OPEN, cookie, st, 0, 0);
        return 0;
    }

    if (newstate != TCP_CLOSE)
        return 0;

    /* CLOSE: presence in `conns` is the filter — the entry exists only if
     * this connection matched the port on ESTABLISHED or on the data path.
     * Covers failed connects too: they never got an entry, so no event. */
    cookie = bpf_get_socket_cookie(sk);
    st = bpf_map_lookup_elem(&conns, &cookie);
    if (!st)
        return 0;

    emit_conn_event(LK_EV_CONN_CLOSE, cookie, st, 0, 0);
    bpf_map_delete_elem(&conns, &cookie);
    return 0;
}

/* CO-RE flavor for kernels before ~6.4, where the iovec pointer of iov_iter
 * was still spelled `iov` (renamed `__iov` by the iter_iov() accessor rework).
 * The ___old suffix is stripped during BTF matching, so reads through this
 * shape relocate against the real struct iov_iter / struct msghdr; only the
 * fields actually read need declaring. Selected at load time by
 * bpf_core_field_exists in iter_iov_first() below. */
struct iov_iter___old {
    const struct iovec *iov;
} __attribute__((preserve_access_index));

struct msghdr___old {
    struct iov_iter___old msg_iter;
} __attribute__((preserve_access_index));

/* First segment of an ITER_IOVEC iterator under either field spelling:
 * `__iov` (~6.4+, the spelling of the build vmlinux.h) or `iov` (5.15/6.1).
 * Whichever branch the target kernel lacks is dead code after relocation. */
static __always_inline const struct iovec *iter_iov_first(struct msghdr *msg)
{
    if (bpf_core_field_exists(msg->msg_iter.__iov))
        return BPF_CORE_READ(msg, msg_iter.__iov);
    return BPF_CORE_READ((struct msghdr___old *)(void *)msg, msg_iter.iov);
}

/* Snapshot the userspace segments of msg->msg_iter into *s: the
 * generalization of stage-0 iter_first_seg (task 1.4). A snapshot instead of
 * a direct read because on the RECV path the iterator has been advanced past
 * the copied bytes by fexit time — the segment list is taken on fentry and
 * consumed on fexit. All fields are read through CO-RE so the same object
 * relocates across the field renames documented in docs/notes-iov.md.
 *
 * Two iterator shapes matter for socket traffic:
 *   ITER_UBUF  (~6.0+): a single userspace buffer. Current position is
 *              ubuf + iov_offset; `count` is the bytes still to transfer.
 *   ITER_IOVEC:         a vector of userspace buffers, iov[0..nr_segs)
 *              (spelled __iov since ~6.4, see iter_iov_first). The first
 *              segment is adjusted by iov_offset, the rest are taken whole;
 *              capture stops after LK_MAX_SEGS segments.
 *
 * The iter_type comparisons go through bpf_core_enum_value, not the build
 * vmlinux.h constants: adding ITER_UBUF in ~6.0 gave it value 0 and pushed
 * ITER_IOVEC from 0 to 1, so a hardcoded constant silently matches the wrong
 * flavour on the other side of that kernel (on 5.15 every send/recv would be
 * rejected as unsupported — task 8.4, Р52). On pre-6.0 kernels the
 * enum_value_exists/field_exists guards are false at load time and the
 * poisoned UBUF relocations behind them are dead code.
 *
 * KVEC/BVEC/FOLIOQ/XARRAY reference kernel-internal memory, not the
 * application's send/recv buffer, so they are rejected here. Returns 0 and
 * fills *s on success, -1 otherwise (s->nr stays 0). */
static __always_inline int iter_snapshot(struct msghdr *msg, struct lk_segs *s)
{
    __u8 type = BPF_CORE_READ(msg, msg_iter.iter_type);
    __u64 off = BPF_CORE_READ(msg, msg_iter.iov_offset);

    if (bpf_core_enum_value_exists(enum iter_type, ITER_UBUF) &&
        bpf_core_field_exists(msg->msg_iter.ubuf) &&
        type == bpf_core_enum_value(enum iter_type, ITER_UBUF)) {
        __u64 ubuf = (__u64)BPF_CORE_READ(msg, msg_iter.ubuf);
        __u64 count = BPF_CORE_READ(msg, msg_iter.count);

        s->base[0] = ubuf + off;
        s->len[0] = count; /* remaining bytes from the current position */
        s->nr = 1;
        return 0;
    }

    if (type == bpf_core_enum_value(enum iter_type, ITER_IOVEC)) {
        const struct iovec *iov = iter_iov_first(msg);
        __u64 nr = BPF_CORE_READ(msg, msg_iter.nr_segs);

        if (nr > LK_MAX_SEGS)
            nr = LK_MAX_SEGS; /* tail segments are not captured (TRUNC) */
        for (__u32 i = 0; i < LK_MAX_SEGS; i++) {
            __u64 b, l;

            if (i >= nr)
                break;
            b = (__u64)BPF_CORE_READ(&iov[i], iov_base);
            l = BPF_CORE_READ(&iov[i], iov_len);
            if (i == 0) {
                b += off;
                l = l > off ? l - off : 0;
            }
            s->base[i] = b;
            s->len[i] = l;
        }
        s->nr = nr;
        return 0;
    }

    return -1;
}

/* Emit one data event of the compile-constant size class `chunk_sz`
 * (LK_CHUNK_SMALL or LK_CHUNK_FULL — call sites pass literals, so with
 * __always_inline each class verifies as its own constant-size reserve, as
 * bpf_ringbuf_reserve requires). Up to `cap` payload bytes are read from the
 * userspace address `base` into the START of this record's own payload[] —
 * a constant destination offset, which is what keeps the verifier happy
 * (notes-iov: «verifier cost of a variable-offset destination write»).
 * Returns bytes captured; 0 when the user read failed (event still
 * submitted with cap_len 0); -1 when reserve failed. */
static __always_inline int emit_chunk(__u64 cookie, struct lk_conn_state *st, __u8 dir,
                                      __u32 total_len, __u32 off, __u64 base, __u64 cap,
                                      __u16 flags, __u32 chunk_sz)
{
    struct lk_ev_data *ev;
    /* Consumed before reserve — a lost chunk must leave a seq hole (Р5). */
    __u32 seq = __sync_fetch_and_add(&st->seq, 1);

    ev = bpf_ringbuf_reserve(&events, sizeof(*ev) + chunk_sz, 0);
    if (!ev) {
        conn_mark_loss(st, LK_ST_RESERVE_FAIL_DATA);
        return -1;
    }
    flags |= gap_take(st);

    ev->hdr.conn_id = cookie;
    ev->hdr.ts_ns = bpf_ktime_get_ns();
    ev->hdr.seq = seq;
    ev->hdr.type = LK_EV_DATA;
    ev->hdr.dir = dir;
    ev->total_len = total_len;
    ev->off = off;
    ev->_pad = 0;

    /* cap is 64-bit on purpose: the verifier links full-register copies by
     * id and propagates the <= chunk_sz bound to whichever copy clang passes
     * to bpf_probe_read_user; 32-bit subregister copies lose that link.
     * barrier_var pins the clamped value to one register: clang otherwise
     * compares one copy of cap and passes another to the read, and the
     * verifier rejects that copy as unbounded. The bound is re-stated AFTER
     * the barrier: pre-5.19 verifiers do not link register copies by id, so
     * only a check that dominates the call on the very value being passed
     * convinces them (matrix kernel 5.15 rejected the id-linked form with
     * "R2 unbounded memory access", task 8.4). */
    if (cap > chunk_sz)
        cap = chunk_sz;
    barrier_var(cap);
    if (cap == 0 || cap > chunk_sz || base == 0)
        cap = 0;
    else if (bpf_probe_read_user(ev->payload, cap, (const void *)base))
        cap = 0; /* unmapped or paged-out user page */
    if (cap == 0 && total_len > 0)
        flags |= LK_F_TRUNC;
    ev->cap_len = cap;
    ev->hdr.flags = flags;

    bpf_ringbuf_submit(ev, 0);
    stat_add(LK_ST_EVENTS, 1);
    stat_add(LK_ST_BYTES_CAPTURED, cap);
    return cap;
}

/* Emit the payload of one send/recv call as a chain of data events sharing
 * total_len, with increasing off and consecutive seq (format v1). Chunks are
 * sliced so that each one reads from a single iovec segment — the copy always
 * lands at payload[0] of its own record (see emit_chunk); userspace
 * concatenates by off. A segment longer than LK_CHUNK_FULL spans several
 * chunks; segments shorter than that each cost a chunk of their own, so a
 * heavily fragmented iovec can exhaust the LK_MAX_CHUNKS slots before the
 * byte budget — those calls under-capture without a TRUNC flag, which stage
 * 2 still detects from off/cap_len against total_len.
 *
 * cap_budget is this port's byte budget (port_budget, РH14): the caller has
 * already resolved --capture-limit against the port's own limit. */
static __always_inline void emit_data_chunks(__u64 cookie, struct lk_conn_state *st, __u8 dir,
                                             __u32 total_len, const struct lk_segs *segs,
                                             __u32 cap_budget)
{
    __u64 avail_total = 0;
    __u32 budget;
    struct lk_cursor *cur;
    __u16 flags = 0;

    /* The honest denominator: every data call counts its full size, captured
     * or not — bytes_captured/bytes_total is the capture ratio for free. */
    stat_add(LK_ST_BYTES_TOTAL, total_len);

    for (__u32 i = 0; i < LK_MAX_SEGS; i++) {
        if (i >= segs->nr)
            break;
        avail_total += segs->len[i];
    }

    /* The capture plan for the whole call, known before the first reserve:
     * budget < total_len means the chain is truncated (by --capture-limit,
     * the HEADERS mode, an unsupported iterator, or segments beyond
     * LK_MAX_SEGS), and every chunk of the chain carries LK_F_TRUNC. */
    budget = cap_budget;
    /* The per-connection override lives in `capmode`, written by userspace (Р21),
     * so it can flip mid-connection; each call reads the current value. A miss
     * means FULL. Whatever the mode, only cap_len is affected — total_len stays
     * honest. */
    __u8 *cm = bpf_map_lookup_elem(&capmode, &cookie);

    if (cm && *cm == LK_CAP_HEADERS && budget > LK_CAP_HEADERS_LIMIT)
        budget = LK_CAP_HEADERS_LIMIT;
    if (budget > total_len)
        budget = total_len;
    if (budget > avail_total)
        budget = avail_total;
    if (budget < total_len)
        flags = LK_F_TRUNC;

    if (budget == 0) {
        /* Nothing capturable (unsupported iterator or zero-size call):
         * still emit one empty event — total_len must stay honest so the
         * stage 2 reassembler can advance the stream position. */
        emit_chunk(cookie, st, dir, total_len, 0, 0, 0, flags, LK_CHUNK_SMALL);
        return;
    }

    cur = cursor_claim();
    if (!cur) {
        /* Every slot belongs to a preempted chain on this CPU: do not touch
         * them; degrade to a single empty event, total_len stays honest. */
        emit_chunk(cookie, st, dir, total_len, 0, 0, 0, total_len ? LK_F_TRUNC : flags,
                   LK_CHUNK_SMALL);
        return;
    }
    ONCE(cur->si) = 0;
    ONCE(cur->soff) = 0;
    ONCE(cur->pos) = 0;
    ONCE(cur->budget) = budget;

    for (__u32 c = 0; c < LK_MAX_CHUNKS; c++) {
        __u64 base = 0, cap = 0;
        __u32 si, soff, pos;
        int done;

        /* Reload the loop-carried state from the per-CPU cursor — see the
         * lk_cursor comment; this is load-bearing for the verifier. */
        budget = ONCE(cur->budget);
        si = ONCE(cur->si);
        soff = ONCE(cur->soff);
        pos = ONCE(cur->pos);
        if (budget == 0)
            break;
        /* Advance to the first segment with bytes left. The mask re-states
         * the si < LK_MAX_SEGS loop bound as a var_off on the index, and
         * barrier_var stops clang from strength-reducing the indexing into a
         * walking pointer whose bound the verifier cannot tie back to the
         * loop condition; both are semantically no-ops. */
        for (; si < LK_MAX_SEGS; si++) {
            __u32 idx = si & (LK_MAX_SEGS - 1);
            __u32 slen;

            barrier_var(idx);
            if (si >= segs->nr)
                break;
            slen = segs->len[idx];
            if (soff < slen) {
                base = segs->base[idx] + soff;
                cap = slen - soff;
                break;
            }
            soff = 0;
        }
        if (cap == 0)
            break;
        if (cap > budget)
            cap = budget;

        /* Size class by the actual capture size, decided before reserve. */
        if (cap <= LK_CHUNK_SMALL)
            done = emit_chunk(cookie, st, dir, total_len, pos, base, cap, flags, LK_CHUNK_SMALL);
        else
            done = emit_chunk(cookie, st, dir, total_len, pos, base, cap, flags, LK_CHUNK_FULL);
        if (done <= 0)
            break; /* ringbuf full or the user page went away */
        ONCE(cur->si) = si;
        ONCE(cur->soff) = soff + done;
        ONCE(cur->pos) = pos + done;
        ONCE(cur->budget) = budget - done;
    }

    ONCE(cur->busy) = 0;
}

/* ------------------------------------------------------------------------- *
 * TLS SSL* -> socket-cookie bridge (stage 6.2, Р36/Р37). Shared state that both
 * the socket data path (the nested-syscall fallback below) and the SSL_* uprobes
 * (further down) touch, so it is declared here, ahead of tcp_sendmsg.
 *
 * A decrypted event must land in the SAME conn_table entry the socket path
 * created on CONN_OPEN — that entry carries the tuple/labels and has already seen
 * the SSLRequest/'S'. So the uprobe channel has to stamp events with the socket
 * cookie, but a uprobe sees SSL* and userspace registers, not a struct sock. Two
 * independent ways fill ssl_to_conn, keyed by {SSL*, tgid}:
 *   - primary: uprobe on SSL_set_fd/rfd/wfd walks fd -> socket -> sk and reads
 *     the cookie straight out of sk (skc_cookie, already assigned by the socket
 *     path at TCP_ESTABLISHED). Deterministic and before any data. Note a uprobe
 *     cannot call bpf_get_socket_cookie (helper is tracing-only), hence the
 *     direct field read, guarded by bpf_core_field_exists.
 *   - fallback: within a live SSL_read/SSL_write the same thread synchronously
 *     drives tcp_recvmsg/tcp_sendmsg; those fentries run in tracing context, can
 *     call bpf_get_socket_cookie, and bind SSL* -> cookie there (ssl_nested_link).
 * One correlation is enough — the mapping is persistent until SSL_free. */

/* In-flight SSL_write/SSL_read arguments, saved on entry (ssl_entry), consumed on
 * return (ssl_ret). written_ptr is the _ex out-param (userspace size_t*), 0 for
 * the classic calls. Split wr/rd because a thread can have one of each in flight
 * and the two return probes must not collide on the pid_tgid key; the fallback
 * bridge also reads them (wr from tcp_sendmsg, rd from tcp_recvmsg). */
struct lk_ssl_call {
    __u64 ssl;
    __u64 buf;
    __u64 written_ptr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64); /* pid_tgid */
    __type(value, struct lk_ssl_call);
} active_ssl_wr SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64); /* pid_tgid */
    __type(value, struct lk_ssl_call);
} active_ssl_rd SEC(".maps");

/* The bridge itself (Р37), key = {SSL*, tgid}. A bare SSL* is NOT unique across
 * processes: postgres backends are forks with a deterministic heap layout, so
 * two concurrent backends routinely hold their SSL objects at the same address.
 * With first-writer-wins that glued both backends to one socket cookie — their
 * decrypted events interleaved in one conn (false "lost 1" gaps, resync churn,
 * cross-session query attribution) while the other conn saw no decrypted data
 * at all. The tgid disambiguates; every prober runs in the owning task's
 * context, so bpf_get_current_pid_tgid() is the right scope at all five sites.
 * A thread-per-connection server (mysqld/mariadbd: one process, one thread per
 * session) needs no disambiguation — every SSL* is unique within its single
 * tgid — so the composite key is merely redundant there, never wrong.
 * value = the socket cookie the decrypted events must carry, plus the tuple
 * (snapshotted for parity with the socket path / future synthetic use).
 * LRU_HASH with its own ceiling so a missed SSL_free ages out. */
struct lk_ssl_key {
    __u64 ssl;
    __u64 tgid;
};

struct lk_ssl_conn {
    __u64 cookie;
    struct lk_tuple tuple;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct lk_ssl_key);
    __type(value, struct lk_ssl_conn);
} ssl_to_conn SEC(".maps");

/* Per-connection seq space of the decrypted channel (Р38), key = socket cookie.
 * Kept apart from conns.seq: ciphertext socket events are dropped in userspace
 * for a TLS connection, so mixing the two seq spaces would fake holes. LRU so a
 * missed cleanup ages out. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u32);
} tls_seq SEC(".maps");

/* Record SSL* -> {cookie, tuple}. First writer wins: the primary walk usually
 * lands before any data, and re-linking to the same socket would only churn the
 * map. cookie 0 (socket path has not assigned skc_cookie yet, or the walk
 * missed) is not stored — better to fall through to the other mechanism than to
 * pin a bogus mapping. */
static __always_inline void ssl_conn_set(__u64 ssl, __u64 cookie, struct sock *sk)
{
    struct lk_ssl_key k = {.ssl = ssl, .tgid = bpf_get_current_pid_tgid() >> 32};
    struct lk_ssl_conn v = {};

    if (!ssl || !cookie)
        return;
    if (bpf_map_lookup_elem(&ssl_to_conn, &k))
        return;
    v.cookie = cookie;
    fill_tuple(&v.tuple, sk);
    bpf_map_update_elem(&ssl_to_conn, &k, &v, BPF_ANY);
}

/* Fallback bridge (Р37), called from tcp_sendmsg/tcp_recvmsg. If an SSL_* call
 * of the matching direction is in flight for this thread, this tcp_* is the
 * nested syscall OpenSSL issued inside it — bind that SSL* to this socket. The
 * cookie is taken via bpf_get_socket_cookie (legal here, tracing context) so it
 * is identical to the socket path's. */
static __always_inline void ssl_nested_link(void *active_map, __u64 id, struct sock *sk)
{
    struct lk_ssl_call *c = bpf_map_lookup_elem(active_map, &id);

    if (!c || !c->ssl)
        return;
    ssl_conn_set(c->ssl, bpf_get_socket_cookie(sk), sk);
}

/* ------------------------------------------------------------------------- *
 * Go crypto/tls -> socket-cookie bridge (РH13.3). A Go server has no libssl:
 * TLS lives inside the binary, and the only place plaintext is visible is the
 * boundary of crypto/tls.(*Conn).Read/Write. Those uprobes see a *tls.Conn and
 * a slice, never a struct sock, and walking *tls.Conn -> net.Conn -> fd by
 * offset breaks with every Go release — so the correlation is built from what
 * the kernel already knows.
 *
 * The note below is one half of it: every socket call on a watched port records
 * "thread T talked to connection C at time X". A Go call that issued a syscall
 * during its lifetime therefore finds a hint newer than its own start, which
 * identifies its connection beyond doubt; the RET probe then remembers the
 * answer per *tls.Conn (go_conn, further down), so the next call on that same
 * connection is correlated even when it is served entirely out of Go's own
 * buffer and touches no syscall at all.
 *
 * cfg_go_tls gates the write: with no Go binary attached the DB/HTTP socket
 * path must not pay a map update per call. It is .rodata, so the branch is
 * folded away at load time. */
const volatile bool cfg_go_tls;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64); /* pid_tgid: the *thread* that made the socket call */
    __type(value, struct lk_sock_hint);
} sock_hint SEC(".maps");

static __always_inline void go_sock_hint(__u64 cookie)
{
    struct lk_sock_hint h = {.cookie = cookie, .ts_ns = bpf_ktime_get_ns()};
    __u64 id = bpf_get_current_pid_tgid();

    if (!cfg_go_tls)
        return;
    bpf_map_update_elem(&sock_hint, &id, &h, BPF_ANY);
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(lk_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    struct lk_conn_state *st;
    struct lk_segs segs = {};
    struct lk_port_cfg *pc = sk_port_cfg(sk);

    if (!pc || !comm_allowed() || !cgroup_allowed())
        return 0;

    __u64 cookie = bpf_get_socket_cookie(sk);

    st = conn_get(sk, cookie);
    if (!st)
        return 0;

    /* Fallback SSL*->cookie bridge (Р37): if this send is the nested syscall of
     * a live SSL_write on this thread, bind that SSL* to this connection. */
    ssl_nested_link(&active_ssl_wr, bpf_get_current_pid_tgid(), sk);
    /* The Go channel's equivalent (РH13.3), a plain "this thread just wrote to
     * this connection" note. Off unless a Go binary was attached, so the DB
     * path never pays for it. */
    go_sock_hint(cookie);

    /* Data is still in the caller's buffer on entry to tcp_sendmsg; snapshot
     * msg->msg_iter and read straight from userspace. On an unsupported
     * iterator segs.nr stays 0 and a single cap_len=0 event is emitted —
     * total_len must stay honest. */
    if (iter_snapshot(msg, &segs))
        stat_add(LK_ST_ITER_UNSUPPORTED, 1);
    emit_data_chunks(cookie, st, LK_DIR_SEND, size, &segs, port_budget(pc));
    return 0;
}

SEC("fentry/tcp_recvmsg")
int BPF_PROG(lk_tcp_recvmsg_entry, struct sock *sk, struct msghdr *msg, size_t len, int flags,
             int *addr_len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct lk_segs segs = {};

    /* Filtering here also covers fexit: without a recv_state entry the exit
     * program bails out before emitting anything. */
    if (!sk_port_match(sk) || !comm_allowed() || !cgroup_allowed())
        return 0;

    /* Fallback SSL*->cookie bridge (Р37): if this recv is the nested syscall of
     * a live SSL_read on this thread, bind that SSL* to this connection. */
    ssl_nested_link(&active_ssl_rd, pid_tgid, sk);

    /* The destination buffers are empty now, but msg->msg_iter already
     * points at them. By fexit iov_iter has been advanced past the copied
     * bytes, so snapshot the segment list here; fexit reads from it.
     * Recording the entry (even with nr 0) also lets fexit recognise this
     * recv as ours. An update failure (recv_state full) is not counted here:
     * fexit will see the miss and count it once. */
    if (iter_snapshot(msg, &segs))
        stat_add(LK_ST_ITER_UNSUPPORTED, 1);
    bpf_map_update_elem(&recv_state, &pid_tgid, &segs, BPF_ANY);
    return 0;
}

/* Body of fexit/tcp_recvmsg, shared by the signature variants below. The
 * arity of tcp_recvmsg keeps changing: 5.15 has (sk, msg, len, nonblock,
 * flags, addr_len) — `nonblock` removed in 5.19 (ec095263a965) — and recent
 * kernels (~7.1) dropped `addr_len` too. In an fexit context the return value
 * is the slot after the last argument, and CO-RE cannot relocate context
 * slots, so a mismatched variant either reads the wrong slot or is rejected
 * outright (5.15: "arg5 type INT is not a struct"; 7.1: "doesn't have 6-th
 * argument" — both found live by the task 8.4 matrix). Userspace probes the
 * kernel BTF for the arity and autoloads exactly one variant (main.c). */
static __always_inline int recvmsg_exit(struct sock *sk, long ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct lk_conn_state *cs;
    struct lk_segs *segs;

    segs = bpf_map_lookup_elem(&recv_state, &pid_tgid);
    if (!segs) {
        /* No fentry snapshot: usually the call was filtered out (no miss),
         * but a recv that passes the same filters here lost its entry —
         * recv_state overflow or attach mid-call — and its bytes with it. */
        if (ret > 0 && sk_port_match(sk) && comm_allowed() && cgroup_allowed())
            stat_add(LK_ST_RECV_STATE_MISS, 1);
        return 0;
    }

    if (ret > 0) {
        __u64 cookie = bpf_get_socket_cookie(sk);

        cs = conn_get(sk, cookie);
        if (cs) {
            /* ret bytes were copied, in order, into the segments snapshot
             * taken on entry; the emit loop stops after ret bytes, so the
             * tail of a partially filled segment list is never read. */
            emit_data_chunks(cookie, cs, LK_DIR_RECV, ret, segs, port_budget(sk_port_cfg(sk)));
            go_sock_hint(cookie); /* РH13.3, see the send path */
        }
    }

    /* Always drop the entry, including the ret <= 0 path, or the map leaks. */
    bpf_map_delete_elem(&recv_state, &pid_tgid);
    return 0;
}

/* 5.19..7.0 signature (5 args). Exactly one of the three variants is
 * autoloaded, by the arity of tcp_recvmsg in the kernel BTF (recvmsg_exit). */
SEC("fexit/tcp_recvmsg")
int BPF_PROG(lk_tcp_recvmsg_exit, struct sock *sk, struct msghdr *msg, size_t len, int flags,
             int *addr_len, int ret)
{
    return recvmsg_exit(sk, ret);
}

/* Pre-5.19 signature (6 args): the extra `nonblock` int between len and flags. */
SEC("fexit/tcp_recvmsg")
int BPF_PROG(lk_tcp_recvmsg_exit_a6, struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
             int flags, int *addr_len, int ret)
{
    return recvmsg_exit(sk, ret);
}

/* ~7.1+ signature (4 args): addr_len is gone. */
SEC("fexit/tcp_recvmsg")
int BPF_PROG(lk_tcp_recvmsg_exit_a4, struct sock *sk, struct msghdr *msg, size_t len, int flags,
             int ret)
{
    return recvmsg_exit(sk, ret);
}

/* ------------------------------------------------------------------------- *
 * TLS plaintext channel (stage 6, Р35): uprobes on libssl SSL_read/SSL_write
 * (and the _ex variants). The library boundary is where the application buffer
 * is still/already decrypted; we capture it there and feed the very same
 * lk_ev_data records (with LK_F_DECRYPTED) into the pipeline, so the framer and
 * PG parser never learn the stream was encrypted.
 *
 * Entry saves {ssl, buf, written_ptr} keyed by pid_tgid; the return probe reads
 * the real byte count (ret for the classic calls, *written for _ex) and, on a
 * positive length, copies the buffer out. pid_tgid keys the in-flight call per
 * *thread*, which is correct for both server models we observe: a postgres
 * backend is a single-threaded process per connection, and a mysqld/mariadbd
 * session is one thread inside the server process (its VIO layer issues one
 * blocking SSL_read/SSL_write at a time). Neither nests the calls on a thread;
 * one read and one write may be in flight concurrently, hence the wr/rd split.
 *
 * SSL* is correlated to the socket cookie by the bridge above (ssl_to_conn); the
 * return probe stamps each decrypted event with that cookie, so it lands in the
 * socket path's own conn_table entry. The per-cookie seq lives in tls_seq (its
 * own space, Р38), independent of the socket path's conns.seq. The in-flight
 * argument maps (active_ssl_wr/rd) and ssl_to_conn are declared with the bridge
 * above, since the socket data path reads them too. Attach lifecycle and
 * comm/path selection live in userspace (tls_attach.c); these programs
 * auto-attach nothing. */

/* Next decrypted-channel seq for this cookie, lazily starting the counter at 0.
 * Like conns.seq, consumed before the reserve so a lost event leaves a hole. */
static __always_inline __u32 tls_next_seq(__u64 cookie)
{
    __u32 *s = bpf_map_lookup_elem(&tls_seq, &cookie);
    __u32 init = 0;

    if (!s) {
        bpf_map_update_elem(&tls_seq, &cookie, &init, BPF_NOEXIST);
        s = bpf_map_lookup_elem(&tls_seq, &cookie);
        if (!s)
            return 0;
    }
    return __sync_fetch_and_add(s, 1);
}

/* Emit one decrypted chunk of the compile-constant size class `chunk_sz`. The
 * decrypted buffer is one contiguous userspace pointer (no iov_iter), so the
 * copy is a single bpf_probe_read_user at a constant destination offset — the
 * same verifier-friendly shape as emit_chunk, minus the segment machinery and
 * the per-conn loss/gap tracking (no conn_state on this path yet, stage 6.2).
 * Returns bytes captured; 0 on a failed user read (event still submitted);
 * -1 when reserve failed. */
static __always_inline int emit_ssl_chunk(__u64 cookie, __u8 dir, __u32 total_len, __u32 off,
                                          __u64 base, __u64 cap, __u16 flags, __u32 chunk_sz)
{
    struct lk_ev_data *ev;
    __u32 seq = tls_next_seq(cookie);

    ev = bpf_ringbuf_reserve(&events, sizeof(*ev) + chunk_sz, 0);
    if (!ev) {
        stat_add(LK_ST_TLS_RESERVE_FAIL, 1);
        return -1;
    }

    ev->hdr.conn_id = cookie;
    ev->hdr.ts_ns = bpf_ktime_get_ns();
    ev->hdr.seq = seq;
    ev->hdr.type = LK_EV_DATA;
    ev->hdr.dir = dir;
    ev->total_len = total_len;
    ev->off = off;
    ev->_pad = 0;

    /* Same 64-bit clamp + barrier_var + post-barrier re-check dance as
     * emit_chunk: the bound must sit on the exact register copy passed to the
     * read for pre-5.19 verifiers (see the emit_chunk comment). */
    if (cap > chunk_sz)
        cap = chunk_sz;
    barrier_var(cap);
    if (cap == 0 || cap > chunk_sz || base == 0)
        cap = 0;
    else if (bpf_probe_read_user(ev->payload, cap, (const void *)base))
        cap = 0; /* unmapped or paged-out user page */
    if (cap == 0 && total_len > 0)
        flags |= LK_F_TRUNC;
    ev->cap_len = cap;
    ev->hdr.flags = flags | LK_F_DECRYPTED;

    bpf_ringbuf_submit(ev, 0);
    stat_add(LK_ST_EVENTS, 1);
    stat_add(LK_ST_TLS_UPROBE_EVENTS, 1);
    stat_add(LK_ST_TLS_DECRYPTED_BYTES, cap);
    return cap;
}

/* Emit the decrypted buffer of one SSL_read/SSL_write call as a chain of data
 * events sharing total_len, with increasing off and consecutive seq — the
 * decrypted twin of emit_data_chunks. The buffer is contiguous, so the chain is
 * a straight walk by offset; the byte budget is applied (never the HEADERS
 * capmode — that governs the ciphertext socket path, the plaintext must stay
 * full for the parser, Р40). cap_budget is the port's budget resolved by the
 * caller from the connection's local port (РH14): an HTTPS port needs the head
 * of each message and no more, exactly like its plaintext twin. The per-CPU
 * cursor holds the loop-carried state exactly as emit_data_chunks needs it for
 * the verifier. */
static __always_inline void emit_ssl_data(__u64 cookie, __u8 dir, __u32 total_len, __u64 buf,
                                          __u32 cap_budget)
{
    __u32 budget;
    struct lk_cursor *cur;
    __u16 flags = 0;

    stat_add(LK_ST_BYTES_TOTAL, total_len);

    budget = cap_budget;
    if (budget > total_len)
        budget = total_len;
    if (budget < total_len)
        flags = LK_F_TRUNC;

    if (budget == 0) {
        /* Zero-length capture: still emit one empty event so total_len stays
         * honest (a ret>0 call always has total_len>0 here, but keep parity). */
        emit_ssl_chunk(cookie, dir, total_len, 0, 0, 0, flags, LK_CHUNK_SMALL);
        return;
    }

    cur = cursor_claim();
    if (!cur) {
        /* Every slot taken by a preempted chain: degrade to a single event. */
        emit_ssl_chunk(cookie, dir, total_len, 0, 0, 0, total_len ? LK_F_TRUNC : flags,
                       LK_CHUNK_SMALL);
        return;
    }
    ONCE(cur->pos) = 0;
    ONCE(cur->budget) = budget;

    for (__u32 c = 0; c < LK_MAX_CHUNKS; c++) {
        __u64 base, cap;
        __u32 pos;
        int done;

        budget = ONCE(cur->budget);
        pos = ONCE(cur->pos);
        if (budget == 0)
            break;
        cap = budget;
        if (cap > LK_CHUNK_FULL)
            cap = LK_CHUNK_FULL;
        base = buf + pos;

        if (cap <= LK_CHUNK_SMALL)
            done = emit_ssl_chunk(cookie, dir, total_len, pos, base, cap, flags, LK_CHUNK_SMALL);
        else
            done = emit_ssl_chunk(cookie, dir, total_len, pos, base, cap, flags, LK_CHUNK_FULL);
        if (done <= 0)
            break;
        ONCE(cur->pos) = pos + done;
        ONCE(cur->budget) = budget - done;
    }

    ONCE(cur->busy) = 0;
}

/* Entry: stash the call arguments for the matching return probe. comm-filtered
 * (cfg_tls_comm_filter) so attaching on pid=-1 does not turn every libssl user
 * on the host into events. */
static __always_inline int ssl_entry(void *active_map, __u64 ssl, __u64 buf, __u64 written_ptr)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct lk_ssl_call call = {.ssl = ssl, .buf = buf, .written_ptr = written_ptr};

    /* A uprobe runs in the backend's task context, so the cgroup id is valid
     * here too (Р48): a TLS backend in a non-target cgroup stays out, mirroring
     * the plaintext send/recv gate. */
    if (!tls_comm_allowed() || !cgroup_allowed())
        return 0;
    bpf_map_update_elem(active_map, &id, &call, BPF_ANY);
    return 0;
}

/* Return: recover the saved buffer, resolve the real length (ret for the
 * classic calls, *written for _ex) and emit it. ret <= 0 (WANT_READ/WRITE,
 * error, EOF) yields nothing (Р35). The event is stamped with the socket cookie
 * looked up in ssl_to_conn (Р37); without a correlation the plaintext has no
 * address and is useless, so it is dropped and counted (LK_ST_TLS_CORR_MISS)
 * rather than sent to nowhere. The entry is always dropped so the map cannot
 * leak. */
static __always_inline int ssl_ret(void *active_map, __u8 dir, long ret, int is_ex)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct lk_ssl_call *call = bpf_map_lookup_elem(active_map, &id);
    __u64 len = 0;

    if (!call)
        return 0;

    if (!is_ex) {
        if (ret > 0)
            len = (__u64)ret;
    } else if (ret == 1 && call->written_ptr) {
        __u64 written = 0;

        if (bpf_probe_read_user(&written, sizeof(written), (const void *)call->written_ptr) == 0)
            len = written;
    }
    if (len > 0xffffffffULL)
        len = 0xffffffffULL; /* total_len is u32; a single SSL call never nears this */

    if (len > 0) {
        struct lk_ssl_key k = {.ssl = call->ssl, .tgid = id >> 32};
        struct lk_ssl_conn *c = bpf_map_lookup_elem(&ssl_to_conn, &k);

        if (c)
            /* The tuple snapshot carries the local port, so the plaintext of an
             * HTTPS connection gets the same per-port budget as its ciphertext
             * (РH14); a cookie without a tuple falls back to the global limit. */
            emit_ssl_data(c->cookie, dir, (__u32)len, call->buf, port_cfg_budget(c->tuple.sport));
        else
            stat_add(LK_ST_TLS_CORR_MISS, 1);
    }

    bpf_map_delete_elem(active_map, &id);
    return 0;
}

/* SSL_write(SSL *ssl, const void *buf, int num): application plaintext handed to
 * OpenSSL -> backend->frontend (SEND). Buffer is valid already on entry, but the
 * count written is known only on return. */
SEC("uprobe")
int BPF_UPROBE(lk_ssl_write, void *ssl, void *buf, int num)
{
    return ssl_entry(&active_ssl_wr, (__u64)ssl, (__u64)buf, 0);
}

SEC("uretprobe")
int BPF_URETPROBE(lk_ssl_write_ret, int ret)
{
    return ssl_ret(&active_ssl_wr, LK_DIR_SEND, ret, 0);
}

/* SSL_write_ex(SSL*, const void *buf, size_t num, size_t *written). */
SEC("uprobe")
int BPF_UPROBE(lk_ssl_write_ex, void *ssl, void *buf, __u64 num, void *written)
{
    return ssl_entry(&active_ssl_wr, (__u64)ssl, (__u64)buf, (__u64)written);
}

SEC("uretprobe")
int BPF_URETPROBE(lk_ssl_write_ex_ret, int ret)
{
    return ssl_ret(&active_ssl_wr, LK_DIR_SEND, ret, 1);
}

/* SSL_read(SSL *ssl, void *buf, int num): OpenSSL fills buf with decrypted
 * plaintext -> frontend->backend (RECV). buf holds garbage on entry; it is only
 * valid at return, so the copy must happen there. */
SEC("uprobe")
int BPF_UPROBE(lk_ssl_read, void *ssl, void *buf, int num)
{
    return ssl_entry(&active_ssl_rd, (__u64)ssl, (__u64)buf, 0);
}

SEC("uretprobe")
int BPF_URETPROBE(lk_ssl_read_ret, int ret)
{
    return ssl_ret(&active_ssl_rd, LK_DIR_RECV, ret, 0);
}

/* SSL_read_ex(SSL*, void *buf, size_t num, size_t *readbytes). */
SEC("uprobe")
int BPF_UPROBE(lk_ssl_read_ex, void *ssl, void *buf, __u64 num, void *readbytes)
{
    return ssl_entry(&active_ssl_rd, (__u64)ssl, (__u64)buf, (__u64)readbytes);
}

SEC("uretprobe")
int BPF_URETPROBE(lk_ssl_read_ex_ret, int ret)
{
    return ssl_ret(&active_ssl_rd, LK_DIR_RECV, ret, 1);
}

/* Primary SSL*->cookie bridge (Р37): resolve a userspace fd of the current task
 * to its struct sock. The fd-table walk (task->files->fdt->fd[fd]->private_data
 * -> struct socket -> sk) is a known bcc idiom but version-fragile, so every hop
 * is a bpf_probe_read that fails soft (returns NULL); the caller then falls
 * through to the nested-syscall mechanism. Reads the fd array element by hand
 * because fd is a variable index into struct file **. */
static __always_inline struct sock *fd_to_sock(int fd)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct file **fdarr = BPF_CORE_READ(task, files, fdt, fd);
    struct file *f = NULL;
    struct socket *sock;
    struct sock *sk;
    unsigned int maxfd;

    if (fd < 0 || !fdarr)
        return NULL;
    maxfd = BPF_CORE_READ(task, files, fdt, max_fds);
    if ((unsigned int)fd >= maxfd)
        return NULL;
    if (bpf_probe_read_kernel(&f, sizeof(f), &fdarr[fd]) || !f)
        return NULL;
    /* file->private_data is the struct socket for a socket fd; sock->sk is the
     * struct sock. A non-socket fd yields a bogus sk whose cookie read below is
     * meaningless — the family/cookie guards in ssl_set_fd_link discard it. */
    sock = BPF_CORE_READ(f, private_data);
    sk = BPF_CORE_READ(sock, sk);
    return sk;
}

/* SSL_set_fd(SSL *ssl, int fd) and the rfd/wfd variants: postgres calls
 * SSL_set_fd(port->ssl, port->sock) in be_tls_open_server, before the handshake
 * and any data. Walk fd -> sk, read the socket cookie straight out of sk
 * (skc_cookie — the socket path assigned it at TCP_ESTABLISHED, well before
 * this) and record the SSL*->cookie mapping. A uprobe may not call
 * bpf_get_socket_cookie, so the field is read directly, guarded by
 * bpf_core_field_exists; a family sanity check rejects a non-socket fd. */
static __always_inline int ssl_set_fd_link(void *ssl, int fd)
{
    struct sock *sk;
    __u64 cookie = 0;
    __u16 family;

    if (!tls_comm_allowed())
        return 0;
    sk = fd_to_sock(fd);
    if (!sk)
        return 0;
    family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6)
        return 0;
    if (bpf_core_field_exists(sk->__sk_common.skc_cookie))
        cookie = BPF_CORE_READ(sk, __sk_common.skc_cookie.counter);
    ssl_conn_set((__u64)ssl, cookie, sk);
    return 0;
}

SEC("uprobe")
int BPF_UPROBE(lk_ssl_set_fd, void *ssl, int fd)
{
    return ssl_set_fd_link(ssl, fd);
}

SEC("uprobe")
int BPF_UPROBE(lk_ssl_set_rfd, void *ssl, int fd)
{
    return ssl_set_fd_link(ssl, fd);
}

SEC("uprobe")
int BPF_UPROBE(lk_ssl_set_wfd, void *ssl, int fd)
{
    return ssl_set_fd_link(ssl, fd);
}

/* SSL_free(SSL *ssl): the connection is done, drop its bridge entry (Р37). The
 * LRU ceiling of ssl_to_conn is the backstop for a missed SSL_free (client
 * crash); this is the common-case cleanup. */
SEC("uprobe")
int BPF_UPROBE(lk_ssl_free, void *ssl)
{
    struct lk_ssl_key key = {.ssl = (__u64)ssl, .tgid = bpf_get_current_pid_tgid() >> 32};

    bpf_map_delete_elem(&ssl_to_conn, &key);
    return 0;
}

/* ------------------------------------------------------------------------- *
 * Go crypto/tls plaintext channel (РH13.3, PLAN-HTTP.md М7). Same shape as the
 * OpenSSL channel above — entry probe saves the arguments, return probe emits
 * the buffer as LK_F_DECRYPTED data events — with three differences forced by
 * the runtime:
 *
 *   - **no uretprobe.** A uretprobe replaces the return address on the stack,
 *     and a goroutine stack can be copied and moved (growth, shrink), which
 *     rewrites that address behind the kernel's back: the trampoline is then
 *     never reached, or worse, reached with the wrong stack. So userspace
 *     (tls_go.c) decodes the function body, finds every RET instruction and
 *     attaches these programs as ordinary uprobes at those offsets. Several
 *     links share one program; each of them is a real return site.
 *   - **the Go register ABI (1.17+).** Arguments are not on the stack:
 *     `func (c *Conn) Write(b []byte) (int, error)` passes the receiver in RAX,
 *     b.ptr in RBX, b.len in RCX, b.cap in RDI, and returns n in RAX. The
 *     macros below name exactly those, and nothing outside this comment depends
 *     on Go's calling convention.
 *   - **correlation without struct offsets.** See go_sock_hint above: the
 *     thread's last socket call answers "which connection", and the answer is
 *     memoised per *tls.Conn so buffered calls stay correlated.
 *
 * x86-64 only in v1 (arm64 is a separate task, РH13.3): on other targets the
 * bodies compile to a bare `return 0` and userspace refuses to attach — the
 * skeleton keeps the same programs either way, so nothing else is arch-aware. */

#if defined(__TARGET_ARCH_x86)
#define GO_RECV(ctx)        ((__u64)BPF_CORE_READ((ctx), ax)) /* receiver / return n */
#define GO_ARG_PTR(ctx)     ((__u64)BPF_CORE_READ((ctx), bx))
#define GO_ARG_LEN(ctx)     ((__u64)BPF_CORE_READ((ctx), cx))
#define GO_CURG(ctx)        ((__u64)BPF_CORE_READ((ctx), r14)) /* the running goroutine */
#define LK_GO_TLS_SUPPORTED 1
#else
#define GO_RECV(ctx)        0ULL
#define GO_ARG_PTR(ctx)     0ULL
#define GO_ARG_LEN(ctx)     0ULL
#define GO_CURG(ctx)        0ULL
#define LK_GO_TLS_SUPPORTED 0
#endif

/* Key of both Go maps: a userspace pointer plus the process it belongs to — a
 * goroutine pointer for the in-flight calls, a *tls.Conn for the learned
 * connections. The tgid is there for the reason the SSL bridge needs it too:
 * two processes can hold their objects at the same address. */
struct lk_go_key {
    __u64 ptr;
    __u64 tgid;
};

/* In-flight crypto/tls.(*Conn).Write / .Read arguments, keyed like
 * their OpenSSL twins — except that the key is the *goroutine*, not the thread.
 * That difference is not a refinement, it is what makes the channel work: a
 * server's Read blocks in the netpoller, and the goroutine that resumes when
 * the bytes arrive routinely resumes on another M. Keyed by thread, the return
 * probe would find no entry and the request would be lost — measured, on the
 * first connection of the first test. The goroutine pointer lives in R14 for
 * the whole call by the same ABI that puts the arguments in RAX/RBX/RCX, so it
 * costs one register read and survives every migration.
 *
 * LRU rather than plain HASH (their SSL twins are HASH) so that an entry whose
 * return probe never runs — a panic unwinding past it — ages out on its own. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct lk_go_key);
    __type(value, struct lk_go_call);
} active_go_wr SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct lk_go_key);
    __type(value, struct lk_go_call);
} active_go_rd SEC(".maps");

/* Learned *tls.Conn -> socket cookie, the Go twin of ssl_to_conn. Only ever
 * written from a hint that provably belongs to the call in progress, so a stale
 * entry cannot outlive a reused address — the first call on a fresh connection
 * always performs the handshake syscalls and overwrites it. LRU is the
 * backstop; Go frees no Conn we could hook. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct lk_go_key);
    __type(value, __u64); /* socket cookie */
} go_conn SEC(".maps");

static __always_inline int go_entry(void *active_map, __u64 g, __u64 conn, __u64 buf, __u64 len)
{
    struct lk_go_key k = {.ptr = g, .tgid = bpf_get_current_pid_tgid() >> 32};
    struct lk_go_call call = {.conn = conn, .buf = buf, .len = len, .ts_ns = bpf_ktime_get_ns()};

    /* A Go binary is attached by path, so the comm gate is not what selects it —
     * but an explicit --comm/--cgroup still applies, and the derived set carries
     * this binary's own basename (main.c) so a probe cannot fire for a namesake
     * the operator did not name. */
    if (!g || !tls_comm_allowed() || !cgroup_allowed())
        return 0;
    bpf_map_update_elem(active_map, &k, &call, BPF_ANY);
    return 0;
}

/* Which connection does the finished call belong to? Three answers, strongest
 * first — and the order is the whole correlation design:
 *
 *   1. the thread made a socket call while this one ran (the hint is newer than
 *      the call's own start): that socket is this connection, beyond doubt.
 *      Remembered against the *tls.Conn for next time;
 *   2. nothing happened on the socket during the call — a Read served out of
 *      Go's own buffered record, which is routine — so the answer remembered
 *      for this *tls.Conn stands;
 *   3. neither, which in practice means the first call on a connection whose
 *      handshake did the reading: the request bytes arrived in the same segment
 *      as the client's last handshake flight, so the Read that returns them
 *      makes no syscall at all and there is nothing learned yet. The thread's
 *      most recent socket activity is that same handshake — the goroutine
 *      serving a connection stays with it — so the older hint is used, and
 *      learned, rather than throwing the request away.
 *
 * Rule 3 is the one assumption in the chain (a thread whose last socket call
 * belonged to another connection would misattribute a *first* call on a Conn),
 * and it is bounded by rules 1 and 2 taking precedence everywhere after that
 * first call. Without it, measured: the first request of every keep-alive
 * connection is lost. */
static __always_inline __u64 go_cookie(const struct lk_go_call *call, __u64 tgid)
{
    struct lk_go_key k = {.ptr = call->conn, .tgid = tgid};
    __u64 id = bpf_get_current_pid_tgid();
    struct lk_sock_hint *h = bpf_map_lookup_elem(&sock_hint, &id);
    __u64 *learned;

    if (h && h->cookie && h->ts_ns >= call->ts_ns) {
        if (call->conn)
            bpf_map_update_elem(&go_conn, &k, &h->cookie, BPF_ANY);
        return h->cookie; /* rule 1 */
    }
    learned = call->conn ? bpf_map_lookup_elem(&go_conn, &k) : NULL;
    if (learned)
        return *learned; /* rule 2 */
    if (h && h->cookie) {
        if (call->conn)
            bpf_map_update_elem(&go_conn, &k, &h->cookie, BPF_ANY);
        return h->cookie; /* rule 3 */
    }
    return 0;
}

/* Return site of a Go TLS call: `n` bytes of the saved buffer are plaintext.
 * n <= 0 (error, EOF, a Write that wrote nothing) yields nothing, exactly like
 * the SSL_* path. The entry is always dropped so the map cannot leak. */
static __always_inline int go_ret(void *active_map, __u64 g, __u8 dir, __s64 n)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct lk_go_key k = {.ptr = g, .tgid = id >> 32};
    struct lk_go_call *call = g ? bpf_map_lookup_elem(active_map, &k) : NULL;

    if (!call) {
        /* No entry for this goroutine: the call started before the probes were
         * attached, or it was filtered out at entry (not a miss), or the entry
         * was evicted. Counted only when this call would have been captured. */
        if (tls_comm_allowed() && cgroup_allowed())
            stat_add(LK_ST_TLS_CORR_MISS, 1);
        return 0;
    }

    if (n > 0) {
        __u64 len = (__u64)n;
        __u64 cookie;

        if (len > call->len)
            len = call->len; /* a return larger than the buffer is not ours to trust */
        cookie = go_cookie(call, id >> 32);
        if (cookie) {
            /* The socket path registered this cookie, so its tuple names the
             * local port and with it the port's capture budget (РH14). */
            struct lk_conn_state *cs = bpf_map_lookup_elem(&conns, &cookie);

            emit_ssl_data(cookie, dir, (__u32)len, call->buf,
                          port_cfg_budget(cs ? cs->tuple.sport : 0));
        } else {
            stat_add(LK_ST_TLS_CORR_MISS, 1);
        }
    }
    bpf_map_delete_elem(active_map, &k);
    return 0;
}

/* crypto/tls.(*Conn).Write(b []byte): application plaintext on its way out —
 * backend->frontend (SEND). The slice belongs to the caller and stays valid
 * across the call, so the copy happens at the return site, where the count
 * written is known and the socket write has already happened (which is what
 * makes the hint above land). */
SEC("uprobe")
int lk_go_tls_write(struct pt_regs *ctx)
{
    if (!LK_GO_TLS_SUPPORTED)
        return 0;
    return go_entry(&active_go_wr, GO_CURG(ctx), GO_RECV(ctx), GO_ARG_PTR(ctx), GO_ARG_LEN(ctx));
}

SEC("uprobe")
int lk_go_tls_write_ret(struct pt_regs *ctx)
{
    if (!LK_GO_TLS_SUPPORTED)
        return 0;
    return go_ret(&active_go_wr, GO_CURG(ctx), LK_DIR_SEND, (__s64)GO_RECV(ctx));
}

/* crypto/tls.(*Conn).Read(b []byte): decrypted plaintext on its way in —
 * frontend->backend (RECV). The buffer holds nothing at entry; only the return
 * site sees the bytes. */
SEC("uprobe")
int lk_go_tls_read(struct pt_regs *ctx)
{
    if (!LK_GO_TLS_SUPPORTED)
        return 0;
    return go_entry(&active_go_rd, GO_CURG(ctx), GO_RECV(ctx), GO_ARG_PTR(ctx), GO_ARG_LEN(ctx));
}

SEC("uprobe")
int lk_go_tls_read_ret(struct pt_regs *ctx)
{
    if (!LK_GO_TLS_SUPPORTED)
        return 0;
    return go_ret(&active_go_rd, GO_CURG(ctx), LK_DIR_RECV, (__s64)GO_RECV(ctx));
}

/* ------------------------------------------------------------------------- *
 * UDP volume counters (РH16). HTTP/3 is QUIC over UDP and is not parsed — it
 * does not even reach this agent's capture point (docs/notes-httpproto.md §8).
 * The failure mode that costs an operator an afternoon is the *silent* one: a
 * dashboard with no data and no reason. So the watched ports are counted on the
 * UDP path too — packets and bytes, nothing else. No payload is read, no
 * connection is registered, no ringbuf record is written; a non-zero
 * latkit_udp_bytes_total on port 443 with no HTTP observations is the
 * diagnosis, printed as such by the agent.
 *
 * Send is hooked per family (udp_sendmsg / udpv6_sendmsg — same signature,
 * different call sites); receive is hooked once, at skb_consume_udp, which both
 * families funnel through with the byte count already known. That avoids a
 * third fexit-arity dance on udp_recvmsg for what is, in the end, a diagnostic
 * counter. Each program is autoloaded only if its function exists in the
 * running kernel's BTF (main.c). */
static __always_inline void udp_count(struct sock *sk, __u8 dir, __s64 bytes)
{
    struct lk_udp_key k = {};
    struct lk_udp_stat *s, init = {};
    __u16 lport = BPF_CORE_READ(sk, __sk_common.skc_num);

    if (bytes <= 0 || !bpf_map_lookup_elem(&ports, &lport))
        return;
    k.port = lport;
    k.dir = dir;
    s = bpf_map_lookup_elem(&udp_stats, &k);
    if (!s) {
        bpf_map_update_elem(&udp_stats, &k, &init, BPF_NOEXIST);
        s = bpf_map_lookup_elem(&udp_stats, &k);
        if (!s)
            return;
    }
    s->packets += 1; /* per-CPU value: a plain add is enough */
    s->bytes += (__u64)bytes;
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(lk_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    udp_count(sk, LK_DIR_SEND, (__s64)len);
    return 0;
}

SEC("fentry/udpv6_sendmsg")
int BPF_PROG(lk_udpv6_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    udp_count(sk, LK_DIR_SEND, (__s64)len);
    return 0;
}

/* skb_consume_udp(sk, skb, len): the single point both udp_recvmsg and
 * udpv6_recvmsg reach once a datagram has been handed to userspace. */
SEC("fentry/skb_consume_udp")
int BPF_PROG(lk_skb_consume_udp, struct sock *sk, struct sk_buff *skb, int len)
{
    udp_count(sk, LK_DIR_RECV, len);
    return 0;
}
