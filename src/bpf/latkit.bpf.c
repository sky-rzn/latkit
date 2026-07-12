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

/* Optional comm filter (task 1.3), off when the first byte is 0. Checked on
 * the send/recv path only: fentry/fexit of tcp_sendmsg/tcp_recvmsg run in the
 * calling task's context, while the lifecycle tracepoint may fire in softirq
 * where comm is garbage. */
const volatile char cfg_comm_filter[16];

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
 * Keys are host-order local ports. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, LK_MAX_PORTS);
    __type(key, __u16);
    __type(value, __u8);
} ports SEC(".maps");

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
static __always_inline int sk_port_match(struct sock *sk)
{
    __u16 lport = BPF_CORE_READ(sk, __sk_common.skc_num);

    return bpf_map_lookup_elem(&ports, &lport) != NULL;
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

/* Exact-match comm filter; a no-op unless cfg_comm_filter is set. Send/recv
 * path only, see cfg_comm_filter above. */
static __always_inline int comm_allowed(void)
{
    char comm[sizeof(cfg_comm_filter)];

    if (!cfg_comm_filter[0])
        return 1;
    if (bpf_get_current_comm(comm, sizeof(comm)))
        return 0;
    for (unsigned i = 0; i < sizeof(comm); i++) {
        if (comm[i] != cfg_comm_filter[i])
            return 0;
        if (!comm[i])
            break;
    }
    return 1;
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
 *   ITER_IOVEC:         a vector of userspace buffers, __iov[0..nr_segs).
 *              The first segment is adjusted by iov_offset, the rest are
 *              taken whole; capture stops after LK_MAX_SEGS segments.
 *              The pre-~6.4 spelling of __iov (`iov`) is wired up in stage 8.
 *
 * KVEC/BVEC/FOLIOQ/XARRAY reference kernel-internal memory, not the
 * application's send/recv buffer, so they are rejected here. Returns 0 and
 * fills *s on success, -1 otherwise (s->nr stays 0). */
static __always_inline int iter_snapshot(struct msghdr *msg, struct lk_segs *s)
{
    __u8 type = BPF_CORE_READ(msg, msg_iter.iter_type);
    __u64 off = BPF_CORE_READ(msg, msg_iter.iov_offset);

    if (bpf_core_field_exists(msg->msg_iter.ubuf) && type == ITER_UBUF) {
        __u64 ubuf = (__u64)BPF_CORE_READ(msg, msg_iter.ubuf);
        __u64 count = BPF_CORE_READ(msg, msg_iter.count);

        s->base[0] = ubuf + off;
        s->len[0] = count; /* remaining bytes from the current position */
        s->nr = 1;
        return 0;
    }

    if (type == ITER_IOVEC) {
        const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
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
     * verifier rejects that copy as unbounded. */
    if (cap > chunk_sz)
        cap = chunk_sz;
    barrier_var(cap);
    if (cap == 0 || base == 0)
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
 * 2 still detects from off/cap_len against total_len. */
static __always_inline void emit_data_chunks(__u64 cookie, struct lk_conn_state *st, __u8 dir,
                                             __u32 total_len, const struct lk_segs *segs)
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
    budget = cfg_capture_limit;
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

SEC("fentry/tcp_sendmsg")
int BPF_PROG(lk_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    struct lk_conn_state *st;
    struct lk_segs segs = {};

    if (!sk_port_match(sk) || !comm_allowed() || !cgroup_allowed())
        return 0;

    __u64 cookie = bpf_get_socket_cookie(sk);

    st = conn_get(sk, cookie);
    if (!st)
        return 0;

    /* Fallback SSL*->cookie bridge (Р37): if this send is the nested syscall of
     * a live SSL_write on this thread, bind that SSL* to this connection. */
    ssl_nested_link(&active_ssl_wr, bpf_get_current_pid_tgid(), sk);

    /* Data is still in the caller's buffer on entry to tcp_sendmsg; snapshot
     * msg->msg_iter and read straight from userspace. On an unsupported
     * iterator segs.nr stays 0 and a single cap_len=0 event is emitted —
     * total_len must stay honest. */
    if (iter_snapshot(msg, &segs))
        stat_add(LK_ST_ITER_UNSUPPORTED, 1);
    emit_data_chunks(cookie, st, LK_DIR_SEND, size, &segs);
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

SEC("fexit/tcp_recvmsg")
int BPF_PROG(lk_tcp_recvmsg_exit, struct sock *sk, struct msghdr *msg, size_t len, int flags,
             int *addr_len, int ret)
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
        if (cs)
            /* ret bytes were copied, in order, into the segments snapshot
             * taken on entry; the emit loop stops after ret bytes, so the
             * tail of a partially filled segment list is never read. */
            emit_data_chunks(cookie, cs, LK_DIR_RECV, ret, segs);
    }

    /* Always drop the entry, including the ret <= 0 path, or the map leaks. */
    bpf_map_delete_elem(&recv_state, &pid_tgid);
    return 0;
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
 * positive length, copies the buffer out. postgres backends are single-threaded
 * per connection and never nest SSL_read/SSL_write, so pid_tgid uniquely keys
 * the in-flight call.
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

    /* Same 64-bit clamp + barrier_var dance as emit_chunk: keep the bound the
     * verifier propagates to bpf_probe_read_user pinned to one register. */
    if (cap > chunk_sz)
        cap = chunk_sz;
    barrier_var(cap);
    if (cap == 0 || base == 0)
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
 * a straight walk by offset; the --capture-limit budget is applied (never the
 * HEADERS capmode — that governs the ciphertext socket path, the plaintext must
 * stay full for the parser, Р40). The per-CPU cursor holds the loop-carried
 * state exactly as emit_data_chunks needs it for the verifier. */
static __always_inline void emit_ssl_data(__u64 cookie, __u8 dir, __u32 total_len, __u64 buf)
{
    __u32 budget;
    struct lk_cursor *cur;
    __u16 flags = 0;

    stat_add(LK_ST_BYTES_TOTAL, total_len);

    budget = cfg_capture_limit;
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
 * (same cfg_comm_filter as the socket path) so attaching on pid=-1 does not turn
 * every libssl user on the host into events. */
static __always_inline int ssl_entry(void *active_map, __u64 ssl, __u64 buf, __u64 written_ptr)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct lk_ssl_call call = {.ssl = ssl, .buf = buf, .written_ptr = written_ptr};

    /* Same filters as the socket path: a uprobe runs in the backend's task
     * context, so the cgroup id is valid here too (Р48). Keeps a TLS backend in
     * a non-target cgroup out, mirroring the plaintext send/recv gate. */
    if (!comm_allowed() || !cgroup_allowed())
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
            emit_ssl_data(c->cookie, dir, (__u32)len, call->buf);
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

    if (!comm_allowed())
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
