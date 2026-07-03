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
#define AF_INET 2
#define AF_INET6 10

/* Force a real load/store, no clang store-to-load forwarding. The chunk loop
 * depends on its cursor values actually round-tripping through map memory —
 * see the lk_cursor comment. */
#define ONCE(x) (*(volatile typeof(x) *)&(x))

/* Capture budget in bytes per send/recv call (design decision Р6). Affects
 * cap_len only — total_len always reports the real call size, so the stage 2
 * reassembler knows the exact size of the hole. Per-connection capture_mode
 * is task 1.6. */
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
 * the cursor mid-chain: the preemptor degrades to a single empty event and
 * the original chain stays intact. */
struct lk_cursor {
    __u32 busy;
    __u32 si;     /* current segment index */
    __u32 soff;   /* bytes of segs->len[si] already consumed */
    __u32 pos;    /* stream offset within the call = sum of emitted cap_len */
    __u32 budget; /* capture bytes still allowed for this call */
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct lk_cursor);
} cursor SEC(".maps");

/* Port filter, filled by the agent from --port after load, before attach.
 * Keys are host-order local ports. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, LK_MAX_PORTS);
    __type(key, __u16);
    __type(value, __u8);
} ports SEC(".maps");

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

    if (family == AF_INET6 &&
        bpf_core_field_exists(sk->__sk_common.skc_v6_rcv_saddr)) {
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

    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return; /* loss accounting is task 1.5 */

    __builtin_memset(ev, 0, sizeof(*ev)); /* ringbuf memory is not zeroed */
    ev->hdr.conn_id = cookie;
    ev->hdr.ts_ns = bpf_ktime_get_ns();
    ev->hdr.seq = __sync_fetch_and_add(&st->seq, 1);
    ev->hdr.type = type;
    ev->hdr.flags = flags;
    ev->tuple = st->tuple;
    ev->pid = pid;
    ev->conn_dropped = st->dropped;
    bpf_ringbuf_submit(ev, 0);
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

    ev = bpf_ringbuf_reserve(&events, sizeof(*ev) + chunk_sz, 0);
    if (!ev)
        return -1; /* loss accounting is task 1.5 */

    ev->hdr.conn_id = cookie;
    ev->hdr.ts_ns = bpf_ktime_get_ns();
    ev->hdr.seq = __sync_fetch_and_add(&st->seq, 1);
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
    __u32 zero = 0, budget;
    struct lk_cursor *cur;
    __u16 flags = 0;

    for (__u32 i = 0; i < LK_MAX_SEGS; i++) {
        if (i >= segs->nr)
            break;
        avail_total += segs->len[i];
    }

    /* The capture plan for the whole call, known before the first reserve:
     * budget < total_len means the chain is truncated (by --capture-limit,
     * an unsupported iterator, or segments beyond LK_MAX_SEGS), and every
     * chunk of the chain carries LK_F_TRUNC. */
    budget = cfg_capture_limit;
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

    cur = bpf_map_lookup_elem(&cursor, &zero);
    if (!cur)
        return;
    if (__sync_lock_test_and_set(&cur->busy, 1)) {
        /* Preempted another chain on this CPU: do not touch its cursor;
         * degrade to a single empty event, total_len stays honest. */
        emit_chunk(cookie, st, dir, total_len, 0, 0, 0,
                   total_len ? LK_F_TRUNC : flags, LK_CHUNK_SMALL);
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
            done = emit_chunk(cookie, st, dir, total_len, pos, base, cap, flags,
                              LK_CHUNK_SMALL);
        else
            done = emit_chunk(cookie, st, dir, total_len, pos, base, cap, flags,
                              LK_CHUNK_FULL);
        if (done <= 0)
            break; /* ringbuf full or the user page went away */
        ONCE(cur->si) = si;
        ONCE(cur->soff) = soff + done;
        ONCE(cur->pos) = pos + done;
        ONCE(cur->budget) = budget - done;
    }

    ONCE(cur->busy) = 0;
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(lk_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    struct lk_conn_state *st;
    struct lk_segs segs = {};

    if (!sk_port_match(sk) || !comm_allowed())
        return 0;

    __u64 cookie = bpf_get_socket_cookie(sk);

    st = conn_get(sk, cookie);
    if (!st)
        return 0;

    /* Data is still in the caller's buffer on entry to tcp_sendmsg; snapshot
     * msg->msg_iter and read straight from userspace. On an unsupported
     * iterator segs.nr stays 0 and a single cap_len=0 event is emitted —
     * total_len must stay honest. */
    iter_snapshot(msg, &segs);
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
    if (!sk_port_match(sk) || !comm_allowed())
        return 0;

    /* The destination buffers are empty now, but msg->msg_iter already
     * points at them. By fexit iov_iter has been advanced past the copied
     * bytes, so snapshot the segment list here; fexit reads from it.
     * Recording the entry (even with nr 0) also lets fexit recognise this
     * recv as ours. */
    iter_snapshot(msg, &segs);
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
    if (!segs)
        return 0;

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
