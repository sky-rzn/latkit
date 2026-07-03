// SPDX-License-Identifier: GPL-2.0
/* Stage 1 capture layer: TCP traffic of sockets whose LOCAL port is in the
 * `ports` map — the server side only (design decision Р7) — in both
 * directions, keyed by connection.
 *
 * SEND is observed on entry to tcp_sendmsg; RECV uses the paired fentry/fexit
 * scheme on tcp_recvmsg (buffer known only on exit, once ret bytes have been
 * copied). Payload bytes are read out of the userspace iov_iter for both
 * directions; see iter_first_seg() and docs/notes-iov.md.
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

/* Capture budget in bytes per send/recv call (design decision Р6). Affects
 * cap_len only — total_len always reports the real call size, so the stage 2
 * reassembler knows the exact size of the hole. Per-connection capture_mode
 * and multi-chunk emission are tasks 1.4/1.6. */
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

/* Per-in-flight-recv state saved on fentry(tcp_recvmsg) and consumed on
 * fexit. Keyed by pid_tgid: tcp_recvmsg does not switch task between entry
 * and exit, so the caller's pid_tgid uniquely identifies the pending call.
 * buf holds the user buffer base. */
struct lk_recv_state {
    __u64 buf;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct lk_recv_state);
} recv_state SEC(".maps");

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

/* Resolve the userspace base pointer and remaining length of the FIRST
 * segment of msg->msg_iter. Both fields are read through CO-RE so the same
 * object relocates across the field renames documented in docs/notes-iov.md.
 *
 * Two iterator shapes matter for socket traffic:
 *   ITER_UBUF  (~6.0+): a single userspace buffer. Current position is
 *              ubuf + iov_offset; `count` is the bytes still to transfer.
 *   ITER_IOVEC:         a vector of userspace buffers. We only look at the
 *              current segment __iov[0]; multi-segment capture is task 1.4.
 *              The pre-~6.4 spelling of __iov (`iov`) is wired up in stage 8.
 *
 * KVEC/BVEC/FOLIOQ/XARRAY reference kernel-internal memory, not the
 * application's send/recv buffer, so they are rejected here. Returns 0 and
 * writes base/len on success, -1 otherwise. */
static __always_inline int iter_first_seg(struct msghdr *msg, __u64 *base, __u32 *len)
{
    __u8 type = BPF_CORE_READ(msg, msg_iter.iter_type);
    __u64 off = BPF_CORE_READ(msg, msg_iter.iov_offset);

    if (bpf_core_field_exists(msg->msg_iter.ubuf) && type == ITER_UBUF) {
        __u64 ubuf = (__u64)BPF_CORE_READ(msg, msg_iter.ubuf);
        __u64 count = BPF_CORE_READ(msg, msg_iter.count);

        *base = ubuf + off;
        *len = count; /* remaining bytes from the current position */
        return 0;
    }

    if (type == ITER_IOVEC) {
        const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
        __u64 iov_base = (__u64)BPF_CORE_READ(iov, iov_base);
        __u64 iov_len = BPF_CORE_READ(iov, iov_len);

        *base = iov_base + off;
        *len = iov_len > off ? iov_len - off : 0;
        return 0;
    }

    return -1;
}

/* Emit one small-class data event with up to LK_CHUNK_SMALL payload bytes
 * read from the userspace buffer at `base`. The clamp keeps the size the
 * verifier sees within the reserved payload; a failed read (unmapped or
 * paged-out user page) degrades to cap_len = 0. Full-class selection and
 * multi-chunk emission are task 1.4. */
static __always_inline void emit_data_event(__u64 cookie, struct lk_conn_state *st, __u8 dir,
                                            __u32 total_len, __u64 base, __u32 avail)
{
    struct lk_ev_data *ev;
    /* 64-bit on purpose: the verifier links full-register copies by id and
     * propagates the <= LK_CHUNK_SMALL bound to whichever copy clang passes
     * to bpf_probe_read_user; 32-bit subregister copies lose that link. */
    __u64 cap = avail;

    ev = bpf_ringbuf_reserve(&events, sizeof(*ev) + LK_CHUNK_SMALL, 0);
    if (!ev)
        return; /* loss accounting is task 1.5 */

    ev->hdr.conn_id = cookie;
    ev->hdr.ts_ns = bpf_ktime_get_ns();
    ev->hdr.seq = __sync_fetch_and_add(&st->seq, 1);
    ev->hdr.type = LK_EV_DATA;
    ev->hdr.dir = dir;
    ev->hdr.flags = 0;
    ev->total_len = total_len;
    ev->off = 0;
    ev->_pad = 0;

    if (cap > cfg_capture_limit)
        cap = cfg_capture_limit;
    if (cap > total_len)
        cap = total_len;
    if (cap > LK_CHUNK_SMALL)
        cap = LK_CHUNK_SMALL;
    /* Pin the clamped value to one register: clang otherwise compares one
     * copy of cap and passes another to the read, and the verifier rejects
     * that copy as unbounded. */
    barrier_var(cap);
    if (cap == 0 || base == 0)
        cap = 0;
    else if (bpf_probe_read_user(ev->payload, cap, (const void *)base))
        cap = 0;
    ev->cap_len = cap;
    if (cap < total_len)
        ev->hdr.flags |= LK_F_TRUNC;

    bpf_ringbuf_submit(ev, 0);
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(lk_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    struct lk_conn_state *st;
    __u64 base = 0;
    __u32 avail = 0;

    if (!sk_port_match(sk) || !comm_allowed())
        return 0;

    __u64 cookie = bpf_get_socket_cookie(sk);

    st = conn_get(sk, cookie);
    if (!st)
        return 0;

    /* Data is still in the caller's buffer on entry to tcp_sendmsg; read it
     * straight from msg->msg_iter. On an unsupported iterator the event is
     * still emitted with cap_len 0 — total_len must stay honest. */
    if (iter_first_seg(msg, &base, &avail))
        base = 0;

    emit_data_event(cookie, st, LK_DIR_SEND, size, base, avail);
    return 0;
}

SEC("fentry/tcp_recvmsg")
int BPF_PROG(lk_tcp_recvmsg_entry, struct sock *sk, struct msghdr *msg, size_t len, int flags,
             int *addr_len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct lk_recv_state st = {};
    __u64 base = 0;
    __u32 avail = 0;

    /* Filtering here also covers fexit: without a recv_state entry the exit
     * program bails out before emitting anything. */
    if (!sk_port_match(sk) || !comm_allowed())
        return 0;

    /* The destination buffer is empty now, but msg->msg_iter already points
     * at it. By fexit iov_iter has been advanced past the copied bytes, so
     * stash the base pointer here; fexit reads from it. Recording the entry
     * (even with base 0) also lets fexit recognise this recv as ours. */
    if (iter_first_seg(msg, &base, &avail) == 0)
        st.buf = base;
    bpf_map_update_elem(&recv_state, &pid_tgid, &st, BPF_ANY);
    return 0;
}

SEC("fexit/tcp_recvmsg")
int BPF_PROG(lk_tcp_recvmsg_exit, struct sock *sk, struct msghdr *msg, size_t len, int flags,
             int *addr_len, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct lk_recv_state *st;
    struct lk_conn_state *cs;
    __u64 buf;

    st = bpf_map_lookup_elem(&recv_state, &pid_tgid);
    if (!st)
        return 0;
    buf = st->buf;

    /* Always drop the entry, including the ret <= 0 path, or the map leaks. */
    bpf_map_delete_elem(&recv_state, &pid_tgid);

    if (ret <= 0)
        return 0;

    __u64 cookie = bpf_get_socket_cookie(sk);

    cs = conn_get(sk, cookie);
    if (!cs)
        return 0;

    /* ret bytes were copied to the buffer whose base we saved on entry. This
     * captures the first iov segment only; multi-segment recv is task 1.4. */
    emit_data_event(cookie, cs, LK_DIR_RECV, ret, buf, ret);
    return 0;
}
