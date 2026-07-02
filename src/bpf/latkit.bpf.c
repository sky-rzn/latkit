// SPDX-License-Identifier: GPL-2.0
/* Task 0.2: capture TCP traffic on the PostgreSQL port in both directions.
 *
 * SEND is observed on entry to tcp_sendmsg; RECV uses the paired
 * fentry/fexit scheme on tcp_recvmsg (buffer known only on exit, once ret
 * bytes have been copied). Task 0.3 reads the actual payload bytes out of
 * the userspace iov_iter for both directions; see iter_first_seg() and
 * docs/notes-iov.md. */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "latkit.h"

char LICENSE[] SEC("license") = "GPL";

/* Hardcoded for the PoC; a configurable port map is stage 1. */
#define LK_PG_PORT 5432

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, LK_RINGBUF_SZ);
} events SEC(".maps");

/* Per-in-flight-recv state saved on fentry(tcp_recvmsg) and consumed on
 * fexit. Keyed by pid_tgid: tcp_recvmsg does not switch task between entry
 * and exit, so the caller's pid_tgid uniquely identifies the pending call.
 * buf holds the user buffer base (populated in task 0.3). */
struct lk_recv_state {
    __u64 buf;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct lk_recv_state);
} recv_state SEC(".maps");

/* Event is interesting if either endpoint is the PostgreSQL port. skc_num is
 * already host order; skc_dport is network order. */
static __always_inline int sk_is_pg(struct sock *sk)
{
    __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    return sport == LK_PG_PORT || dport == LK_PG_PORT;
}

static __always_inline void fill_tuple(struct lk_event *ev, struct sock *sk)
{
    ev->ts_ns = bpf_ktime_get_ns();
    ev->pid = bpf_get_current_pid_tgid() >> 32;
    ev->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    ev->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    ev->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    ev->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    ev->_pad[0] = ev->_pad[1] = ev->_pad[2] = 0;
}

/* Resolve the userspace base pointer and remaining length of the FIRST
 * segment of msg->msg_iter. Both fields are read through CO-RE so the same
 * object relocates across the field renames documented in docs/notes-iov.md.
 *
 * Two iterator shapes matter for socket traffic:
 *   ITER_UBUF  (~6.0+): a single userspace buffer. Current position is
 *              ubuf + iov_offset; `count` is the bytes still to transfer.
 *   ITER_IOVEC:         a vector of userspace buffers. We only look at the
 *              current segment __iov[0]; multi-segment payloads are captured
 *              as their first segment for the PoC (see notes-iov.md). The
 *              pre-~6.4 spelling of __iov (`iov`) is wired up in stage 8.
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

/* Copy up to POC_CHUNK bytes from the userspace buffer at `base` into the
 * event payload and record how many landed. The clamp keeps the size the
 * verifier sees within payload[] (mask/if per task 0.3 notes); a failed
 * read (unmapped/paged-out user page) degrades to cap_len = 0. */
static __always_inline void capture_payload(struct lk_event *ev, __u64 base, __u32 avail)
{
    __u32 cap = avail;

    if (cap > POC_CHUNK)
        cap = POC_CHUNK;
    if (cap == 0 || base == 0) {
        ev->cap_len = 0;
        return;
    }

    if (bpf_probe_read_user(ev->payload, cap, (const void *)base))
        cap = 0;
    ev->cap_len = cap;
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(lk_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    struct lk_event *ev;
    __u64 base = 0;
    __u32 avail = 0;

    if (!sk_is_pg(sk))
        return 0;

    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    fill_tuple(ev, sk);
    ev->dir = LK_DIR_SEND;
    ev->total_len = size;

    /* Data is still in the caller's buffer on entry to tcp_sendmsg; read it
     * straight from msg->msg_iter. */
    if (iter_first_seg(msg, &base, &avail) == 0)
        capture_payload(ev, base, avail);
    else
        ev->cap_len = 0;

    bpf_ringbuf_submit(ev, 0);
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

    if (!sk_is_pg(sk))
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
    struct lk_event *ev;
    __u64 buf;

    st = bpf_map_lookup_elem(&recv_state, &pid_tgid);
    if (!st)
        return 0;
    buf = st->buf;

    /* Always drop the entry, including the ret <= 0 path, or the map leaks. */
    bpf_map_delete_elem(&recv_state, &pid_tgid);

    if (ret <= 0)
        return 0;

    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    fill_tuple(ev, sk);
    ev->dir = LK_DIR_RECV;
    ev->total_len = ret;
    /* ret bytes were copied to the buffer whose base we saved on entry. This
     * captures the first iov segment only; multi-segment recv is a known PoC
     * gap (see docs/notes-iov.md, stage 1 TODO). */
    capture_payload(ev, buf, ret);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
