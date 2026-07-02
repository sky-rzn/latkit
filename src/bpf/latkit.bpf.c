// SPDX-License-Identifier: GPL-2.0
/* Task 0.2: capture TCP traffic on the PostgreSQL port in both directions.
 *
 * SEND is observed on entry to tcp_sendmsg; RECV uses the paired
 * fentry/fexit scheme on tcp_recvmsg (buffer known only on exit, once ret
 * bytes have been copied). Both paths currently emit tuple + length only;
 * reading the actual payload bytes out of iov_iter is task 0.3, which fills
 * in cap_len/payload where marked below. */
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

SEC("fentry/tcp_sendmsg")
int BPF_PROG(lk_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    struct lk_event *ev;

    if (!sk_is_pg(sk))
        return 0;

    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    fill_tuple(ev, sk);
    ev->dir = LK_DIR_SEND;
    ev->total_len = size;
    ev->cap_len = 0; /* payload capture from msg->msg_iter: task 0.3 */

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("fentry/tcp_recvmsg")
int BPF_PROG(lk_tcp_recvmsg_entry, struct sock *sk, struct msghdr *msg, size_t len, int flags,
             int *addr_len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct lk_recv_state st = {};

    if (!sk_is_pg(sk))
        return 0;

    /* st.buf (user buffer base from msg->msg_iter) is filled in task 0.3.
     * Recording the pending call now lets fexit know this recv is ours. */
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

    st = bpf_map_lookup_elem(&recv_state, &pid_tgid);
    if (!st)
        return 0;

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
    ev->cap_len = 0; /* payload capture via st->buf + bpf_probe_read_user: task 0.3 */

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
