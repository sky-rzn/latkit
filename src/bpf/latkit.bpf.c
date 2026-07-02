// SPDX-License-Identifier: GPL-2.0
/* Stage 0.1 hello-world: fentry on tcp_sendmsg, event without payload.
 * Port filtering and payload capture land in tasks 0.2/0.3. */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "latkit.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, LK_RINGBUF_SZ);
} events SEC(".maps");

SEC("fentry/tcp_sendmsg")
int BPF_PROG(lk_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    struct lk_event *ev;

    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->ts_ns = bpf_ktime_get_ns();
    ev->pid = bpf_get_current_pid_tgid() >> 32;
    ev->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    ev->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    ev->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    ev->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    ev->dir = LK_DIR_SEND;
    ev->_pad[0] = ev->_pad[1] = ev->_pad[2] = 0;
    ev->total_len = size;
    ev->cap_len = 0;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
