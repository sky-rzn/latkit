/* SPDX-License-Identifier: GPL-2.0 */
/* Shared kernel<->userspace event definitions. Included from BPF code
 * (after vmlinux.h) and from userspace (after <linux/types.h>). */
#ifndef LATKIT_H
#define LATKIT_H

#define POC_CHUNK 256 /* PoC payload capture limit; 4 KiB is stage 1 */

#define LK_RINGBUF_SZ (1024 * 1024) /* PoC ringbuf size, loss accounting is stage 1 */

enum lk_dir { LK_DIR_SEND = 0, LK_DIR_RECV = 1 };

struct lk_event {
    __u64 ts_ns; /* bpf_ktime_get_ns */
    __u32 pid;
    __u32 saddr, daddr; /* IPv4 only for now; v6 is stage 1 */
    __u16 sport, dport;
    __u8 dir;        /* enum lk_dir */
    __u8 _pad[3];    /* explicit: no compiler holes before total_len */
    __u32 total_len; /* bytes requested in send/recv */
    __u32 cap_len;   /* bytes copied into payload */
    __u8 payload[POC_CHUNK];
};

#endif /* LATKIT_H */
