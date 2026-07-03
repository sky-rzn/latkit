/* SPDX-License-Identifier: GPL-2.0 */
/* Shared kernel<->userspace event definitions (format v1, STAGE1.md). Included
 * from BPF code (after vmlinux.h) and from userspace (after <linux/types.h>). */
#ifndef LATKIT_H
#define LATKIT_H

#define LK_RINGBUF_SZ (8 * 1024 * 1024) /* default; --ringbuf-bytes overrides */

#define LK_MAX_PORTS 16      /* capacity of the `ports` filter map */
#define LK_DEFAULT_PORT 5432 /* used when no --port is given */

/* Default --capture-limit: capture budget in bytes per send/recv call (Р6). */
#define LK_CAPTURE_LIMIT 8192

/* Data-event payload size classes (design decision Р4): the reserve size is
 * picked per event from the actual capture size, so small control messages do
 * not burn 4 KiB of ringbuf each. Class selection and multi-chunk emission are
 * task 1.4; until then the data path reserves LK_CHUNK_SMALL only. */
#define LK_CHUNK_SMALL 256
#define LK_CHUNK_FULL 4096

enum lk_ev_type { LK_EV_DATA = 0, LK_EV_CONN_OPEN = 1, LK_EV_CONN_CLOSE = 2 };
enum lk_dir { LK_DIR_SEND = 0, LK_DIR_RECV = 1 };

/* lk_ev_hdr.flags */
#define LK_F_TRUNC (1 << 0)     /* cap_len < total_len: cut by capture budget */
#define LK_F_GAP (1 << 1)       /* events for this conn were lost before this one */
#define LK_F_SYNTHETIC (1 << 2) /* CONN_OPEN created lazily; startup not seen */

struct lk_tuple {
    __u8 family; /* AF_INET / AF_INET6 */
    __u8 _pad[3];
    __u32 netns;                /* netns inode: skc_net.net->ns.inum */
    __u8 saddr[16], daddr[16];  /* v4 in the first 4 bytes */
    __u16 sport, dport;
};

/* Common prefix of every ringbuf record; userspace discriminates on type. */
struct lk_ev_hdr {
    __u64 conn_id; /* socket cookie (bpf_get_socket_cookie) */
    __u64 ts_ns;   /* bpf_ktime_get_ns */
    __u32 seq;     /* per-conn, monotonic; a hole means loss */
    __u8 type;     /* enum lk_ev_type */
    __u8 dir;      /* enum lk_dir, for LK_EV_DATA */
    __u16 flags;   /* LK_F_* */
};

struct lk_ev_conn { /* CONN_OPEN / CONN_CLOSE */
    struct lk_ev_hdr hdr;
    struct lk_tuple tuple;
    __u32 pid;          /* 0 when the context is unreliable (tracepoint) */
    __u32 conn_dropped; /* in CLOSE: total losses on this connection */
};

struct lk_ev_data { /* payload is LK_CHUNK_SMALL or LK_CHUNK_FULL */
    struct lk_ev_hdr hdr;
    __u32 total_len; /* full size of the send/recv call */
    __u32 off;       /* chunk offset within the call */
    __u32 cap_len;   /* bytes in payload */
    __u32 _pad;
    __u8 payload[];
};

/* Kernel-side connection registry entry (map `conns`, key = cookie).
 * Userspace writes capture_mode here (task 1.6), hence shared. */

#define LK_CS_OPEN_SENT (1 << 0) /* CONN_OPEN already emitted for this conn */

enum lk_cap_mode { LK_CAP_FULL = 0, LK_CAP_HEADERS = 1 }; /* policy is stage 3 */

struct lk_conn_state {
    struct lk_tuple tuple; /* for synthetic CONN_OPEN and debugging */
    __u32 seq;             /* event counter (design decision Р5) */
    __u32 dropped;         /* events lost on reserve failure (task 1.5) */
    __u8 flags;            /* LK_CS_* */
    __u8 capture_mode;     /* enum lk_cap_mode (task 1.6) */
};

#endif /* LATKIT_H */
