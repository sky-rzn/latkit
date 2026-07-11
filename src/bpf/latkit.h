/* SPDX-License-Identifier: GPL-2.0 */
/* Shared kernel<->userspace event definitions (format v1, STAGE1.md). Included
 * from BPF code (after vmlinux.h) and from userspace (after <linux/types.h>). */
#ifndef LATKIT_H
#define LATKIT_H

#define LK_RINGBUF_SZ (8 * 1024 * 1024) /* default; --ringbuf-bytes overrides */

#define LK_MAX_PORTS    16   /* capacity of the `ports` filter map */
#define LK_DEFAULT_PORT 5432 /* used when no --port is given */

/* Capacity of the `cgroups` filter map (task 7.1, Р48): a handful of postgres
 * pods per node; the userspace resolver caps matched paths at this too. */
#define LK_MAX_CGROUPS 64

/* Default --capture-limit: capture budget in bytes per send/recv call (Р6).
 * Invariant of every budget mechanism (this, LK_CAP_HEADERS, LK_MAX_SEGS,
 * LK_MAX_CHUNKS): total_len always reports the real call size — budgets cut
 * cap_len only, so the stage-2 reassembler knows the exact size of the hole. */
#define LK_CAPTURE_LIMIT 8192

/* Data-event payload size classes (design decision Р4): the reserve size is
 * picked per chunk from the actual capture size, so small control messages do
 * not burn 4 KiB of ringbuf each. */
#define LK_CHUNK_SMALL 256
#define LK_CHUNK_FULL  4096

/* Hard per-call bounds of the data path (task 1.4). Both are verifier loop
 * bounds, so they must be compile-time constants: at most LK_MAX_SEGS iovec
 * segments are captured per send/recv call, and at most LK_MAX_CHUNKS data
 * events emitted. The effective --capture-limit ceiling is therefore
 * LK_MAX_CHUNKS * LK_CHUNK_FULL; the CLI rejects larger values. */
#define LK_MAX_SEGS   8
#define LK_MAX_CHUNKS 8

/* Global loss/volume statistics (design decision Р5): indices into the
 * `stats` PERCPU_ARRAY map, one __u64 per CPU per counter. The agent sums
 * across CPUs and reports periodically; stage 4 turns these into metrics
 * (latkit_ringbuf_dropped_total etc.). */
enum lk_stat_id {
    LK_ST_EVENTS = 0,        /* records submitted to the ringbuf */
    LK_ST_RESERVE_FAIL_DATA, /* bpf_ringbuf_reserve failures, by event type */
    LK_ST_RESERVE_FAIL_OPEN,
    LK_ST_RESERVE_FAIL_CLOSE,
    LK_ST_BYTES_TOTAL,      /* sum of total_len over data calls, incl. lost */
    LK_ST_BYTES_CAPTURED,   /* payload bytes actually submitted */
    LK_ST_ITER_UNSUPPORTED, /* iter_snapshot rejected the iterator type */
    LK_ST_RECV_STATE_MISS,  /* fexit(tcp_recvmsg) found no fentry snapshot */
    /* TLS uprobe channel (stage 6, Р35/Р41). */
    LK_ST_TLS_CORR_MISS,       /* uretprobe without a known cookie (Р37; stage 6.2) */
    LK_ST_TLS_UPROBE_EVENTS,   /* decrypted data events submitted */
    LK_ST_TLS_DECRYPTED_BYTES, /* sum of cap_len over decrypted events */
    LK_ST_TLS_RESERVE_FAIL,    /* bpf_ringbuf_reserve failures on the decrypted path */
    LK_ST_MAX,
};

enum lk_ev_type { LK_EV_DATA = 0, LK_EV_CONN_OPEN = 1, LK_EV_CONN_CLOSE = 2 };
enum lk_dir { LK_DIR_SEND = 0, LK_DIR_RECV = 1 };

/* lk_ev_hdr.flags */
#define LK_F_TRUNC     (1 << 0) /* cap_len < total_len: cut by capture budget */
#define LK_F_GAP       (1 << 1) /* events for this conn were lost before this one */
#define LK_F_SYNTHETIC (1 << 2) /* CONN_OPEN created lazily; startup not seen */
#define LK_F_DECRYPTED                                                                             \
    (1 << 3) /* payload came from an SSL_* uprobe (stage 6, Р35):                                 \
                plaintext of a TLS connection, framed like a                                       \
                normal stream but sourced from userspace */

struct lk_tuple {
    __u8 family; /* AF_INET / AF_INET6 */
    __u8 _pad[3];
    __u32 netns;               /* netns inode: skc_net.net->ns.inum */
    __u8 saddr[16], daddr[16]; /* v4 in the first 4 bytes */
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

/* Kernel-side connection registry entry (map `conns`, key = cookie). */

#define LK_CS_OPEN_SENT (1 << 0) /* CONN_OPEN already emitted for this conn */

/* Per-connection capture budget override. The value lives in its own `capmode`
 * map (key = cookie, value = __u8 enum lk_cap_mode), written *only* by userspace
 * and read by the kernel data path (Р21): keeping it out of lk_conn_state means
 * the userspace writer no longer read-modify-writes the whole struct, so it can
 * never clobber the kernel's concurrent seq/dropped updates. Absent entry ==
 * FULL. HEADERS caps the capture at LK_CAP_HEADERS_LIMIT bytes per send/recv
 * call; total_len stays honest. Policy (stage 3): TLS / CANCEL / replication —
 * connections whose payload is never needed — are flipped to HEADERS; stage 1's
 * --cap-headers test hook writes the same map. */
enum lk_cap_mode { LK_CAP_FULL = 0, LK_CAP_HEADERS = 1 };

#define LK_CAP_HEADERS_LIMIT 64 /* HEADERS budget, bytes per call */

struct lk_conn_state {
    struct lk_tuple tuple; /* for synthetic CONN_OPEN and debugging */
    __u32 seq;             /* event counter (design decision Р5) */
    __u32 dropped;         /* events lost on reserve failure */
    __u32 gap_pending;     /* loss recorded; next event carries LK_F_GAP */
    __u8 flags;            /* LK_CS_* */
};

#endif /* LATKIT_H */
