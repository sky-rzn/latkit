/* SPDX-License-Identifier: GPL-2.0 */
/* Userspace connection table (Р12, STAGE2.md): cookie -> struct lk_conn,
 * chained hash + LRU list. Absorbs the stage-1 seqtrack stub: the seq-hole
 * detector is now a table method, and a detected hole marks both directions
 * dirty (Р9: seq is per-connection, attribution to a direction is deferred).
 *
 * Lifecycle:
 *   - created on CONN_OPEN (regular or synthetic), or lazily on the first
 *     data event with an unknown cookie — the latter starts dirty, because
 *     it means the entry was evicted (or its OPEN lost) mid-stream and the
 *     kernel will not resend a synthetic OPEN (LK_CS_OPEN_SENT is still set
 *     in the kernel map);
 *   - removed on CONN_CLOSE (frame buffers freed, partial messages dropped);
 *   - leak insurance: lk_conn_table_sweep evicts entries idle longer than
 *     the timeout, and creation past max_conns evicts the LRU tail.
 *
 * Pure state manipulation, no I/O: the caller (events.c) does the logging,
 * unit tests feed synthetic events. */
#ifndef LATKIT_CONN_TABLE_H
#define LATKIT_CONN_TABLE_H

#include <linux/types.h>
#include <stdbool.h>

#include "latkit.h"

/* Userspace defaults for the CLI knobs. max_conns matches the kernel `conns`
 * map capacity; the idle timeout is deliberately conservative (a pooled
 * connection idling minutes between transactions must survive). */
#define LK_MAX_CONNS_DEFAULT     65536
#define LK_CONN_IDLE_TIMEOUT_SEC 600

/* Per-direction framer state (Р9-Р11). The state machine lives in
 * reassembly.c (task 2.3); it is declared here because it is embedded in
 * lk_conn and the table owns its lifetime (buf freed when the entry goes
 * away). The table itself only flips st to LK_FR_DIRTY on seq holes. */
enum lk_frame_state { LK_FR_HEADER = 0, LK_FR_BODY, LK_FR_SKIP, LK_FR_DIRTY };

struct lk_frame {
    enum lk_frame_state st;
    __u64 skip_left;            /* SKIP: wire bytes of the body left to discard */
    __u32 call_pos, call_total; /* chunk off-arithmetic within one call;
                                   call_total == 0: no call in progress */
    /* Message being assembled (valid in BODY/SKIP, hdr[] while in HEADER). */
    __u64 msg_ts;        /* ts of the event with the first header byte (Р13) */
    __u32 msg_len;       /* protocol len field of the current message */
    __u8 msg_type;       /* 0 while in startup framing */
    __u8 startup_done;   /* frontend: StartupMessage seen, normal framing on */
    __u8 after_resync;   /* next emitted message gets LK_MSG_AFTER_RESYNC */
    __u8 resync_matched; /* DIRTY backend: bytes of the 'Z' anchor matched so
                            far — the sliding window surviving event borders */
    __u8 hdr_len;        /* bytes accumulated in hdr */
    __u8 hdr[8];         /* header accumulator: 5 (normal) / 4 (startup) */
    __u8 *buf;           /* lazy body-prefix buffer, <= LK_MSG_BODY_MAX; used
                            only when a message spans chunks (Р11) */
    __u32 buf_len;
};

/* lk_conn.flags */
#define LK_CONN_SYNTHETIC (1 << 0) /* kernel synthetic OPEN: startup not seen */
#define LK_CONN_TLS                                                                                \
    (1 << 1) /* SSL/GSSENC request answered 'S'/'G': the                                           \
                stream is encrypted, framing is off and                                            \
                socket events are silently discarded                                               \
                (plaintext source: stage-6 uprobes) */
#define LK_CONN_SSL_REPLY                                                                          \
    (1 << 2) /* SSLRequest/GSSENCRequest seen: the next                                            \
                backend byte is the one-byte reply (Р10;                                          \
                cross-direction flag is sound — ringbuf                                          \
                order is global, recv(SSLRequest) in the                                           \
                kernel happens-before send of the reply) */
#define LK_CONN_CANCEL                                                                             \
    (1 << 3) /* CancelRequest seen: nothing else travels                                           \
                on this connection, discard until CLOSE */
#define LK_CONN_REPLICATION                                                                        \
    (1 << 4) /* CopyBothResponse: walsender/logical                                                \
                replication (set by the PG parser, Р20);                                           \
                payload is never needed -> HEADERS (Р21) */
#define LK_CONN_CAP_HEADERS                                                                        \
    (1 << 5) /* userspace already flipped this connection                                          \
                to HEADERS capture: a one-shot guard so the                                        \
                capmode map is written once, not per event */

struct lk_conn {
    struct lk_conn *hnext; /* hash chain */
    struct lk_conn *lru_prev, *lru_next;
    __u64 cookie;
    struct lk_tuple tuple; /* zeroed for lazily created entries */
    __u16 flags;           /* LK_CONN_* */
    __u32 last_seq;
    __u32 dropped; /* events lost on this connection (userspace-detected) */
    /* Decrypted-channel seq space (Р38, stage 6.4): the plaintext uprobe events
     * carry their own kernel seq counter (tls_seq), independent of the socket
     * path's. Tracked apart from last_seq/dropped so a ciphertext gap never
     * fakes a hole in the plaintext stream, nor a plaintext gap in ciphertext. */
    __u32 tls_last_seq;
    __u32 tls_dropped;
    __u8 tls_seq_seen; /* tls_last_seq seeded from a first decrypted event */
    __u64 last_activity_ns;
    struct lk_frame frame[2]; /* index: enum lk_dir */
    void *proto_state;        /* owned by the protocol handler (Р15, STAGE3):
                                 allocated lazily on the first message, released
                                 by the destroy hook on every removal path */
};

/* Cumulative counters; `active` is the current entry count. Reported in the
 * 10 s stats line; stage 4 turns them into metrics. */
struct lk_conn_table_stats {
    __u64 created;
    __u64 closed;       /* removed by CONN_CLOSE */
    __u64 evicted_lru;  /* pushed out by the max_conns ceiling */
    __u64 evicted_idle; /* collected by the idle sweep */
    __u64 seq_gaps;     /* holes detected (connections dirtied) */
    __u64 lost_events;  /* events lost in those holes, summed */
    __u64 tls_socket_dropped; /* ciphertext socket events dropped on TLS conns
                                 (Р38, stage 6.4): the decrypted uprobe channel
                                 is the only data source once a conn goes TLS */
    __u32 active;
};

struct lk_conn_table;

struct lk_conn_table *lk_conn_table_new(__u32 max_conns, __u64 idle_timeout_ns);
void lk_conn_table_free(struct lk_conn_table *t);

/* Register a hook fired for every entry removal — CONN_CLOSE, LRU eviction,
 * idle sweep, and lk_conn_table_free teardown — while the entry is still fully
 * valid, right before its memory is released. This is how the owner of
 * lk_conn.proto_state frees it on *all* paths (Р15, STAGE3): a partial parser
 * state must not outlive the connection it belongs to. At most one hook; NULL
 * ctx/fn clears it. Set it once, immediately after lk_conn_table_new, before
 * any event is fed. */
void lk_conn_table_on_destroy(struct lk_conn_table *t, void (*fn)(void *ctx, struct lk_conn *c),
                              void *ctx);

/* Event entry points. Each runs the seq-hole detector and stores the number
 * of events lost before this one into *lost (0 if none); a hole marks both
 * directions dirty. A backward seq step is not loss: seq assignment
 * (fetch_add in the kernel) and ringbuf reserve are not one atomic step, so
 * two CPUs can submit adjacent seqs out of order — such a pair first reports
 * a spurious 1-event gap, then the straggler arrives (tolerated, see the
 * STAGE2.md risk table).
 *
 * open/data return the entry (NULL only on allocation failure — degrade to
 * no tracking, not to exit); close removes it. data on an unknown cookie
 * creates the entry dirty (see the header comment). */
struct lk_conn *lk_conn_table_open(struct lk_conn_table *t, __u64 cookie, __u32 seq, __u64 ts_ns,
                                   const struct lk_tuple *tuple, bool synthetic, __u32 *lost);
struct lk_conn *lk_conn_table_data(struct lk_conn_table *t, __u64 cookie, __u32 seq, __u64 ts_ns,
                                   __u32 *lost);
void lk_conn_table_close(struct lk_conn_table *t, __u64 cookie, __u32 seq, __u64 ts_ns,
                         __u32 *lost);

/* --- TLS decrypted-channel routing (Р38, stage 6.4) ------------------------ */

/* Non-touching lookup: return the entry for cookie or NULL, with no seq check,
 * no LRU bump and no lazy creation. The TLS router uses it to test LK_CONN_TLS
 * before deciding to drop a ciphertext socket event — that drop must land
 * before any seq bookkeeping, so a ciphertext gap can never dirty the decrypted
 * framer through the shared seq detector. */
struct lk_conn *lk_conn_table_peek(struct lk_conn_table *t, __u64 cookie);

/* Decrypted-channel data event (Р38): like lk_conn_table_data, but the seq-hole
 * detector runs against the connection's own decrypted seq space (tls_last_seq)
 * rather than last_seq. A hole here still dirties both framer directions — the
 * decrypted stream is the framed one — but a raw-space gap leaves it alone. The
 * first decrypted event seeds the baseline and reports no loss. */
struct lk_conn *lk_conn_table_data_decrypted(struct lk_conn_table *t, __u64 cookie, __u32 seq,
                                             __u64 ts_ns, __u32 *lost);

/* Count one ciphertext socket event dropped on a TLS connection (Р38/Р41):
 * exposed as latkit_tls_socket_events_dropped_total. */
void lk_conn_table_note_tls_drop(struct lk_conn_table *t);

/* Reset both directions' framer state to a fresh startup (Р36), called once by
 * the router when a connection flips to LK_CONN_TLS. The real StartupMessage
 * arrives inside TLS, so the decrypted frontend stream must begin in startup
 * framing exactly like a fresh plaintext connection. Frees the partial-message
 * buffers; cookie, tuple, seq spaces and flags are kept. */
void lk_conn_tls_reset_framing(struct lk_conn *c);

/* Evict entries with last_activity_ns + idle_timeout <= now_ns; returns how
 * many were evicted. The LRU order makes this a tail walk, not a full scan.
 * Call every 60 s (events.c) with CLOCK_MONOTONIC now — the same clock as
 * event timestamps (bpf_ktime_get_ns). */
unsigned int lk_conn_table_sweep(struct lk_conn_table *t, __u64 now_ns);

const struct lk_conn_table_stats *lk_conn_table_stats(const struct lk_conn_table *t);

#endif /* LATKIT_CONN_TABLE_H */
