/* SPDX-License-Identifier: GPL-2.0 */
/* Scenario byte-format shared by fuzz_pipe.c (the interpreter) and gen_seeds.c
 * (the seed writer). Task 8.3, Р51: the fuzz input is not a byte stream but a
 * scenario of *events* — open/close/data/gaps/sweeps over a handful of
 * connections — so the fuzzer mutates exactly the dimensions the pipeline's
 * cross-module seams are sensitive to (resync after holes, startup phase,
 * lazy-created dirty entries, the TLS flip, LRU/idle eviction).
 *
 * The very first input byte is the protocol selector (MYSQL.md М7): bit 0
 * chooses the wire protocol every connection frames and parses as — 0 = pg
 * (the registry head, the historical behaviour), 1 = mysql. The rest of the
 * byte is reserved. This lets one corpus fuzz both framers and both handlers
 * through the same pipeline seams; the scenario proper begins at byte 1.
 *
 * A scenario is a sequence of ops. The op byte packs three fields:
 *
 *      bit 7..5   arg   (3-bit immediate; DATA: high bits of the payload len)
 *      bit 4..2   code  (PIPE_OP_*)
 *      bit 1..0   slot  (one of 4 connection slots)
 *
 * followed by code-specific operands. Every field is consumed with saturating
 * reads (missing tail bytes read as 0), so any byte string is a valid — if
 * short — scenario and the interpreter always terminates.
 *
 *   OPEN   —                       CONN_OPEN for the slot's cookie.
 *                                  arg bit0: synthetic (born dirty, Р10);
 *                                  arg bit1: fresh cookie (bump generation —
 *                                            the old entry leaks until LRU/idle
 *                                            eviction collects it, Р12);
 *                                  arg bit2: seq gap before the event (Р9).
 *   CLOSE  —                       CONN_CLOSE. arg bit0: seq gap before it.
 *   RECV / SEND — u8 meta, u8 len, payload[]:
 *                                  one LK_EV_DATA. Payload is the next
 *                                  ((arg & 7) << 8 | len) input bytes (clamped
 *                                  to what remains — the fuzzer owns the wire
 *                                  bytes, the dictionary seeds PG framing).
 *                                  meta bit0: LK_F_DECRYPTED (uprobe channel,
 *                                             its own seq space, Р38);
 *                                  meta bit1: seq gap before the event;
 *                                  meta bit3..2: uncaptured tail after the
 *                                             payload (budget-cut hole, Р9):
 *                                             {0, 1, 64, 4096} bytes;
 *                                  meta bit5..4: call shape (PIPE_SHAPE_*).
 *   SWEEP  —                       advance the clock (arg+1)*100 s and run the
 *                                  idle sweep (Р12).
 *   RAW    — u8 len, bytes[]:      feed the next len bytes to the pipeline as
 *                                  a raw ringbuf record: decode's SHORT/UNKNOWN
 *                                  gating and arbitrary-header paths.
 *   TICK   —                       advance the clock by (arg+1) µs.
 *
 * Call shapes (how off/total_len are derived for a DATA event):
 *   NEW_TAIL — off=0, total = cap+tail: a fresh call, tail uncaptured;
 *   CONT     — continue the call in progress at its current position
 *              (a message torn across events), or a clean exact call;
 *   CONT_HOLE— continue after skipping `tail` bytes: an intra-call hole;
 *   ANOMALY  — off derived from the len byte, total = cap: off-arithmetic
 *              anomalies (off backwards / past total_len, Р9 debris paths).
 */
#ifndef LATKIT_FUZZ_PIPE_OPS_H
#define LATKIT_FUZZ_PIPE_OPS_H

enum pipe_op {
    PIPE_OP_OPEN = 0,
    PIPE_OP_CLOSE = 1,
    PIPE_OP_RECV = 2,
    PIPE_OP_SEND = 3,
    PIPE_OP_SWEEP = 4,
    PIPE_OP_RAW = 5,
    PIPE_OP_TICK = 6, /* 7 decodes as TICK too */
};

enum pipe_shape {
    PIPE_SHAPE_NEW_TAIL = 0,
    PIPE_SHAPE_CONT = 1,
    PIPE_SHAPE_CONT_HOLE = 2,
    PIPE_SHAPE_ANOMALY = 3,
};

/* OPEN arg bits */
#define PIPE_OPEN_SYNTHETIC 1
#define PIPE_OPEN_FRESH     2
#define PIPE_OPEN_GAP       4
/* CLOSE arg bits */
#define PIPE_CLOSE_GAP 1
/* DATA meta bits */
#define PIPE_DATA_DECRYPTED 0x01
#define PIPE_DATA_GAP       0x02
#define PIPE_DATA_TAIL(sel) (((sel) & 3) << 2) /* {0, 1, 64, 4096} bytes */
#define PIPE_DATA_SHAPE(sh) (((sh) & 3) << 4)

#define PIPE_OP(code, slot, arg) (__u8)((((arg) & 7) << 5) | (((code) & 7) << 2) | ((slot) & 3))

#define PIPE_SLOTS    4
#define PIPE_DATA_MAX 2048 /* 3-bit arg << 8 | len byte */

/* Leading protocol-selector byte: bit 0 picks mysql over the pg default. */
#define PIPE_PROTO_MYSQL 1

#endif /* LATKIT_FUZZ_PIPE_OPS_H */
