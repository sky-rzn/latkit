/* SPDX-License-Identifier: GPL-2.0 */
/* Raw event trace format (Р14, STAGE2.md): `--record` dumps every ringbuf
 * record to a file verbatim, so a session can be replayed offline through the
 * exact decode -> conn table -> framer path the live agent runs (pipeline.c).
 * The replay harness (tests/replay) and the stage-3 protocol fixtures are
 * built on it — one code path over live and recorded streams.
 *
 * File layout: the 4-byte magic "LKT1", then a sequence of records, each a
 * u32 length in host byte order followed by that many bytes — the ringbuf
 * record exactly as the kernel wrote it. Those bytes are native-endian kernel
 * structs (lk_ev_*), so a trace only replays on hosts of the same endianness;
 * the committed fixtures are little-endian.
 *
 * libbpf-free and self-contained (stdio only): usable from the agent and from
 * the unit tests without pulling in the BPF stack. */
#ifndef LATKIT_RECORD_H
#define LATKIT_RECORD_H

#include <linux/types.h>
#include <stddef.h>

#define LK_RECORD_MAGIC     "LKT1"
#define LK_RECORD_MAGIC_LEN 4

struct lk_recorder;

/* Create/truncate `path` and write the magic. NULL on open/write failure
 * (errno set); the agent then keeps running without recording. */
struct lk_recorder *lk_recorder_open(const char *path);

/* Append one record. Once any write fails the recorder latches into an error
 * state and drops further records silently; the failure surfaces at close. */
void lk_recorder_write(struct lk_recorder *rec, const void *data, __u32 size);

/* Flush, close, free (NULL tolerated). Returns -1 if any write or the final
 * flush failed, else 0. */
int lk_recorder_close(struct lk_recorder *rec);

/* Replay: call `fn` for each record in the trace. `fn` returns nonzero to
 * stop early (that value is returned). Returns 0 on a fully consumed,
 * well-formed trace; -1 on an open/read error or a malformed trace (bad
 * magic, truncated length or record). */
typedef int (*lk_replay_fn)(void *ctx, const void *data, __u32 size);
int lk_replay_file(const char *path, lk_replay_fn fn, void *ctx);
int lk_replay_mem(const void *buf, size_t len, lk_replay_fn fn, void *ctx);

#endif /* LATKIT_RECORD_H */
