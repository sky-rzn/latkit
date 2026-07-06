/* SPDX-License-Identifier: GPL-2.0 */
/* SQL normaliser + fingerprint (Р22, STAGE4.md task 4.1).
 *
 * Same spirit as pg_stat_statements — collapse the volatile parts of a query
 * so that select * from t where id = 1 and where id = 42 and where id = $1 all
 * land on one fingerprint — but WITHOUT a real SQL parser: a single pass over
 * the bytes, a small lexer state machine, zero heap allocation (the canonical
 * text is written into the caller's struct). The rules, in priority order, are:
 *
 *   - comments (-- to newline, and C-style block comments with nesting — PG
 *     nests them) are dropped, acting as whitespace;
 *   - string literals ('...' with '' escape, E'...' with backslash escapes,
 *     B'...'/X'...', dollar-quoting $tag$...$tag$) -> the placeholder token ?;
 *   - numbers (integer, decimal, exponent, 0x/0o/0b, 1_000 separators) -> ?;
 *   - bind parameters $1, $2 -> ? and a bare ? (JDBC-style) -> ?, so the simple,
 *     prepared and JDBC spellings of the same query merge (a deliberate
 *     departure from pg_stat_statements, which keeps $N — see notes-metrics.md);
 *   - unquoted identifiers and keywords are lower-cased (PG folds them to lower
 *     too, so semantics are preserved); null/true/false are NOT turned into ?
 *     (a lexer cannot tell `is null` from a literal);
 *   - quoted identifiers "..." (with "" escape) are kept verbatim, case
 *     significant;
 *   - runs of whitespace become a single separator; a trailing ; is dropped, so
 *     `select 1` and `select 1;` share a fingerprint; an inner ; (multi-
 *     statement Q) stays a token;
 *   - list collapse: `( ? , ? , ... )` -> `( ? )` (covers IN (1,2,3)); then
 *     `( ? ) , ( ? ) , ...` -> `( ? )` (covers multi-row VALUES).
 *
 * The canonical text is the tokens joined by single spaces. The fingerprint is
 * XXH3-64 over the token stream (each token followed by a NUL separator),
 * computed STREAMING and INDEPENDENTLY of the text buffer: if the canonical
 * text does not fit in LK_NORM_TEXT_MAX the text is truncated but the hash
 * keeps consuming tokens to the end of the input, so a truncated label never
 * changes a query's identity.
 *
 * The input is untrusted and may itself be a truncated prefix (capture budget):
 * a lexer that runs off the end of the buffer mid-token finishes cleanly (the
 * partial token is emitted, `trunc` is set), and by construction never reads
 * outside [sql, sql+len). Two long queries sharing a prefix longer than the
 * capture budget collapse to one fingerprint — the accepted price, documented.
 *
 * Pure: no I/O, no libbpf. Depends only on libc and the vendored xxhash. */
#ifndef LATKIT_NORM_SQL_H
#define LATKIT_NORM_SQL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Canonical text cap. The fingerprint is unaffected by this bound (see above);
 * it only clips the human-readable label. */
#define LK_NORM_TEXT_MAX 1024

struct lk_norm_out {
    char text[LK_NORM_TEXT_MAX]; /* canonical text, NUL-terminated, may be clipped */
    uint32_t text_len;           /* strlen(text); < LK_NORM_TEXT_MAX */
    uint64_t fp;                 /* XXH3-64 of the full token stream */
    bool trunc;                  /* input ran out mid-token, or text was clipped */
};

/* Always succeeds: garbage in is just more tokens, and the bounds hold by
 * construction. `out` is fully written (no need to pre-zero it). */
void lk_norm_sql(const char *sql, size_t len, struct lk_norm_out *out);

/* Fuzz entry (groundwork for stage 8, like lk_pg_fuzz_one): normalise the raw
 * bytes and touch every output field so an out-of-bounds read or a
 * non-deterministic hash surfaces under a sanitizer. Returns 0 always. */
int lk_norm_fuzz_one(const uint8_t *data, size_t n);

#endif /* LATKIT_NORM_SQL_H */
