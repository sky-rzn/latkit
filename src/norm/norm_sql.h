/* SPDX-License-Identifier: GPL-2.0 */
/* SQL normaliser + fingerprint (Р22, STAGE4.md task 4.1; MySQL dialect РМ9).
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
 * Those are the LK_SQL_PG rules. LK_SQL_MYSQL (РМ9) shares the machine and the
 * collapse filters; only the lexer diverges, and the PG branch stays
 * byte-for-byte what it was (fingerprints are pinned in test_norm_sql.c):
 *
 *   - comments: `# ...` to newline; `-- ...` (MySQL wants whitespace after the
 *     dashes, we accept both spellings); block comments do NOT nest; versioned
 *     comments "slash * ! 12345 ... * slash" are EXECUTED by the server, so
 *     their content is lexed into ordinary tokens (the version gate digits and
 *     the closing star-slash are dropped) — otherwise INSERT IGNORE spelled
 *     through a versioned comment would split fingerprints with the plain one;
 *   - strings: both '...' and "..." with backslash escapes AND doubling;
 *     ANSI_QUOTES is not detected — "..." is always a string, the accepted
 *     price; N'...' / B'...' / X'...' -> ?; hex/bin numbers 0xFF, 0b01 -> ?;
 *     charset introducers `_utf8mb4'...'` (quote glued to the identifier) are
 *     one string literal -> ?;
 *   - identifiers are quoted with backticks (`` doubling), kept verbatim, case
 *     significant; `$` is plain identifier material — $N parameters and
 *     dollar-quoting do not exist, the only placeholder is the bare `?`.
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

/* Which lexer rule set to apply. Deliberately not `enum lk_proto` from proto.h:
 * this header stays pure (libc + xxhash only); the proto handler picks the
 * dialect for its observations (MYSQL.md М6 threads it through conn->ops). */
enum lk_sql_dialect {
    LK_SQL_PG = 0,
    LK_SQL_MYSQL,
};

struct lk_norm_out {
    char text[LK_NORM_TEXT_MAX]; /* canonical text, NUL-terminated, may be clipped */
    uint32_t text_len;           /* strlen(text); < LK_NORM_TEXT_MAX */
    uint64_t fp;                 /* XXH3-64 of the full token stream */
    bool trunc;                  /* input ran out mid-token, or text was clipped */
};

/* Always succeeds: garbage in is just more tokens, and the bounds hold by
 * construction. `out` is fully written (no need to pre-zero it). */
void lk_norm_sql(const char *sql, size_t len, enum lk_sql_dialect dialect, struct lk_norm_out *out);

/* Fuzz entry (groundwork for stage 8, like lk_pg_fuzz_one): normalise the raw
 * bytes and touch every output field so an out-of-bounds read or a
 * non-deterministic hash surfaces under a sanitizer. Returns 0 always. */
int lk_norm_fuzz_one(const uint8_t *data, size_t n, enum lk_sql_dialect dialect);

#endif /* LATKIT_NORM_SQL_H */
