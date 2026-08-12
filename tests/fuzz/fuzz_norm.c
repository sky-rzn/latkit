// SPDX-License-Identifier: GPL-2.0
/* Normaliser libFuzzer target (task 8.3, Р51; harness laid down in 4.1).
 *
 * Both normalisers take untrusted, possibly-truncated bytes — the same input an
 * attacker controls off the wire (Р22, РH7) — and both promise the same two
 * things: bounded output and a fingerprint that is a pure function of the input.
 * lk_norm_fuzz_one / lk_norm_route_fuzz_one (in src/norm/) run the module and
 * read back every output field, so an OOB write into the text buffer or a
 * missing NUL terminator surfaces under ASAN/UBSAN. On top of them,
 * fz_check_norm_stable and fz_check_route_stable assert the Р51 contracts:
 * text_len under the cap, terminated text, two runs agreeing bit-for-bit — and,
 * for the route, that no control byte and no byte of the query string reaches
 * the template.
 *
 * Three inputs share one target, selected by a first byte that cannot begin
 * meaningful input in either dialect (РМ9, М4):
 *
 *   0xFF  the rest is SQL in the MySQL dialect
 *   0xFE  the rest is an HTTP route input (`method \n target \n route-map`)
 *   else  the whole input is SQL in the PG dialect
 *
 * so the whole pre-existing corpus keeps exercising the PG branch unshifted and
 * the fuzzer flips inputs by mutating one byte.
 *
 * Built only in the -DLATKIT_FUZZ=ON profile, like fuzz_pg. The committed corpus
 * lives in tests/fuzz/corpus/norm/. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "fuzz_invariants.h"
#include "norm_redact.h"
#include "norm_route.h"
#include "norm_sql.h"

/* The route half of the input, in the layout lk_norm_route_fuzz_one documents:
 * a method line, a target line, and everything after the second newline as an
 * `--http-routes` map. Parsed twice — once inside fuzz_one for the OOB reads,
 * once here for the contract checks — because the invariants need the pieces. */
static void route_input(const uint8_t *data, size_t size)
{
    struct lk_route_cfg cfg = {0};
    const char *s = (const char *)data;
    const char *nl, *nl2;
    size_t mlen = 0, tlen = size;

    lk_norm_route_fuzz_one(data, size);

    nl = size ? memchr(s, '\n', size) : NULL;
    if (!nl) {
        fz_check_route_stable("GET", 3, s, size, NULL);
        fz_check_redact_stable(s, size);
        return;
    }
    mlen = (size_t)(nl - s);
    tlen = size - mlen - 1;
    nl2 = memchr(nl + 1, '\n', tlen);
    if (nl2) {
        size_t maplen = (size_t)(s + size - nl2 - 1);

        tlen = (size_t)(nl2 - nl - 1);
        cfg.map = lk_route_map_parse(nl2 + 1, maplen, NULL);
    }
    /* Both with and without the map: a map hit and a heuristic miss are
     * different code paths and both owe the same invariants. */
    fz_check_route_stable(s, mlen, nl + 1, tlen, &cfg);
    fz_check_route_stable(s, mlen, nl + 1, tlen, NULL);
    /* The same target through the redactor (РH12, М6): it sees exactly these
     * bytes in production, and its growth bound is what sizes a heap buffer. */
    fz_check_redact_stable(nl + 1, tlen);
    lk_route_map_free((struct lk_route_map *)cfg.map);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    enum lk_sql_dialect dialect = LK_SQL_PG;

    if (size > 0 && data[0] == 0xFE) {
        route_input(data + 1, size - 1);
        return 0;
    }
    if (size > 0 && data[0] == 0xFF) {
        dialect = LK_SQL_MYSQL;
        data++;
        size--;
    }
    lk_norm_fuzz_one(data, size, dialect);
    fz_check_norm_stable((const char *)data, size, dialect);
    return 0;
}
