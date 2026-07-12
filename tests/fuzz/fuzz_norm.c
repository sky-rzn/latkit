// SPDX-License-Identifier: GPL-2.0
/* SQL normaliser libFuzzer target (task 8.3, Р51; harness laid down in 4.1).
 *
 * lk_norm_sql takes untrusted, possibly-truncated bytes (Р22): the same input
 * an attacker controls off the wire. lk_norm_fuzz_one (in src/norm/norm_sql.c)
 * normalises the bytes and reads back every output field, so an OOB write into
 * the text buffer or a missing NUL terminator surfaces under ASAN/UBSAN. On top
 * of it, fz_check_norm_stable asserts the Р51 contract: text_len under the cap,
 * terminated text, and a fingerprint that is a pure function of the input (two
 * runs agree bit-for-bit — a hash reading uninitialised memory fails this
 * before ASAN ever notices).
 *
 * Built only in the -DLATKIT_FUZZ=ON profile, like fuzz_pg. The committed
 * corpus (plain SQL bytes) lives in tests/fuzz/corpus/norm/. */
#include <stddef.h>
#include <stdint.h>

#include "fuzz_invariants.h"
#include "norm_sql.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    lk_norm_fuzz_one(data, size);
    fz_check_norm_stable((const char *)data, size);
    return 0;
}
