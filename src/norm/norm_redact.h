/* SPDX-License-Identifier: GPL-2.0 */
/* Query-string redactor (РH12, PLAN-HTTP.md М6) — the third member of src/norm/,
 * and the smallest: given a raw request-target it replaces the values of query
 * keys that name a credential with `***`.
 *
 * Why it exists at all. The route templater (norm_route.h) already guarantees
 * that nothing from a URL reaches a *metric label* — it drops the query whole
 * unless a key was explicitly promoted. But a sampled span carries `url.path`
 * raw, with the query, because that is the specimen a person opens when a route
 * is slow; and `--queries` prints the same target for debugging. A URL is the
 * most talkative data the agent ever sees, and secrets in query strings are not
 * an edge case — presigned S3 links, password-reset links, OAuth callbacks and
 * `?api_key=` APIs are all built that way.
 *
 * Where it runs. At the one point where the target leaves the HTTP handler (the
 * observation, http.c), not in each sink. A redactor that every consumer must
 * remember to call is a redactor that one of them will forget, and the failure
 * is silent and permanent — the bytes are already in someone's trace backend.
 * So `--http-redact` (on by default) applies to *every* path: the span, the
 * debug logger, and anything added later.
 *
 * Matching is deliberately over-eager: a key is sensitive if it *contains* one of
 * the names below, case-insensitively. `access_token`, `csrftoken` and
 * `X-Amz-Security-Token` all fall out of `token`; `X-Amz-Signature` out of `sig`.
 * The cost of over-redaction is one unreadable query value in one span; the cost
 * of under-redaction is a live credential in a log aggregator, so the asymmetry
 * decides the rule. What is never touched is the path — a template of it is the
 * route, and collapsing path segments is norm_route.c's job, not this one's.
 * Nor is a query key an operator promoted into the route with
 * `--http-query-keys`: naming a key there is an explicit statement that its
 * value is a route and not a secret, and the templater's own bounds apply to it.
 *
 * Pure, like its two neighbours: no I/O, no allocation, no globals, bounded
 * reads over an explicit (pointer, length) pair. */
#ifndef LATKIT_NORM_REDACT_H
#define LATKIT_NORM_REDACT_H

#include <stdbool.h>
#include <stdint.h>

/* What a redacted value is replaced by. Three bytes, so a redacted target is
 * almost always *shorter* than the original — the growth case is a value of
 * fewer than three characters, and the caller's bound covers it. */
#define LK_REDACT_MARK     "***"
#define LK_REDACT_MARK_LEN 3

/* Would lk_url_redact change anything? A scan with no copy and no output buffer,
 * so the common answer — no query string at all — costs one pass over the
 * target and nothing else. Callers use it to keep pointing at the original
 * bytes instead of allocating somewhere to put a copy. */
bool lk_url_redact_needed(const char *in, uint32_t n);

/* Copy `in` into out[outcap] with the values of sensitive query keys replaced by
 * `***`. Returns the number of bytes written, never more than outcap; output is
 * not NUL-terminated (the caller carries a length, as everything on the
 * observation does). Truncation at outcap is safe by construction: the copy runs
 * left to right and a value is emitted only after its key was classified, so a
 * clipped result can never end in the middle of a secret it decided to keep. */
uint32_t lk_url_redact(const char *in, uint32_t n, char *out, uint32_t outcap);

/* The same rule applied where there is nowhere to put a second copy: overwrite
 * each sensitive query value *in place* with `*`, one for one, leaving the
 * length alone. Used by the `--messages` head dumper (РH3), which shows the wire
 * bytes and must keep every offset in the hexdump where it was — a view whose
 * addresses no longer match the capture is a debugging tool that lies. The value
 * length stays visible, which is the right trade for a hexdump: it is a fact
 * about the framing, not about the secret. */
void lk_url_redact_inplace(char *p, uint32_t n);

#endif /* LATKIT_NORM_REDACT_H */
