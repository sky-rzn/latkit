/* SPDX-License-Identifier: GPL-2.0 */
/* HTTP route templater + fingerprint (РH7, PLAN-HTTP.md М4) — the norm_sql.h of
 * the HTTP track, and the one genuinely new problem of it.
 *
 * A SQL statement is a bounded identity by construction: `select * from t where
 * id = $1` is what an application ships, and the normaliser only has to collapse
 * the literals. A URL has no such property. `/orders/8123/items/9` is one of
 * millions of paths a single handler serves, and putting it in a Prometheus
 * label would multiply the series count by the number of orders in the database.
 * So the label is not the path, it is the *route*: the template the path came
 * from. Building it back out of the bytes is what this module does.
 *
 * Three layers, in priority order, and the guarantee comes from the third:
 *
 *   1. **an explicit map** (`--http-routes FILE`, lk_route_map below): lines of
 *      `GET /users/{id}/orders/{id}`, matched segment by segment, first match
 *      wins. For anyone who wants their `http.route` to be exactly what their
 *      framework calls it.
 *   2. **the heuristic** (the default): every path segment is classified, and
 *      one that looks like an identifier — a number, a UUID, a ULID, a long hex
 *      or base64-ish blob, a date, anything overlong or digit-heavy — becomes
 *      `{id}`; a file name whose stem looks generated becomes `{file}.ext`.
 *      Depth is capped (`--http-route-depth`, default 8) with the tail folded
 *      into `/...`, and the query string is dropped whole except for the keys
 *      `--http-query-keys` names.
 *   3. **the top-K registry** downstream (М5): a route that did not make the
 *      dictionary is reported as `route="other"`. This is what makes the
 *      cardinality bound structural rather than a hope about the heuristic —
 *      even against an API the classifiers read completely wrong, the series
 *      count is capped, and the *share* of `route="other"` is the visible
 *      quality signal on the dashboard.
 *
 * The heuristic will be wrong somewhere: a slug (`/posts/why-we-left-the-cloud`)
 * stays literal, and a numeric-looking product code that really is one route
 * collapses. Both failures are bounded by layer 3 and fixable by layer 1, which
 * is the whole reason the three layers exist in that order.
 *
 * What never happens, in any layer: a byte the module was not asked to keep does
 * not reach the output. Query values are dropped unless their key was named,
 * control bytes turn their segment into `{id}` rather than travelling into a
 * label, and the template is bounded by LK_ROUTE_TEXT_MAX while the fingerprint
 * keeps consuming the whole input — a clipped label never changes a route's
 * identity, exactly as in norm_sql.h.
 *
 * The fingerprint is XXH3-64 over `method NUL template`: the method is part of
 * the route's identity (РH7), so `GET /orders/{id}` and `DELETE /orders/{id}`
 * are two routes and not one, which is what makes a per-route latency panel
 * readable.
 *
 * Pure: no I/O, no libbpf, no globals. Depends only on libc and the vendored
 * xxhash — including the map, which is parsed from a buffer the caller read
 * (reading the file is CLI plumbing and lives in main.c). */
#ifndef LATKIT_NORM_ROUTE_H
#define LATKIT_NORM_ROUTE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Template text cap. Generous next to what a route is (a handful of segments)
 * and small next to what a URL may be (kilobytes): a template that does not fit
 * here is not a template, it is a path we failed to collapse. The fingerprint is
 * unaffected by the bound. */
#define LK_ROUTE_TEXT_MAX 256

/* Path depth kept before the tail folds into `/...`. Eight is deep enough for
 * every REST hierarchy in the М0 corpus and shallow enough that a crawler
 * walking a generated tree cannot inflate the template. */
#define LK_ROUTE_DEPTH_DEF 8
#define LK_ROUTE_DEPTH_MAX 32

/* Query keys promoted into the route (`--http-query-keys action,op`): for the
 * RPC-over-GET APIs where `?action=DescribeInstances` *is* the route and the
 * path is one constant. Deliberately few — every key here is a multiplier on
 * the series count, and the values are attacker-controlled. */
#define LK_ROUTE_QUERY_KEYS_MAX 8
#define LK_ROUTE_QUERY_KEY_MAX  32
/* A kept query value longer than this is an identifier whatever it looks like. */
#define LK_ROUTE_QUERY_VAL_MAX 32

/* Explicit-map limits (lk_route_map_parse). Both are ceilings on a config file
 * the operator writes, not on anything from the wire; a file past them loads its
 * prefix and reports the rest as rejected lines. */
#define LK_ROUTE_MAP_MAX 512 /* patterns */
#define LK_ROUTE_SEG_MAX 16  /* segments per pattern, and per matched path */

/* lk_route_out.flags */
#define LK_ROUTE_F_TEMPLATED  (1 << 0) /* at least one segment was collapsed */
#define LK_ROUTE_F_DEPTH_CLIP (1 << 1) /* deeper than cfg->depth: tail is `/...` */
#define LK_ROUTE_F_FROM_MAP   (1 << 2) /* an explicit --http-routes pattern matched */
#define LK_ROUTE_F_GIVEN      (1 << 3) /* the app declared it (--http-route-header) */
#define LK_ROUTE_F_QUERY      (1 << 4) /* a --http-query-keys pair is part of the route */
#define LK_ROUTE_F_TRUNC      (1 << 5) /* the template hit LK_ROUTE_TEXT_MAX */

/* An explicit route map, parsed from `--http-routes FILE`. Opaque: it owns one
 * copy of the text the patterns point into, so a caller keeps a single pointer
 * and frees it once. Immutable after parsing — the agent builds it at startup
 * and every later reader is a lookup, so no locking is involved. */
struct lk_route_map;

/* Config for one classification. All pointers are *borrowed* and must outlive
 * every lk_norm_route call that sees this cfg — in the agent they are argv and
 * the startup-built map. A NULL cfg means "defaults": heuristics only, depth
 * LK_ROUTE_DEPTH_DEF, no query keys. */
struct lk_route_cfg {
    const struct lk_route_map *map;                  /* NULL = heuristics only */
    const char *query_keys[LK_ROUTE_QUERY_KEYS_MAX]; /* NUL-terminated names */
    uint8_t nquery_keys;
    uint8_t depth; /* 0 = LK_ROUTE_DEPTH_DEF; clamped to LK_ROUTE_DEPTH_MAX */
};

struct lk_route_out {
    char text[LK_ROUTE_TEXT_MAX]; /* the template, NUL-terminated, may be clipped */
    uint32_t text_len;            /* strlen(text); < LK_ROUTE_TEXT_MAX */
    uint64_t fp;                  /* XXH3-64 of `method NUL template` (whole input) */
    uint16_t flags;               /* LK_ROUTE_F_* */
};

/* Template one request target. `target` is the raw request-target as it came off
 * the wire minus any absolute-form authority — path plus, optionally, `?query`
 * (what http_req.c keeps in lk_query_obs.text). Splitting it here rather than in
 * the caller is deliberate: "the query never reaches the template unless a key
 * was named" is then a property of one function, and the fuzzer checks it there.
 *
 * Always succeeds: garbage in is a template made of literal garbage segments,
 * bounded and NUL-terminated. `out` is fully written (no need to pre-zero it). */
void lk_norm_route(const char *method, uint32_t method_len, const char *target, uint32_t target_len,
                   const struct lk_route_cfg *cfg, struct lk_route_out *out);

/* A route the application declared itself (`--http-route-header X-Route`, РH7).
 * The text is trusted for its *content* — it is the app's own name for its
 * handler and no templating applies — but not for its shape: it is still
 * bounded, still stripped of control bytes, and still only a label, so the top-K
 * dictionary downstream is what protects cardinality. That is why the knob is
 * off by default: the header arrives from the network like everything else. */
void lk_norm_route_given(const char *method, uint32_t method_len, const char *route,
                         uint32_t route_len, struct lk_route_out *out);

/* Parse `--http-routes` text into a map. One pattern per line:
 *
 *     # comments and blank lines are ignored
 *     GET  /users/{id}/orders/{id}
 *     *    /health
 *
 * The method is a case-sensitive token or `*` for "any method"; the pattern is a
 * path whose `{...}` segments match any one segment and whose other segments
 * match byte for byte. No regular expressions and no wildcards spanning
 * segments: matching cost stays proportional to the path, which is the property
 * that lets this run on every observation.
 *
 * Returns NULL only on allocation failure or when not one line parsed. Lines
 * that do not parse are skipped and counted in *rejected (may be NULL), so the
 * caller can tell "empty file" from "file of typos". The returned map must be
 * freed with lk_route_map_free. */
struct lk_route_map *lk_route_map_parse(const char *text, size_t len, uint32_t *rejected);
void lk_route_map_free(struct lk_route_map *m);
uint32_t lk_route_map_count(const struct lk_route_map *m);

/* Fuzz entry (Р51, the lk_norm_fuzz_one twin): split the input into a method, a
 * target and an optional map, classify, and touch every output field so an
 * out-of-bounds read or a non-deterministic hash surfaces under a sanitizer.
 * Returns 0 always. */
int lk_norm_route_fuzz_one(const uint8_t *data, size_t n);

#endif /* LATKIT_NORM_ROUTE_H */
