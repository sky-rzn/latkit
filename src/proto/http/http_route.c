// SPDX-License-Identifier: GPL-2.0
/* The base HTTP dialect and the handler's route step (РH7/РH8, PLAN-HTTP.md М4).
 *
 * Two small things live here, and they are separate on purpose.
 *
 * `lk_http_dialect_base` is the seam: the classification of a request into the
 * thing a metric may be labelled with. For plain HTTP that is the templated
 * route out of norm_route.c; for the S3 dialect (PLAN-MINIO.md РS2,
 * src/proto/s3/s3_dialect.c) it is an operation from a closed table, computed
 * from the same spans and nothing else. One registry entry per dialect, one
 * implementation underneath — and the base one below is the measure of what
 * that costs: one hook filled in, out of the six the struct offers.
 *
 * `http_route_resolve` is the policy *around* the dialect, and it is deliberately
 * not part of it: an app-declared route (`--http-route-header`) wins over any
 * classifier, and a unit with no target has no route at all. Those two rules are
 * the same whatever the dialect is, so a dialect that forgot them would be a bug
 * per dialect rather than one place to get right.
 *
 * Pure, like the rest of src/proto: no I/O, no allocation, no globals beyond the
 * configuration the CLI installed once at startup. */
#include "http.h"

static void base_classify(const struct lk_http_req *rq, const struct lk_http_cfg *cfg,
                          struct lk_route_out *out)
{
    lk_norm_route(rq->method, rq->method_len, rq->target, rq->target_len, &cfg->route, out);
}

const struct lk_http_dialect lk_http_dialect_base = {
    .name = "http",
    .classify = base_classify,
    /* Every other hook stays NULL, and that is the measure of the seam: plain
     * HTTP needs nothing off a head that http_req.c does not already read, and
     * no byte of any body at all. */
};

void http_route_resolve(const struct http_conn *hc, const struct http_unit *u,
                        struct lk_route_out *out)
{
    const struct lk_http_cfg *cfg = http_cfg();
    __u32 mlen = (__u32)strlen(u->method);
    struct lk_http_req rq = {
        .method = u->method,
        .method_len = mlen,
        .target = u->target,
        .target_len = u->target_len,
        .host = u->host,
        .host_len = (__u32)strlen(u->host),
        .dflags = u->dflags,
    };

    /* The application's own name for its handler, when the operator asked us to
     * believe it (--http-route-header). It beats the classifier because it is
     * the answer the classifier is *trying to reconstruct*: a framework knows
     * `/posts/{slug}` is one route, and no shape test on `why-we-left-the-cloud`
     * ever will. Still only a label, still bounded, still behind the top-K
     * dictionary — trusting the text is not trusting the cardinality. */
    if (u->route_hdr[0]) {
        lk_norm_route_given(u->method, mlen, u->route_hdr, (__u32)strlen(u->route_hdr), out);
        return;
    }
    /* No target at all: an authority-form CONNECT, or a head a capture hole cut
     * before the request line. There is no route to report and inventing one
     * ("/" is the obvious temptation) would put real traffic under a label that
     * means "we did not see the path". */
    if ((u->flags & LK_QO_NO_TEXT) || !u->target_len) {
        out->text[0] = '\0';
        out->text_len = 0;
        out->flags = 0;
        out->fp = 0;
        return;
    }
    hc->d->classify(&rq, cfg, out);
}
