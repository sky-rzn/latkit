// SPDX-License-Identifier: GPL-2.0
/* Metrics facade (Р26, task 4.2). See metrics.h for the stage-4 task split;
 * this file is the lifecycle and the dump entry point. It owns the registry
 * (registry.c) — the lk_query_sink (task 4.3) and the self-metric providers
 * (task 4.4) attach here without touching the histogram or the registry. */
#include "metrics.h"

#include <stdlib.h>

#include "registry.h"

struct lk_metrics {
    struct lk_metrics_cfg cfg;
    struct lk_registry *reg;
};

void lk_metrics_cfg_defaults(struct lk_metrics_cfg *cfg)
{
    cfg->top_queries = LK_TOP_QUERIES_DEFAULT;
    cfg->query_label_len = LK_QUERY_LABEL_LEN_DEFAULT;
    cfg->max_session_dims = LK_MAX_SESSION_DIMS_DEFAULT;
    cfg->first_row_hist = false;
}

struct lk_metrics *lk_metrics_new(const struct lk_metrics_cfg *cfg)
{
    struct lk_metrics *m = calloc(1, sizeof(*m));

    if (!m)
        return NULL;
    if (cfg)
        m->cfg = *cfg;
    else
        lk_metrics_cfg_defaults(&m->cfg);
    m->reg = lk_reg_new(&m->cfg);
    if (!m->reg) {
        free(m);
        return NULL;
    }
    return m;
}

void lk_metrics_free(struct lk_metrics *m)
{
    if (!m)
        return;
    lk_reg_free(m->reg);
    free(m);
}

int lk_metrics_dump(struct lk_metrics *m, FILE *f)
{
    return lk_reg_dump(m->reg, f);
}
