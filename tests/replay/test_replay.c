// SPDX-License-Identifier: GPL-2.0
/* Replay integration test (task 2.5): the whole userspace pipeline
 * (decode -> conn table -> framer) over recorded traces, with no BPF and no
 * privileges — the same lk_pipeline the live agent runs (Р14). For each
 * fixture it checks two things:
 *
 *   1. reproducibility: the committed tests/fixtures/<name>.lkt is byte-for-
 *      byte what the in-tree builder produces (a live --record capture would
 *      replace the builder without changing this harness);
 *   2. framing: replaying the committed file yields exactly the expected
 *      messages (dir/type/len/flags), the expected resync/tls counters, no
 *      unexpected dirtying, and a connection table that returns to empty.
 */
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conn_table.h"
#include "fixtures_gen.h"
#include "pipeline.h"
#include "proto.h"
#include "record.h"

#ifndef LK_FIXTURES_DIR
#define LK_FIXTURES_DIR "."
#endif

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

/* --- message-collecting sink + PG-parser tee ------------------------------
 * The pipeline sink both records the framer's message stream (the stage-2
 * framing assertions) and tees every message / resync / close into the PG
 * handler (Р15), whose query sink records the sessions and observations the
 * stage-3 assertions check. This mirrors how events.c wires the two together
 * over live traffic. */

struct collector {
    struct lk_pipeline pipe;
    struct lk_proto *proto;               /* PG handler under test */
    const struct lk_msg_sink *psink;      /* = lk_proto_sink(proto) */
    struct fx_msg got[FX_MAX_MSGS * 2];
    size_t ngot;
    bool overflow;

    /* Query-sink side: what the PG parser emitted upward. */
    size_t nsessions;
    size_t nqueries;
    struct lk_session last_session;
    struct lk_query_obs last_obs; /* text pointer nulled; see last_text */
    char last_text[256];          /* last_obs.text copied out (it dangles) */
};

static void on_session(void *ctx, const struct lk_conn *c, const struct lk_session *s)
{
    struct collector *col = ctx;

    (void)c;
    col->nsessions++;
    col->last_session = *s;
}

static void on_query(void *ctx, const struct lk_conn *c, const struct lk_session *s,
                     const struct lk_query_obs *o)
{
    struct collector *col = ctx;

    (void)c;
    (void)s;
    col->nqueries++;
    col->last_obs = *o;
    /* o->text is only valid during this call; copy it out for the assertions. */
    col->last_text[0] = '\0';
    if (o->text && o->text_len < sizeof(col->last_text)) {
        memcpy(col->last_text, o->text, o->text_len);
        col->last_text[o->text_len] = '\0';
    }
    col->last_obs.text = NULL;
}

static void on_msg(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m)
{
    struct collector *col = ctx;

    if (col->ngot >= sizeof(col->got) / sizeof(col->got[0]))
        col->overflow = true;
    else
        col->got[col->ngot++] = (struct fx_msg){
            .dir = (__u8)dir,
            .type = m->type,
            .len = m->len,
            .flags = m->flags,
        };
    if (col->psink->on_msg)
        col->psink->on_msg(col->psink->ctx, c, dir, m);
}

static void on_resync(void *ctx, struct lk_conn *c, enum lk_dir dir)
{
    struct collector *col = ctx;

    if (col->psink->on_resync)
        col->psink->on_resync(col->psink->ctx, c, dir);
}

/* The pipeline routes the conn-table destroy hook here; forward it so the
 * parser frees proto_state on every removal path (Р15) — otherwise ASAN sees a
 * leak on teardown. */
static void on_conn_close(void *ctx, struct lk_conn *c)
{
    struct collector *col = ctx;

    if (col->psink->on_conn_close)
        col->psink->on_conn_close(col->psink->ctx, c);
}

static int feed_record(void *ctx, const void *data, __u32 size)
{
    struct lk_pipeline_ev ev;

    lk_pipeline_feed(&((struct collector *)ctx)->pipe, data, size, &ev);
    return 0;
}

/* --- helpers -------------------------------------------------------------- */

static __u8 *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    long sz;
    __u8 *buf;

    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) || (sz = ftell(f)) < 0 || fseek(f, 0, SEEK_SET)) {
        fclose(f);
        return NULL;
    }
    buf = malloc((size_t)sz + 1);
    if (buf && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        buf = NULL;
    }
    fclose(f);
    if (buf)
        *len = (size_t)sz;
    return buf;
}

static const char *msg_str(const struct fx_msg *m, char *out, size_t n)
{
    snprintf(out, n, "dir=%u type=%d len=%u flags=0x%x", m->dir, m->type, m->len, m->flags);
    return out;
}

static int run_fixture(const struct fixture *fix)
{
    struct fx x;
    char path[1024];
    __u8 *committed;
    size_t clen;
    struct collector col;
    const struct lk_reasm_stats *rs;
    const struct lk_conn_table_stats *cs;

    fix->build(&x);
    CHECK(x.buf && x.len > 0);

    /* 1. Reproducibility: committed file == freshly built bytes. */
    snprintf(path, sizeof(path), "%s/%s.lkt", LK_FIXTURES_DIR, fix->name);
    committed = read_file(path, &clen);
    if (!committed) {
        fprintf(stderr,
                "FAIL %s: cannot read committed fixture %s "
                "(run gen_fixtures to create it)\n",
                fix->name, path);
        free(x.buf);
        return 1;
    }
    if (clen != x.len || memcmp(committed, x.buf, x.len)) {
        fprintf(stderr,
                "FAIL %s: committed fixture differs from builder "
                "(committed %zu bytes, built %zu) — regenerate with gen_fixtures\n",
                fix->name, clen, x.len);
        free(committed);
        free(x.buf);
        return 1;
    }

    /* 2. Replay the committed trace through the shared pipeline, teeing every
     * message into the PG handler. */
    memset(&col, 0, sizeof(col));
    col.proto = lk_proto_pg_new(
        &(struct lk_query_sink){.ctx = &col, .on_session = on_session, .on_query = on_query});
    if (!col.proto) {
        free(committed);
        free(x.buf);
        return 1;
    }
    col.psink = lk_proto_sink(col.proto);
    if (lk_pipeline_init(&col.pipe, LK_MAX_CONNS_DEFAULT, 600ULL * 1000000000ULL,
                         &(struct lk_msg_sink){.ctx = &col,
                                               .on_msg = on_msg,
                                               .on_resync = on_resync,
                                               .on_conn_close = on_conn_close})) {
        lk_proto_free(col.proto);
        free(committed);
        free(x.buf);
        return 1;
    }
    if (lk_replay_mem(committed, clen, feed_record, &col)) {
        fprintf(stderr, "FAIL %s: malformed trace\n", fix->name);
        goto fail;
    }
    CHECK(!col.overflow);

    /* Message stream matches the expectation exactly. */
    if (col.ngot != x.nmsgs) {
        fprintf(stderr, "FAIL %s: expected %zu messages, got %zu\n", fix->name, x.nmsgs, col.ngot);
        goto fail;
    }
    for (size_t i = 0; i < x.nmsgs; i++) {
        if (memcmp(&col.got[i], &x.msgs[i], sizeof(struct fx_msg))) {
            char a[64], b[64];

            fprintf(stderr, "FAIL %s: message %zu: expected {%s}, got {%s}\n", fix->name, i,
                    msg_str(&x.msgs[i], a, sizeof(a)), msg_str(&col.got[i], b, sizeof(b)));
            goto fail;
        }
    }

    rs = &col.pipe.reasm.st;
    cs = lk_conn_table_stats(col.pipe.conns);
    if (x.clean && (rs->bad_len || rs->hdr_holes || rs->off_anomalies)) {
        fprintf(stderr, "FAIL %s: expected clean, got bad_len=%llu hdr_holes=%llu off=%llu\n",
                fix->name, (unsigned long long)rs->bad_len, (unsigned long long)rs->hdr_holes,
                (unsigned long long)rs->off_anomalies);
        goto fail;
    }
    if (rs->resyncs != x.resyncs) {
        fprintf(stderr, "FAIL %s: expected %llu resyncs, got %llu\n", fix->name,
                (unsigned long long)x.resyncs, (unsigned long long)rs->resyncs);
        goto fail;
    }
    if (rs->tls_conns != x.tls_conns) {
        fprintf(stderr, "FAIL %s: expected %llu tls_conns, got %llu\n", fix->name,
                (unsigned long long)x.tls_conns, (unsigned long long)rs->tls_conns);
        goto fail;
    }
    /* Every fixture closes its connection: the table must return to empty. */
    if (cs->active != 0) {
        fprintf(stderr, "FAIL %s: %u connection(s) left active\n", fix->name, cs->active);
        goto fail;
    }

    /* Stage-3 parser expectations (task 3.2): sessions and observations. */
    if (col.nsessions != x.sessions) {
        fprintf(stderr, "FAIL %s: expected %llu sessions, got %zu\n", fix->name,
                (unsigned long long)x.sessions, col.nsessions);
        goto fail;
    }
    if (x.sessions && (strcmp(col.last_session.user, x.sess_user) ||
                       strcmp(col.last_session.database, x.sess_db))) {
        fprintf(stderr, "FAIL %s: session labels expected user=%s db=%s, got user=%s db=%s\n",
                fix->name, x.sess_user, x.sess_db, col.last_session.user,
                col.last_session.database);
        goto fail;
    }
    if (col.nqueries != x.queries) {
        fprintf(stderr, "FAIL %s: expected %llu observations, got %zu\n", fix->name,
                (unsigned long long)x.queries, col.nqueries);
        goto fail;
    }
    if (lk_proto_stats(col.proto)->errors_sql != x.errors_sql) {
        fprintf(stderr, "FAIL %s: expected %llu errors_sql, got %llu\n", fix->name,
                (unsigned long long)x.errors_sql,
                (unsigned long long)lk_proto_stats(col.proto)->errors_sql);
        goto fail;
    }
    /* Last observation's fields (task 3.3): kind/rows/flags always, text and
     * SQLSTATE only when the fixture pins them. */
    if (x.queries) {
        if (col.last_obs.kind != x.obs_kind || col.last_obs.rows != x.obs_rows ||
            col.last_obs.flags != x.obs_flags || col.last_obs.bytes != x.obs_bytes) {
            fprintf(stderr,
                    "FAIL %s: obs expected kind=%u rows=%llu bytes=%llu flags=0x%x, "
                    "got kind=%u rows=%llu bytes=%llu flags=0x%x\n",
                    fix->name, x.obs_kind, (unsigned long long)x.obs_rows,
                    (unsigned long long)x.obs_bytes, x.obs_flags, col.last_obs.kind,
                    (unsigned long long)col.last_obs.rows, (unsigned long long)col.last_obs.bytes,
                    col.last_obs.flags);
            goto fail;
        }
        if (x.obs_text && strcmp(col.last_text, x.obs_text)) {
            fprintf(stderr, "FAIL %s: obs text expected \"%s\", got \"%s\"\n", fix->name,
                    x.obs_text, col.last_text);
            goto fail;
        }
        if (x.obs_sqlstate && strcmp(col.last_obs.sqlstate, x.obs_sqlstate)) {
            fprintf(stderr, "FAIL %s: obs sqlstate expected \"%s\", got \"%s\"\n", fix->name,
                    x.obs_sqlstate, col.last_obs.sqlstate);
            goto fail;
        }
    }

    /* Tear the table down first (its destroy hooks free proto_state through the
     * parser, which must still be alive), then release the handler. */
    lk_pipeline_fini(&col.pipe);
    lk_proto_free(col.proto);
    free(committed);
    free(x.buf);
    printf("ok %s (%zu msgs, %zu sessions)\n", fix->name, col.ngot, col.nsessions);
    return 0;

fail:
    lk_pipeline_fini(&col.pipe);
    lk_proto_free(col.proto);
    free(committed);
    free(x.buf);
    return 1;
}

/* --- recorder round-trip -------------------------------------------------- */
/* The fixtures lay down LKT bytes directly; this exercises the lk_recorder
 * writer the live agent uses (Р14), confirming a --record file reads back
 * byte-for-byte through lk_replay_file. */

struct rt_rec {
    __u32 size;
    __u8 bytes[64];
};
static const struct rt_rec rt_in[] = {
    {5, {1, 2, 3, 4, 5}},
    {1, {0xff}},
    {12, {'r', 'e', 'c', 'o', 'r', 'd', '-', 't', 'e', 's', 't', 0}},
};

struct rt_check {
    size_t idx;
    int failed;
};

static int rt_cb(void *ctx, const void *data, __u32 size)
{
    struct rt_check *rc = ctx;

    if (rc->idx >= sizeof(rt_in) / sizeof(rt_in[0]) || size != rt_in[rc->idx].size ||
        memcmp(data, rt_in[rc->idx].bytes, size)) {
        rc->failed = 1;
        return 1;
    }
    rc->idx++;
    return 0;
}

static int test_recorder_roundtrip(void)
{
    const char *path = "test_replay_roundtrip.tmp";
    struct lk_recorder *rec = lk_recorder_open(path);
    struct rt_check rc = {0};
    int rv;

    CHECK(rec);
    for (size_t i = 0; i < sizeof(rt_in) / sizeof(rt_in[0]); i++)
        lk_recorder_write(rec, rt_in[i].bytes, rt_in[i].size);
    CHECK(lk_recorder_close(rec) == 0);

    rv = lk_replay_file(path, rt_cb, &rc);
    remove(path);
    CHECK(rv == 0 && !rc.failed);
    CHECK(rc.idx == sizeof(rt_in) / sizeof(rt_in[0]));
    printf("ok recorder-roundtrip\n");
    return 0;
}

int main(void)
{
    for (size_t i = 0; i < lk_nfixtures; i++)
        if (run_fixture(&lk_fixtures[i]))
            return 1;
    if (test_recorder_roundtrip())
        return 1;
    printf("ok\n");
    return 0;
}
