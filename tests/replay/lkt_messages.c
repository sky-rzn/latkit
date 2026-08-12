// SPDX-License-Identifier: GPL-2.0
/* Dev tool: the agent's --messages view over recorded LKT1 traces (МYSQL.md
 * М2 acceptance — "packet boundaries are correct on every М0 scenario").
 * Replays each file through the same lk_pipeline the live agent runs —
 * decode -> conn table -> framer, protocol picked per connection — and prints
 * one line per reassembled message in the events.c --messages format, plus a
 * per-file framer/table summary. Decrypted (LK_F_DECRYPTED) events route
 * through the pipeline exactly as live, so TLS traces frame their plaintext
 * channel too.
 *
 *   lkt_messages [--proto pg|mysql|http] [--quiet] [--hexdump] FILE.lkt...
 *
 * --proto sets the protocol every connection frames as (default pg — the
 * registry head, matching the agent's bare --port). --quiet drops the
 * per-message lines, leaving the summaries. --hexdump adds the captured body
 * prefix, through the same display mask the agent applies (РH3/РH12, М6): a
 * credential header is blanked and a credential-shaped query value overwritten
 * before either reaches a terminal. Exit is nonzero only when a file fails to
 * replay; framer counters are diagnostics, not verdicts — dirty stretches are
 * legitimate on budget-cut traces. */
#include <linux/types.h>
#include <stdio.h>
#include <string.h>

#include "pipeline.h"
#include "proto.h"
#include "record.h"

static bool quiet;
static bool opt_hexdump;

/* The events.c --hexdump layout, byte for byte, so a trace replay and a live
 * capture read the same. */
static void hexdump(const __u8 *buf, __u32 len)
{
    for (__u32 off = 0; off < len; off += 16) {
        printf("  %08x: ", off);
        for (__u32 i = 0; i < 16; i++) {
            if (off + i < len)
                printf("%02x", buf[off + i]);
            else
                printf("  ");
            if (i % 2 == 1)
                printf(" ");
        }
        printf(" ");
        for (__u32 i = 0; i < 16 && off + i < len; i++) {
            __u8 c = buf[off + i];

            putchar(c >= 0x20 && c < 0x7f ? c : '.');
        }
        printf("\n");
    }
}

static void on_msg(void *ctx, struct lk_conn *c, enum lk_dir dir, const struct lk_msg *m)
{
    char type[8];

    (void)ctx;
    if (quiet)
        return;
    if (m->flags & LK_MSG_STARTUP)
        snprintf(type, sizeof(type), "startup");
    else if (m->type >= 0x20 && m->type < 0x7f)
        snprintf(type, sizeof(type), "%c", m->type);
    else
        snprintf(type, sizeof(type), "0x%02x", (unsigned char)m->type);
    printf("%llu %s conn=%llx %s len=%u cap=%u%s%s\n", (unsigned long long)m->ts_ns,
           dir == LK_DIR_RECV ? "fe>" : "<be", (unsigned long long)c->cookie, type, m->len,
           m->body_cap, m->flags & LK_MSG_BODY_TRUNC ? " trunc" : "",
           m->flags & LK_MSG_AFTER_RESYNC ? " resync" : "");
    if (opt_hexdump && m->body_cap) {
        __u8 shown[LK_MSG_BODY_MAX];
        __u32 n = lk_msg_body_for_display(lk_conn_proto(c), m, shown, sizeof(shown));

        hexdump(shown, n);
    }
}

static void on_resync(void *ctx, struct lk_conn *c, enum lk_dir dir)
{
    (void)ctx;
    if (!quiet)
        printf("-- conn=%llx resync (%s)\n", (unsigned long long)c->cookie,
               dir == LK_DIR_RECV ? "fe>" : "<be");
}

static int on_record(void *ctx, const void *data, __u32 size)
{
    struct lk_pipeline_ev ev;

    lk_pipeline_feed(ctx, data, size, &ev);
    return 0;
}

int main(int argc, char **argv)
{
    static const struct lk_msg_sink sink = {.on_msg = on_msg, .on_resync = on_resync};
    const struct lk_proto_ops *ops = lk_proto_registry[0];
    int rc = 0, first = 1;

    while (first < argc && argv[first][0] == '-') {
        if (!strcmp(argv[first], "--quiet")) {
            quiet = true;
            first++;
        } else if (!strcmp(argv[first], "--hexdump")) {
            opt_hexdump = true;
            first++;
        } else if (!strcmp(argv[first], "--proto") && first + 1 < argc) {
            ops = lk_proto_find(argv[first + 1], strlen(argv[first + 1]));
            if (!ops) {
                fprintf(stderr, "unknown protocol '%s'\n", argv[first + 1]);
                return 2;
            }
            first += 2;
        } else {
            break;
        }
    }
    if (first >= argc) {
        fprintf(stderr, "usage: %s [--proto pg|mysql|http] [--quiet] [--hexdump] FILE.lkt...\n",
                argv[0]);
        return 2;
    }

    for (int i = first; i < argc; i++) {
        struct lk_pipeline pipe;

        if (lk_pipeline_init(&pipe, 1024, ~0ull, &sink)) {
            fprintf(stderr, "%s: pipeline init failed\n", argv[i]);
            return 2;
        }
        lk_conn_table_set_protos(pipe.conns, NULL, 0, ops);
        if (lk_replay_file(argv[i], on_record, &pipe)) {
            printf("%s: REPLAY FAILED (bad magic or truncated record)\n", argv[i]);
            rc = 1;
        } else {
            const struct lk_reasm_stats *rs = &pipe.reasm.st;
            const struct lk_conn_table_stats *cs = lk_conn_table_stats(pipe.conns);

            printf("%s: proto=%s msgs=%llu trunc=%llu holes=%llu resyncs=%llu"
                   " bad_len=%llu hdr_holes=%llu off_anom=%llu tls=%llu"
                   " conns=%llu/%llu tls_drop=%llu\n",
                   argv[i], ops->name, (unsigned long long)rs->msgs,
                   (unsigned long long)rs->msgs_trunc, (unsigned long long)rs->holes,
                   (unsigned long long)rs->resyncs, (unsigned long long)rs->bad_len,
                   (unsigned long long)rs->hdr_holes, (unsigned long long)rs->off_anomalies,
                   (unsigned long long)rs->tls_conns, (unsigned long long)cs->created,
                   (unsigned long long)cs->closed, (unsigned long long)cs->tls_socket_dropped);
        }
        lk_pipeline_fini(&pipe);
    }
    return rc;
}
