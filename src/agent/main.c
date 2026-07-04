// SPDX-License-Identifier: GPL-2.0
/* latkit agent entry point: parse CLI, configure filters (ports map,
 * .rodata), load and attach the skeleton, then hand control to the epoll
 * loop (loop.c); event decoding, printing and stats live in events.c
 * (task 2.1). */
#include <errno.h>
#include <getopt.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

#include <bpf/libbpf.h>

#include "conn_table.h"
#include "events.h"
#include "latkit.h"
#include "latkit.skel.h"
#include "loop.h"

static bool opt_hexdump;
static bool opt_cap_headers;
static bool opt_events;
static bool opt_messages;
static __u16 opt_ports[LK_MAX_PORTS];
static int opt_nports;
static __u64 opt_ringbuf_bytes = LK_RINGBUF_SZ;
static __u32 opt_capture_limit = LK_CAPTURE_LIMIT;
static __u32 opt_max_conns = LK_MAX_CONNS_DEFAULT;
static __u32 opt_conn_idle_timeout = LK_CONN_IDLE_TIMEOUT_SEC;
static char opt_comm[16];

static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, args);
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [options]\n"
            "  -p, --port PORT       local (server) port to capture; repeatable,\n"
            "                        up to %d ports (default: %d)\n"
            "      --ringbuf-bytes N ringbuf size, power-of-two bytes (default: %d)\n"
            "      --capture-limit N capture budget per send/recv call, bytes\n"
            "                        (default: %d, max: %d; total_len stays honest)\n"
            "      --comm NAME       only capture send/recv from processes with\n"
            "                        this exact comm, e.g. postgres (default: off)\n"
            "      --cap-headers     test hook: switch every connection to HEADERS\n"
            "                        capture mode (%d bytes per call) at OPEN\n"
            "      --max-conns N     userspace conn table ceiling; the least\n"
            "                        recently active entry is evicted past it\n"
            "                        (default: %d)\n"
            "      --conn-idle-timeout SEC\n"
            "                        evict connections without events for SEC\n"
            "                        seconds (default: %d)\n"
            "      --events          print one line per raw ringbuf event\n"
            "      --messages        print one line per reassembled protocol\n"
            "                        message\n"
            "  -x, --hexdump         dump payload of events (--events) and the\n"
            "                        captured body prefix (--messages)\n",
            argv0, LK_MAX_PORTS, LK_DEFAULT_PORT, LK_RINGBUF_SZ, LK_CAPTURE_LIMIT,
            LK_MAX_CHUNKS * LK_CHUNK_FULL, LK_CAP_HEADERS_LIMIT, LK_MAX_CONNS_DEFAULT,
            LK_CONN_IDLE_TIMEOUT_SEC);
}

/* Strict decimal parse into [min, max]; -1 on any trailing garbage. */
static int parse_num(const char *s, __u64 min, __u64 max, __u64 *out)
{
    char *end;
    __u64 v;

    errno = 0;
    v = strtoull(s, &end, 10);
    if (errno || end == s || *end || v < min || v > max)
        return -1;
    *out = v;
    return 0;
}

static int parse_args(int argc, char **argv)
{
    enum {
        OPT_RINGBUF_BYTES = 256,
        OPT_CAPTURE_LIMIT,
        OPT_COMM,
        OPT_CAP_HEADERS,
        OPT_MAX_CONNS,
        OPT_CONN_IDLE_TIMEOUT,
        OPT_EVENTS,
        OPT_MESSAGES,
    };
    static const struct option opts[] = {
        {"port", required_argument, NULL, 'p'},
        {"ringbuf-bytes", required_argument, NULL, OPT_RINGBUF_BYTES},
        {"capture-limit", required_argument, NULL, OPT_CAPTURE_LIMIT},
        {"comm", required_argument, NULL, OPT_COMM},
        {"cap-headers", no_argument, NULL, OPT_CAP_HEADERS},
        {"max-conns", required_argument, NULL, OPT_MAX_CONNS},
        {"conn-idle-timeout", required_argument, NULL, OPT_CONN_IDLE_TIMEOUT},
        {"events", no_argument, NULL, OPT_EVENTS},
        {"messages", no_argument, NULL, OPT_MESSAGES},
        {"hexdump", no_argument, NULL, 'x'},
        {},
    };
    __u64 v;
    int c;

    while ((c = getopt_long(argc, argv, "p:x", opts, NULL)) != -1) {
        switch (c) {
        case 'p':
            if (opt_nports == LK_MAX_PORTS) {
                fprintf(stderr, "--port: at most %d ports\n", LK_MAX_PORTS);
                return -1;
            }
            if (parse_num(optarg, 1, 65535, &v)) {
                fprintf(stderr, "--port: bad port '%s'\n", optarg);
                return -1;
            }
            opt_ports[opt_nports++] = v;
            break;
        case OPT_RINGBUF_BYTES:
            /* Kernel-side constraint: power of two and page-aligned. */
            if (parse_num(optarg, 4096, 1ULL << 30, &v) || (v & (v - 1))) {
                fprintf(stderr, "--ringbuf-bytes: expected a power of two in [4096, 1G]\n");
                return -1;
            }
            opt_ringbuf_bytes = v;
            break;
        case OPT_CAPTURE_LIMIT:
            /* The BPF data path emits at most LK_MAX_CHUNKS chunks per call
             * (a verifier loop bound), so a larger limit could not be
             * honored anyway. */
            if (parse_num(optarg, 1, LK_MAX_CHUNKS * LK_CHUNK_FULL, &v)) {
                fprintf(stderr, "--capture-limit: expected 1..%d, got '%s'\n",
                        LK_MAX_CHUNKS * LK_CHUNK_FULL, optarg);
                return -1;
            }
            opt_capture_limit = v;
            break;
        case OPT_COMM:
            if (strlen(optarg) >= sizeof(opt_comm)) {
                fprintf(stderr, "--comm: name longer than %zu chars\n", sizeof(opt_comm) - 1);
                return -1;
            }
            strncpy(opt_comm, optarg, sizeof(opt_comm) - 1);
            break;
        case OPT_CAP_HEADERS:
            opt_cap_headers = true;
            break;
        case OPT_MAX_CONNS:
            if (parse_num(optarg, 1, 1 << 24, &v)) {
                fprintf(stderr, "--max-conns: expected 1..%d, got '%s'\n", 1 << 24, optarg);
                return -1;
            }
            opt_max_conns = v;
            break;
        case OPT_CONN_IDLE_TIMEOUT:
            /* Upper bound keeps sec -> ns conversions far from overflow. */
            if (parse_num(optarg, 1, 86400 * 365, &v)) {
                fprintf(stderr, "--conn-idle-timeout: expected seconds 1..%d, got '%s'\n",
                        86400 * 365, optarg);
                return -1;
            }
            opt_conn_idle_timeout = v;
            break;
        case OPT_EVENTS:
            opt_events = true;
            break;
        case OPT_MESSAGES:
            opt_messages = true;
            break;
        case 'x':
            opt_hexdump = true;
            break;
        default:
            usage(argv[0]);
            return -1;
        }
    }
    if (optind < argc) {
        fprintf(stderr, "unexpected argument '%s'\n", argv[optind]);
        usage(argv[0]);
        return -1;
    }

    if (opt_nports == 0)
        opt_ports[opt_nports++] = LK_DEFAULT_PORT;
    return 0;
}

/* The `ports` map exists only after load; attach happens after this, so the
 * filter is in place before the first event can fire. */
static int fill_ports(struct latkit_bpf *skel)
{
    for (int i = 0; i < opt_nports; i++) {
        __u8 one = 1;
        int err = bpf_map__update_elem(skel->maps.ports, &opt_ports[i], sizeof(opt_ports[i]), &one,
                                       sizeof(one), BPF_ANY);

        if (err) {
            fprintf(stderr, "failed to add port %u to filter: %d\n", opt_ports[i], err);
            return err;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    struct lk_events *events = NULL;
    struct lk_loop *loop = NULL;
    struct latkit_bpf *skel;
    int err;

    if (parse_args(argc, argv))
        return 1;

    libbpf_set_print(libbpf_print);

    /* Needed on pre-5.11 kernels; harmless on newer ones. */
    if (setrlimit(RLIMIT_MEMLOCK, &rlim))
        fprintf(stderr, "warn: setrlimit(MEMLOCK): %s\n", strerror(errno));

    skel = latkit_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }

    /* .rodata and map sizes are frozen at load time. */
    skel->rodata->cfg_capture_limit = opt_capture_limit;
    memcpy((char *)skel->rodata->cfg_comm_filter, opt_comm, sizeof(opt_comm));
    err = bpf_map__set_max_entries(skel->maps.events, opt_ringbuf_bytes);
    if (err) {
        fprintf(stderr, "failed to size ringbuf: %d\n", err);
        goto cleanup;
    }

    err = latkit_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = fill_ports(skel);
    if (err)
        goto cleanup;

    err = latkit_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    struct lk_events_cfg ecfg = {
        .ringbuf = skel->maps.events,
        .stats = skel->maps.stats,
        .conns = skel->maps.conns,
        .max_conns = opt_max_conns,
        .conn_idle_timeout_sec = opt_conn_idle_timeout,
        .hexdump = opt_hexdump,
        .cap_headers = opt_cap_headers,
        .events = opt_events,
        .messages = opt_messages,
    };

    events = lk_events_new(&ecfg);
    if (!events) {
        err = -1;
        goto cleanup;
    }

    loop = lk_loop_new();
    if (!loop) {
        err = -1;
        goto cleanup;
    }
    err = lk_events_register(events, loop);
    if (err)
        goto cleanup;

    fprintf(stderr, "latkit: attached, capturing local port(s)");
    for (int i = 0; i < opt_nports; i++)
        fprintf(stderr, " %u", opt_ports[i]);
    if (opt_comm[0])
        fprintf(stderr, ", comm=%s", opt_comm);
    fprintf(stderr, " (Ctrl-C to exit)\n");

    err = lk_loop_run(loop);
    if (!err)
        lk_events_print_stats(events); /* final totals on shutdown */

cleanup:
    lk_loop_free(loop);
    lk_events_free(events);
    latkit_bpf__destroy(skel);
    return err < 0 ? 1 : 0;
}
