// SPDX-License-Identifier: GPL-2.0
/* latkit agent: configure filters (ports map, .rodata), load skeleton,
 * attach, poll ringbuf, decode events by hdr.type. One line per event;
 * payload hexdump behind --hexdump. Loss accounting (task 1.5): global
 * `stats` counters are summed and printed every 10 s, per-connection seq
 * holes are detected and logged as they arrive. Capture budget (task 1.6):
 * --capture-limit is frozen into .rodata; --cap-headers exercises the
 * per-connection capture_mode control surface. */
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <linux/types.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "latkit.h"
#include "latkit.skel.h"

static volatile sig_atomic_t exiting;
static bool opt_hexdump;
static bool opt_cap_headers;
static __u16 opt_ports[LK_MAX_PORTS];
static int opt_nports;
static __u64 opt_ringbuf_bytes = LK_RINGBUF_SZ;
static __u32 opt_capture_limit = LK_CAPTURE_LIMIT;
static char opt_comm[16];

static void sig_handler(int sig)
{
    (void)sig;
    exiting = 1;
}

/* --- seq-hole detector (task 1.5) ----------------------------------------
 * cookie -> last seen seq, a chained hash table. This is the stub of the
 * stage-2 "dirty connection" flag, not a full conn table: entries appear on
 * the first event of a connection and are freed on CONN_CLOSE. Connections
 * whose CLOSE was lost leave their entry behind — bounded cleanup is a
 * stage-2 concern, stated in STAGE1.md. */
struct seq_track {
    struct seq_track *next;
    __u64 cookie;
    __u32 last_seq;
};

#define SEQ_BUCKETS 4096 /* power of two; matches the conns map scale /16 */

static struct seq_track *seq_tab[SEQ_BUCKETS];

static struct seq_track **seq_bucket(__u64 cookie)
{
    /* Fibonacci hash: cookies are sequential, spread them. */
    return &seq_tab[(cookie * 0x9E3779B97F4A7C15ULL) >> 32 & (SEQ_BUCKETS - 1)];
}

/* Feed one event through the detector; logs when seq jumps forward.
 * A backward step is not loss: seq assignment (fetch_add in the kernel) and
 * ringbuf reserve are not one atomic step, so two CPUs can submit adjacent
 * seqs out of order. Such a pair first logs a spurious 1-event gap, then the
 * straggler arrives — rare enough to tolerate in stage 1. */
static void seq_check(__u64 cookie, __u32 seq, bool closing)
{
    struct seq_track **slot = seq_bucket(cookie), *t;

    for (t = *slot; t; t = t->next)
        if (t->cookie == cookie)
            break;

    if (!t) {
        if (closing)
            return;
        t = malloc(sizeof(*t));
        if (!t)
            return; /* degrade to no detection, not to exit */
        t->cookie = cookie;
        t->last_seq = seq;
        t->next = *slot;
        *slot = t;
        return;
    }

    if (seq > t->last_seq + 1)
        fprintf(stderr, "latkit: conn=%llx gap detected (lost %u events)\n",
                (unsigned long long)cookie, seq - (t->last_seq + 1));
    if (seq > t->last_seq)
        t->last_seq = seq;

    if (closing) {
        for (; *slot != t; slot = &(*slot)->next)
            ;
        *slot = t->next;
        free(t);
    }
}

/* --- global stats (task 1.5) ---------------------------------------------
 * Sum the per-CPU `stats` counters and print one line to stderr; called
 * every LK_STATS_INTERVAL_SEC from the poll loop and once on exit. */
#define LK_STATS_INTERVAL_SEC 10

static void print_stats(struct bpf_map *map)
{
    __u64 sum[LK_ST_MAX] = {0}, drops;
    int ncpus = libbpf_num_possible_cpus();
    __u64 *vals;

    if (ncpus < 1)
        return;
    vals = calloc(ncpus, sizeof(*vals));
    if (!vals)
        return;

    for (__u32 id = 0; id < LK_ST_MAX; id++) {
        if (bpf_map__lookup_elem(map, &id, sizeof(id), vals, ncpus * sizeof(*vals), 0))
            continue; /* leaves the counter at 0 rather than aborting */
        for (int cpu = 0; cpu < ncpus; cpu++)
            sum[id] += vals[cpu];
    }
    free(vals);

    drops = sum[LK_ST_RESERVE_FAIL_DATA] + sum[LK_ST_RESERVE_FAIL_OPEN] +
            sum[LK_ST_RESERVE_FAIL_CLOSE];
    fprintf(stderr,
            "latkit: stats events=%llu drops=%llu (data %llu, open %llu, close %llu) "
            "bytes=%llu/%llu captured/total iter_unsupported=%llu recv_miss=%llu\n",
            (unsigned long long)sum[LK_ST_EVENTS], (unsigned long long)drops,
            (unsigned long long)sum[LK_ST_RESERVE_FAIL_DATA],
            (unsigned long long)sum[LK_ST_RESERVE_FAIL_OPEN],
            (unsigned long long)sum[LK_ST_RESERVE_FAIL_CLOSE],
            (unsigned long long)sum[LK_ST_BYTES_CAPTURED],
            (unsigned long long)sum[LK_ST_BYTES_TOTAL],
            (unsigned long long)sum[LK_ST_ITER_UNSUPPORTED],
            (unsigned long long)sum[LK_ST_RECV_STATE_MISS]);
}

/* xxd-style: offset, 16 hex bytes, ASCII column. */
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

/* v4 addresses live in the first 4 bytes of the 16-byte array; tuple.family
 * carries the kernel AF_* value, which matches userspace. */
static const char *tuple_addr(const struct lk_tuple *t, const __u8 *addr, char *buf, size_t len)
{
    if (!inet_ntop(t->family, addr, buf, len))
        snprintf(buf, len, "?");
    return buf;
}

static void print_conn_event(const struct lk_ev_conn *ev)
{
    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];

    printf("%llu %s conn=%llx seq=%u pid=%u netns=%u %s:%u -> %s:%u",
           (unsigned long long)ev->hdr.ts_ns,
           ev->hdr.type == LK_EV_CONN_OPEN ? "OPEN " : "CLOSE",
           (unsigned long long)ev->hdr.conn_id, ev->hdr.seq, ev->pid, ev->tuple.netns,
           tuple_addr(&ev->tuple, ev->tuple.saddr, src, sizeof(src)), ev->tuple.sport,
           tuple_addr(&ev->tuple, ev->tuple.daddr, dst, sizeof(dst)), ev->tuple.dport);
    if (ev->hdr.flags & LK_F_SYNTHETIC)
        printf(" synthetic");
    if (ev->hdr.flags & LK_F_GAP)
        printf(" gap");
    if (ev->hdr.type == LK_EV_CONN_CLOSE)
        printf(" dropped=%u", ev->conn_dropped);
    printf("\n");
}

static void print_data_event(const struct lk_ev_data *ev, size_t size)
{
    __u32 cap = ev->cap_len;

    /* Trust the record boundary over the kernel-written length. */
    if (cap > size - sizeof(*ev))
        cap = size - sizeof(*ev);

    printf("%llu %s conn=%llx seq=%u total=%u cap=%u off=%u%s%s\n",
           (unsigned long long)ev->hdr.ts_ns, ev->hdr.dir == LK_DIR_SEND ? "SEND " : "RECV ",
           (unsigned long long)ev->hdr.conn_id, ev->hdr.seq, ev->total_len, cap, ev->off,
           ev->hdr.flags & LK_F_TRUNC ? " trunc" : "", ev->hdr.flags & LK_F_GAP ? " gap" : "");
    if (opt_hexdump && cap > 0)
        hexdump(ev->payload, cap);
}

/* --cap-headers test hook (task 1.6): flip the connection into HEADERS mode
 * by writing capture_mode into its live `conns` entry — the same control
 * surface the stage-3 parser will use, just with a trivial policy (every
 * connection, right at OPEN). The read-modify-write races with kernel-side
 * seq/dropped updates and can lose an increment (a spurious one-event "gap"
 * in the log); acceptable for a test hook, revisit with the real policy. */
static void set_cap_headers(struct bpf_map *conns, __u64 cookie)
{
    struct lk_conn_state st;

    if (bpf_map__lookup_elem(conns, &cookie, sizeof(cookie), &st, sizeof(st), 0))
        return; /* already closed or LRU-evicted */
    st.capture_mode = LK_CAP_HEADERS;
    if (bpf_map__update_elem(conns, &cookie, sizeof(cookie), &st, sizeof(st), BPF_EXIST))
        fprintf(stderr, "warn: conn=%llx: failed to set HEADERS mode\n",
                (unsigned long long)cookie);
}

static int handle_event(void *ctx, void *data, size_t size)
{
    struct latkit_bpf *skel = ctx;
    const struct lk_ev_hdr *hdr = data;

    if (size < sizeof(*hdr))
        return 0;

    seq_check(hdr->conn_id, hdr->seq, hdr->type == LK_EV_CONN_CLOSE);

    switch (hdr->type) {
    case LK_EV_CONN_OPEN:
        if (opt_cap_headers)
            set_cap_headers(skel->maps.conns, hdr->conn_id);
        /* fallthrough */
    case LK_EV_CONN_CLOSE:
        if (size >= sizeof(struct lk_ev_conn))
            print_conn_event(data);
        break;
    case LK_EV_DATA:
        if (size >= sizeof(struct lk_ev_data))
            print_data_event(data, size);
        break;
    default:
        fprintf(stderr, "warn: unknown event type %u (size %zu)\n", hdr->type, size);
        break;
    }
    return 0;
}

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
            "  -x, --hexdump         dump payload of data events\n",
            argv0, LK_MAX_PORTS, LK_DEFAULT_PORT, LK_RINGBUF_SZ, LK_CAPTURE_LIMIT,
            LK_MAX_CHUNKS * LK_CHUNK_FULL, LK_CAP_HEADERS_LIMIT);
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
    enum { OPT_RINGBUF_BYTES = 256, OPT_CAPTURE_LIMIT, OPT_COMM, OPT_CAP_HEADERS };
    static const struct option opts[] = {
        {"port", required_argument, NULL, 'p'},
        {"ringbuf-bytes", required_argument, NULL, OPT_RINGBUF_BYTES},
        {"capture-limit", required_argument, NULL, OPT_CAPTURE_LIMIT},
        {"comm", required_argument, NULL, OPT_COMM},
        {"cap-headers", no_argument, NULL, OPT_CAP_HEADERS},
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
    struct ring_buffer *rb = NULL;
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

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, skel, NULL);
    if (!rb) {
        err = -errno;
        fprintf(stderr, "failed to create ring buffer\n");
        goto cleanup;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    fprintf(stderr, "latkit: attached, capturing local port(s)");
    for (int i = 0; i < opt_nports; i++)
        fprintf(stderr, " %u", opt_ports[i]);
    if (opt_comm[0])
        fprintf(stderr, ", comm=%s", opt_comm);
    fprintf(stderr, " (Ctrl-C to exit)\n");

    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    time_t next_stats = now.tv_sec + LK_STATS_INTERVAL_SEC;

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* ms */);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ring_buffer__poll: %d\n", err);
            break;
        }
        err = 0;

        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec >= next_stats) {
            print_stats(skel->maps.stats);
            next_stats = now.tv_sec + LK_STATS_INTERVAL_SEC;
        }
    }
    if (!err)
        print_stats(skel->maps.stats); /* final totals on shutdown */

cleanup:
    ring_buffer__free(rb);
    latkit_bpf__destroy(skel);
    return err < 0 ? 1 : 0;
}
