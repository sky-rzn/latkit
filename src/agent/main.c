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
#include <strings.h>
#include <sys/resource.h>

#include <bpf/libbpf.h>

#include "cgroup_filter.h"
#include "conn_table.h"
#include "events.h"
#include "latkit.h"
#include "latkit.skel.h"
#include "loop.h"
#include "metrics.h"
#include "otel_env.h"
#include "spans.h"
#include "tls_attach.h"
#include "version.h"

#define LK_OTLP_MAX_KV 32 /* --otlp-header / --otlp-resource entries accepted */

static bool opt_hexdump;
static bool opt_cap_headers;
static bool opt_events;
static bool opt_messages;
static bool opt_queries;
static __u16 opt_ports[LK_MAX_PORTS];
static int opt_nports;
static __u64 opt_ringbuf_bytes = LK_RINGBUF_SZ;
static __u32 opt_capture_limit = LK_CAPTURE_LIMIT;
static __u32 opt_max_conns = LK_MAX_CONNS_DEFAULT;
static __u32 opt_conn_idle_timeout = LK_CONN_IDLE_TIMEOUT_SEC;
static const char *opt_record;
static char opt_comm[16];
static const char *opt_cgroup[LK_MAX_CGROUPS]; /* --cgroup glob patterns */
static int opt_ncgroup;
#define LK_CGROUP_RESCAN_SEC 30   /* re-resolve cgroup globs every N s (Р48; same ritm as TLS) */
static __u32 opt_top_queries;     /* 0 = metrics default (K = 500) */
static __u32 opt_query_label_len; /* 0 = metrics default (256) */
static bool opt_first_row_hist;
static bool opt_dump_metrics;
static const char *opt_dump_metrics_path;                    /* NULL = stderr */
static const char *opt_prom_listen = LK_PROM_LISTEN_DEFAULT; /* "none" disables */
static const char *opt_otlp_endpoint;                        /* NULL disables the OTLP exporter */
static __u64 opt_otlp_interval;                              /* 0 = exporter default (15 s) */
static const char *opt_otlp_headers[LK_OTLP_MAX_KV];
static int opt_otlp_nheaders;
static const char *opt_otlp_resource[LK_OTLP_MAX_KV];
static int opt_otlp_nresource;
static const char *opt_otlp_service_name;
static double opt_otlp_span_ratio;   /* --otlp-spans RATIO; 0 = off */
static __u64 opt_otlp_span_slow_ms;  /* --otlp-spans-slow-ms; 0 = off */
static __u64 opt_otlp_span_text_max; /* --otlp-span-text-max; 0 = default */
static bool opt_otlp_span_masked;
static enum lk_tls_mode opt_tls_mode = LK_TLS_OFF; /* --tls; default off */
static const char *opt_libssl;                     /* --libssl PATH: explicit uprobe target */
static char opt_tls_comm[16]; /* --tls-comm: comm to scan for (default postgres) */
#define LK_TLS_RESCAN_SEC 30  /* --tls auto: rescan /proc for new libssl paths every N s (Р39) */
/* Env-derived header/resource arrays (freed at exit for ASAN cleanliness). */
static char **env_headers, **env_resource;
static int env_nheaders, env_nresource;
static bool opt_print_config; /* --print-config: resolve config, print it, exit 0 */
static bool opt_version;      /* --version: print the version string, exit 0 */
/* Which options were given on the CLI, indexed by getopt id (< 512: ASCII ids
 * plus the OPT_* enum below). The env layer (Р34) fills only the unseen ones,
 * so a flag always wins over its LATKIT_* environment equivalent. */
static bool opt_seen[512];

static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, args);
}

static void usage(FILE *out, const char *argv0)
{
    fprintf(out,
            "latkit %s\n"
            "usage: %s [options]\n"
            "  -p, --port PORT       local (server) port to capture; repeatable,\n"
            "                        up to %d ports (default: %d)\n"
            "      --ringbuf-bytes N ringbuf size, power-of-two bytes (default: %d)\n"
            "      --capture-limit N capture budget per send/recv call, bytes\n"
            "                        (default: %d, max: %d; total_len stays honest)\n"
            "      --comm NAME       only capture send/recv from processes with\n"
            "                        this exact comm, e.g. postgres (default: off)\n"
            "      --cgroup PATTERN  only capture traffic from cgroups whose path\n"
            "                        under /sys/fs/cgroup matches this glob;\n"
            "                        repeatable. * stays within a path segment, **\n"
            "                        spans segments. Requires cgroup v2. (default: off)\n"
            "      --cap-headers     test hook: switch every connection to HEADERS\n"
            "                        capture mode (%d bytes per call) at OPEN\n"
            "      --max-conns N     userspace conn table ceiling; the least\n"
            "                        recently active entry is evicted past it\n"
            "                        (default: %d)\n"
            "      --conn-idle-timeout SEC\n"
            "                        evict connections without events for SEC\n"
            "                        seconds (default: %d)\n"
            "      --record FILE     append every raw ringbuf record to FILE for\n"
            "                        offline replay (LKT1 trace, see record.h)\n"
            "      --events          print one line per raw ringbuf event\n"
            "      --messages        print one line per reassembled protocol\n"
            "                        message\n"
            "      --queries         print one line per session and query\n"
            "                        observation (debug tee before the aggregator)\n"
            "      --top-queries N   distinct normalised queries tracked before the\n"
            "                        rest fold into query=\"other\" (default: %d)\n"
            "      --query-label-len N\n"
            "                        max chars of the normalised text kept as the\n"
            "                        `query` label (default: %d)\n"
            "      --first-row-hist  also record latkit_query_first_row_seconds\n"
            "                        (doubles the query-labelled series; off)\n"
            "      --dump-metrics[=FILE]\n"
            "                        write the Prometheus exposition on SIGUSR1 and\n"
            "                        at exit, to FILE (default: stderr)\n"
            "      --prom-listen ADDR:PORT|none\n"
            "                        serve Prometheus /metrics and /healthz on this\n"
            "                        address (default: %s; 'none' disables). Bind\n"
            "                        0.0.0.0 to scrape from outside the host.\n"
            "      --otlp-endpoint URL\n"
            "                        push OTLP/HTTP metrics to this Collector base URL\n"
            "                        (http:// only); enables the exporter. Defaults to\n"
            "                        $OTEL_EXPORTER_OTLP_ENDPOINT.\n"
            "      --otlp-interval SEC\n"
            "                        OTLP export period (default: 15)\n"
            "      --otlp-header K=V repeatable OTLP request header (auth); defaults to\n"
            "                        $OTEL_EXPORTER_OTLP_HEADERS\n"
            "      --otlp-resource K=V\n"
            "                        repeatable OTLP resource attribute; defaults to\n"
            "                        $OTEL_RESOURCE_ATTRIBUTES\n"
            "      --otlp-spans RATIO\n"
            "                        sample this fraction [0,1] of queries as OTLP\n"
            "                        spans (raw SQL!); needs --otlp-endpoint. Off by\n"
            "                        default. SECURITY: spans carry literal SQL.\n"
            "      --otlp-spans-slow-ms N\n"
            "                        also sample every query at least N ms long\n"
            "      --otlp-span-text-max N\n"
            "                        cap db.query.text at N bytes (default: %d)\n"
            "      --otlp-span-masked\n"
            "                        send the normalised (literal-free) SQL as\n"
            "                        db.query.text instead of the raw text\n"
            "      --tls auto|off    capture TLS plaintext via libssl uprobes\n"
            "                        (default: off). 'auto' scans /proc for the\n"
            "                        libssl of the matching processes and rescans\n"
            "                        periodically for new ones\n"
            "      --libssl PATH     attach the SSL_* uprobes to this libssl,\n"
            "                        skipping the scan (e.g. a container's copy)\n"
            "      --tls-comm NAME   with --tls auto, scan only processes with\n"
            "                        this comm (default: postgres)\n"
            "      --print-config    resolve config (flag > LATKIT_* env > default)\n"
            "                        to stdout and exit; every flag has a LATKIT_*\n"
            "                        env equivalent (see README)\n"
            "      --version         print the agent version and exit\n"
            "  -x, --hexdump         dump payload of events (--events) and the\n"
            "                        captured body prefix (--messages)\n"
            "  -h, --help            print this help and exit\n",
            LK_VERSION, argv0, LK_MAX_PORTS, LK_DEFAULT_PORT, LK_RINGBUF_SZ, LK_CAPTURE_LIMIT,
            LK_MAX_CHUNKS * LK_CHUNK_FULL, LK_CAP_HEADERS_LIMIT, LK_MAX_CONNS_DEFAULT,
            LK_CONN_IDLE_TIMEOUT_SEC, LK_TOP_QUERIES_DEFAULT, LK_QUERY_LABEL_LEN_DEFAULT,
            LK_PROM_LISTEN_DEFAULT, LK_SPAN_TEXT_MAX_DEF);
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

/* getopt long-option ids beyond the ASCII range. File scope so both the option
 * dispatcher (set_option) and the LATKIT_* env table below can name them. */
enum {
    OPT_RINGBUF_BYTES = 256,
    OPT_CAPTURE_LIMIT,
    OPT_COMM,
    OPT_CGROUP,
    OPT_CAP_HEADERS,
    OPT_MAX_CONNS,
    OPT_CONN_IDLE_TIMEOUT,
    OPT_RECORD,
    OPT_EVENTS,
    OPT_MESSAGES,
    OPT_QUERIES,
    OPT_TOP_QUERIES,
    OPT_QUERY_LABEL_LEN,
    OPT_FIRST_ROW_HIST,
    OPT_DUMP_METRICS,
    OPT_PROM_LISTEN,
    OPT_OTLP_ENDPOINT,
    OPT_OTLP_INTERVAL,
    OPT_OTLP_HEADER,
    OPT_OTLP_RESOURCE,
    OPT_OTLP_SPANS,
    OPT_OTLP_SPANS_SLOW_MS,
    OPT_OTLP_SPAN_TEXT_MAX,
    OPT_OTLP_SPAN_MASKED,
    OPT_TLS,
    OPT_LIBSSL,
    OPT_TLS_COMM,
    OPT_PRINT_CONFIG,
    OPT_VERSION,
};

/* Apply one parsed option, from the CLI or (via apply_env_defaults) from the
 * environment. optarg is NULL for no-argument options. Returns 0, or -1 on a
 * bad value with the specific message already printed. */
static int set_option(int c, char *optarg)
{
    __u64 v;

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
    case OPT_CGROUP: {
        char *dup;

        if (opt_ncgroup == LK_MAX_CGROUPS) {
            fprintf(stderr, "--cgroup: at most %d patterns\n", LK_MAX_CGROUPS);
            return -1;
        }
        if (!optarg[0]) {
            fprintf(stderr, "--cgroup: empty pattern\n");
            return -1;
        }
        /* Own the string: an env pattern (LATKIT_CGROUP=a,b) is a token into a
         * temporary buffer the env layer frees; a CLI optarg is stable but
         * strdup'd too so cleanup is uniform. Freed at exit for ASAN. */
        dup = strdup(optarg);
        if (!dup)
            return -1;
        opt_cgroup[opt_ncgroup++] = dup;
        break;
    }
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
            fprintf(stderr, "--conn-idle-timeout: expected seconds 1..%d, got '%s'\n", 86400 * 365,
                    optarg);
            return -1;
        }
        opt_conn_idle_timeout = v;
        break;
    case OPT_RECORD:
        opt_record = optarg;
        break;
    case OPT_EVENTS:
        opt_events = true;
        break;
    case OPT_MESSAGES:
        opt_messages = true;
        break;
    case OPT_QUERIES:
        opt_queries = true;
        break;
    case OPT_TOP_QUERIES:
        if (parse_num(optarg, 1, 1 << 20, &v)) {
            fprintf(stderr, "--top-queries: expected 1..%d, got '%s'\n", 1 << 20, optarg);
            return -1;
        }
        opt_top_queries = v;
        break;
    case OPT_QUERY_LABEL_LEN:
        if (parse_num(optarg, 1, LK_QUERY_LABEL_MAX - 1, &v)) {
            fprintf(stderr, "--query-label-len: expected 1..%d, got '%s'\n", LK_QUERY_LABEL_MAX - 1,
                    optarg);
            return -1;
        }
        opt_query_label_len = v;
        break;
    case OPT_FIRST_ROW_HIST:
        opt_first_row_hist = true;
        break;
    case OPT_DUMP_METRICS:
        opt_dump_metrics = true;
        opt_dump_metrics_path = optarg; /* NULL unless --dump-metrics=FILE */
        break;
    case OPT_PROM_LISTEN:
        opt_prom_listen = optarg; /* "none" disables the /metrics server */
        break;
    case OPT_OTLP_ENDPOINT:
        opt_otlp_endpoint = optarg;
        break;
    case OPT_OTLP_INTERVAL:
        if (parse_num(optarg, 1, 86400, &v)) {
            fprintf(stderr, "--otlp-interval: expected seconds 1..86400, got '%s'\n", optarg);
            return -1;
        }
        opt_otlp_interval = v;
        break;
    case OPT_OTLP_HEADER:
        if (opt_otlp_nheaders >= LK_OTLP_MAX_KV) {
            fprintf(stderr, "--otlp-header: at most %d headers\n", LK_OTLP_MAX_KV);
            return -1;
        }
        opt_otlp_headers[opt_otlp_nheaders++] = optarg;
        break;
    case OPT_OTLP_RESOURCE:
        if (opt_otlp_nresource >= LK_OTLP_MAX_KV) {
            fprintf(stderr, "--otlp-resource: at most %d attributes\n", LK_OTLP_MAX_KV);
            return -1;
        }
        opt_otlp_resource[opt_otlp_nresource++] = optarg;
        break;
    case OPT_OTLP_SPANS: {
        char *end;

        errno = 0;
        opt_otlp_span_ratio = strtod(optarg, &end);
        if (errno || end == optarg || *end || opt_otlp_span_ratio < 0.0 ||
            opt_otlp_span_ratio > 1.0) {
            fprintf(stderr, "--otlp-spans: expected a ratio in [0, 1], got '%s'\n", optarg);
            return -1;
        }
        break;
    }
    case OPT_OTLP_SPANS_SLOW_MS:
        if (parse_num(optarg, 1, 3600000, &v)) {
            fprintf(stderr, "--otlp-spans-slow-ms: expected 1..3600000, got '%s'\n", optarg);
            return -1;
        }
        opt_otlp_span_slow_ms = v;
        break;
    case OPT_OTLP_SPAN_TEXT_MAX:
        if (parse_num(optarg, 1, 1 << 20, &v)) {
            fprintf(stderr, "--otlp-span-text-max: expected 1..%d, got '%s'\n", 1 << 20, optarg);
            return -1;
        }
        opt_otlp_span_text_max = v;
        break;
    case OPT_OTLP_SPAN_MASKED:
        opt_otlp_span_masked = true;
        break;
    case OPT_TLS:
        if (!strcmp(optarg, "off"))
            opt_tls_mode = LK_TLS_OFF;
        else if (!strcmp(optarg, "auto"))
            opt_tls_mode = LK_TLS_AUTO;
        else {
            fprintf(stderr, "--tls: expected 'auto' or 'off', got '%s'\n", optarg);
            return -1;
        }
        break;
    case OPT_LIBSSL:
        opt_libssl = optarg;
        break;
    case OPT_TLS_COMM:
        if (strlen(optarg) >= sizeof(opt_tls_comm)) {
            fprintf(stderr, "--tls-comm: name longer than %zu chars\n", sizeof(opt_tls_comm) - 1);
            return -1;
        }
        strncpy(opt_tls_comm, optarg, sizeof(opt_tls_comm) - 1);
        break;
    case 'x':
        opt_hexdump = true;
        break;
    case OPT_PRINT_CONFIG:
        opt_print_config = true;
        break;
    case OPT_VERSION:
        opt_version = true;
        break;
    default:
        return -1;
    }
    return 0;
}

/* True unless the env value spells a "false" (empty/0/false/no/off) — used to
 * gate the no-argument flags, whose CLI form takes no value. */
static bool env_truthy(const char *v)
{
    return v && v[0] && strcmp(v, "0") && strcasecmp(v, "false") && strcasecmp(v, "no") &&
           strcasecmp(v, "off");
}

/* A bare truthy word (1/true/yes/on) vs. a value carrying data (e.g. a path). */
static bool env_bool_word(const char *v)
{
    return !strcmp(v, "1") || !strcasecmp(v, "true") || !strcasecmp(v, "yes") ||
           !strcasecmp(v, "on");
}

/* One LATKIT_* env variable ↔ its flag (Р34). Repeatable flags read a
 * comma-separated list from the single env variable. The OTEL-standard vars
 * (endpoint/interval/headers/resource/service) are handled by
 * apply_otlp_env_defaults, which also honours their OTEL_* spellings. */
struct env_opt {
    const char *name;
    int val;
    bool has_arg;
    bool repeat;
};

static const struct env_opt env_opts[] = {
    {"LATKIT_PORT", 'p', true, true},
    {"LATKIT_RINGBUF_BYTES", OPT_RINGBUF_BYTES, true, false},
    {"LATKIT_CAPTURE_LIMIT", OPT_CAPTURE_LIMIT, true, false},
    {"LATKIT_COMM", OPT_COMM, true, false},
    {"LATKIT_CGROUP", OPT_CGROUP, true, true},
    {"LATKIT_CAP_HEADERS", OPT_CAP_HEADERS, false, false},
    {"LATKIT_MAX_CONNS", OPT_MAX_CONNS, true, false},
    {"LATKIT_CONN_IDLE_TIMEOUT", OPT_CONN_IDLE_TIMEOUT, true, false},
    {"LATKIT_RECORD", OPT_RECORD, true, false},
    {"LATKIT_EVENTS", OPT_EVENTS, false, false},
    {"LATKIT_MESSAGES", OPT_MESSAGES, false, false},
    {"LATKIT_QUERIES", OPT_QUERIES, false, false},
    {"LATKIT_TOP_QUERIES", OPT_TOP_QUERIES, true, false},
    {"LATKIT_QUERY_LABEL_LEN", OPT_QUERY_LABEL_LEN, true, false},
    {"LATKIT_FIRST_ROW_HIST", OPT_FIRST_ROW_HIST, false, false},
    {"LATKIT_PROM_LISTEN", OPT_PROM_LISTEN, true, false},
    {"LATKIT_HEXDUMP", 'x', false, false},
    {"LATKIT_OTLP_SPANS", OPT_OTLP_SPANS, true, false},
    {"LATKIT_OTLP_SPANS_SLOW_MS", OPT_OTLP_SPANS_SLOW_MS, true, false},
    {"LATKIT_OTLP_SPAN_TEXT_MAX", OPT_OTLP_SPAN_TEXT_MAX, true, false},
    {"LATKIT_OTLP_SPAN_MASKED", OPT_OTLP_SPAN_MASKED, false, false},
    {"LATKIT_TLS", OPT_TLS, true, false},
    {"LATKIT_LIBSSL", OPT_LIBSSL, true, false},
    {"LATKIT_TLS_COMM", OPT_TLS_COMM, true, false},
};

/* Apply LATKIT_* env variables to flags not given on the CLI (Р34): flag > env
 * > default. Runs after getopt, before the port default is filled, so
 * LATKIT_PORT can seed the port set. Returns -1 on a bad env value. */
static int apply_env_defaults(void)
{
    /* --dump-metrics is optional-arg: a bare truthy word means stderr, any
     * other value is a target path. */
    if (!opt_seen[OPT_DUMP_METRICS]) {
        const char *v = getenv("LATKIT_DUMP_METRICS");

        if (env_truthy(v)) {
            opt_dump_metrics = true;
            opt_dump_metrics_path = env_bool_word(v) ? NULL : v;
        }
    }
    for (size_t i = 0; i < sizeof(env_opts) / sizeof(env_opts[0]); i++) {
        const struct env_opt *e = &env_opts[i];
        char *v;

        if (opt_seen[e->val])
            continue;
        v = getenv(e->name);
        if (!v || !v[0])
            continue;
        if (!e->has_arg) {
            if (env_truthy(v) && set_option(e->val, NULL))
                return -1;
        } else if (e->repeat) {
            char *copy = strdup(v), *save = NULL, *tok;

            if (!copy)
                return -1;
            for (tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
                if (set_option(e->val, tok)) {
                    free(copy);
                    return -1;
                }
            }
            free(copy);
        } else if (set_option(e->val, v)) {
            return -1;
        }
    }
    return 0;
}

static int parse_args(int argc, char **argv)
{
    static const struct option opts[] = {
        {"port", required_argument, NULL, 'p'},
        {"ringbuf-bytes", required_argument, NULL, OPT_RINGBUF_BYTES},
        {"capture-limit", required_argument, NULL, OPT_CAPTURE_LIMIT},
        {"comm", required_argument, NULL, OPT_COMM},
        {"cgroup", required_argument, NULL, OPT_CGROUP},
        {"cap-headers", no_argument, NULL, OPT_CAP_HEADERS},
        {"max-conns", required_argument, NULL, OPT_MAX_CONNS},
        {"conn-idle-timeout", required_argument, NULL, OPT_CONN_IDLE_TIMEOUT},
        {"record", required_argument, NULL, OPT_RECORD},
        {"events", no_argument, NULL, OPT_EVENTS},
        {"messages", no_argument, NULL, OPT_MESSAGES},
        {"queries", no_argument, NULL, OPT_QUERIES},
        {"top-queries", required_argument, NULL, OPT_TOP_QUERIES},
        {"query-label-len", required_argument, NULL, OPT_QUERY_LABEL_LEN},
        {"first-row-hist", no_argument, NULL, OPT_FIRST_ROW_HIST},
        {"dump-metrics", optional_argument, NULL, OPT_DUMP_METRICS},
        {"prom-listen", required_argument, NULL, OPT_PROM_LISTEN},
        {"otlp-endpoint", required_argument, NULL, OPT_OTLP_ENDPOINT},
        {"otlp-interval", required_argument, NULL, OPT_OTLP_INTERVAL},
        {"otlp-header", required_argument, NULL, OPT_OTLP_HEADER},
        {"otlp-resource", required_argument, NULL, OPT_OTLP_RESOURCE},
        {"otlp-spans", required_argument, NULL, OPT_OTLP_SPANS},
        {"otlp-spans-slow-ms", required_argument, NULL, OPT_OTLP_SPANS_SLOW_MS},
        {"otlp-span-text-max", required_argument, NULL, OPT_OTLP_SPAN_TEXT_MAX},
        {"otlp-span-masked", no_argument, NULL, OPT_OTLP_SPAN_MASKED},
        {"tls", required_argument, NULL, OPT_TLS},
        {"libssl", required_argument, NULL, OPT_LIBSSL},
        {"tls-comm", required_argument, NULL, OPT_TLS_COMM},
        {"print-config", no_argument, NULL, OPT_PRINT_CONFIG},
        {"version", no_argument, NULL, OPT_VERSION},
        {"hexdump", no_argument, NULL, 'x'},
        {"help", no_argument, NULL, 'h'},
        {},
    };
    int c;

    while ((c = getopt_long(argc, argv, "p:xh", opts, NULL)) != -1) {
        if (c == 'h') {
            usage(stdout, argv[0]);
            exit(0);
        }
        if (c == '?') { /* unknown option or missing argument: getopt printed it */
            usage(stderr, argv[0]);
            return -1;
        }
        if (set_option(c, optarg))
            return -1;
        opt_seen[c] = true;
    }
    if (optind < argc) {
        fprintf(stderr, "unexpected argument '%s'\n", argv[optind]);
        usage(stderr, argv[0]);
        return -1;
    }

    if (apply_env_defaults())
        return -1;
    if (opt_nports == 0)
        opt_ports[opt_nports++] = LK_DEFAULT_PORT;
    return 0;
}

/* First non-empty of $a (agent-native LATKIT_*) then $b (standard OTel var). */
static const char *env_or(const char *a, const char *b)
{
    const char *v = getenv(a);

    if (v && v[0])
        return v;
    v = b ? getenv(b) : NULL;
    return (v && v[0]) ? v : NULL;
}

/* Fill the OTLP config from the environment where a flag was not given (Р34):
 * flag > LATKIT_* > OTEL_* > default. Standard OTel variables are honoured so an
 * agent deployed beside other OTel tooling inherits the ambient config. */
static void apply_otlp_env_defaults(void)
{
    if (!opt_otlp_endpoint)
        opt_otlp_endpoint = env_or("LATKIT_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_ENDPOINT");
    if (!opt_otlp_interval) {
        const char *s = env_or("LATKIT_OTLP_INTERVAL", NULL);
        __u64 v;

        if (s && !parse_num(s, 1, 86400, &v))
            opt_otlp_interval = v;
    }
    if (!opt_otlp_service_name)
        opt_otlp_service_name = env_or("LATKIT_OTLP_SERVICE_NAME", "OTEL_SERVICE_NAME");
    /* Repeated flags replace, rather than merge with, their env equivalent. */
    if (opt_otlp_nheaders == 0)
        env_headers = lk_split_pairs(env_or("LATKIT_OTLP_HEADERS", "OTEL_EXPORTER_OTLP_HEADERS"),
                                     &env_nheaders);
    if (opt_otlp_nresource == 0)
        env_resource = lk_split_pairs(env_or("LATKIT_OTLP_RESOURCE", "OTEL_RESOURCE_ATTRIBUTES"),
                                      &env_nresource);
}

/* Print the effective configuration after CLI + env resolution and exit (Р34):
 * a no-BPF way to confirm flag > LATKIT_* > OTEL_* > default without a running
 * agent. The `0 = default` sentinels are resolved to their concrete values so
 * the output reads as what the agent will actually use. Drives the priority
 * test (tests/unit/config_priority.sh). */
static void print_config(void)
{
    for (int i = 0; i < opt_nports; i++)
        printf("port=%u\n", opt_ports[i]);
    printf("ringbuf_bytes=%llu\n", (unsigned long long)opt_ringbuf_bytes);
    printf("capture_limit=%u\n", opt_capture_limit);
    printf("comm=%s\n", opt_comm);
    for (int i = 0; i < opt_ncgroup; i++)
        printf("cgroup=%s\n", opt_cgroup[i]);
    printf("cap_headers=%d\n", opt_cap_headers);
    printf("max_conns=%u\n", opt_max_conns);
    printf("conn_idle_timeout=%u\n", opt_conn_idle_timeout);
    printf("record=%s\n", opt_record ? opt_record : "");
    printf("events=%d\n", opt_events);
    printf("messages=%d\n", opt_messages);
    printf("queries=%d\n", opt_queries);
    printf("top_queries=%u\n", opt_top_queries ? opt_top_queries : LK_TOP_QUERIES_DEFAULT);
    printf("query_label_len=%u\n",
           opt_query_label_len ? opt_query_label_len : LK_QUERY_LABEL_LEN_DEFAULT);
    printf("first_row_hist=%d\n", opt_first_row_hist);
    printf("dump_metrics=%d\n", opt_dump_metrics);
    printf("dump_metrics_path=%s\n", opt_dump_metrics_path ? opt_dump_metrics_path : "");
    printf("prom_listen=%s\n", opt_prom_listen ? opt_prom_listen : "");
    printf("otlp_endpoint=%s\n", opt_otlp_endpoint ? opt_otlp_endpoint : "");
    printf("otlp_interval=%llu\n",
           (unsigned long long)(opt_otlp_interval ? opt_otlp_interval : 15));
    printf("otlp_service_name=%s\n", opt_otlp_service_name ? opt_otlp_service_name : "");
    printf("otlp_nheaders=%d\n", opt_otlp_nheaders ? opt_otlp_nheaders : env_nheaders);
    printf("otlp_nresource=%d\n", opt_otlp_nresource ? opt_otlp_nresource : env_nresource);
    printf("otlp_span_ratio=%g\n", opt_otlp_span_ratio);
    printf("otlp_span_slow_ms=%llu\n", (unsigned long long)opt_otlp_span_slow_ms);
    printf("otlp_span_text_max=%llu\n",
           (unsigned long long)(opt_otlp_span_text_max ? opt_otlp_span_text_max
                                                       : LK_SPAN_TEXT_MAX_DEF));
    printf("otlp_span_masked=%d\n", opt_otlp_span_masked);
    printf("tls=%s\n", opt_tls_mode == LK_TLS_AUTO ? "auto" : "off");
    printf("libssl=%s\n", opt_libssl ? opt_libssl : "");
    printf("tls_comm=%s\n", opt_tls_comm);
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
    struct lk_tls *tls = NULL;
    struct lk_cgroup *cgroup = NULL;
    int err;

    if (parse_args(argc, argv))
        return 1;
    if (opt_version) {
        printf("latkit %s\n", LK_VERSION);
        return 0;
    }
    apply_otlp_env_defaults();
    if (opt_print_config) {
        print_config();
        return 0;
    }

    libbpf_set_print(libbpf_print);

    /* Needed on pre-5.11 kernels; harmless on newer ones. */
    if (setrlimit(RLIMIT_MEMLOCK, &rlim))
        fprintf(stderr, "warn: setrlimit(MEMLOCK): %s\n", strerror(errno));

    skel = latkit_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }

    /* The effective comm to gate the TLS uprobes on (Р39): --tls-comm, else the
     * general --comm, else the postgres default. Attaching on pid=-1 hooks every
     * process mapping a shared libssl — including a psql client that maps the same
     * file — so the in-program comm filter is what keeps foreign SSL traffic out.
     * When --comm was not set, adopt this comm for the whole BPF filter; the
     * socket path is port-filtered to the server side anyway, so narrowing it to
     * the postgres comm changes nothing there. */
    bool tls_enabled = opt_tls_mode == LK_TLS_AUTO || opt_libssl;
    const char *tls_comm = opt_tls_comm[0] ? opt_tls_comm : (opt_comm[0] ? opt_comm : "postgres");

    /* .rodata and map sizes are frozen at load time. */
    skel->rodata->cfg_capture_limit = opt_capture_limit;
    if (opt_comm[0])
        memcpy((char *)skel->rodata->cfg_comm_filter, opt_comm, sizeof(opt_comm));
    else if (tls_enabled)
        /* .rodata starts zeroed, so a bounded memcpy stays NUL-terminated
         * (strncpy of exactly size-1 trips gcc -Wstringop-truncation at -O2). */
        memcpy((char *)skel->rodata->cfg_comm_filter, tls_comm,
               strnlen(tls_comm, sizeof(skel->rodata->cfg_comm_filter) - 1));
    err = bpf_map__set_max_entries(skel->maps.events, opt_ringbuf_bytes);
    if (err) {
        fprintf(stderr, "failed to size ringbuf: %d\n", err);
        goto cleanup;
    }

    /* Decide autoload of the SSL_* uprobe programs before load (Р39): with no
     * libssl to attach, they are dropped from the load entirely. */
    struct lk_tls_cfg tlscfg = {
        .mode = opt_tls_mode,
        .libssl_override = opt_libssl,
        .comm_filter = tls_comm,
        .rescan_sec = tls_enabled && !opt_libssl ? LK_TLS_RESCAN_SEC : 0,
    };

    tls = lk_tls_new(skel, &tlscfg);
    if (!tls) {
        err = -1;
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

    /* cgroup filter (Р48): resolve the globs and fill the maps before attach,
     * like fill_ports, so the filter is live before the first event. A v1 host
     * with --cgroup fails here. */
    struct lk_cgroup_cfg cgcfg = {
        .patterns = opt_cgroup,
        .npatterns = opt_ncgroup,
        .rescan_sec = LK_CGROUP_RESCAN_SEC,
    };

    cgroup = lk_cgroup_new(skel->maps.cgroups, skel->maps.cgroup_on, &cgcfg);
    if (!cgroup) {
        err = -1;
        goto cleanup;
    }
    err = lk_cgroup_apply(cgroup);
    if (err)
        goto cleanup;

    err = latkit_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    /* Attach the TLS uprobes after the core programs; a missing libssl is a
     * soft none, not a startup failure (Р39). */
    err = lk_tls_attach(tls);
    if (err)
        goto cleanup;

    struct lk_events_cfg ecfg = {
        .ringbuf = skel->maps.events,
        .stats = skel->maps.stats,
        .capmode = skel->maps.capmode,
        .tls = tls,       /* attach-state gauge source (latkit_tls_attached) */
        .cgroup = cgroup, /* latkit_cgroup_filter_paths gauge source */
        .max_conns = opt_max_conns,
        .conn_idle_timeout_sec = opt_conn_idle_timeout,
        .record_path = opt_record,
        .hexdump = opt_hexdump,
        .cap_headers = opt_cap_headers,
        .events = opt_events,
        .messages = opt_messages,
        .queries = opt_queries,
        .top_queries = opt_top_queries,
        .query_label_len = opt_query_label_len,
        .first_row_hist = opt_first_row_hist,
        .dump_metrics = opt_dump_metrics,
        .dump_metrics_path = opt_dump_metrics_path,
        .prom_listen = opt_prom_listen,
        .otlp_endpoint = opt_otlp_endpoint,
        .otlp_interval = (unsigned)opt_otlp_interval,
        .otlp_headers = opt_otlp_nheaders ? opt_otlp_headers : (const char *const *)env_headers,
        .otlp_nheaders = opt_otlp_nheaders ? opt_otlp_nheaders : env_nheaders,
        .otlp_resource = opt_otlp_nresource ? opt_otlp_resource : (const char *const *)env_resource,
        .otlp_nresource = opt_otlp_nresource ? opt_otlp_nresource : env_nresource,
        .otlp_service_name = opt_otlp_service_name,
        .otlp_span_ratio = opt_otlp_span_ratio,
        .otlp_span_slow_ms = (unsigned)opt_otlp_span_slow_ms,
        .otlp_span_text_max = (unsigned)opt_otlp_span_text_max,
        .otlp_span_masked = opt_otlp_span_masked,
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

    /* AUTO only: periodically rescan /proc so a postgres cluster that starts (or
     * pulls in a new libssl) after us gets attached without an agent restart. */
    err = lk_tls_register(tls, loop);
    if (err)
        goto cleanup;

    /* Re-resolve the cgroup globs periodically so a recreated pod (new cgroup
     * id under the same glob) is re-picked up without a restart (Р48). */
    err = lk_cgroup_register(cgroup, loop);
    if (err)
        goto cleanup;

    fprintf(stderr, "latkit %s: attached, capturing local port(s)", LK_VERSION);
    for (int i = 0; i < opt_nports; i++)
        fprintf(stderr, " %u", opt_ports[i]);
    if (opt_comm[0])
        fprintf(stderr, ", comm=%s", opt_comm);
    if (opt_ncgroup)
        fprintf(stderr, ", cgroup=%d pattern(s)/%d path(s)", opt_ncgroup, lk_cgroup_paths(cgroup));
    fprintf(stderr, " (Ctrl-C to exit)\n");

    err = lk_loop_run(loop);
    if (!err) {
        lk_events_print_stats(events);  /* final totals on shutdown */
        lk_events_dump_metrics(events); /* final exposition (no-op without --dump-metrics) */
    }

cleanup:
    /* Free events before the loop: the HTTP server (task 5.1) deregisters its
     * listen and client fds from the loop as it tears down. */
    lk_events_free(events);
    lk_loop_free(loop);
    lk_tls_free(tls); /* detach uprobe links before the skeleton owning them */
    lk_cgroup_free(cgroup);
    latkit_bpf__destroy(skel);
    for (int i = 0; i < opt_ncgroup; i++)
        free((char *)opt_cgroup[i]);
    lk_free_pairs(env_headers, env_nheaders);
    lk_free_pairs(env_resource, env_nresource);
    return err < 0 ? 1 : 0;
}
