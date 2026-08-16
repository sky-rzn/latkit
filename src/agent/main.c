// SPDX-License-Identifier: GPL-2.0
/* latkit agent entry point: parse CLI, configure filters (ports map,
 * .rodata), load and attach the skeleton, then hand control to the epoll
 * loop (loop.c); event decoding, printing and stats live in events.c */

#include <errno.h>
#include <getopt.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "cgroup_filter.h"
#include "conn_table.h"
#include "events.h"
#include "latkit.h"
#include "latkit.skel.h"
#include "loop.h"
#include "metrics.h"
#include "otel_env.h"
#include "proto.h"
#include "spans.h"
#include "tls_attach.h"
#include "tls_go.h"
#include "version.h"

#define LK_OTLP_MAX_KV            32 /* --otlp-header / --otlp-resource entries accepted */
#define LK_CGROUP_RESCAN_SEC      30 /* re-resolve cgroup globs every N s */
#define LK_TLS_RESCAN_SEC         30 /* --tls auto: rescan /proc for new libssl paths every N s*/
#define LK_MAX_CONN_IDLE_TIMEOUT  (86400 * 365) /* 1 year in seconds */
#define LK_MAX_OTLP_INTERVAL      86400         /* 1 day in seconds */
#define LK_MAX_CONNS              (1 << 24)
#define LK_MAX_TOP_QUERIES        (1 << 20)
#define LK_MAX_OTLP_SPANS_SLOW_MS 3600000 /* 1 hour in ms */
#define LK_MAX_OTLP_SPAN_TEXT_MAX (1 << 20)

static bool opt_hexdump;
static bool opt_cap_headers;
static bool opt_events;
static bool opt_messages;
static bool opt_queries;
static __u16 opt_ports[LK_MAX_PORTS];
/* Protocol per port (РМ2): parallel to opt_ports, from
 * `--port N[=pg|mysql|http|s3|redis]`; a bare number is the default protocol
 * (pg, the registry head). */
static const struct lk_proto_ops *opt_port_ops[LK_MAX_PORTS];
/* Per-port capture budget (РH14): the `:BYTES` suffix of `--port 8080=http:2048`,
 * 0 = "no explicit value", which resolves to the protocol's own default (http:
 * 2048, LK_HTTP_CAPTURE_LIMIT; redis: 512, LK_REDIS_CAPTURE_LIMIT — РR13)
 * capped by --capture-limit, or to --capture-limit
 * itself for a protocol that asks for nothing special. port_cap_limit() below is
 * the single place that precedence lives; the kernel only applies the result. */
static __u32 opt_port_caps[LK_MAX_PORTS];
/* `--http-user basic` (РH10): take the `user` label from the name half of an
 * `Authorization: Basic` header. Off by default — an identity is not something
 * to lift off the wire unless it was asked for (РH12) — and, like the port
 * budget above, absent from --help until М9 documents the HTTP surface. */
static bool opt_http_user_basic;
/* Route templating knobs (РH7, М4), all of them equally absent from --help for
 * now and all borrowed by the handler for the process lifetime: the query-key
 * pointers are argv, the map is parsed once here and freed at exit. */
static const char *opt_http_routes;             /* --http-routes FILE */
static struct lk_route_map *opt_http_route_map; /* ... parsed */
static __u32 opt_http_route_depth;              /* 0 = LK_ROUTE_DEPTH_DEF */
static const char *opt_http_query_keys[LK_ROUTE_QUERY_KEYS_MAX];
static int opt_http_nquery_keys;
static char opt_http_route_header[32]; /* --http-route-header, folded lowercase */
/* `--http-redact off` (РH12, М6): the one HTTP knob whose default is *on*. With
 * it on, the values of credential-shaped query keys are replaced by `***` where
 * the target leaves the handler, so no export path can carry one; off restores
 * the byte-exact target everywhere, which is a debugging choice and has to be
 * made deliberately. Stored as the opt-out so a zeroed config redacts. */
static bool opt_http_no_redact;
/* The two S3 knobs (РS3/РS4, PLAN-MINIO.md МS1), read only by the `s3` dialect
 * and inert for every other port. `--s3-domain` is repeatable and borrowed from
 * argv (or from a strdup'd copy when it arrives through the env layer);
 * `--s3-user off` turns the access-key dimension off entirely, which is the
 * escape hatch for a deployment whose STS credentials are so short-lived that
 * even the max_session_dims spill cannot keep up. */
static const char *opt_s3_domains[LK_S3_DOMAIN_MAX];
static int opt_s3_ndomains;
static bool opt_s3_no_user;
/* The one Redis knob (РR6, PLAN-REDIS.md МR3), read only by the `redis` handler
 * and inert for every other port. On by default, unlike --http-user and like
 * --s3-user: the ACL user is its own array element of an `AUTH`, so reading it
 * decodes nothing and touches no password — and a per-user latency panel is what
 * a shared Redis is watched for. `off` is for a deployment that rotates ACL
 * users faster than max_session_dims can spill them into `other`. */
static bool opt_redis_no_user;
static struct lk_port_proto opt_port_protos[LK_MAX_PORTS];
static int opt_nports;
static __u64 opt_ringbuf_bytes = LK_RINGBUF_SZ;
static __u32 opt_capture_limit = LK_CAPTURE_LIMIT;
static __u32 opt_max_conns = LK_MAX_CONNS_DEFAULT;
static __u32 opt_conn_idle_timeout = LK_CONN_IDLE_TIMEOUT_SEC;
static const char *opt_record;
static char opt_comm[16];
static const char *opt_cgroup[LK_MAX_CGROUPS]; /* --cgroup glob patterns */
static int opt_ncgroup;
static __u32 opt_top_queries;      /* 0 = metrics default (K = 500) */
static __u32 opt_max_session_dims; /* 0 = metrics default (32); raised for an s3 port, РS4 */
static __u32 opt_query_label_len;  /* 0 = metrics default (256) */
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
static char opt_tls_comm[16];                      /* --tls-comm: the one comm to scan for (default:
                                                    * the lk_tls_default_comms DB-server set) */
/* `--tls-go PATH` (РH13.3): Go servers link their TLS in, so there is no libssl
 * to scan for — the binary itself is the attach target and has to be named. */
static const char *opt_tls_go[LK_TLS_GO_MAX_PATHS];
static int opt_ntls_go;
/* Env-derived header/resource arrays (freed at exit for ASAN cleanliness). */
static char **env_headers, **env_resource;
static int env_nheaders, env_nresource;
static bool opt_print_config; /* --print-config: resolve config, print it, exit 0 */
static bool opt_version;      /* --version: print the version string, exit 0 */
/* Which options were given on the CLI, indexed by getopt id (< 512: ASCII ids
 * plus the OPT_* enum below). The env layer fills only the unseen ones,
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
            "  -p, --port PORT[=PROTO[:BYTES]]\n"
            "                        local (server) port to capture, optionally with\n"
            "                        its wire protocol (pg | mysql | http | s3 |\n"
            "                        redis; default: pg) and a per-port capture\n"
            "                        budget in bytes (default: 8192 for a database\n"
            "                        port, 2048 for http/s3, where only heads are\n"
            "                        read, 512 for redis, where a command is a verb\n"
            "                        and a key);\n"
            "                        repeatable, up to %d ports (default: %d)\n"
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
            "                        this comm (default: postgres, mysqld,\n"
            "                        mariadbd; plus nginx, httpd, apache2,\n"
            "                        haproxy for an http port, minio for an\n"
            "                        s3 one; --print-config prints the set)\n"
            "      --tls-go PATH     capture TLS plaintext of a Go server by\n"
            "                        probing crypto/tls in this binary (x86-64;\n"
            "                        stripped is fine, and is the only TLS\n"
            "                        channel an s3 port has); repeatable, up to %d\n"
            "      --http-routes FILE\n"
            "                        route map, one `METHOD /users/{id}/orders`\n"
            "                        per line; a matching pattern wins over the\n"
            "                        templater below (default: off)\n"
            "      --http-route-depth N\n"
            "                        keep at most N path segments in a route\n"
            "                        label; deeper paths end in /... (default: %d)\n"
            "      --http-query-keys K[,K...]\n"
            "                        query-string keys whose value is part of the\n"
            "                        route (?action=... APIs); every other key and\n"
            "                        value is dropped before the label (default: none)\n"
            "      --http-route-header NAME\n"
            "                        take the route from this request header when\n"
            "                        present. UNTRUSTED input — only top-K bounds\n"
            "                        the cardinality (default: off)\n"
            "      --http-user basic|none\n"
            "                        derive the `user` label from the name half of\n"
            "                        Authorization: Basic; the password is never\n"
            "                        decoded (default: none, i.e. user=\"-\")\n"
            "      --http-redact on|off\n"
            "                        replace credential-looking query values with\n"
            "                        *** wherever a request target leaves the\n"
            "                        handler, and blank credential headers in the\n"
            "                        --messages dump (default: on)\n"
            "      --s3-domain NAME  on an `s3` port, treat a Host of the form\n"
            "                        <bucket>.NAME as virtual-host addressing;\n"
            "                        repeatable, up to %d (default: none, i.e.\n"
            "                        every request is read path-style)\n"
            "      --s3-user accesskey|off\n"
            "                        derive the `user` label from the access key\n"
            "                        in an S3 signature — the public half of the\n"
            "                        pair, never the signature (default: accesskey)\n"
            "      --redis-user acl|off\n"
            "                        derive the `user` label from the ACL user of\n"
            "                        AUTH/HELLO; the password is never read, and\n"
            "                        no key or argument is ever a label (default: acl)\n"
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
            LK_PROM_LISTEN_DEFAULT, LK_SPAN_TEXT_MAX_DEF, LK_TLS_GO_MAX_PATHS, LK_ROUTE_DEPTH_DEF,
            LK_S3_DOMAIN_MAX);
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
    OPT_HTTP_USER,
    OPT_HTTP_ROUTES,
    OPT_HTTP_ROUTE_DEPTH,
    OPT_HTTP_QUERY_KEYS,
    OPT_HTTP_ROUTE_HEADER,
    OPT_HTTP_REDACT,
    OPT_S3_DOMAIN,
    OPT_S3_USER,
    OPT_REDIS_USER,
    OPT_TLS,
    OPT_LIBSSL,
    OPT_TLS_COMM,
    OPT_TLS_GO,
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
    case 'p': {
        /* PORT[=PROTO[:BYTES]] — the protocol selector is РМ2, the capture
         * budget РH14: a bare number keeps the pg default and the global
         * --capture-limit. */
        const char *eq = strchr(optarg, '=');
        const struct lk_proto_ops *ops = lk_proto_registry[0];
        __u32 cap = 0;
        char port_str[8];

        if (opt_nports == LK_MAX_PORTS) {
            fprintf(stderr, "--port: at most %d ports\n", LK_MAX_PORTS);
            return -1;
        }
        if (eq) {
            const char *name = eq + 1;
            const char *colon = strchr(name, ':');
            size_t name_len = colon ? (size_t)(colon - name) : strlen(name);

            ops = lk_proto_find(name, name_len);
            if (!ops) {
                fprintf(stderr, "--port: unknown protocol '%.*s' (supported:", (int)name_len, name);
                for (unsigned i = 0; i < lk_proto_nregistry; i++)
                    fprintf(stderr, " %s", lk_proto_registry[i]->name);
                fprintf(stderr, ")\n");
                return -1;
            }
            if (colon) {
                /* Same ceiling as --capture-limit: the BPF data path emits at
                 * most LK_MAX_CHUNKS chunks per call, so a larger per-port
                 * budget could not be honoured either. */
                if (parse_num(colon + 1, 1, LK_MAX_CHUNKS * LK_CHUNK_FULL, &v)) {
                    fprintf(stderr, "--port: expected a capture budget of 1..%d, got '%s'\n",
                            LK_MAX_CHUNKS * LK_CHUNK_FULL, colon + 1);
                    return -1;
                }
                cap = (__u32)v;
            }
            if ((size_t)(eq - optarg) >= sizeof(port_str)) {
                fprintf(stderr, "--port: bad port '%s'\n", optarg);
                return -1;
            }
            memcpy(port_str, optarg, eq - optarg);
            port_str[eq - optarg] = '\0';
            optarg = port_str;
        }
        if (parse_num(optarg, 1, 65535, &v)) {
            fprintf(stderr, "--port: bad port '%s'\n", optarg);
            return -1;
        }
        opt_port_ops[opt_nports] = ops;
        opt_port_caps[opt_nports] = cap;
        opt_ports[opt_nports++] = v;
        break;
    }
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
         * (a verifier loop bound), so a larger limit could not be honored anyway. */
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
        if (parse_num(optarg, 1, LK_MAX_CONNS, &v)) {
            fprintf(stderr, "--max-conns: expected 1..%d, got '%s'\n", LK_MAX_CONNS, optarg);
            return -1;
        }
        opt_max_conns = v;
        break;
    case OPT_CONN_IDLE_TIMEOUT:
        /* Upper bound keeps sec -> ns conversions far from overflow. */
        if (parse_num(optarg, 1, LK_MAX_CONN_IDLE_TIMEOUT, &v)) {
            fprintf(stderr, "--conn-idle-timeout: expected seconds 1..%d, got '%s'\n",
                    LK_MAX_CONN_IDLE_TIMEOUT, optarg);
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
        if (parse_num(optarg, 1, LK_MAX_TOP_QUERIES, &v)) {
            fprintf(stderr, "--top-queries: expected 1..%d, got '%s'\n", LK_MAX_TOP_QUERIES,
                    optarg);
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
        if (parse_num(optarg, 1, LK_MAX_OTLP_INTERVAL, &v)) {
            fprintf(stderr, "--otlp-interval: expected seconds 1..%d, got '%s'\n",
                    LK_MAX_OTLP_INTERVAL, optarg);
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
        if (parse_num(optarg, 1, LK_MAX_OTLP_SPANS_SLOW_MS, &v)) {
            fprintf(stderr, "--otlp-spans-slow-ms: expected 1..%d, got '%s'\n",
                    LK_MAX_OTLP_SPANS_SLOW_MS, optarg);
            return -1;
        }
        opt_otlp_span_slow_ms = v;
        break;
    case OPT_OTLP_SPAN_TEXT_MAX:
        if (parse_num(optarg, 1, LK_MAX_OTLP_SPAN_TEXT_MAX, &v)) {
            fprintf(stderr, "--otlp-span-text-max: expected 1..%d, got '%s'\n",
                    LK_MAX_OTLP_SPAN_TEXT_MAX, optarg);
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
    case OPT_HTTP_USER:
        /* РH10: `--http-user basic` takes the `user` label from the name half of
         * `Authorization: Basic`. Off by default — a `user` label is a
         * cardinality multiplier, and most HTTP has no user at all. */
        if (!strcmp(optarg, "basic")) {
            opt_http_user_basic = true;
        } else if (!strcmp(optarg, "none")) {
            opt_http_user_basic = false;
        } else {
            fprintf(stderr, "--http-user: expected 'basic' or 'none', got '%s'\n", optarg);
            return -1;
        }
        break;
    case OPT_HTTP_REDACT:
        /* РH12: on by default, so this flag exists to turn the redactor *off*.
         * Spelled as a value rather than a bare --no-http-redact because the
         * former reads the same way in a systemd unit as on a command line, and
         * this is a setting an operator has to be able to find and justify. */
        if (!strcmp(optarg, "on")) {
            opt_http_no_redact = false;
        } else if (!strcmp(optarg, "off")) {
            opt_http_no_redact = true;
        } else {
            fprintf(stderr, "--http-redact: expected 'on' or 'off', got '%s'\n", optarg);
            return -1;
        }
        break;
    case OPT_S3_DOMAIN: {
        /* РS3: the suffixes under which a leading Host label names a bucket.
         * There is no way to tell the two addressing forms apart from the
         * request alone — `GET /x` against `Host: photos.minio` is `photos/x`
         * or a ListObjects on bucket `x` depending on a server-side setting we
         * cannot see — so the server's configuration decides and ours has to
         * as well. With no suffix given every request is read path-style, which
         * is also what MinIO does without MINIO_DOMAIN. */
        size_t n = strlen(optarg);

        if (opt_s3_ndomains >= LK_S3_DOMAIN_MAX) {
            fprintf(stderr, "--s3-domain: at most %d suffixes\n", LK_S3_DOMAIN_MAX);
            return -1;
        }
        if (!n || optarg[0] == '.') {
            fprintf(stderr, "--s3-domain: expected a bare suffix like 's3.example.com', got '%s'\n",
                    optarg);
            return -1;
        }
        /* Copied rather than pointed into optarg: the env layer hands this
         * function a buffer it owns and frees (as --http-query-keys does). */
        opt_s3_domains[opt_s3_ndomains] = strndup(optarg, n);
        if (!opt_s3_domains[opt_s3_ndomains]) {
            fprintf(stderr, "--s3-domain: out of memory\n");
            return -1;
        }
        opt_s3_ndomains++;
        break;
    }
    case OPT_S3_USER:
        /* РS4: on by default, unlike --http-user, because an S3 request always
         * carries an access key and the key *is* the tenant — a per-tenant
         * latency panel is half the reason to watch an object store at all. The
         * off switch is for a deployment whose STS credentials churn faster than
         * max_session_dims can spill them into `other`. */
        if (!strcmp(optarg, "accesskey")) {
            opt_s3_no_user = false;
        } else if (!strcmp(optarg, "off")) {
            opt_s3_no_user = true;
        } else {
            fprintf(stderr, "--s3-user: expected 'accesskey' or 'off', got '%s'\n", optarg);
            return -1;
        }
        break;
    case OPT_REDIS_USER:
        /* РR6: on by default, like --s3-user and unlike --http-user. The name
         * sits in its own element of the `AUTH` array, so nothing has to be
         * decoded to find it and nothing near a password is touched — which is
         * exactly the argument --http-user could not make about
         * `Authorization: Basic`. */
        if (!strcmp(optarg, "acl")) {
            opt_redis_no_user = false;
        } else if (!strcmp(optarg, "off")) {
            opt_redis_no_user = true;
        } else {
            fprintf(stderr, "--redis-user: expected 'acl' or 'off', got '%s'\n", optarg);
            return -1;
        }
        break;
    case OPT_HTTP_ROUTES:
        /* The file is read after parsing, not here: an option handler that does
         * I/O runs from the env layer too, and "the config was rejected" should
         * be one message from one place. */
        opt_http_routes = optarg;
        break;
    case OPT_HTTP_ROUTE_DEPTH:
        if (parse_num(optarg, 1, LK_ROUTE_DEPTH_MAX, &v)) {
            fprintf(stderr, "--http-route-depth: expected 1..%d, got '%s'\n", LK_ROUTE_DEPTH_MAX,
                    optarg);
            return -1;
        }
        opt_http_route_depth = (__u32)v;
        break;
    case OPT_HTTP_QUERY_KEYS: {
        /* `a,b,c` — the query keys promoted into the route (РH7). Each one is a
         * multiplier on the series count, hence the small ceiling and the
         * explicit error instead of silently keeping the first few. */
        const char *s = optarg;

        /* The flag replaces rather than appends (the --otlp-header rule), so a
         * second spelling of it frees the first one's copies. */
        for (int i = 0; i < opt_http_nquery_keys; i++)
            free((char *)opt_http_query_keys[i]);
        opt_http_nquery_keys = 0;
        while (*s) {
            const char *e = strchr(s, ',');
            size_t n = e ? (size_t)(e - s) : strlen(s);

            if (n) {
                char *key;

                if (opt_http_nquery_keys == LK_ROUTE_QUERY_KEYS_MAX) {
                    fprintf(stderr, "--http-query-keys: at most %d keys\n",
                            LK_ROUTE_QUERY_KEYS_MAX);
                    return -1;
                }
                if (n >= LK_ROUTE_QUERY_KEY_MAX) {
                    fprintf(stderr, "--http-query-keys: key longer than %d chars\n",
                            LK_ROUTE_QUERY_KEY_MAX - 1);
                    return -1;
                }
                /* Copied rather than pointed into optarg: the env layer hands
                 * this function a buffer it owns and frees. */
                key = strndup(s, n);
                if (!key) {
                    fprintf(stderr, "--http-query-keys: out of memory\n");
                    return -1;
                }
                opt_http_query_keys[opt_http_nquery_keys++] = key;
            }
            if (!e)
                break;
            s = e + 1;
        }
        break;
    }
    case OPT_HTTP_ROUTE_HEADER: {
        /* Lower-cased here as well as in lk_proto_http_configure, so that
         * --print-config shows the name the handler will actually compare
         * against rather than the spelling that was typed. */
        size_t n = strlen(optarg);

        if (!n || n >= sizeof(opt_http_route_header)) {
            fprintf(stderr, "--http-route-header: expected 1..%zu chars, got '%s'\n",
                    sizeof(opt_http_route_header) - 1, optarg);
            return -1;
        }
        for (size_t i = 0; i < n; i++) {
            char ch = optarg[i];

            opt_http_route_header[i] = (ch >= 'A' && ch <= 'Z') ? (char)(ch - 'A' + 'a') : ch;
        }
        opt_http_route_header[n] = '\0';
        break;
    }
    case OPT_LIBSSL:
        opt_libssl = optarg;
        break;
    case OPT_TLS_GO: {
        /* Repeatable and never merged with anything: the Go channel attaches to
         * exactly the binaries it is pointed at (РH13.3). Copied rather than
         * pointed into optarg, because the env layer hands this function a
         * buffer it frees on the way out (the --cgroup rule). */
        char *dup;

        if (opt_ntls_go == LK_TLS_GO_MAX_PATHS) {
            fprintf(stderr, "--tls-go: at most %d binaries\n", LK_TLS_GO_MAX_PATHS);
            return -1;
        }
        if (!optarg[0]) {
            fprintf(stderr, "--tls-go: empty path\n");
            return -1;
        }
        dup = strdup(optarg);
        if (!dup)
            return -1;
        opt_tls_go[opt_ntls_go++] = dup;
        break;
    }
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

/* One LATKIT_* env variable ↔ its flag. Repeatable flags read a comma-separated
 * list from the single env variable. The OTEL-standard vars (endpoint/interval/
 * headers/resource/service) are handled by apply_otlp_env_defaults, which also
 * honours their OTEL_* spellings. */
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
    {"LATKIT_TLS_GO", OPT_TLS_GO, true, true},
    {"LATKIT_HTTP_ROUTES", OPT_HTTP_ROUTES, true, false},
    {"LATKIT_HTTP_ROUTE_DEPTH", OPT_HTTP_ROUTE_DEPTH, true, false},
    /* Not `repeat`: the flag itself takes the comma-separated list and each
     * spelling of it *replaces* the previous one, so splitting the variable here
     * would leave only its last key. */
    {"LATKIT_HTTP_QUERY_KEYS", OPT_HTTP_QUERY_KEYS, true, false},
    {"LATKIT_HTTP_ROUTE_HEADER", OPT_HTTP_ROUTE_HEADER, true, false},
    {"LATKIT_HTTP_USER", OPT_HTTP_USER, true, false},
    /* Value-carrying rather than boolean (`on`/`off`) because its default is on:
     * a truthy-word variable could only ever turn on what is already on. */
    {"LATKIT_HTTP_REDACT", OPT_HTTP_REDACT, true, false},
    {"LATKIT_S3_DOMAIN", OPT_S3_DOMAIN, true, true},
    {"LATKIT_S3_USER", OPT_S3_USER, true, false},
    {"LATKIT_REDIS_USER", OPT_REDIS_USER, true, false},
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
        {"http-user", required_argument, NULL, OPT_HTTP_USER},
        {"http-routes", required_argument, NULL, OPT_HTTP_ROUTES},
        {"http-route-depth", required_argument, NULL, OPT_HTTP_ROUTE_DEPTH},
        {"http-query-keys", required_argument, NULL, OPT_HTTP_QUERY_KEYS},
        {"http-route-header", required_argument, NULL, OPT_HTTP_ROUTE_HEADER},
        {"http-redact", required_argument, NULL, OPT_HTTP_REDACT},
        {"s3-domain", required_argument, NULL, OPT_S3_DOMAIN},
        {"s3-user", required_argument, NULL, OPT_S3_USER},
        {"redis-user", required_argument, NULL, OPT_REDIS_USER},
        {"tls", required_argument, NULL, OPT_TLS},
        {"libssl", required_argument, NULL, OPT_LIBSSL},
        {"tls-comm", required_argument, NULL, OPT_TLS_COMM},
        {"tls-go", required_argument, NULL, OPT_TLS_GO},
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
    if (opt_nports == 0) {
        opt_port_ops[opt_nports] = lk_proto_registry[0]; /* pg (РМ2) */
        opt_ports[opt_nports++] = LK_DEFAULT_PORT;
    }
    /* The port→protocol map handed to the conn table (РМ2). */
    for (int i = 0; i < opt_nports; i++)
        opt_port_protos[i] = (struct lk_port_proto){.port = opt_ports[i], .ops = opt_port_ops[i]};
    /* РS4: the dimension of an S3 port is (bucket, access key), and a
     * deployment has thousands of buckets where a database has a handful of
     * schemas — 32 would spill into (other,other) almost at once and take the
     * split by bucket, half of what an S3 dashboard is for, with it. Derived
     * from the port set rather than given a flag of its own: the limit follows
     * what is being watched, and an agent watching both a database and an
     * object store gets the larger of the two for kilobytes. */
    for (int i = 0; i < opt_nports; i++)
        if (opt_port_ops[i] && opt_port_ops[i]->profile == LK_PROTO_PROF_S3) {
            opt_max_session_dims = LK_MAX_SESSION_DIMS_S3;
            break;
        }
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

/* Fill the OTLP config from the environment where a flag was not given:
 * flag > LATKIT_* > OTEL_* > default. Standard OTel variables are honoured so an
 * agent deployed beside other OTel tooling inherits the ambient config. */
static void apply_otlp_env_defaults(void)
{
    if (!opt_otlp_endpoint)
        opt_otlp_endpoint = env_or("LATKIT_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_ENDPOINT");
    if (!opt_otlp_interval) {
        const char *s = env_or("LATKIT_OTLP_INTERVAL", NULL);
        __u64 v;

        if (s && !parse_num(s, 1, LK_MAX_OTLP_INTERVAL, &v))
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

/* Largest `--http-routes` file we will read. A route map is written by hand and
 * bounded by LK_ROUTE_MAP_MAX patterns anyway; the cap is here so a wrong path
 * (a core dump, a log) fails as a config error rather than as an allocation. */
#define LK_HTTP_ROUTES_MAX_BYTES (1u << 20)

/* Read and parse `--http-routes FILE` (РH7 layer 1). Returns 0 when there is
 * nothing to load or the map is in place, -1 with a printed message otherwise:
 * an operator who asked for an explicit route map and got a typo instead should
 * hear about it at startup, not by finding `route="other"` on a dashboard. */
static int load_route_map(void)
{
    char *buf;
    size_t len = 0, cap = 8192;
    __u32 rejected = 0;
    FILE *f;

    if (!opt_http_routes)
        return 0;
    f = fopen(opt_http_routes, "re");
    if (!f) {
        fprintf(stderr, "--http-routes: cannot open '%s': %s\n", opt_http_routes, strerror(errno));
        return -1;
    }
    buf = malloc(cap);
    while (buf) {
        size_t n = fread(buf + len, 1, cap - len, f);

        len += n;
        if (len < cap)
            break; /* EOF or error; ferror is checked below */
        if (cap >= LK_HTTP_ROUTES_MAX_BYTES) {
            fprintf(stderr, "--http-routes: '%s' is larger than %u bytes\n", opt_http_routes,
                    LK_HTTP_ROUTES_MAX_BYTES);
            free(buf);
            fclose(f);
            return -1;
        }
        cap *= 2;
        char *nb = realloc(buf, cap);

        if (!nb)
            free(buf);
        buf = nb;
    }
    if (!buf || ferror(f)) {
        fprintf(stderr, "--http-routes: cannot read '%s'\n", opt_http_routes);
        free(buf);
        fclose(f);
        return -1;
    }
    fclose(f);
    opt_http_route_map = lk_route_map_parse(buf, len, &rejected);
    free(buf); /* the map owns its own copy */
    if (!opt_http_route_map) {
        fprintf(stderr, "--http-routes: no usable pattern in '%s'\n", opt_http_routes);
        return -1;
    }
    if (rejected)
        fprintf(stderr,
                "latkit: --http-routes: %u line(s) of '%s' rejected "
                "(expected `METHOD /path/{id}`)\n",
                rejected, opt_http_routes);
    return 0;
}

/* Everything the http handler needs from the CLI, in one place (РH10/РH7).
 * Applied before the first event; the handler reads it through http_cfg(), and
 * every pointer in it — the map, the query keys, the header name — outlives the
 * event loop by construction (statics and startup allocations). */
static void configure_http(void)
{
    struct lk_http_cfg cfg = {
        .no_redact = opt_http_no_redact,
        .user_basic = opt_http_user_basic,
        .route = {.map = opt_http_route_map, .depth = (uint8_t)opt_http_route_depth},
        .s3 = {.no_user = opt_s3_no_user},
    };

    for (int i = 0; i < opt_http_nquery_keys; i++)
        cfg.route.query_keys[i] = opt_http_query_keys[i];
    cfg.route.nquery_keys = (uint8_t)opt_http_nquery_keys;
    for (int i = 0; i < opt_s3_ndomains; i++)
        cfg.s3.domains[i] = opt_s3_domains[i];
    cfg.s3.ndomains = (uint8_t)opt_s3_ndomains;
    memcpy(cfg.route_header, opt_http_route_header, sizeof(cfg.route_header));
    lk_proto_http_configure(&cfg);
}

/* The redis handler's one setting (РR6). Its own call rather than a field on the
 * http config, because Redis is a protocol and not a dialect: nothing it reads
 * has an HTTP equivalent, and a shared struct would say otherwise. */
static void configure_redis(void)
{
    struct lk_redis_cfg cfg = {.no_user = opt_redis_no_user};

    lk_proto_redis_configure(&cfg);
}

/* Capture budget of one configured port, in bytes (РH14). The whole precedence
 * of the three knobs lives here and nowhere else:
 *
 *   `--port 8080=http:4096`  an explicit per-port value wins outright — it was
 *                            typed for this port, by someone who meant it;
 *   protocol default         http asks for 2048 (heads are all it reads), redis
 *                            for 512 (a command is a verb and a key, and the
 *                            rate is an order of magnitude higher — РR13), the
 *                            database protocols ask for nothing. Capped by
 *                            --capture-limit: a global budget is a ceiling, so
 *                            lowering it must lower every port with it;
 *   0                        follow --capture-limit, the pre-РH14 behaviour and
 *                            what every PG/MySQL deployment keeps getting.
 *
 * The kernel stores the result and applies it as-is (port_budget), so what
 * --print-config prints is exactly what the data path will use. */
static __u32 port_cap_limit(int i)
{
    __u32 proto_def = opt_port_ops[i] ? opt_port_ops[i]->cap_limit : 0;

    if (opt_port_caps[i])
        return opt_port_caps[i];
    if (proto_def)
        return proto_def < opt_capture_limit ? proto_def : opt_capture_limit;
    return 0;
}

/* The comm set the kernel filter and the libssl scan work from, derived from
 * what is actually being captured (РH13.1). Before М7 there was one list — the
 * DB servers — because there was one kind of server; an HTTP port brings in the
 * OpenSSL-linked web servers instead, and an s3 port (РS8, МS3) the object
 * store. Deriving the set from the configured protocols keeps a PG-only
 * deployment byte-for-byte as it was (РH15) and keeps a single-protocol host's
 * filter short: `-p 9000=s3` scans for `minio` and not for four web servers that
 * are not installed.
 *
 * The s3 branch is not a subset of the HTTP one even though an S3 port *is*
 * HTTP: what these lists select is a *server implementation*, and the two do not
 * overlap at all — nginx never serves the S3 API, and MinIO has no libssl for
 * the entry to point at (its half of the channel is `--tls-go`, whose basename
 * main() adds to the gate separately).
 *
 * Fills *out (NULL-terminated, at most `max` entries) and returns the count. */
static int derive_scan_comms(const char **out, int max)
{
    int n = 0;
    bool want_db = false, want_http = false, want_s3 = false;

    for (int i = 0; i < opt_nports; i++) {
        const struct lk_proto_ops *ops = opt_port_ops[i];

        if (ops && ops->profile == LK_PROTO_PROF_S3)
            want_s3 = true;
        else if (ops && ops->otel_kind == LK_OTEL_KIND_HTTP)
            want_http = true;
        else
            want_db = true;
    }
    if (!want_db && !want_http && !want_s3)
        want_db = true; /* no ports resolved yet: the historical default */

    if (want_db)
        for (const char *const *c = lk_tls_default_comms; *c && n < max - 1; c++)
            out[n++] = *c;
    if (want_http)
        for (const char *const *c = lk_tls_http_comms; *c && n < max - 1; c++)
            out[n++] = *c;
    if (want_s3)
        for (const char *const *c = lk_tls_s3_comms; *c && n < max - 1; c++)
            out[n++] = *c;
    out[n] = NULL;
    return n;
}

/* Print the effective configuration after CLI + env resolution and exit:
 * a no-BPF way to confirm flag > LATKIT_* > OTEL_* > default without a running
 * agent. The `0 = default` sentinels are resolved to their concrete values so
 * the output reads as what the agent will actually use. Drives the priority
 * test (tests/unit/config_priority.sh). */
static void print_config(void)
{
    for (int i = 0; i < opt_nports; i++) {
        /* The pg default with no per-port budget prints bare — the pre-РМ2
         * format, pinned by config_priority.sh; anything explicit prints as
         * it was given. */
        char cap[16] = "";

        if (opt_port_caps[i])
            snprintf(cap, sizeof(cap), ":%u", opt_port_caps[i]);
        if (opt_port_ops[i] == lk_proto_registry[0] && !cap[0])
            printf("port=%u\n", opt_ports[i]);
        else
            printf("port=%u=%s%s\n", opt_ports[i], opt_port_ops[i]->name, cap);
    }
    /* The resolved per-port budget (РH14), one line per port: the `port=` lines
     * above echo what was typed, this is what the data path will actually
     * apply — the protocol default and --capture-limit already folded in. */
    for (int i = 0; i < opt_nports; i++) {
        __u32 cap = port_cap_limit(i);

        printf("port_cap=%u:%u\n", opt_ports[i], cap ? cap : opt_capture_limit);
    }
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
    printf("http_user=%s\n", opt_http_user_basic ? "basic" : "none");
    /* The map prints as its pattern count, not its path: what matters for "is
     * my config live" is how many patterns actually parsed (РH7). */
    printf("http_routes=%u\n", lk_route_map_count(opt_http_route_map));
    printf("http_route_depth=%u\n",
           opt_http_route_depth ? opt_http_route_depth : LK_ROUTE_DEPTH_DEF);
    printf("http_query_keys=");
    for (int i = 0; i < opt_http_nquery_keys; i++)
        printf("%s%s", i ? "," : "", opt_http_query_keys[i]);
    printf("\n");
    printf("http_route_header=%s\n", opt_http_route_header);
    printf("http_redact=%s\n", opt_http_no_redact ? "off" : "on");
    printf("s3_domain=");
    for (int i = 0; i < opt_s3_ndomains; i++)
        printf("%s%s", i ? "," : "", opt_s3_domains[i]);
    printf("\n");
    printf("s3_user=%s\n", opt_s3_no_user ? "off" : "accesskey");
    printf("redis_user=%s\n", opt_redis_no_user ? "off" : "acl");
    printf("top_queries=%u\n", opt_top_queries ? opt_top_queries : LK_TOP_QUERIES_DEFAULT);
    printf("max_session_dims=%u\n",
           opt_max_session_dims ? opt_max_session_dims : LK_MAX_SESSION_DIMS_DEFAULT);
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
    /* The *derived* scan set (РH13.1/РS8), which `--tls-comm` above replaces
     * wholesale when given: what the libssl scan will look for and what the
     * uprobe gate will admit, resolved from the port protocols. Printed because
     * it is the one TLS input nobody typed — a MinIO deployment that sees
     * `nginx, httpd, …` here is a deployment whose port is not `=s3`. */
    printf("tls_scan_comm=");
    {
        const char *scan[LK_COMM_FILTER_MAX + 1];
        int n = derive_scan_comms(scan, LK_COMM_FILTER_MAX + 1);

        for (int i = 0; i < n; i++)
            printf("%s%s", i ? "," : "", scan[i]);
    }
    printf("\n");
    printf("tls_go=");
    for (int i = 0; i < opt_ntls_go; i++)
        printf("%s%s", i ? "," : "", opt_tls_go[i]);
    printf("\n");
}

/* Argument count of this kernel's tcp_recvmsg, from its BTF; -1 when the
 * probe fails. The arity has changed twice (6 args before 5.19, 5 until ~7.0,
 * 4 after), each change moving the fexit return-value slot, which CO-RE
 * cannot relocate - the BPF object carries one lk_tcp_recvmsg_exit* variant
 * per shape and main() autoloads exactly one. On a probe failure or an arity
 * without a variant the 5-arg default is loaded and, if wrong for the kernel,
 * fails loudly at load rather than capturing half a stream. */
/* Everything main() needs to know about the running kernel before the load, in
 * one pass over its BTF (loading vmlinux BTF is the expensive part, so it
 * happens once): the arity above, and whether each optional attach target
 * exists at all. A missing fentry target is a hard load/attach failure, so the
 * UDP programs of РH16 — three functions that are ordinary kernel internals, not
 * uapi — are autoloaded only where they are real. */
struct lk_kernel_btf {
    int recvmsg_args; /* -1 when the probe failed */
    bool udp_sendmsg;
    bool udpv6_sendmsg;
    bool skb_consume_udp;
};

static bool btf_has_func(struct btf *btf, const char *name)
{
    return btf__find_by_name_kind(btf, name, BTF_KIND_FUNC) > 0;
}

static void probe_kernel_btf(struct lk_kernel_btf *k)
{
    struct btf *btf = btf__load_vmlinux_btf();
    const struct btf_type *t;
    int id;

    k->recvmsg_args = -1;
    k->udp_sendmsg = k->udpv6_sendmsg = k->skb_consume_udp = false;
    if (!btf)
        return;
    id = btf__find_by_name_kind(btf, "tcp_recvmsg", BTF_KIND_FUNC);
    if (id > 0) {
        t = btf__type_by_id(btf, id);                 /* FUNC */
        t = t ? btf__type_by_id(btf, t->type) : NULL; /* -> FUNC_PROTO */
        if (t)
            k->recvmsg_args = btf_vlen(t);
    }
    k->udp_sendmsg = btf_has_func(btf, "udp_sendmsg");
    k->udpv6_sendmsg = btf_has_func(btf, "udpv6_sendmsg");
    k->skb_consume_udp = btf_has_func(btf, "skb_consume_udp");
    btf__free(btf);
}

/* The `ports` map exists only after load; attach happens after this, so the
 * filter is in place before the first event can fire. */
static int fill_ports(struct latkit_bpf *skel)
{
    for (int i = 0; i < opt_nports; i++) {
        struct lk_port_cfg cfg = {.cap_limit = port_cap_limit(i)};
        int err = bpf_map__update_elem(skel->maps.ports, &opt_ports[i], sizeof(opt_ports[i]), &cfg,
                                       sizeof(cfg), BPF_ANY);

        if (err) {
            fprintf(stderr, "failed to add port %u to filter: %d\n", opt_ports[i], err);
            return err;
        }
    }
    return 0;
}

/* Append one name to the kernel comm-filter list in .rodata (frozen at load;
 * called before latkit_bpf__load only). Entries are packed from 0, duplicates
 * skipped; .rodata starts zeroed, so a bounded memcpy stays NUL-terminated
 * (strncpy of exactly size-1 trips gcc -Wstringop-truncation at -O2). */
static void comm_list_add(char (*flt)[LK_COMM_LEN], const char *what, const char *name)
{
    int i;

    for (i = 0; i < LK_COMM_FILTER_MAX && flt[i][0]; i++)
        if (!strncmp(flt[i], name, LK_COMM_LEN))
            return;
    if (i == LK_COMM_FILTER_MAX) {
        fprintf(stderr, "warn: %s filter full (%d entries), ignoring '%s'\n", what,
                LK_COMM_FILTER_MAX, name);
        return;
    }
    memcpy(flt[i], name, strnlen(name, LK_COMM_LEN - 1));
}

/* `--comm`: the operator's capture filter, applied on every path. */
static void comm_filter_add(struct latkit_bpf *skel, const char *name)
{
    comm_list_add((char (*)[LK_COMM_LEN])skel->rodata->cfg_comm_filter, "comm", name);
}

/* The agent-derived TLS set, applied to the uprobe channels only (see
 * cfg_tls_comm_filter in latkit.bpf.c). Kept apart from the list above because
 * the two answer different questions: this one says *which server the uprobes
 * are for*, and using it to gate the socket path as well used to make a
 * plaintext port served by any other process silently invisible. */
static void tls_comm_filter_add(struct latkit_bpf *skel, const char *name)
{
    comm_list_add((char (*)[LK_COMM_LEN])skel->rodata->cfg_tls_comm_filter, "TLS comm", name);
}

/* The comm a Go binary will show up as: its basename, truncated the way the
 * kernel truncates a task comm. Used only to widen an *agent-derived* kernel
 * filter — an explicit --comm stays the user's exact filter. */
static const char *path_basename(const char *path)
{
    const char *slash = strrchr(path, '/');

    return slash ? slash + 1 : path;
}

int main(int argc, char **argv)
{
    struct lk_events *events = NULL;
    struct lk_loop *loop = NULL;
    struct latkit_bpf *skel;
    struct lk_tls *tls = NULL;
    struct lk_tls_go *tls_go = NULL;
    struct lk_cgroup *cgroup = NULL;
    const char *scan_comms[LK_COMM_FILTER_MAX + 1];
    int err;

    if (parse_args(argc, argv))
        return 1;
    if (opt_version) {
        printf("latkit %s\n", LK_VERSION);
        return 0;
    }
    apply_otlp_env_defaults();
    if (load_route_map())
        return 1;
    if (opt_print_config) {
        print_config();
        return 0;
    }

    /* Hard floor: every program here is CO-RE and relocates against the running
     * kernel's BTF, so a kernel without CONFIG_DEBUG_INFO_BTF cannot work - fail
     * with one clear line instead of a wall of libbpf relocation errors. The
     * no-BTF negative test of the kernel matrix (kernels.yml) asserts this exact
     * behaviour. */
    if (access("/sys/kernel/btf/vmlinux", R_OK)) {
        fprintf(stderr, "latkit: kernel 5.15+ with BTF is required "
                        "(/sys/kernel/btf/vmlinux is missing; CONFIG_DEBUG_INFO_BTF=y)\n");
        return 1;
    }

    libbpf_set_print(libbpf_print);

    skel = latkit_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }

    /* The process comm(s) the TLS /proc scan looks for: --tls-comm, else the
     * general --comm, else NULL = the built-in DB-server set (РМ10,
     * lk_tls_default_comms in tls_attach). */
    bool tls_enabled = opt_tls_mode == LK_TLS_AUTO || opt_libssl;
    const char *tls_scan_comm = opt_tls_comm[0] ? opt_tls_comm : (opt_comm[0] ? opt_comm : NULL);

    derive_scan_comms(scan_comms, LK_COMM_FILTER_MAX + 1);

    /* An s3 port with the libssl channel asked for and no Go binary named is a
     * configuration that cannot work, and the failure it produces on its own is
     * silent: the scan finds no libssl under `minio` (there is none to find),
     * the gauge reads state="none", and a TLS-only workload reports nothing at
     * all. Every S3 implementation in scope terminates TLS in Go (РS8), so say
     * so here rather than let the operator find it in a flat dashboard. */
    if (tls_enabled && !opt_ntls_go)
        for (int i = 0; i < opt_nports; i++)
            if (opt_port_ops[i] && opt_port_ops[i]->profile == LK_PROTO_PROF_S3) {
                fprintf(stderr,
                        "warn: port %u=s3 with TLS capture on but no --tls-go: an S3 server\n"
                        "      terminates TLS inside Go's crypto/tls and maps no libssl, so the\n"
                        "      scan will find nothing to attach to. Name the server binary\n"
                        "      (--tls-go /usr/bin/minio; in a container,\n"
                        "      --tls-go /proc/<pid>/root/usr/bin/minio), or terminate TLS in\n"
                        "      front of it and capture the plaintext hop.\n",
                        opt_ports[i]);
                break;
            }

    /* .rodata and map sizes are frozen at load time. */
    skel->rodata->cfg_capture_limit = opt_capture_limit;
    /* --comm: the operator's exact kernel filter, with or without TLS, on every
     * path. Nothing else is ever added to it — see the second list below. */
    if (opt_comm[0])
        comm_filter_add(skel, opt_comm);
    if (tls_enabled) {
        /* The uprobe gate (cfg_tls_comm_filter). Go binaries first (РH13.3):
         * they were named explicitly, so if the slots run out it must be a
         * default that falls off the end, not the target the operator asked
         * for. Their basename matters because the Go probes attach by path but
         * fire for anything mapping that binary's text.
         *
         * Attaching on pid=-1 hooks every process mapping a shared libssl —
         * including a psql/mysql client that maps the same file — so this
         * filter is what keeps foreign SSL traffic out of the channel. It
         * matches the *thread* comm while the scan matches the *process* comm,
         * and the two differ (находка М0): MySQL 8.x renames its session
         * threads to `connection` while the process stays `mysqld` — a filter
         * of just the scanned comm would silently drop every decrypted event of
         * an 8.x server. So the gate is the scan set widened by `connection`.
         *
         * It stays out of the socket path, which is port-filtered to the server
         * side already (Р7). Until М9 the two shared one list, and the cost was
         * a plaintext `--port 8081=http` served by a Go/Node/Python process
         * going silently unobserved whenever TLS capture was on. */
        for (int i = 0; i < opt_ntls_go; i++)
            tls_comm_filter_add(skel, path_basename(opt_tls_go[i]));
        if (tls_scan_comm)
            tls_comm_filter_add(skel, tls_scan_comm);
        else
            for (const char **c = scan_comms; *c; c++)
                tls_comm_filter_add(skel, *c);
        tls_comm_filter_add(skel, "connection");
    }
    err = bpf_map__set_max_entries(skel->maps.events, opt_ringbuf_bytes);
    if (err) {
        fprintf(stderr, "failed to size ringbuf: %d\n", err);
        goto cleanup;
    }

    /* Decide autoload of the SSL_* uprobe programs before load: with no
     * libssl to attach, they are dropped from the load entirely. */
    struct lk_tls_cfg tlscfg = {
        .mode = opt_tls_mode,
        .libssl_override = opt_libssl,
        .comm_filter = tls_scan_comm,
        .comms = scan_comms,
        .rescan_sec = tls_enabled && !opt_libssl ? LK_TLS_RESCAN_SEC : 0,
        .go_channel = opt_ntls_go > 0,
    };

    tls = lk_tls_new(skel, &tlscfg);
    if (!tls) {
        err = -1;
        goto cleanup;
    }

    /* The Go plaintext channel (РH13.3). Like the libssl one, its programs are
     * dropped from the load when no binary was named — and with them the
     * per-thread socket hint the correlation needs, so the DB path pays nothing
     * for a channel it does not use. */
    struct lk_tls_go_cfg gocfg = {
        .paths = opt_tls_go,
        .npaths = opt_ntls_go,
        .rescan_sec = opt_ntls_go ? LK_TLS_RESCAN_SEC : 0,
    };

    tls_go = lk_tls_go_new(skel, &gocfg);
    if (!tls_go) {
        err = -1;
        goto cleanup;
    }

    /* Load the lk_tcp_recvmsg_exit variant matching this kernel's signature
     * (see probe_kernel_btf above); the other two stay out entirely. The UDP
     * counters of РH16 follow the same rule for a different reason: their
     * targets are kernel internals that a stripped-down or future kernel may
     * not have, and an fentry on a function that does not exist fails the whole
     * attach. */
    struct lk_kernel_btf kbtf;

    probe_kernel_btf(&kbtf);
    bpf_program__set_autoload(skel->progs.lk_tcp_recvmsg_exit_a6, kbtf.recvmsg_args == 6);
    bpf_program__set_autoload(skel->progs.lk_tcp_recvmsg_exit_a4, kbtf.recvmsg_args == 4);
    bpf_program__set_autoload(skel->progs.lk_tcp_recvmsg_exit,
                              kbtf.recvmsg_args != 6 && kbtf.recvmsg_args != 4);
    bpf_program__set_autoload(skel->progs.lk_udp_sendmsg, kbtf.udp_sendmsg);
    bpf_program__set_autoload(skel->progs.lk_udpv6_sendmsg, kbtf.udpv6_sendmsg);
    bpf_program__set_autoload(skel->progs.lk_skb_consume_udp, kbtf.skb_consume_udp);

    err = latkit_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = fill_ports(skel);
    if (err)
        goto cleanup;

    /* cgroup filter: resolve the globs and fill the maps before attach, like
     * fill_ports, so the filter is live before the first event. A v1 host
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
     * soft none, not a startup failure. A named Go binary is not: it was
     * pointed at explicitly, so failing to hook it is a config error. */
    err = lk_tls_attach(tls);
    if (err)
        goto cleanup;
    err = lk_tls_go_attach(tls_go);
    if (err)
        goto cleanup;

    struct lk_events_cfg ecfg = {
        .ringbuf = skel->maps.events,
        .stats = skel->maps.stats,
        .capmode = skel->maps.capmode,
        .port_protos = opt_port_protos, /* port→protocol map (РМ2) */
        .n_port_protos = (unsigned)opt_nports,
        .tls = tls,                        /* attach-state gauge source (latkit_tls_attached) */
        .tls_go = tls_go,                  /* ... its Go half (РH13.3), same gauge */
        .udp_stats = skel->maps.udp_stats, /* РH16: QUIC-on-a-watched-port counters */
        .cgroup = cgroup,                  /* latkit_cgroup_filter_paths gauge source */
        .max_conns = opt_max_conns,
        .conn_idle_timeout_sec = opt_conn_idle_timeout,
        .record_path = opt_record,
        .hexdump = opt_hexdump,
        .cap_headers = opt_cap_headers,
        .events = opt_events,
        .messages = opt_messages,
        .queries = opt_queries,
        .top_queries = opt_top_queries,
        .max_session_dims = opt_max_session_dims,
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

    /* Handler-wide HTTP settings (РH10/РH7): the identity knobs and the route
     * templater's config. Applied before the first event; the per-port half of
     * the seam — which dialect classifies a request (РH8) — travels on
     * lk_proto_ops instead, chosen by `--port N=<name>`. */
    configure_http();
    configure_redis();

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

    /* Same idea for a Go binary replaced in place: uprobes stay on the inode
     * they were created on, so the timer notices a new one and re-attaches. */
    err = lk_tls_go_register(tls_go, loop);
    if (err)
        goto cleanup;

    /* Re-resolve the cgroup globs periodically so a recreated pod (new cgroup
     * id under the same glob) is re-picked up without a restart. */
    err = lk_cgroup_register(cgroup, loop);
    if (err)
        goto cleanup;

    fprintf(stderr, "latkit %s: attached, capturing local port(s)", LK_VERSION);
    for (int i = 0; i < opt_nports; i++) {
        char cap[16] = "";

        if (opt_port_caps[i])
            snprintf(cap, sizeof(cap), ":%u", opt_port_caps[i]);
        if (opt_port_ops[i] == lk_proto_registry[0] && !cap[0])
            fprintf(stderr, " %u", opt_ports[i]);
        else
            fprintf(stderr, " %u=%s%s", opt_ports[i], opt_port_ops[i]->name, cap);
    }
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
    lk_events_free(events);
    lk_loop_free(loop);
    lk_tls_free(tls);
    lk_tls_go_free(tls_go);
    lk_cgroup_free(cgroup);
    latkit_bpf__destroy(skel);
    for (int i = 0; i < opt_ncgroup; i++)
        free((char *)opt_cgroup[i]);
    for (int i = 0; i < opt_http_nquery_keys; i++)
        free((char *)opt_http_query_keys[i]);
    for (int i = 0; i < opt_ntls_go; i++)
        free((char *)opt_tls_go[i]);
    lk_route_map_free(opt_http_route_map);
    lk_free_pairs(env_headers, env_nheaders);
    lk_free_pairs(env_resource, env_nresource);
    return err < 0 ? 1 : 0;
}
