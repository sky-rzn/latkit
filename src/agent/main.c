// SPDX-License-Identifier: GPL-2.0
/* latkit agent: load skeleton, attach, poll ringbuf, decode events by
 * hdr.type. One line per event; payload hexdump behind --hexdump. */
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <linux/types.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "latkit.h"
#include "latkit.skel.h"

static volatile sig_atomic_t exiting;
static bool opt_hexdump;

static void sig_handler(int sig)
{
    (void)sig;
    exiting = 1;
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

static int handle_event(void *ctx, void *data, size_t size)
{
    const struct lk_ev_hdr *hdr = data;

    (void)ctx;
    if (size < sizeof(*hdr))
        return 0;

    switch (hdr->type) {
    case LK_EV_CONN_OPEN:
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

static int parse_args(int argc, char **argv)
{
    static const struct option opts[] = {
        {"hexdump", no_argument, NULL, 'x'},
        {},
    };
    int c;

    while ((c = getopt_long(argc, argv, "x", opts, NULL)) != -1) {
        switch (c) {
        case 'x':
            opt_hexdump = true;
            break;
        default:
            fprintf(stderr, "usage: %s [--hexdump]\n", argv[0]);
            return -1;
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

    skel = latkit_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load BPF skeleton\n");
        return 1;
    }

    err = latkit_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        err = -errno;
        fprintf(stderr, "failed to create ring buffer\n");
        goto cleanup;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    fprintf(stderr, "latkit: attached, polling events (Ctrl-C to exit)\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* ms */);
        if (err == -EINTR) {
            err = 0;
            continue;
        }
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    latkit_bpf__destroy(skel);
    return err < 0 ? 1 : 0;
}
