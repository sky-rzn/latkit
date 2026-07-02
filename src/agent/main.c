// SPDX-License-Identifier: GPL-2.0
/* latkit PoC agent: load skeleton, attach, poll ringbuf, hexdump events. */
#include <arpa/inet.h>
#include <errno.h>
#include <linux/types.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "latkit.h"
#include "latkit.skel.h"

static volatile sig_atomic_t exiting;

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

static int handle_event(void *ctx, void *data, size_t size)
{
    const struct lk_event *ev = data;
    char src[INET_ADDRSTRLEN] = "?", dst[INET_ADDRSTRLEN] = "?";

    (void)ctx;
    if (size < sizeof(*ev))
        return 0;

    inet_ntop(AF_INET, &ev->saddr, src, sizeof(src));
    inet_ntop(AF_INET, &ev->daddr, dst, sizeof(dst));
    printf("%llu %s pid=%u %s:%u -> %s:%u total=%u captured=%u\n", (unsigned long long)ev->ts_ns,
           ev->dir == LK_DIR_SEND ? "SEND" : "RECV", ev->pid, src, ev->sport, dst, ev->dport,
           ev->total_len, ev->cap_len);
    if (ev->cap_len > 0)
        hexdump(ev->payload, ev->cap_len <= POC_CHUNK ? ev->cap_len : POC_CHUNK);
    return 0;
}

static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, args);
}

int main(void)
{
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    struct ring_buffer *rb = NULL;
    struct latkit_bpf *skel;
    int err;

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
        if (err == -EINTR)
        {
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
