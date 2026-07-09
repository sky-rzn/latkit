// SPDX-License-Identifier: GPL-2.0
/* See loop.h. The signalfd and timerfd are dispatched through the same
 * fd → handler table as user fds; their handlers just live here. */
#include "loop.h"

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

/* Fixed capacities: the agent registers a handful of long-lived fds (ringbuf,
 * signal, timer, HTTP listen fd) plus, in stage 5, up to a few short-lived HTTP
 * client fds that come and go through lk_loop_add_fd / lk_loop_del_fd. */
#define LK_LOOP_MAX_FDS   32
#define LK_LOOP_MAX_TASKS 8

/* An fd slot lives in a fixed array so epoll's data.ptr (set to &fds[i] at ADD)
 * stays valid for the entry's whole life. Deregistration marks the slot
 * inactive rather than compacting the array, keeping every other slot's stored
 * pointer stable. `freed_gen` guards the classic epoll hazard where an fd is
 * dropped mid-batch and its slot is reused before a stale event referencing it
 * is dispatched: a slot freed during dispatch records the current generation
 * and is not handed out again until the next epoll_wait advances `gen`. */
struct lk_loop_fd {
    int fd;
    lk_loop_fd_fn fn;
    void *ctx;
    bool active;
    uint64_t freed_gen;
};

struct lk_loop_task {
    unsigned int interval_sec;
    unsigned int elapsed_sec;
    lk_loop_task_fn fn;
    void *ctx;
};

struct lk_loop {
    int epfd, sigfd, tfd;
    bool stop;
    bool dispatching;               /* true while inside a dispatch batch */
    uint64_t gen;                   /* advances once per epoll_wait batch */
    struct lk_loop_fd fds[LK_LOOP_MAX_FDS];
    int ntasks;
    struct lk_loop_task tasks[LK_LOOP_MAX_TASKS];
    lk_loop_task_fn usr1_fn; /* SIGUSR1 handler (--dump-metrics), NULL = ignore */
    void *usr1_ctx;
};

/* First slot that is inactive and not on hold from a same-batch free. */
static struct lk_loop_fd *alloc_slot(struct lk_loop *l)
{
    for (int i = 0; i < LK_LOOP_MAX_FDS; i++)
        if (!l->fds[i].active && l->fds[i].freed_gen != l->gen)
            return &l->fds[i];
    return NULL;
}

static struct lk_loop_fd *find_slot(struct lk_loop *l, int fd)
{
    for (int i = 0; i < LK_LOOP_MAX_FDS; i++)
        if (l->fds[i].active && l->fds[i].fd == fd)
            return &l->fds[i];
    return NULL;
}

static int add_masked(struct lk_loop *l, int fd, uint32_t events, lk_loop_fd_fn fn, void *ctx)
{
    struct lk_loop_fd *ent = alloc_slot(l);
    struct epoll_event ev = {.events = events};

    if (!ent) {
        fprintf(stderr, "loop: fd table full (%d)\n", LK_LOOP_MAX_FDS);
        return -ENOSPC;
    }
    ent->fd = fd;
    ent->fn = fn;
    ent->ctx = ctx;
    ev.data.ptr = ent;
    if (epoll_ctl(l->epfd, EPOLL_CTL_ADD, fd, &ev)) {
        fprintf(stderr, "loop: epoll_ctl(ADD, %d): %s\n", fd, strerror(errno));
        return -errno; /* slot left inactive: reusable */
    }
    ent->active = true;
    return 0;
}

int lk_loop_add_fd(struct lk_loop *l, int fd, lk_loop_fd_fn fn, void *ctx)
{
    return add_masked(l, fd, EPOLLIN, fn, ctx);
}

int lk_loop_mod_fd(struct lk_loop *l, int fd, bool want_read, bool want_write)
{
    struct lk_loop_fd *ent = find_slot(l, fd);
    struct epoll_event ev = {
        .events = (want_read ? EPOLLIN : 0) | (want_write ? EPOLLOUT : 0),
    };

    if (!ent)
        return -ENOENT;
    ev.data.ptr = ent;
    if (epoll_ctl(l->epfd, EPOLL_CTL_MOD, fd, &ev)) {
        fprintf(stderr, "loop: epoll_ctl(MOD, %d): %s\n", fd, strerror(errno));
        return -errno;
    }
    return 0;
}

int lk_loop_del_fd(struct lk_loop *l, int fd)
{
    struct lk_loop_fd *ent = find_slot(l, fd);

    if (!ent)
        return -ENOENT;
    /* EPOLL_CTL_DEL can fail only on a programming error here; drop the slot
     * regardless so a doomed fd never lingers as active. */
    if (epoll_ctl(l->epfd, EPOLL_CTL_DEL, fd, NULL) && errno != EBADF && errno != ENOENT)
        fprintf(stderr, "loop: epoll_ctl(DEL, %d): %s\n", fd, strerror(errno));
    ent->active = false;
    /* Hold the slot until the next batch if a stale event for it might still be
     * pending in the batch currently dispatching. */
    ent->freed_gen = l->dispatching ? l->gen : 0;
    return 0;
}

int lk_loop_every(struct lk_loop *l, unsigned int interval_sec, lk_loop_task_fn fn, void *ctx)
{
    struct lk_loop_task *t;

    if (l->ntasks == LK_LOOP_MAX_TASKS) {
        fprintf(stderr, "loop: task table full (%d)\n", LK_LOOP_MAX_TASKS);
        return -ENOSPC;
    }
    t = &l->tasks[l->ntasks++];
    t->interval_sec = interval_sec;
    t->elapsed_sec = 0;
    t->fn = fn;
    t->ctx = ctx;
    return 0;
}

void lk_loop_stop(struct lk_loop *l)
{
    l->stop = true;
}

void lk_loop_on_sigusr1(struct lk_loop *l, lk_loop_task_fn fn, void *ctx)
{
    l->usr1_fn = fn;
    l->usr1_ctx = ctx;
}

static int on_signal(void *ctx)
{
    struct lk_loop *l = ctx;
    struct signalfd_siginfo si;

    if (read(l->sigfd, &si, sizeof(si)) < 0)
        return errno == EAGAIN ? 0 : -errno;
    /* SIGUSR1 is a live request (dump metrics), not a shutdown; anything else
     * on this fd (SIGINT/SIGTERM) stops the loop. */
    if (si.ssi_signo == SIGUSR1) {
        if (l->usr1_fn)
            l->usr1_fn(l->usr1_ctx);
        return 0;
    }
    lk_loop_stop(l);
    return 0;
}

static int on_timer(void *ctx)
{
    struct lk_loop *l = ctx;
    uint64_t expirations;

    if (read(l->tfd, &expirations, sizeof(expirations)) < 0)
        return errno == EAGAIN ? 0 : -errno;

    /* A task fires once per due interval; if the loop stalled past several
     * intervals (expirations > 1), the missed runs collapse into one. */
    for (int i = 0; i < l->ntasks; i++) {
        struct lk_loop_task *t = &l->tasks[i];

        t->elapsed_sec += expirations;
        if (t->elapsed_sec >= t->interval_sec) {
            t->elapsed_sec = 0;
            t->fn(t->ctx);
        }
    }
    return 0;
}

struct lk_loop *lk_loop_new(void)
{
    struct itimerspec tick = {.it_interval = {.tv_sec = 1}, .it_value = {.tv_sec = 1}};
    struct lk_loop *l;
    sigset_t mask;

    l = calloc(1, sizeof(*l));
    if (!l)
        return NULL;
    l->epfd = l->sigfd = l->tfd = -1;
    /* gen starts at 1 so pristine slots (freed_gen == 0) are allocatable and a
     * slot freed outside dispatch (freed_gen := 0) is reusable at once. */
    l->gen = 1;

    l->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (l->epfd < 0) {
        fprintf(stderr, "loop: epoll_create1: %s\n", strerror(errno));
        goto fail;
    }

    /* Block the shutdown signals process-wide and take delivery through the
     * fd; the agent stays single-threaded, so no other mask to care about. */
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &mask, NULL)) {
        fprintf(stderr, "loop: sigprocmask: %s\n", strerror(errno));
        goto fail;
    }
    l->sigfd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
    if (l->sigfd < 0) {
        fprintf(stderr, "loop: signalfd: %s\n", strerror(errno));
        goto fail;
    }

    l->tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    if (l->tfd < 0) {
        fprintf(stderr, "loop: timerfd_create: %s\n", strerror(errno));
        goto fail;
    }
    if (timerfd_settime(l->tfd, 0, &tick, NULL)) {
        fprintf(stderr, "loop: timerfd_settime: %s\n", strerror(errno));
        goto fail;
    }

    if (lk_loop_add_fd(l, l->sigfd, on_signal, l) || lk_loop_add_fd(l, l->tfd, on_timer, l))
        goto fail;
    return l;

fail:
    lk_loop_free(l);
    return NULL;
}

void lk_loop_free(struct lk_loop *l)
{
    if (!l)
        return;
    if (l->tfd >= 0)
        close(l->tfd);
    if (l->sigfd >= 0)
        close(l->sigfd);
    if (l->epfd >= 0)
        close(l->epfd);
    free(l);
}

int lk_loop_poll(struct lk_loop *l, int timeout_ms)
{
    struct epoll_event evs[LK_LOOP_MAX_FDS];
    int n = epoll_wait(l->epfd, evs, LK_LOOP_MAX_FDS, timeout_ms);
    int rv = 0;

    if (n < 0) {
        if (errno == EINTR)
            return 0;
        fprintf(stderr, "loop: epoll_wait: %s\n", strerror(errno));
        return -errno;
    }
    /* New batch: advance the generation, then dispatch. A slot freed during
     * this dispatch keeps its stale event from being mistaken for a fresh
     * registration (freed_gen == gen) and is not reused until the next batch. */
    l->gen++;
    l->dispatching = true;
    for (int i = 0; i < n; i++) {
        const struct lk_loop_fd *ent = evs[i].data.ptr;

        if (!ent->active) /* deregistered earlier in this same batch */
            continue;
        rv = ent->fn(ent->ctx);
        if (rv < 0)
            break;
    }
    l->dispatching = false;
    return rv;
}

int lk_loop_run(struct lk_loop *l)
{
    while (!l->stop) {
        int rv = lk_loop_poll(l, -1);

        if (rv < 0)
            return rv;
    }
    return 0;
}
