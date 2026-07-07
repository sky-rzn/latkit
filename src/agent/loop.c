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

/* Fixed capacities: the agent registers a handful of fds (ringbuf, signal,
 * timer, later the HTTP listen fd) and a couple of periodic tasks. */
#define LK_LOOP_MAX_FDS   8
#define LK_LOOP_MAX_TASKS 8

struct lk_loop_fd {
    int fd;
    lk_loop_fd_fn fn;
    void *ctx;
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
    int nfds;
    struct lk_loop_fd fds[LK_LOOP_MAX_FDS];
    int ntasks;
    struct lk_loop_task tasks[LK_LOOP_MAX_TASKS];
    lk_loop_task_fn usr1_fn; /* SIGUSR1 handler (--dump-metrics), NULL = ignore */
    void *usr1_ctx;
};

int lk_loop_add_fd(struct lk_loop *l, int fd, lk_loop_fd_fn fn, void *ctx)
{
    struct epoll_event ev = {.events = EPOLLIN};
    struct lk_loop_fd *ent;

    if (l->nfds == LK_LOOP_MAX_FDS) {
        fprintf(stderr, "loop: fd table full (%d)\n", LK_LOOP_MAX_FDS);
        return -ENOSPC;
    }
    ent = &l->fds[l->nfds];
    ent->fd = fd;
    ent->fn = fn;
    ent->ctx = ctx;
    ev.data.ptr = ent;
    if (epoll_ctl(l->epfd, EPOLL_CTL_ADD, fd, &ev)) {
        fprintf(stderr, "loop: epoll_ctl(ADD, %d): %s\n", fd, strerror(errno));
        return -errno;
    }
    l->nfds++;
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

int lk_loop_run(struct lk_loop *l)
{
    struct epoll_event evs[LK_LOOP_MAX_FDS];

    while (!l->stop) {
        int n = epoll_wait(l->epfd, evs, LK_LOOP_MAX_FDS, -1);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "loop: epoll_wait: %s\n", strerror(errno));
            return -errno;
        }
        for (int i = 0; i < n; i++) {
            const struct lk_loop_fd *ent = evs[i].data.ptr;
            int err = ent->fn(ent->ctx);

            if (err < 0)
                return err;
        }
    }
    return 0;
}
