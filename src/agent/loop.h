/* SPDX-License-Identifier: GPL-2.0 */
/* Single-thread epoll event loop (Р8, STAGE2.md): a small fd → handler
 * dispatcher rather than hardcoded ifs, so stage 5 can add the HTTP listen
 * fd without rework. The loop owns two fds of its own:
 *   - a signalfd for SIGINT/SIGTERM: the signals are blocked at creation and
 *     delivered through the fd; delivery stops the loop cleanly;
 *   - a timerfd ticking once per second, driving registered periodic tasks
 *     via per-task countdowns (10 s stats now, 60 s conn sweep in task 2.2).
 */
#ifndef LATKIT_LOOP_H
#define LATKIT_LOOP_H

#include <stdbool.h>

struct lk_loop;

/* Called when the registered fd is ready. Return <0 to stop the loop with
 * that error. A handler may deregister its own fd (lk_loop_del_fd) or add new
 * ones (lk_loop_add_fd) safely, even from inside the dispatch of a batch that
 * still holds a stale reference to the deregistered fd (stage 5: the HTTP
 * server registers, re-arms and drops client fds from within their handlers).
 *
 * The handler is not told which readiness (EPOLLIN/EPOLLOUT) fired: a consumer
 * that arms both keeps its own state (which operation it is waiting on) and,
 * under level-triggered epoll, simply retries the operation its state calls for
 * and tolerates EAGAIN. */
typedef int (*lk_loop_fd_fn)(void *ctx);
typedef void (*lk_loop_task_fn)(void *ctx);

struct lk_loop *lk_loop_new(void);
void lk_loop_free(struct lk_loop *l);

/* Register fd with EPOLLIN interest. */
int lk_loop_add_fd(struct lk_loop *l, int fd, lk_loop_fd_fn fn, void *ctx);

/* Change an already-registered fd's readiness interest (stage 5: an HTTP
 * connection flips EPOLLIN -> EPOLLOUT when it switches from reading the
 * request to writing the response). -ENOENT if fd is not registered. */
int lk_loop_mod_fd(struct lk_loop *l, int fd, bool want_read, bool want_write);

/* Deregister fd (does NOT close it — the caller owns the fd). Safe to call from
 * within any handler, including the fd's own. -ENOENT if fd is not registered. */
int lk_loop_del_fd(struct lk_loop *l, int fd);

int lk_loop_every(struct lk_loop *l, unsigned int interval_sec, lk_loop_task_fn fn, void *ctx);

/* Register a handler for SIGUSR1 (delivered through the same signalfd as the
 * shutdown signals, so it is serialised with the rest of the loop rather than
 * running in async-signal context). Used for --dump-metrics on demand. At most
 * one; without it SIGUSR1 is ignored. */
void lk_loop_on_sigusr1(struct lk_loop *l, lk_loop_task_fn fn, void *ctx);

/* Blocks in epoll_wait until SIGINT/SIGTERM (returns 0) or a handler fails
 * (returns its error). */
int lk_loop_run(struct lk_loop *l);
void lk_loop_stop(struct lk_loop *l); /* clean stop from inside a handler */

/* One epoll_wait + dispatch pass (timeout_ms; -1 blocks). Returns 0, or a
 * handler's negative error. lk_loop_run is a loop over this; exposed so tests
 * can drive the loop cooperatively without a background thread. */
int lk_loop_poll(struct lk_loop *l, int timeout_ms);

#endif /* LATKIT_LOOP_H */
