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

struct lk_loop;

/* Called when the registered fd is ready. Return <0 to stop the loop with
 * that error; the fd stays registered until the loop is freed. */
typedef int (*lk_loop_fd_fn)(void *ctx);
typedef void (*lk_loop_task_fn)(void *ctx);

struct lk_loop *lk_loop_new(void);
void lk_loop_free(struct lk_loop *l);

int lk_loop_add_fd(struct lk_loop *l, int fd, lk_loop_fd_fn fn, void *ctx);
int lk_loop_every(struct lk_loop *l, unsigned int interval_sec, lk_loop_task_fn fn, void *ctx);

/* Blocks in epoll_wait until SIGINT/SIGTERM (returns 0) or a handler fails
 * (returns its error). */
int lk_loop_run(struct lk_loop *l);
void lk_loop_stop(struct lk_loop *l); /* clean stop from inside a handler */

#endif /* LATKIT_LOOP_H */
