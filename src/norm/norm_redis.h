/* SPDX-License-Identifier: GPL-2.0 */
/* Redis command classification and session labels (РR4–РR6, PLAN-REDIS.md МR3)
 * — the norm_s3.h of the Redis track, and for the same reason.
 *
 * norm_route.h exists because a URL has no bounded identity and one has to be
 * *reconstructed* by a heuristic, then bounded again by a top-K dictionary.
 * Redis has the property HTTP lacks, and has it more completely than S3 does:
 * the identity of a command is the command's **name**, the server publishes the
 * whole set of names itself (`COMMAND`), and it is 379 of them. So there is no
 * heuristic here at all — a lookup in a closed table, and the cardinality of the
 * `cmd` label is a compile-time constant.
 *
 * What that buys is the rule this file exists to enforce: **an argument is
 * never an identity and never a label.** A Redis key is `user:42:session` —
 * an identifier, exactly like an S3 object key — and the second element of a
 * command is a key for every command except the fifteen containers, where it is
 * a subcommand from the same closed set. Everything else a command carries
 * (values, fields, scores, script bodies, channel names, passwords) is read by
 * nothing here and reaches no output.
 *
 * Four things live in this file, and all four are the same kind of thing: a
 * value that arrives from the wire and may become a label only after it has
 * been checked against a closed set or a bounded rule.
 *
 *   1. **the identity** (lk_redis_cmd): `(argv[0], argv[1])` → a table id whose
 *      name is `GET`, `CONFIG|GET`, `CONFIG|other` or `other`. Case is folded;
 *      the answer is always a pointer into the table and never into the input,
 *      which is what makes the closed-set invariant checkable (the fuzz entry
 *      at the bottom asserts it).
 *   2. **the database** (lk_redis_session → LK_REDIS_SESS_DB): the argument of
 *      a `SELECT`, validated against LK_REDIS_MAX_DB. It is connection state,
 *      so what this module answers is "what would this command make it", and
 *      the handler applies it only when the server said `+OK` (РR5).
 *   3. **the ACL user** (LK_REDIS_SESS_USER): the *first* argument of the
 *      two-argument `AUTH`, or the name inside `HELLO … AUTH`. The password is
 *      a separate array element and is never read — the whole difference
 *      between this and `--http-user basic`, where the name had to be dug out of
 *      the same base64 blob as the secret and the flag therefore had to default
 *      to off (РH12 vs РR6).
 *   4. **what must never be shown** (lk_redis_secret_mask): the argv indices a
 *      viewer has to blank before printing, which is the `mask_body` hook of
 *      РR6 expressed as data. Redis sets the precedent itself: its own `MONITOR`
 *      feed prints `"AUTH" "(redacted)" "(redacted)"`.
 *
 * Pure, like the rest of src/norm: no I/O, no allocation, no globals. Every
 * accessor takes explicit (pointer, length) pairs — nothing here is
 * NUL-terminated, because none of it is NUL-terminated on the wire. Walking the
 * RESP value to *find* the elements is framing knowledge and stays in
 * src/proto/redis; this module is handed the elements and never the bytes
 * around them. */
#ifndef LATKIT_NORM_REDIS_H
#define LATKIT_NORM_REDIS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Elements of a command this module is ever shown. Two bounds, because the two
 * questions have different depths:
 *
 *   LABELS  what an identity and a session label need. The deepest is the user
 *           of `HELLO 3 AUTH <user> <pass>` at element 3, and nothing past
 *           element 1 takes part in an identity at all — a command with two
 *           hundred arguments is an `MSET`, and it is an `MSET` because of its
 *           first element. This is what the handler reads per command, on the
 *           hot path, so it is deliberately small.
 *   MAX     what *hiding a credential* needs, which is further out: an
 *           `ACL SETUSER lkreader on >lkpass ~lk:* +get …` puts the password
 *           in element 3 of eleven, and a `MIGRATE … AUTH <pass>` in element 7.
 *           Only the display path pays for it, and it pays once per printed
 *           message rather than once per command.
 *
 * Both are bounds and neither is a guess: a credential past element 15 of a
 * hand-written `ACL SETUSER` would not be masked, which is stated here rather
 * than discovered later. */
#define LK_REDIS_ARGV_MAX    16
#define LK_REDIS_ARGV_LABELS 5

/* The longest identity in the table is `CLUSTER|COUNT-FAILURE-REPORTS` at 29
 * bytes; 32 holds it with the terminator, and a token longer than this cannot
 * be a command name and is not compared against one. */
#define LK_REDIS_NAME_MAX 32

/* The `user` label slot (sizeof lk_session.user). An ACL user name is an
 * operator-chosen word — `default`, `lkreader`, an application name — and 64
 * bytes is what the session struct gives every protocol for one. */
#define LK_REDIS_USER_MAX 64

/* `databases` is configurable (16 by default) and a server may legitimately be
 * started with more, so the bound here is a sanity rule and not the server's:
 * past it the number is not a database, it is a client writing arbitrary digits
 * into a label (РR5). */
#define LK_REDIS_MAX_DB 1024

/* "we know a `SELECT` happened and we do not know what it selected" — an
 * out-of-range or unparsable argument, which becomes `db="?"` rather than a
 * silent stay in the previous database. Distinct from "we never saw a `SELECT`",
 * which is the connection's initial state and is the handler's business. */
#define LK_REDIS_DB_UNKNOWN 0xffffu

/* --- the table's bits ------------------------------------------------------
 * The first three are the *server's*, quoted through docs/notes-redisproto.md
 * §"The table" and regenerated with it. The rest are ours: semantic groups the
 * handler acts on, which no server flag names — `SUBSCRIBE` and `PUBLISH` share
 * the server's `pubsub` flag, and nothing on the wire marks `AUTH` as the
 * command that moves a label.
 *
 *   WRITE      the server's `write` flag
 *   BLOCKING   its `blocking` flag (РR10). `XREAD` and `XREADGROUP` carry it
 *              unconditionally and block only with a `BLOCK` argument, which is
 *              МR4's refinement: the bit here is the server's answer, not the
 *              final one
 *   CONTAINER  the second word is a subcommand and is therefore part of the
 *              identity — the fifteen commands where argv[1] is not a key (РR4)
 *   SUBFAM     a (P|S)(UN)SUBSCRIBE: its reply is a confirmation, and only such
 *              a unit may be closed by one (РR8)
 *   SUBON      ... and these three enter subscribe mode
 *   SELECT     moves the database label (РR5)
 *   AUTH       moves the user label (РR6)
 *   HELLO      ... and may, in its `AUTH` clause
 *   RESET      back to database 0, user `default`, out of subscribe mode and
 *              out of the transaction
 *   REPL       `PSYNC`/`SYNC`/`REPLCONF`: after this the connection is a
 *              replication link and not a request/response stream at all (РR14)
 *   MONITOR    ... and this one turns it into a feed of other clients' commands
 *
 * The last three mark the commands besides `AUTH`/`HELLO` that carry a
 * credential in an argument — РR6 widened by what the МR0 corpus actually
 * contains. Each is a different shape, which is why each is its own bit rather
 * than one "there is a secret here" flag: a viewer has to know *which* element
 * to blank.
 *
 *   SEC_RULE   `ACL SETUSER u on >pass …`: a rule starting with `>`, `<`, `#`
 *              or `!` is a password or its hash
 *   SEC_PARAM  `CONFIG SET requirepass <pass>`: the value of a credential-named
 *              parameter, and `CONFIG SET` takes several pairs
 *   SEC_KW     `MIGRATE … AUTH <pass>` / `AUTH2 <user> <pass>`: the element(s)
 *              after the keyword */
#define LK_REDIS_C_WRITE     (1u << 0)
#define LK_REDIS_C_BLOCKING  (1u << 1)
#define LK_REDIS_C_CONTAINER (1u << 2)
#define LK_REDIS_C_SUBFAM    (1u << 3)
#define LK_REDIS_C_SUBON     (1u << 4)
#define LK_REDIS_C_SELECT    (1u << 5)
#define LK_REDIS_C_AUTH      (1u << 6)
#define LK_REDIS_C_HELLO     (1u << 7)
#define LK_REDIS_C_RESET     (1u << 8)
#define LK_REDIS_C_REPL      (1u << 9)
#define LK_REDIS_C_MONITOR   (1u << 10)
#define LK_REDIS_C_SEC_RULE  (1u << 11)
#define LK_REDIS_C_SEC_PARAM (1u << 12)
#define LK_REDIS_C_SEC_KW    (1u << 13)

/* One element of a command, borrowed from the caller's buffer. */
struct lk_redis_arg {
    const char *p;
    uint32_t n;
};

/* The head of a command: as many leading elements as LK_REDIS_ARGV_MAX allows,
 * already unwrapped from their RESP framing by the caller (src/proto/redis).
 * `n` is how many were actually readable — a prefix cut short by the capture
 * budget yields fewer, and yielding fewer is the honest answer: half a verb is
 * not a verb. */
struct lk_redis_argv {
    struct lk_redis_arg a[LK_REDIS_ARGV_MAX];
    uint32_t n;
};

/* --- identity (РR4) -------------------------------------------------------- */

/* Classify a command. Returns a table id, which is what the caller keeps: it is
 * two bytes rather than a pointer and a length, which matters because it is
 * stored per in-flight unit and there are 256 of those on every connection.
 *
 * `other` for anything the table does not know — a module command (`JSON.SET`),
 * a fork's admin extension, an empty command, a first element that is not a verb
 * at all. Never a value derived from the input.
 *
 * The second element takes part *only* for a container (`CONFIG GET` →
 * `CONFIG|GET`, an unknown subcommand → `CONFIG|other`, a bare `CONFIG` →
 * `CONFIG`). For every other command it is a key, a field or a value and is not
 * read — the invariant the privacy test of РH12 checks with Redis cases. */
uint16_t lk_redis_cmd(const struct lk_redis_argv *v);

/* The identity of a table id, as a borrowed pointer into the static table:
 * `"GET"`, `"CONFIG|GET"`, `"other"`. Never NULL, never allocated. */
const char *lk_redis_cmd_name(uint16_t id, uint32_t *len);

/* The LK_REDIS_C_* bits of a table id; 0 for `other`, which is the right answer
 * — nothing is known about a command the table does not have, and guessing that
 * an unknown module command is a read would be a guess. */
uint16_t lk_redis_cmd_flags(uint16_t id);

/* XXH3-64 of the identity: the fingerprint the top-K series dictionary keys on,
 * in the same role as lk_route_out.fp. Computed rather than stored — the hash of
 * a 3-to-29-byte name costs less than the branch that would look it up, and a
 * cached one would be a global in a module that has none. */
uint64_t lk_redis_cmd_fp(uint16_t id);

/* The `other` id, so a caller can compare instead of strcmp. */
uint16_t lk_redis_cmd_other(void);

/* Enumerate the table: ids 0 … lk_redis_cmd_count() - 1, every value
 * lk_redis_cmd can return, `other` included. What lets a test state the
 * closed-set invariant against the table itself rather than a copy of it that
 * can drift (the S3 rule, РS2). */
uint32_t lk_redis_cmd_count(void);

/* --- the session (РR5, РR6) ------------------------------------------------ */

enum lk_redis_sess {
    LK_REDIS_SESS_NONE = 0, /* an ordinary command: it changes no label */
    LK_REDIS_SESS_DB,       /* `SELECT n` — *db is the target, LK_REDIS_DB_UNKNOWN
                               when the argument is not a database number */
    LK_REDIS_SESS_USER,     /* `AUTH …` / `HELLO … AUTH …` — *user is the name,
                               empty for the one-argument `AUTH <password>`, which
                               authenticates as `default` */
    LK_REDIS_SESS_RESET,    /* `RESET` — database 0, user `default` */
};

/* What this command would do to the session's labels if the server accepts it.
 * "If": success is not knowable from the command, only from the reply
 * (`-WRONGPASS` leaves the user alone, `SELECT 16` leaves the database alone),
 * so the caller holds the answer until the unit closes. That split is the whole
 * of РR5/РR6's correctness — a label that moved on the request would be wrong
 * for exactly as long as the connection lived.
 *
 * `id` is the classification from lk_redis_cmd, so the four commands are
 * recognised by table bit rather than by comparing strings twice. */
enum lk_redis_sess lk_redis_session(uint16_t id, const struct lk_redis_argv *v, uint16_t *db,
                                    struct lk_redis_arg *user);

/* Is this a name that may become a label? Printable ASCII, no space, no quote,
 * no backslash, 1..LK_REDIS_USER_MAX-1 bytes. An ACL user name is chosen by an
 * operator and always passes; anything that does not is a client writing
 * arbitrary bytes into a series and folds to `other` upstream — the same rule
 * and the same reason as lk_s3_bucket_valid (РS3). */
bool lk_redis_user_valid(const char *p, uint32_t n);

/* --- what a viewer must not print (РR6) ------------------------------------ */

/* Bitmask of argv indices whose bytes are a credential: the password of either
 * `AUTH` form and of `HELLO … AUTH`. 0 = nothing to hide, which is the answer
 * for every command but two.
 *
 * Data rather than a hook so that the *one* rule serves both places the question
 * is asked — the `mask_body` implementation that blanks a body before it is
 * displayed, and the test that greps every surface for the corpus's planted
 * passwords. A second copy of "which element is the secret" is exactly how one
 * of them ends up wrong. */
uint32_t lk_redis_secret_mask(uint16_t id, const struct lk_redis_argv *v);

/* Fuzz entry (the lk_norm_s3_fuzz_one twin): split the input into elements,
 * classify, and assert the invariant the whole label bound rests on — the
 * identity is a pointer *into the table*, and every byte of every output is one
 * the table owns. Returns 0 always. */
int lk_norm_redis_fuzz_one(const uint8_t *data, size_t n);

#endif /* LATKIT_NORM_REDIS_H */
