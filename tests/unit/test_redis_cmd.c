// SPDX-License-Identifier: GPL-2.0
/* Unit tests for the Redis identity table (PLAN-REDIS.md МR3, РR4 —
 * src/norm/norm_redis.c): the classifier, the container rule, the session
 * parses, the mask, and the two invariants the `cmd` label's cardinality bound
 * rests on.
 *
 * Pure, like the module: no framer, no connection, no events — a command here is
 * the array of elements src/proto/redis hands the classifier, and everything
 * asserted is a property of one function call.
 *
 * Two of the cases are worth naming up front, because they are the milestone's
 * acceptance criteria rather than ordinary coverage:
 *
 *   test_whole_table    every identity the table holds classifies back to
 *                       itself, from the same text the notes list — 395 of them,
 *                       so a generated table that dropped or misordered an entry
 *                       cannot pass.
 *   test_closed_set     a million random arrays, and every `cmd` they produce is
 *                       a table pointer. The fuzz invariant of МR3, run
 *                       deterministically here so it is part of every ctest run
 *                       rather than only of an МR8 campaign.
 *
 * `--dump` prints the table as `NAME flags` lines for tests/unit/redis_table.sh,
 * which compares them with docs/notes-redisproto.md §"The table" — the compiled
 * table against the notes it was generated from, so drift on either side fails
 * a test instead of quietly renaming a metric label. */
#include <stdio.h>
#include <string.h>

#include "norm_redis.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

/* Build an argv out of NUL-terminated literals — the shape the handler passes
 * in, minus the RESP framing the framer has already removed. */
static void argv_of(struct lk_redis_argv *v, const char *const *args, uint32_t n)
{
    memset(v, 0, sizeof(*v));
    for (uint32_t i = 0; i < n && i < LK_REDIS_ARGV_MAX; i++) {
        v->a[i].p = args[i];
        v->a[i].n = (uint32_t)strlen(args[i]);
    }
    v->n = n < LK_REDIS_ARGV_MAX ? n : LK_REDIS_ARGV_MAX;
}

/* The identity of a one- or two-element command, as text. */
static const char *classify(const char *verb, const char *sub)
{
    const char *args[2] = {verb, sub};
    struct lk_redis_argv v;

    argv_of(&v, args, sub ? 2 : 1);
    return lk_redis_cmd_name(lk_redis_cmd(&v), NULL);
}

static bool is(const char *verb, const char *sub, const char *want)
{
    return !strcmp(classify(verb, sub), want);
}

/* --- the table ------------------------------------------------------------- */

/* Every identity round-trips: split `CONFIG|GET` back into its two words, feed
 * them in, and the answer is the very entry we started from. Run over the whole
 * table rather than a sample, because the failure this catches — a generated
 * entry out of C order, which a binary search silently skips — hits exactly one
 * name at a time. */
static int test_whole_table(void)
{
    uint32_t n = lk_redis_cmd_count();

    CHECK(n > 300); /* 250 commands + 129 subcommands + 15 + 1 (notes §"The table") */
    for (uint32_t id = 0; id < n; id++) {
        char name[LK_REDIS_NAME_MAX], *bar;
        uint32_t len;
        const char *p = lk_redis_cmd_name(id, &len);

        CHECK(len && len < sizeof(name));
        memcpy(name, p, len);
        name[len] = '\0';
        if (id == lk_redis_cmd_other()) {
            CHECK(!strcmp(name, "other"));
            continue;
        }
        bar = strchr(name, '|');
        if (bar) {
            *bar = '\0';
            /* `CONFIG|other` is reachable by the container rule, not by name:
             * `other` is lower case on purpose so no upper-cased input can find
             * it, and what an unknown subcommand classifies to is checked below. */
            if (!strcmp(bar + 1, "other"))
                continue;
            CHECK(is(name, bar + 1, p));
        } else {
            CHECK(is(name, NULL, p));
        }
    }
    return 0;
}

/* Case is free on the wire: go-redis sends `set`/`get`/`hello` in lower case and
 * every other client in the МR0 corpus in upper (notes §"The table"). Both are
 * the same command, and the label is the table's spelling either way. */
static int test_case_folding(void)
{
    CHECK(is("get", NULL, "GET"));
    CHECK(is("GeT", NULL, "GET"));
    CHECK(is("config", "get", "CONFIG|GET"));
    CHECK(is("CoNfIg", "GeT", "CONFIG|GET"));
    CHECK(is("client", "no-evict", "CLIENT|NO-EVICT"));
    return 0;
}

/* The container rule (РR4), which is the *only* place a second element is read
 * at all. All four outcomes: a known subcommand, an unknown one, a container
 * called bare, and `DEBUG` — which the server declares no subcommands for, so
 * `DEBUG SLEEP` is one identity and `SLEEP` is an argument like any other. */
static int test_containers(void)
{
    CHECK(is("CONFIG", "GET", "CONFIG|GET"));
    CHECK(is("CONFIG", "NOSUCHSUB", "CONFIG|other"));
    CHECK(is("CONFIG", NULL, "CONFIG"));
    CHECK(is("XINFO", "STREAM", "XINFO|STREAM"));
    CHECK(is("CLUSTER", "COUNT-FAILURE-REPORTS", "CLUSTER|COUNT-FAILURE-REPORTS"));
    CHECK(is("DEBUG", "SLEEP", "DEBUG"));
    CHECK(is("DEBUG", "PROTOCOL", "DEBUG"));
    return 0;
}

/* The invariant that makes the whole track's cardinality argument true: for
 * every command that is not a container, the second element is a key, a field or
 * a value, and it changes nothing. `SET CONFIG …` is a `SET` of a key that
 * happens to be spelled like a container. */
static int test_key_is_never_an_identity(void)
{
    CHECK(is("GET", "user:42:session", "GET"));
    CHECK(is("SET", "CONFIG", "SET"));
    CHECK(is("SET", "GET", "SET")); /* `SET k v GET` is a real form, too */
    CHECK(is("DEL", "WHOAMI", "DEL"));
    CHECK(is("SUBSCRIBE", "CHANNELS", "SUBSCRIBE"));
    return 0;
}

/* Everything the table does not know is one bounded bucket — a module command, a
 * fork's admin extension, a client that sent nothing recognisable at all. It is
 * the same `other` for all of them, which is what keeps an unknown deployment
 * from inventing series (РR4, and риск 6 for the forks). */
static int test_other(void)
{
    struct lk_redis_argv v;
    char big[LK_REDIS_NAME_MAX + 8];

    CHECK(is("JSON.SET", NULL, "other"));   /* RedisJSON */
    CHECK(is("FT.SEARCH", "idx", "other")); /* RediSearch */
    CHECK(is("COMMANDLOG", NULL, "other")); /* Valkey's, absent from Redis */
    CHECK(is("HEXPIRE", NULL, "HEXPIRE"));  /* ... and Redis's, absent from Valkey */
    CHECK(is("", NULL, "other"));
    CHECK(is("\xff\xfe\x01", NULL, "other"));
    CHECK(is("GET\r\n", NULL, "other")); /* a token that is not a token */

    memset(big, 'A', sizeof(big));
    big[sizeof(big) - 1] = '\0';
    CHECK(is(big, NULL, "other")); /* longer than any name: refused before the search */

    memset(&v, 0, sizeof(v));
    CHECK(!strcmp(lk_redis_cmd_name(lk_redis_cmd(&v), NULL), "other")); /* no elements */
    return 0;
}

/* The bits. The first three are the server's, quoted through the notes; the rest
 * are the semantic groups the handler acts on, and getting one of them wrong is
 * how a replication link would be parsed as replies (РR14) or a `SUBSCRIBE` left
 * open for ever (РR8). */
static int test_flags(void)
{
    struct lk_redis_argv v;
    const char *args[2];
#define FLAGS(verb) (argv_of(&v, args, 1), args[0] = (verb), lk_redis_cmd_flags(lk_redis_cmd(&v)))

    args[0] = "SET";
    argv_of(&v, args, 1);
    CHECK(lk_redis_cmd_flags(lk_redis_cmd(&v)) & LK_REDIS_C_WRITE);
    args[0] = "GET";
    argv_of(&v, args, 1);
    CHECK(!(lk_redis_cmd_flags(lk_redis_cmd(&v)) & LK_REDIS_C_WRITE));

    args[0] = "BLPOP";
    argv_of(&v, args, 1);
    CHECK(lk_redis_cmd_flags(lk_redis_cmd(&v)) & LK_REDIS_C_BLOCKING);
    /* The server flags `XREAD` blocking unconditionally; whether it *blocks*
     * depends on a `BLOCK` argument, which is МR4's refinement of this bit. */
    args[0] = "XREAD";
    argv_of(&v, args, 1);
    CHECK(lk_redis_cmd_flags(lk_redis_cmd(&v)) & LK_REDIS_C_BLOCKING);

    args[0] = "SUBSCRIBE";
    argv_of(&v, args, 1);
    CHECK((lk_redis_cmd_flags(lk_redis_cmd(&v)) & (LK_REDIS_C_SUBFAM | LK_REDIS_C_SUBON)) ==
          (LK_REDIS_C_SUBFAM | LK_REDIS_C_SUBON));
    /* An `UNSUBSCRIBE` is answered by confirmations too, but it does not put the
     * connection *into* subscribe mode — the two bits are not one. */
    args[0] = "UNSUBSCRIBE";
    argv_of(&v, args, 1);
    CHECK(lk_redis_cmd_flags(lk_redis_cmd(&v)) & LK_REDIS_C_SUBFAM);
    CHECK(!(lk_redis_cmd_flags(lk_redis_cmd(&v)) & LK_REDIS_C_SUBON));

    args[0] = "PSYNC";
    argv_of(&v, args, 1);
    CHECK(lk_redis_cmd_flags(lk_redis_cmd(&v)) & LK_REDIS_C_REPL);
    args[0] = "REPLCONF";
    argv_of(&v, args, 1);
    CHECK(lk_redis_cmd_flags(lk_redis_cmd(&v)) & LK_REDIS_C_REPL);
    args[0] = "MONITOR";
    argv_of(&v, args, 1);
    CHECK(lk_redis_cmd_flags(lk_redis_cmd(&v)) & LK_REDIS_C_MONITOR);

    args[0] = "SELECT";
    argv_of(&v, args, 1);
    CHECK(lk_redis_cmd_flags(lk_redis_cmd(&v)) & LK_REDIS_C_SELECT);
    args[0] = "JSON.SET";
    argv_of(&v, args, 1);
    CHECK(lk_redis_cmd_flags(lk_redis_cmd(&v)) == 0); /* nothing is known about `other` */
#undef FLAGS
    return 0;
}

/* The fingerprint is the top-K dictionary's key, so two identities must not
 * share one. Checked over the whole table rather than by spot check: a collision
 * would merge two commands' series and be visible only as a number that is
 * quietly too large. */
static int test_fp_unique(void)
{
    uint32_t n = lk_redis_cmd_count();

    for (uint32_t i = 0; i < n; i++) {
        CHECK(lk_redis_cmd_fp(i) == lk_redis_cmd_fp(i)); /* stable across calls */
        for (uint32_t j = i + 1; j < n; j++)
            CHECK(lk_redis_cmd_fp(i) != lk_redis_cmd_fp(j));
    }
    return 0;
}

/* --- the session parses (РR5, РR6) ----------------------------------------- */

static enum lk_redis_sess sess(const char *const *args, uint32_t n, uint16_t *db,
                               struct lk_redis_arg *user)
{
    struct lk_redis_argv v;

    argv_of(&v, args, n);
    return lk_redis_session(lk_redis_cmd(&v), &v, db, user);
}

static int test_select(void)
{
    const char *ok[] = {"SELECT", "3"};
    const char *big[] = {"SELECT", "99999"};
    const char *txt[] = {"SELECT", "abc"};
    const char *neg[] = {"SELECT", "-1"};
    const char *bare[] = {"SELECT"};
    uint16_t db;

    CHECK(sess(ok, 2, &db, NULL) == LK_REDIS_SESS_DB && db == 3);
    /* Out of any plausible range, unparsable, negative, missing: all four are
     * "a SELECT we could not read", which is `db="?"` and never a silent stay in
     * the previous database (РR5). */
    CHECK(sess(big, 2, &db, NULL) == LK_REDIS_SESS_DB && db == LK_REDIS_DB_UNKNOWN);
    CHECK(sess(txt, 2, &db, NULL) == LK_REDIS_SESS_DB && db == LK_REDIS_DB_UNKNOWN);
    CHECK(sess(neg, 2, &db, NULL) == LK_REDIS_SESS_DB && db == LK_REDIS_DB_UNKNOWN);
    CHECK(sess(bare, 1, &db, NULL) == LK_REDIS_SESS_DB && db == LK_REDIS_DB_UNKNOWN);
    return 0;
}

/* Both `AUTH` forms and every `HELLO` shape, which is the whole of what РR6 has
 * to read — and, more to the point, the whole of what it must *not*: the element
 * after the name is a password and no case here returns a pointer into it. */
static int test_auth_forms(void)
{
    const char *two[] = {"AUTH", "lkuser", "lkpass"};
    const char *one[] = {"AUTH", "lkrootpass"};
    const char *hello3[] = {"HELLO", "3", "AUTH", "lkuser", "lkpass", "SETNAME", "lkapp"};
    const char *hello_bare[] = {"HELLO"};
    const char *hello_ver[] = {"HELLO", "3"};
    const char *hello_trunc[] = {"HELLO", "3", "AUTH", "lkuser"}; /* no password element */
    struct lk_redis_arg u;

    CHECK(sess(two, 3, NULL, &u) == LK_REDIS_SESS_USER);
    CHECK(u.n == 6 && !memcmp(u.p, "lkuser", 6));
    CHECK(u.p == two[1]); /* the *first* argument, never the second */

    /* The one-argument form authenticates as `default` and names nobody. An
     * empty span rather than the password is the point of the whole rule. */
    CHECK(sess(one, 2, NULL, &u) == LK_REDIS_SESS_USER && !u.n);

    CHECK(sess(hello3, 7, NULL, &u) == LK_REDIS_SESS_USER);
    CHECK(u.n == 6 && u.p == hello3[3]);

    /* A `HELLO` without an `AUTH` clause is a version negotiation and moves no
     * label — including the truncated form, where guessing would mean reading
     * whatever came next as a name. */
    CHECK(sess(hello_bare, 1, NULL, &u) == LK_REDIS_SESS_NONE);
    CHECK(sess(hello_ver, 2, NULL, &u) == LK_REDIS_SESS_NONE);
    CHECK(sess(hello_trunc, 4, NULL, &u) == LK_REDIS_SESS_NONE);
    return 0;
}

static int test_reset_and_ordinary(void)
{
    const char *reset[] = {"RESET"};
    const char *get[] = {"GET", "lk:k"};
    const char *sub[] = {"SUBSCRIBE", "news"};

    CHECK(sess(reset, 1, NULL, NULL) == LK_REDIS_SESS_RESET);
    CHECK(sess(get, 2, NULL, NULL) == LK_REDIS_SESS_NONE);
    CHECK(sess(sub, 2, NULL, NULL) == LK_REDIS_SESS_NONE);
    return 0;
}

/* A user name may become a label only if it is one. An operator's name always
 * passes; a client putting control bytes, quotes or a kilobyte where a series
 * name goes does not, and folds to `other` upstream (the РS3 rule). */
static int test_user_valid(void)
{
    char big[LK_REDIS_USER_MAX + 1];

    CHECK(lk_redis_user_valid("default", 7));
    CHECK(lk_redis_user_valid("lkreader", 8));
    CHECK(lk_redis_user_valid("app-1.svc", 9));
    CHECK(!lk_redis_user_valid("", 0));
    CHECK(!lk_redis_user_valid("lk user", 7));
    CHECK(!lk_redis_user_valid("lk\nuser", 7));
    CHECK(!lk_redis_user_valid("lk\"user", 7));
    CHECK(!lk_redis_user_valid("lk\\user", 7));
    CHECK(!lk_redis_user_valid("\xc3\xa9", 2)); /* not ASCII: not a label */
    memset(big, 'a', sizeof(big));
    CHECK(!lk_redis_user_valid(big, sizeof(big)));
    return 0;
}

/* --- the mask (РR6) -------------------------------------------------------- */

/* Which elements a viewer must blank. `AUTH` hides all of its arguments, as
 * Redis's own `MONITOR` feed does; `HELLO` hides the password only, so the
 * version and the `SETNAME` stay readable in a `--messages` dump. */
static int test_secret_mask(void)
{
    const char *two[] = {"AUTH", "lkuser", "lkpass"};
    const char *one[] = {"AUTH", "lkrootpass"};
    const char *hello3[] = {"HELLO", "3", "AUTH", "lkuser", "lkpass", "SETNAME", "lkapp"};
    const char *hello_ver[] = {"HELLO", "3"};
    const char *set[] = {"SET", "lk:k", "value"};
    /* The three forms the МR0 corpus turned up that carry a credential without
     * an `AUTH` in sight (РR6, widened by measurement): an ACL user created
     * with a password, the server's own password being set, and a cluster tool
     * migrating a key to an authenticated node. */
    const char *acl[] = {"ACL", "SETUSER", "lkreader", "on", ">lkpass", "~lk:*", "+get"};
    const char *aclhash[] = {"ACL", "SETUSER", "u", "#c0ffee", "!badc0de"};
    const char *conf[] = {"CONFIG", "SET", "requirepass", "lkrootpass"};
    const char *conf2[] = {"CONFIG", "SET", "maxmemory", "1gb", "masterauth", "lkpass"};
    const char *confok[] = {"CONFIG", "SET", "maxmemory", "1gb"};
    const char *migrate[] = {"MIGRATE", "h", "6379", "lk:k", "0", "5000", "AUTH", "lkpass"};
    struct lk_redis_argv v;

#define MASK(a, n) (argv_of(&v, (a), (n)), lk_redis_secret_mask(lk_redis_cmd(&v), &v))
    CHECK(MASK(two, 3) == 0x6);     /* elements 1 and 2 */
    CHECK(MASK(one, 2) == 0x2);     /* element 1 */
    CHECK(MASK(hello3, 7) == 0x10); /* element 4: the password, and only it */
    CHECK(MASK(hello_ver, 2) == 0); /* nothing secret in a version negotiation */
    CHECK(MASK(set, 3) == 0);       /* a value is not a credential, and is not
                                       hidden — it is simply never read */
    /* `ACL SETUSER`: the rules that carry a password or its hash, and only
     * those — the user name and the permissions are what the command is for. */
    CHECK(MASK(acl, 7) == 0x10);
    CHECK(MASK(aclhash, 5) == 0x18);
    /* `CONFIG SET`: the value of a credential-named parameter, in whichever
     * pair of a multi-pair call it appears. */
    CHECK(MASK(conf, 4) == 0x8);
    CHECK(MASK(conf2, 6) == 0x20);
    CHECK(MASK(confok, 4) == 0);
    /* `MIGRATE … AUTH <pass>`: another server's credential is a credential. */
    CHECK(MASK(migrate, 8) == 0x80);
#undef MASK
    return 0;
}

/* --- the closed set (the МR3 acceptance) ----------------------------------- */

/* "The set of `cmd` values is a subset of the table ∪ {other}", over a million
 * random arrays. xorshift rather than rand() so the run is identical on every
 * machine and a failure can be reproduced from the iteration number alone.
 *
 * The bytes are drawn from a mix of table-ish characters and arbitrary ones, so
 * the search is exercised near real names rather than only in the far field
 * where every input trivially misses. */
static int test_closed_set(void)
{
    static const char pool[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
                               "|-_.: \r\n\x00\xff";
    uint64_t x = 0x9e3779b97f4a7c15ull;
    uint32_t n = lk_redis_cmd_count();

    for (uint32_t iter = 0; iter < 1000000; iter++) {
        char buf[4][LK_REDIS_NAME_MAX + 4];
        const char *args[4];
        struct lk_redis_argv v;
        struct lk_redis_arg user;
        uint16_t id, db;
        uint32_t nargs, len;
        const char *name;

        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        nargs = (uint32_t)(x % 4) + 1;
        memset(&v, 0, sizeof(v));
        for (uint32_t i = 0; i < nargs; i++) {
            uint32_t l;

            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            l = (uint32_t)(x % sizeof(buf[0]));
            for (uint32_t j = 0; j < l; j++) {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                buf[i][j] = pool[x % (sizeof(pool) - 1)];
            }
            args[i] = buf[i];
            v.a[i].p = buf[i];
            v.a[i].n = l;
        }
        v.n = nargs;
        (void)args;

        id = lk_redis_cmd(&v);
        CHECK(id < n);
        name = lk_redis_cmd_name(id, &len);
        /* The identity is a *table pointer*: it cannot be a slice of the input,
         * which is the only form of "no argument ever becomes a label" that a
         * test can check rather than trust. */
        for (uint32_t i = 0; i < nargs; i++)
            CHECK(name < buf[i] || name >= buf[i] + sizeof(buf[i]));
        CHECK(len && len < LK_REDIS_NAME_MAX);
        /* And the session parses stay inside the input they were given. */
        if (lk_redis_session(id, &v, &db, &user) == LK_REDIS_SESS_USER && user.p)
            CHECK(user.n <= sizeof(buf[0]));
        CHECK(lk_redis_secret_mask(id, &v) < (1u << LK_REDIS_ARGV_MAX));
    }
    return 0;
}

/* --- the dump (tests/unit/redis_table.sh) ---------------------------------- */

static void dump(void)
{
    for (uint32_t id = 0; id < lk_redis_cmd_count(); id++) {
        uint16_t f = lk_redis_cmd_flags(id);
        uint32_t len;
        const char *name = lk_redis_cmd_name(id, &len);
        char bits[4];
        int n = 0;

        if (f & LK_REDIS_C_WRITE)
            bits[n++] = 'w';
        if (f & LK_REDIS_C_BLOCKING)
            bits[n++] = 'b';
        if (f & LK_REDIS_C_CONTAINER)
            bits[n++] = 'c';
        if (!n)
            bits[n++] = '-';
        bits[n] = '\0';
        printf("%.*s %s\n", (int)len, name, bits);
    }
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--dump")) {
        dump();
        return 0;
    }
    if (test_whole_table())
        return 1;
    if (test_case_folding())
        return 1;
    if (test_containers())
        return 1;
    if (test_key_is_never_an_identity())
        return 1;
    if (test_other())
        return 1;
    if (test_flags())
        return 1;
    if (test_fp_unique())
        return 1;
    if (test_select())
        return 1;
    if (test_auth_forms())
        return 1;
    if (test_reset_and_ordinary())
        return 1;
    if (test_user_valid())
        return 1;
    if (test_secret_mask())
        return 1;
    if (test_closed_set())
        return 1;
    printf("ok - redis command table (%u identities)\n", lk_redis_cmd_count());
    return 0;
}
