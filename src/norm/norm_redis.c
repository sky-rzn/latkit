// SPDX-License-Identifier: GPL-2.0
/* Redis command classification and session labels (РR4–РR6, PLAN-REDIS.md МR3).
 * See norm_redis.h for the contract; this file is one table and four short
 * walks over it.
 *
 * Shape of one classification:
 *
 *     argv[0] ── upper-case ──▶ binary search over the 250 commands
 *                                   │
 *                                   ├─ not found ─────────────────▶ "other"
 *                                   ├─ not a container ───────────▶ "GET"
 *                                   └─ container ── argv[1] ──▶ binary search
 *                                                      │           in its group
 *                                                      ├─ absent ─▶ "CONFIG"
 *                                                      ├─ found ──▶ "CONFIG|GET"
 *                                                      └─ else ───▶ "CONFIG|other"
 *
 * Three properties are the point of doing it this way, and each is checked
 * rather than asserted:
 *
 *   - **the answer is a table id, and the name behind it is a table pointer.**
 *     Nothing is ever built out of the input, so the set of values a `cmd` label
 *     can take is the set written in norm_redis_table.h — 395 of them — and the
 *     bound is a compile-time constant rather than a hope about the traffic. The
 *     fuzz entry at the bottom asserts exactly that, and test_redis_cmd.c runs
 *     it over a million random arrays (the МR3 acceptance).
 *   - **argv[1] is read for fifteen commands and no others.** For everything
 *     else it is a key, and a key is an identifier that belongs in no label at
 *     any setting. The rule is one branch here rather than a convention spread
 *     over the handler.
 *   - **the password is never read.** lk_redis_session takes the *first*
 *     argument of `AUTH` and steps over the second; lk_redis_secret_mask names
 *     the second so a viewer can blank it. Nothing in this file compares,
 *     copies or hashes a credential.
 *
 * The table itself is generated — the notes are the source of truth and the
 * server is the source of the notes (see norm_redis_table.h, and the ctest
 * `redis_table` that fails when the two drift). */
#include "norm_redis.h"

#include <string.h>

/* Header-only XXH3, as in norm_route.c / norm_s3.c: the implementation lands in
 * this TU. */
#define XXH_INLINE_ALL
#include "xxhash.h"

/* One identity. `name` is what becomes the label; `key_off` is where the
 * *lookup key* starts inside it, which is 0 for a command and past the `|` for
 * a subcommand — so one array holds both and one comparison serves both. */
struct redis_ent {
    const char *name;
    uint16_t flags;
    uint16_t sub_first; /* container: its first subcommand entry */
    uint16_t sub_n;     /* container: how many */
    uint16_t sub_other; /* container: its `<name>|other` entry */
    uint8_t name_len;
    uint8_t key_off;
};

#include "norm_redis_table.h"

#define REDIS_NENT  ((uint16_t)(sizeof(redis_tab) / sizeof(redis_tab[0])))
#define REDIS_OTHER ((uint16_t)(REDIS_NENT - 1))

/* --- the lookup ------------------------------------------------------------ */

/* Case is free on the wire — go-redis sends `set`/`get`/`hello` in lower case,
 * every other client in the МR0 corpus sends upper case, and the server accepts
 * both (notes-redisproto.md §"The table"). Folding into a bounded scratch is
 * what keeps the comparison a memcmp: a token that does not fit the scratch
 * cannot be a name in the table, so it needs no scratch at all. */
static bool upper(const struct lk_redis_arg *t, char *out, uint32_t *out_n)
{
    if (!t->n || t->n >= LK_REDIS_NAME_MAX)
        return false;
    for (uint32_t i = 0; i < t->n; i++) {
        char c = t->p[i];

        out[i] = (c >= 'a' && c <= 'z') ? (char)(c - 'a' + 'A') : c;
    }
    *out_n = t->n;
    return true;
}

/* strcmp order over an explicit length, which is the order LC_ALL=C sort gives
 * the generator — the two have to agree or the search silently misses entries,
 * so the ctest compares the compiled table against the notes it came from. */
static int ent_cmp(const struct redis_ent *e, const char *key, uint32_t n)
{
    const char *name = e->name + e->key_off;
    uint32_t en = (uint32_t)(e->name_len - e->key_off);
    uint32_t m = en < n ? en : n;
    int r = memcmp(name, key, m);

    if (r)
        return r;
    return en < n ? -1 : (en > n ? 1 : 0);
}

/* Binary search in [lo, lo + n). Returns lo + n on a miss, which every caller
 * turns into its own kind of `other`. */
static uint16_t ent_find(uint16_t lo, uint16_t n, const char *key, uint32_t key_n)
{
    uint16_t l = lo, r = (uint16_t)(lo + n);

    while (l < r) {
        uint16_t mid = (uint16_t)(l + (r - l) / 2);
        int c = ent_cmp(&redis_tab[mid], key, key_n);

        if (c == 0)
            return mid;
        if (c < 0)
            l = (uint16_t)(mid + 1);
        else
            r = mid;
    }
    return (uint16_t)(lo + n);
}

uint16_t lk_redis_cmd(const struct lk_redis_argv *v)
{
    char key[LK_REDIS_NAME_MAX];
    uint32_t key_n;
    uint16_t id, sub;

    if (!v || !v->n || !upper(&v->a[0], key, &key_n))
        return REDIS_OTHER;
    id = ent_find(0, LK_REDIS_NCMD, key, key_n);
    if (id >= LK_REDIS_NCMD)
        return REDIS_OTHER;
    if (!(redis_tab[id].flags & LK_REDIS_C_CONTAINER))
        return id;
    /* The one place a second element is read at all (РR4). A container called
     * bare is an arity error on the server and a real observation here — the
     * identity is the container itself, because that is what was sent. */
    if (v->n < 2 || !upper(&v->a[1], key, &key_n))
        return id;
    sub = ent_find(redis_tab[id].sub_first, redis_tab[id].sub_n, key, key_n);
    if (sub >= redis_tab[id].sub_first + redis_tab[id].sub_n)
        return redis_tab[id].sub_other; /* `CONFIG NOSUCHSUB` → `CONFIG|other` */
    return sub;
}

const char *lk_redis_cmd_name(uint16_t id, uint32_t *len)
{
    const struct redis_ent *e = &redis_tab[id < REDIS_NENT ? id : REDIS_OTHER];

    if (len)
        *len = e->name_len;
    return e->name;
}

uint16_t lk_redis_cmd_flags(uint16_t id)
{
    return id < REDIS_NENT ? redis_tab[id].flags : 0;
}

uint64_t lk_redis_cmd_fp(uint16_t id)
{
    const struct redis_ent *e = &redis_tab[id < REDIS_NENT ? id : REDIS_OTHER];

    return XXH3_64bits(e->name, e->name_len);
}

uint16_t lk_redis_cmd_other(void)
{
    return REDIS_OTHER;
}

uint32_t lk_redis_cmd_count(void)
{
    return REDIS_NENT;
}

/* --- the session ----------------------------------------------------------- */

/* A database number, and only a database number: the whole span must be digits
 * and the value must be a database this server could plausibly have. `SELECT
 * abc` and `SELECT 99999` are answered with an error and never applied, but the
 * *label* has to be decided before the reply arrives, and "we saw a SELECT we
 * could not read" is `db="?"` rather than a stay in the previous database
 * (РR5). */
static uint16_t parse_db(const struct lk_redis_arg *t)
{
    uint32_t v = 0;

    if (!t->n || t->n > 5)
        return LK_REDIS_DB_UNKNOWN;
    for (uint32_t i = 0; i < t->n; i++) {
        if (t->p[i] < '0' || t->p[i] > '9')
            return LK_REDIS_DB_UNKNOWN;
        v = v * 10 + (uint32_t)(t->p[i] - '0');
    }
    return v <= LK_REDIS_MAX_DB ? (uint16_t)v : LK_REDIS_DB_UNKNOWN;
}

/* Where the `AUTH` clause of a `HELLO` is: `HELLO [protover [AUTH user pass]
 * [SETNAME name]]`, so the keyword is at element 2 in every legal spelling.
 * Searched for rather than indexed all the same — a client that sends something
 * else has sent something we do not have to guess about, and a search that finds
 * nothing answers "no user here", which is the safe answer in both directions:
 * no label moves, and nothing is mistaken for a password. */
static uint32_t hello_auth(const struct lk_redis_argv *v)
{
    for (uint32_t i = 1; i + 2 < v->n; i++) {
        const struct lk_redis_arg *t = &v->a[i];

        if (t->n == 4 && (t->p[0] == 'A' || t->p[0] == 'a') && (t->p[1] == 'U' || t->p[1] == 'u') &&
            (t->p[2] == 'T' || t->p[2] == 't') && (t->p[3] == 'H' || t->p[3] == 'h'))
            return i;
    }
    return 0;
}

enum lk_redis_sess lk_redis_session(uint16_t id, const struct lk_redis_argv *v, uint16_t *db,
                                    struct lk_redis_arg *user)
{
    uint16_t flags = lk_redis_cmd_flags(id);
    uint32_t i;

    if (db)
        *db = LK_REDIS_DB_UNKNOWN;
    if (user) {
        user->p = NULL;
        user->n = 0;
    }
    if (flags & LK_REDIS_C_SELECT) {
        if (db)
            *db = v->n > 1 ? parse_db(&v->a[1]) : LK_REDIS_DB_UNKNOWN;
        return LK_REDIS_SESS_DB;
    }
    if (flags & LK_REDIS_C_RESET)
        return LK_REDIS_SESS_RESET;
    if (flags & LK_REDIS_C_AUTH) {
        /* `AUTH <user> <pass>` names the user in its first argument; `AUTH
         * <password>` authenticates as `default` and names nobody. The second
         * argument is stepped over in both forms — this function never touches
         * a byte of it, which is the difference from `--http-user basic` that
         * lets the dimension default to on (РR6). */
        if (v->n > 2 && user)
            *user = v->a[1];
        return LK_REDIS_SESS_USER;
    }
    if (flags & LK_REDIS_C_HELLO) {
        i = hello_auth(v);
        if (!i)
            return LK_REDIS_SESS_NONE; /* a version negotiation, not an identity */
        if (user)
            *user = v->a[i + 1];
        return LK_REDIS_SESS_USER;
    }
    return LK_REDIS_SESS_NONE;
}

bool lk_redis_user_valid(const char *p, uint32_t n)
{
    if (!p || !n || n >= LK_REDIS_USER_MAX)
        return false;
    for (uint32_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)p[i];

        /* Printable ASCII minus the three bytes that break an exposition line
         * or a span attribute. Redis itself refuses a space in a user name (the
         * ACL parser splits on it), so nothing legitimate is lost. */
        if (c <= ' ' || c > '~' || c == '"' || c == '\\')
            return false;
    }
    return true;
}

/* --- masking --------------------------------------------------------------- */

/* Case-insensitive compare of one element against a literal — the same fold the
 * lookup does, spelled out here because these are keywords inside a command
 * rather than command names. */
static bool arg_is(const struct lk_redis_arg *t, const char *lit)
{
    uint32_t i = 0;

    for (; i < t->n && lit[i]; i++) {
        char c = t->p[i];

        if (c >= 'A' && c <= 'Z')
            c = (char)(c - 'A' + 'a');
        if (c != lit[i])
            return false;
    }
    return i == t->n && !lit[i];
}

/* The `CONFIG SET` parameters whose *value* is a credential. Everything else the
 * command sets is a number or a policy word, and hiding those would make a
 * `--messages` dump of a live tuning session unreadable for no gain. */
static bool param_is_secret(const struct lk_redis_arg *t)
{
    return arg_is(t, "requirepass") || arg_is(t, "masterauth") || arg_is(t, "primaryauth") ||
           arg_is(t, "masteruser") || arg_is(t, "tls-key-file-pass") ||
           arg_is(t, "tls-client-key-file-pass");
}

uint32_t lk_redis_secret_mask(uint16_t id, const struct lk_redis_argv *v)
{
    uint16_t flags = lk_redis_cmd_flags(id);
    uint32_t mask = 0, i;

    if (!v || !v->n)
        return 0;
    if (flags & LK_REDIS_C_SEC_RULE) {
        /* `ACL SETUSER <user> on >lkpass ~lk:* +get …`: a rule that adds or
         * removes a password starts with `>` or `<`, and one that carries its
         * SHA-256 with `#` or `!`. The user name and the permission rules stay
         * visible — they are what the command is *for*, and a dump that hid
         * them would answer nothing. Measured in `redis/acl-errors.lkt`, which
         * is where this rule came from: the corpus creates its ACL user with a
         * real password, and no `AUTH` is in sight. */
        for (i = 2; i < v->n; i++)
            if (v->a[i].n && (v->a[i].p[0] == '>' || v->a[i].p[0] == '<' || v->a[i].p[0] == '#' ||
                              v->a[i].p[0] == '!'))
                mask |= 1u << i;
        return mask;
    }
    if (flags & LK_REDIS_C_SEC_PARAM) {
        /* `CONFIG SET requirepass <pass>`, and Redis 7 takes several pairs in
         * one call — so the walk is over pairs and not over a fixed position.
         * `redis/acl-errors.lkt` sets and clears `requirepass` around its
         * `-NOAUTH` scenario. */
        for (i = 2; i + 1 < v->n; i += 2)
            if (param_is_secret(&v->a[i]))
                mask |= 1u << (i + 1);
        return mask;
    }
    if (flags & LK_REDIS_C_SEC_KW) {
        /* `MIGRATE host port key db timeout [AUTH <pass> | AUTH2 <user>
         * <pass>]`: the credential of *another* server, which is no less a
         * credential. Not in the corpus — a cluster resharding tool sends it —
         * and cheap enough to cover before it is. */
        for (i = 1; i < v->n; i++) {
            if (arg_is(&v->a[i], "auth") && i + 1 < v->n)
                mask |= 1u << (i + 1);
            else if (arg_is(&v->a[i], "auth2") && i + 2 < v->n)
                mask |= 3u << (i + 1);
        }
        return mask;
    }
    if (flags & LK_REDIS_C_AUTH) {
        /* Every argument, not only the password element. With two arguments the
         * first is the user, which already travels as a label, so hiding it in
         * a hexdump costs nothing; with a malformed number of them there is
         * nothing left to reason about and blanking all of them cannot be
         * wrong. Redis's own `MONITOR` feed prints exactly this:
         * `"AUTH" "(redacted)" "(redacted)"`. */
        for (i = 1; i < v->n; i++)
            mask |= 1u << i;
        return mask;
    }
    if (flags & LK_REDIS_C_HELLO) {
        /* Only the password, so the handshake stays readable: the version and
         * the `SETNAME` are what a `--messages` dump of a `HELLO` is for. */
        i = hello_auth(v);
        if (i)
            mask |= 1u << (i + 2);
        return mask;
    }
    return 0;
}

/* --- fuzz entry ------------------------------------------------------------ */

/* Input layout: elements separated by `\n`, so one flat byte string reaches the
 * case fold, both binary searches, the container branch, the session parses and
 * the mask. The invariants are the two the label bound rests on. */
int lk_norm_redis_fuzz_one(const uint8_t *data, size_t n)
{
    static volatile uint64_t sink;
    struct lk_redis_argv v = {0};
    struct lk_redis_arg user;
    const char *s = (const char *)data;
    uint32_t start = 0, len;
    uint16_t id, db;
    const char *name;
    uint64_t acc;

    for (uint32_t i = 0; i <= (uint32_t)n && v.n < LK_REDIS_ARGV_MAX; i++) {
        if (i == (uint32_t)n || s[i] == '\n') {
            v.a[v.n].p = s + start;
            v.a[v.n].n = i - start;
            v.n++;
            start = i + 1;
        }
    }

    id = lk_redis_cmd(&v);
    name = lk_redis_cmd_name(id, &len);
    /* 1. The identity is a table entry. Not "looks like one" — the very
     *    pointer, which is the only form of the claim that cannot be satisfied
     *    by a lucky copy of the input. */
    if (id >= lk_redis_cmd_count() || name != lk_redis_cmd_name(id, NULL))
        __builtin_trap();
    /* 2. No byte of the answer comes from the input. A name that overlapped the
     *    input would mean an argument had reached a label. */
    if (n && name >= s && name < s + n)
        __builtin_trap();

    acc = (uint64_t)id ^ lk_redis_cmd_fp(id) ^ lk_redis_cmd_flags(id) ^ len;
    acc += lk_redis_session(id, &v, &db, &user);
    acc += db;
    acc += user.n && lk_redis_user_valid(user.p, user.n);
    acc += lk_redis_secret_mask(id, &v);
    for (uint32_t i = 0; i < len; i++)
        acc += (unsigned char)name[i];
    sink += acc;
    return 0;
}
