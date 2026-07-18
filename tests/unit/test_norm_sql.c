// SPDX-License-Identifier: GPL-2.0
/* Table-driven tests for the SQL normaliser (task 4.1, Р22; MySQL dialect РМ9).
 * Drives the public lk_norm_sql over hand-written cases and checks:
 *
 *   - each lexer rule produces the expected canonical text (literals/numbers/
 *     params -> ?, lower-casing, comments dropped, dollar-quoting, trailing ;);
 *   - list collapse inside parens: `( ? , ? , ... )` -> `( ? )` and
 *     `( ? ) , ( ? ) , ...` -> `( ? )`, while a top-level `1, 2` stays distinct;
 *   - "must merge" pairs (simple / $N / bare ? spellings; whitespace; comments;
 *     `a-1` vs `a - 1`) share a fingerprint, and "must differ" pairs
 *     (`"Tbl"` vs `"tbl"`; single vs multi element) do not;
 *   - truncation: an unterminated literal / dollar-quote sets trunc and never
 *     reads out of bounds; a difference past the text cap still changes the fp;
 *   - non-UTF-8 garbage and empty input are handled and deterministic;
 *   - the LK_SQL_MYSQL rules (РМ9): # and non-nested comments, versioned
 *     comments lexed into tokens, "..." as a string with backslash escapes,
 *     backtick identifiers, charset introducers, no $N / dollar-quoting;
 *   - the PG branch is frozen: fingerprints recorded before the dialect split
 *     (М4) still come out bit-for-bit. */
#include <stdio.h>
#include <string.h>

#include "norm_sql.h"

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static struct lk_norm_out normd(const char *s, enum lk_sql_dialect d)
{
    struct lk_norm_out o;

    lk_norm_sql(s, strlen(s), d, &o);
    return o;
}

static struct lk_norm_out norm(const char *s)
{
    return normd(s, LK_SQL_PG);
}

static uint64_t fp(const char *s)
{
    return norm(s).fp;
}

static uint64_t myfp(const char *s)
{
    return normd(s, LK_SQL_MYSQL).fp;
}

/* --- canonical text per rule ---------------------------------------------- */

static int test_text(void)
{
    static const struct {
        const char *in;
        const char *want;
    } cases[] = {
        /* lower-casing, literals/params -> ?, operators, trailing ; dropped */
        {"SELECT * FROM Users WHERE id = 1", "select * from users where id = ?"},
        {"select 1;", "select ?"},
        {"select 1", "select ?"},
        {"SELECT   *\n\tFROM  t", "select * from t"},
        {"select * from t where id = $1", "select * from t where id = ?"},
        {"select * from t where id = ?", "select * from t where id = ?"},
        /* comments dropped (line + nested block) */
        {"select/* c */1", "select ?"},
        {"select 1 -- trailing comment\n", "select ?"},
        {"select /* a /* nested */ b */ 1", "select ?"},
        /* every string flavour + dollar-quoting -> ? */
        {"select 'hello'", "select ?"},
        {"select E'a\\'b'", "select ?"},
        {"select B'1010', X'ff'", "select ? , ?"},
        {"select $$body$$", "select ?"},
        {"select $tag$x$tag$", "select ?"},
        /* number flavours -> ? (no parens: NOT collapsed) */
        {"select 0xFF, 1_000, .5, 1.5e-3", "select ? , ? , ? , ?"},
        {"select -1", "select - ?"}, /* sign is an operator, not the literal */
        /* quoted identifiers kept verbatim, case significant */
        {"select \"Tbl\".\"Col\"", "select \"Tbl\" . \"Col\""},
        /* list collapse inside parens */
        {"select * from t where id in (1,2,3)", "select * from t where id in ( ? )"},
        {"select * from t where id in (1, 2)", "select * from t where id in ( ? )"},
        {"insert into t values (1,2),(3,4)", "insert into t values ( ? )"},
        {"insert into t values (1,2),(3,4),(5,6)", "insert into t values ( ? )"},
        /* a non-placeholder element blocks collapse */
        {"select coalesce(a, 1, 2)", "select coalesce ( a , ? )"},
        /* multi-statement: inner ; kept, trailing ; dropped */
        {"select 1; select 2;", "select ? ; select ?"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct lk_norm_out o = norm(cases[i].in);

        if (strcmp(o.text, cases[i].want) != 0) {
            fprintf(stderr, "FAIL text[%zu] in=<%s>\n  got  <%s>\n  want <%s>\n", i, cases[i].in,
                    o.text, cases[i].want);
            return 1;
        }
        CHECK(o.text_len == strlen(o.text));
    }
    return 0;
}

/* --- fingerprint equivalence ---------------------------------------------- */

static int test_merge(void)
{
    /* the same query, three spellings of the parameter, must share a fp */
    CHECK(fp("select * from t where id = 1") == fp("select * from t where id = $1"));
    CHECK(fp("select * from t where id = 1") == fp("select * from t where id = ?"));
    CHECK(fp("select * from t where id = 42") == fp("select * from t where id = 1"));
    /* whitespace / case / comments are irrelevant */
    CHECK(fp("select 1") == fp("SELECT    1"));
    CHECK(fp("select 1") == fp("select 1;"));
    CHECK(fp("select 1") == fp("/* hint */ select 1 -- x\n"));
    /* the tricky pair that MUST merge: sign glued vs spaced */
    CHECK(fp("select a-1") == fp("select a - 1"));
    /* IN-list length is collapsed away */
    CHECK(fp("select * from t where id in (1,2)") == fp("select * from t where id in (1,2,3,4,5)"));
    /* multi-row VALUES length is collapsed away */
    CHECK(fp("insert into t values (1,2)") == fp("insert into t values (3,4),(5,6)"));
    return 0;
}

static int test_distinct(void)
{
    /* quoted identifiers are case-significant */
    CHECK(fp("select \"Tbl\"") != fp("select \"tbl\""));
    /* a quoted identifier is not the same as the folded bare one */
    CHECK(fp("select \"tbl\"") != fp("select tbl"));
    /* top-level list length is significant (collapse is paren-scoped) */
    CHECK(fp("select 1") != fp("select 1, 2"));
    /* different queries stay different */
    CHECK(fp("select 1") != fp("select 2, 3"));
    CHECK(fp("update t set a = 1") != fp("select 1"));
    /* a single statement vs two */
    CHECK(fp("select 1") != fp("select 1; select 2"));
    return 0;
}

/* --- truncation & robustness ---------------------------------------------- */

static int test_truncation(void)
{
    struct lk_norm_out o;

    /* unterminated literal: clean finish, trunc set, still a ? token */
    o = norm("select * from t where s = 'oo");
    CHECK(o.trunc);
    CHECK(strcmp(o.text, "select * from t where s = ?") == 0);

    /* unterminated dollar-quote */
    o = norm("select $tag$body without close");
    CHECK(o.trunc);
    CHECK(strcmp(o.text, "select ?") == 0);

    /* unterminated block comment */
    o = norm("select 1 /* dangling");
    CHECK(o.trunc);
    CHECK(strcmp(o.text, "select ?") == 0);

    /* a difference PAST the text cap still changes the fp, even though the
     * (clipped) label is identical — the hash spans the whole input (Р22) */
    {
        char a[4096], b[4096];

        memset(a, 'x', sizeof(a));
        memset(b, 'x', sizeof(b));
        memcpy(a, "select ", 7);
        memcpy(b, "select ", 7);
        a[sizeof(a) - 2] = 'a';
        b[sizeof(b) - 2] = 'b';
        a[sizeof(a) - 1] = '\0';
        b[sizeof(b) - 1] = '\0';

        struct lk_norm_out oa = norm(a), ob = norm(b);

        CHECK(oa.trunc && ob.trunc);
        CHECK(oa.text_len == ob.text_len);
        CHECK(strcmp(oa.text, ob.text) == 0); /* labels identical (both clipped) */
        CHECK(oa.fp != ob.fp);                /* identities differ */
    }
    return 0;
}

static int test_garbage(void)
{
    /* empty input: no tokens, deterministic fp, empty NUL-terminated text */
    struct lk_norm_out e1, e2;

    lk_norm_sql(NULL, 0, LK_SQL_PG, &e1);
    lk_norm_sql("", 0, LK_SQL_PG, &e2);
    CHECK(e1.text_len == 0 && e1.text[0] == '\0');
    CHECK(e1.fp == e2.fp);
    CHECK(!e1.trunc);

    /* non-UTF-8 / control-byte garbage: must not crash and must be stable */
    {
        static const char junk[] = {(char)0xff, 0x00, (char)0xfe, ',', '\'', (char)0x80, '('};
        struct lk_norm_out g1, g2;

        lk_norm_sql(junk, sizeof(junk), LK_SQL_PG, &g1);
        lk_norm_sql(junk, sizeof(junk), LK_SQL_PG, &g2);
        CHECK(g1.fp == g2.fp);
        CHECK(g1.text_len == g2.text_len);
        lk_norm_sql(junk, sizeof(junk), LK_SQL_MYSQL, &g1);
        lk_norm_sql(junk, sizeof(junk), LK_SQL_MYSQL, &g2);
        CHECK(g1.fp == g2.fp);
        CHECK(g1.text_len == g2.text_len);
    }

    /* fingerprint stability: no addresses / time seeded into the hash */
    CHECK(fp("select * from accounts where owner = 'alice'") ==
          fp("select * from accounts where owner = 'bob'"));
    return 0;
}

/* --- MySQL dialect (РМ9, MYSQL.md М4) -------------------------------------- */

static int test_my_text(void)
{
    static const struct {
        const char *in;
        const char *want;
    } cases[] = {
        /* shared machinery: lower-casing, ? placeholders, list collapse */
        {"SELECT * FROM Users WHERE id = 1", "select * from users where id = ?"},
        {"select * from t where id = ?", "select * from t where id = ?"},
        {"select * from t where id in (1,2,3)", "select * from t where id in ( ? )"},
        {"insert into t values (1,2),(3,4)", "insert into t values ( ? )"},
        {"select 1; select 2;", "select ? ; select ?"},
        /* comments: #, -- with AND without the space MySQL wants, flat block */
        {"select 1 # trailing\n", "select ?"},
        {"select 1#glued\n+2", "select ? + ?"},
        {"select 1 -- c\n", "select ?"},
        {"select 1 --c\n", "select ?"},
        {"select /* c */ 1", "select ?"},
        /* block comments do NOT nest: the first star-slash closes it */
        {"select /* a /* b */ 1", "select ?"},
        {"select /* a /* b */ c */ 1", "select c */ ?"},
        /* versioned comments are lexed into tokens, version gate dropped */
        {"insert /*! ignore */ into t values (1)", "insert ignore into t values ( ? )"},
        {"select /*!80013 x */ 1", "select x ?"},
        {"select 1 /*! + 2 */", "select ? + ?"},
        /* strings: both quote chars, backslash escapes AND doubling */
        {"select 'it''s', 'a\\'b'", "select ? , ?"},
        {"select \"str\"", "select ?"},
        {"select \"a\\\"b\", \"c\"\"d\"", "select ? , ?"},
        /* N/B/X strings, hex/bin numbers, charset introducers -> ? */
        {"select N'abc', n'abc'", "select ? , ?"},
        {"select 0xFF, X'ff', B'1010', 0b01", "select ? , ? , ? , ?"},
        {"select _utf8mb4'x'", "select ?"},
        {"select _binary\"b\"", "select ?"},
        /* introducer NOT glued to the quote: two tokens (pinned behaviour) */
        {"select _utf8mb4 'x'", "select _utf8mb4 ?"},
        /* backtick identifiers: verbatim, case significant, `` doubling */
        {"select `From` from t", "select `From` from t"},
        {"select `a``b`", "select `a``b`"},
        {"select a=`b`", "select a = `b`"},
        /* $ is identifier material; $N / dollar-quoting do not exist */
        {"select $1", "select $1"},
        {"select a$b, $foo", "select a$b , $foo"},
        /* an operator run stops before a # comment */
        {"select a=#c\n1", "select a = ?"},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct lk_norm_out o = normd(cases[i].in, LK_SQL_MYSQL);

        if (strcmp(o.text, cases[i].want) != 0) {
            fprintf(stderr, "FAIL my_text[%zu] in=<%s>\n  got  <%s>\n  want <%s>\n", i, cases[i].in,
                    o.text, cases[i].want);
            return 1;
        }
        CHECK(o.text_len == strlen(o.text));
    }
    return 0;
}

static int test_my_merge_distinct(void)
{
    /* the versioned-comment spelling merges with the plain one */
    CHECK(myfp("insert /*! ignore */ into t values (1)") ==
          myfp("insert ignore into t values (2)"));
    /* every literal spelling is one ? */
    CHECK(myfp("select 'a'") == myfp("select \"b\""));
    CHECK(myfp("select 'a'") == myfp("select _utf8mb4'b'"));
    CHECK(myfp("select 'a'") == myfp("select N'b'"));
    CHECK(myfp("select 'a\\'b'") == myfp("select 'z'"));
    CHECK(myfp("select 0xFF") == myfp("select X'00'"));
    /* comments are whitespace */
    CHECK(myfp("select 1") == myfp("select # c\n 2"));
    /* list collapse works under the MySQL lexer too */
    CHECK(myfp("select * from t where id in (1,2)") ==
          myfp("select * from t where id in (1,2,3,4,5)"));

    /* backtick identifiers are case significant and not the folded bare one */
    CHECK(myfp("select `Tbl`") != myfp("select `tbl`"));
    CHECK(myfp("select `tbl`") != myfp("select tbl"));
    /* $1 is an identifier here, not a parameter */
    CHECK(myfp("select $1") != myfp("select ?"));
    /* "..." is a string in MySQL but an identifier in PG */
    CHECK(myfp("select \"x\"") != fp("select \"x\""));
    CHECK(myfp("select \"x\"") == myfp("select 'anything'"));
    return 0;
}

static int test_my_truncation(void)
{
    struct lk_norm_out o;

    /* unterminated literal (either quote char) */
    o = normd("select 'oo", LK_SQL_MYSQL);
    CHECK(o.trunc);
    CHECK(strcmp(o.text, "select ?") == 0);
    o = normd("select \"oo", LK_SQL_MYSQL);
    CHECK(o.trunc);
    CHECK(strcmp(o.text, "select ?") == 0);

    /* unterminated backtick identifier */
    o = normd("select `oo", LK_SQL_MYSQL);
    CHECK(o.trunc);
    CHECK(strcmp(o.text, "select `oo") == 0);

    /* unterminated block comment / versioned comment */
    o = normd("select 1 /* dangling", LK_SQL_MYSQL);
    CHECK(o.trunc);
    CHECK(strcmp(o.text, "select ?") == 0);
    o = normd("select /*!50000 1", LK_SQL_MYSQL);
    CHECK(o.trunc);
    CHECK(strcmp(o.text, "select ?") == 0);

    /* unterminated introducer string */
    o = normd("select _utf8mb4'oo", LK_SQL_MYSQL);
    CHECK(o.trunc);
    CHECK(strcmp(o.text, "select ?") == 0);
    return 0;
}

/* --- PG branch is frozen ---------------------------------------------------
 *
 * Fingerprints recorded by running the pre-М4 normaliser (before the dialect
 * parameter existed) over this set. If any of these change, the PG branch
 * stopped being byte-for-byte — existing dashboards and long-lived series
 * would silently split. */
static int test_pg_pinned(void)
{
    static const struct {
        const char *in;
        uint64_t want;
    } cases[] = {
        {"SELECT * FROM Users WHERE id = 1", UINT64_C(0x03a474c21aefeed5)},
        {"select 1", UINT64_C(0xd035037171ed0ebb)},
        {"select * from t where id = $1", UINT64_C(0xc96754f91edda19a)},
        {"select/* c */1", UINT64_C(0xd035037171ed0ebb)},
        {"select /* a /* nested */ b */ 1", UINT64_C(0xd035037171ed0ebb)},
        {"select E'a\\'b'", UINT64_C(0xd035037171ed0ebb)},
        {"select B'1010', X'ff'", UINT64_C(0xf40603092ea7a906)},
        {"select $$body$$", UINT64_C(0xd035037171ed0ebb)},
        {"select $tag$x$tag$", UINT64_C(0xd035037171ed0ebb)},
        {"select 0xFF, 1_000, .5, 1.5e-3", UINT64_C(0x44a161690c9320cb)},
        {"select \"Tbl\".\"Col\"", UINT64_C(0xa27383ab0363da60)},
        {"select * from t where id in (1,2,3)", UINT64_C(0x4121dba48290836d)},
        {"insert into t values (1,2),(3,4)", UINT64_C(0x10a9195c9f1ae46d)},
        {"select coalesce(a, 1, 2)", UINT64_C(0x07692b89a73e3bf4)},
        {"select 1; select 2;", UINT64_C(0xd6217d80dac43677)},
        {"select a-1", UINT64_C(0xcda3b0d50f6e0897)},
        {"update t set a = 1", UINT64_C(0xc58637cb9a4fea21)},
        /* PG must keep treating the MySQL-isms the old way: # and backtick
         * are operators, a versioned comment is just a comment */
        {"select 'hello' # not a comment in pg", UINT64_C(0x2cd9f4c0d6b12f7d)},
        {"select `backtick` + 1", UINT64_C(0x5bff130b59c386f7)},
        {"insert /*! ignore */ into t values (1)", UINT64_C(0x10a9195c9f1ae46d)},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint64_t got = fp(cases[i].in);

        if (got != cases[i].want) {
            fprintf(stderr, "FAIL pg_pinned[%zu] in=<%s>\n  got  0x%016llx\n  want 0x%016llx\n", i,
                    cases[i].in, (unsigned long long)got, (unsigned long long)cases[i].want);
            return 1;
        }
    }
    return 0;
}

int main(void)
{
    if (test_text())
        return 1;
    if (test_merge())
        return 1;
    if (test_distinct())
        return 1;
    if (test_truncation())
        return 1;
    if (test_garbage())
        return 1;
    if (test_my_text())
        return 1;
    if (test_my_merge_distinct())
        return 1;
    if (test_my_truncation())
        return 1;
    if (test_pg_pinned())
        return 1;
    printf("ok test_norm_sql\n");
    return 0;
}
