// SPDX-License-Identifier: GPL-2.0
/* Seed-corpus writer for the three fuzz targets (task 8.3, Р51).
 *
 * Coverage-guided fuzzing starts orders of magnitude faster from inputs that
 * already parse: this tool writes small, valid-ish seeds into
 * <root>/{pg,norm,pipe}/ — PostgreSQL v3 wire sessions for fuzz_pg, plain SQL
 * for fuzz_norm, and scenario-encoded sessions (fuzz_pipe_ops.h) for
 * fuzz_pipe. The campaign script (campaign.sh) regenerates them into the
 * working corpus before every run and minimises the result back into
 * tests/fuzz/corpus/ with -merge=1; the committed corpus, not this tool's
 * output, is the regression set. Sharing fuzz_pipe_ops.h keeps the pipe seeds
 * from drifting when the scenario format changes.
 *
 * Plain host tool: no fuzzer runtime, no sanitizers needed. */
#include <linux/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz_pipe_ops.h"

static uint8_t buf[1 << 16];
static size_t blen;

static void put(const void *p, size_t n)
{
    if (blen + n > sizeof(buf)) {
        fprintf(stderr, "gen_seeds: seed overflow\n");
        exit(1);
    }
    memcpy(buf + blen, p, n);
    blen += n;
}

static void put_u8(unsigned v)
{
    uint8_t b = (uint8_t)v;

    put(&b, 1);
}

static void be32(uint32_t v)
{
    uint8_t b[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};

    put(b, 4);
}

/* One typed v3 message: type byte + len(4, includes itself) + body. */
static void msg(char type, const void *body, size_t n)
{
    put(&type, 1);
    be32((uint32_t)(n + 4));
    put(body, n);
}

/* Body fragments assembled in a side buffer (messages with structured bodies). */
static uint8_t body[4096];
static size_t bodylen;

static void b_reset(void)
{
    bodylen = 0;
}

static void b_raw(const void *p, size_t n)
{
    memcpy(body + bodylen, p, n);
    bodylen += n;
}

static void b_cstr(const char *s)
{
    b_raw(s, strlen(s) + 1);
}

static void b_be32(uint32_t v)
{
    uint8_t b[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};

    b_raw(b, 4);
}

static void b_be16(uint16_t v)
{
    uint8_t b[2] = {(uint8_t)(v >> 8), (uint8_t)v};

    b_raw(b, 2);
}

/* --- canned v3 pieces ------------------------------------------------------ */

static void wire_startup(void)
{
    b_reset();
    b_be32(0x00030000);
    b_cstr("user");
    b_cstr("postgres");
    b_cstr("database");
    b_cstr("postgres");
    b_cstr("application_name");
    b_cstr("fuzz");
    b_raw("", 1);                  /* params terminator */
    be32((uint32_t)(bodylen + 4)); /* startup framing: len first, no type byte */
    put(body, bodylen);
}

static void wire_auth_ok(void)
{
    b_reset();
    b_be32(0);
    msg('R', body, bodylen);
}

static void wire_param(const char *k, const char *v)
{
    b_reset();
    b_cstr(k);
    b_cstr(v);
    msg('S', body, bodylen);
}

static void wire_key_data(void)
{
    b_reset();
    b_be32(4242);
    b_be32(0xfeedface);
    msg('K', body, bodylen);
}

static void wire_ready(char status)
{
    msg('Z', &status, 1);
}

static void wire_query(const char *sql)
{
    msg('Q', sql, strlen(sql) + 1);
}

static void wire_row_desc(void)
{
    b_reset();
    b_be16(1);
    b_cstr("?column?");
    b_be32(0);  /* table oid */
    b_be16(0);  /* attnum */
    b_be32(23); /* int4 */
    b_be16(4);
    b_be32((uint32_t)-1);
    b_be16(0);
    msg('T', body, bodylen);
}

static void wire_data_row(const char *val)
{
    b_reset();
    b_be16(1);
    b_be32((uint32_t)strlen(val));
    b_raw(val, strlen(val));
    msg('D', body, bodylen);
}

static void wire_complete(const char *tag)
{
    msg('C', tag, strlen(tag) + 1);
}

static void wire_error(const char *sqlstate, const char *text)
{
    b_reset();
    b_raw("SERROR", 7);
    b_raw("C", 1);
    b_cstr(sqlstate);
    b_raw("M", 1);
    b_cstr(text);
    b_raw("", 1);
    msg('E', body, bodylen);
}

/* --- seed files ------------------------------------------------------------ */

static void write_seed(const char *root, const char *sub, const char *name)
{
    char path[1024];
    FILE *f;

    snprintf(path, sizeof(path), "%s/%s/%s", root, sub, name);
    f = fopen(path, "wb");
    if (!f || fwrite(buf, 1, blen, f) != blen) {
        fprintf(stderr, "gen_seeds: cannot write %s\n", path);
        exit(1);
    }
    fclose(f);
    printf("wrote %s (%zu bytes)\n", path, blen);
    blen = 0;
}

static void write_text(const char *root, const char *name, const char *sql)
{
    put(sql, strlen(sql));
    write_seed(root, "norm", name);
}

/* Same, behind fuzz_norm's dialect switch: a leading 0xFF selects LK_SQL_MYSQL. */
static void write_text_my(const char *root, const char *name, const char *sql)
{
    put_u8(0xFF);
    put(sql, strlen(sql));
    write_seed(root, "norm", name);
}

/* --- pg seeds: whole sessions, frontend and backend bytes concatenated ------ */

static void pg_seeds(const char *root)
{
    /* simple query round trip */
    wire_startup();
    wire_auth_ok();
    wire_param("server_version", "16.3");
    wire_key_data();
    wire_ready('I');
    wire_query("select 1");
    wire_row_desc();
    wire_data_row("1");
    wire_complete("SELECT 1");
    wire_ready('I');
    msg('X', NULL, 0);
    write_seed(root, "pg", "simple_session");

    /* extended protocol: Parse/Bind/Describe/Execute/Sync and the replies */
    wire_startup();
    wire_auth_ok();
    wire_ready('I');
    b_reset();
    b_cstr("");
    b_cstr("select $1");
    b_be16(0);
    msg('P', body, bodylen);
    b_reset();
    b_cstr("");
    b_cstr("");
    b_be16(0);
    b_be16(1);
    b_be32(1);
    b_raw("7", 1);
    b_be16(0);
    msg('B', body, bodylen);
    b_reset();
    b_raw("P", 1);
    b_cstr("");
    msg('D', body, bodylen);
    b_reset();
    b_cstr("");
    b_be32(0);
    msg('E', body, bodylen);
    msg('S', NULL, 0);
    msg('1', NULL, 0);
    msg('2', NULL, 0);
    wire_row_desc();
    wire_data_row("7");
    wire_complete("SELECT 1");
    wire_ready('I');
    write_seed(root, "pg", "extended_session");

    /* error path: division by zero inside a transaction */
    wire_query("begin");
    wire_complete("BEGIN");
    wire_ready('T');
    wire_query("select 1/0");
    wire_error("22012", "division by zero");
    wire_ready('E');
    wire_query("rollback");
    wire_complete("ROLLBACK");
    wire_ready('I');
    write_seed(root, "pg", "error_txn");

    /* COPY FROM STDIN */
    wire_query("copy t from stdin");
    b_reset();
    b_raw("\0", 1);
    b_be16(2);
    b_be16(0);
    b_be16(0);
    msg('G', body, bodylen);
    msg('d', "1\tfoo\n", 6);
    msg('d', "2\tbar\n", 6);
    msg('c', NULL, 0);
    wire_complete("COPY 2");
    wire_ready('I');
    write_seed(root, "pg", "copy_in");

    /* SSLRequest answered 'S' (stream goes dark), and answered 'N' + startup */
    be32(8);
    be32(80877103);
    put("S", 1);
    write_seed(root, "pg", "ssl_accepted");

    be32(8);
    be32(80877103);
    put("N", 1);
    wire_startup();
    wire_query("select 2");
    write_seed(root, "pg", "ssl_refused");

    /* CancelRequest */
    be32(16);
    be32(80877102);
    be32(4242);
    be32(0xfeedface);
    write_seed(root, "pg", "cancel");
}

/* --- norm seeds: SQL the lexer rules were written against (Р22) ------------ */

static void norm_seeds(const char *root)
{
    write_text(root, "simple", "SELECT * FROM t WHERE id = 42 AND name = 'bob';");
    write_text(root, "in_list", "select id from t where id in (1, 2, 3, 4, 5) limit 10");
    write_text(root, "values_multi", "insert into t (a, b) values (1, 'x'), (2, 'y'), (3, 'z')");
    write_text(root, "binds", "select a from t where a = $1 and b = $2 or c = ?");
    write_text(root, "dollar_quote", "select $tag$it's got 'quotes' inside$tag$, $$plain$$");
    write_text(root, "escapes", "select E'a\\'b', B'1010', X'deadbeef', U&'d!0061t' uescape '!'");
    write_text(root, "comments", "select 1 -- trailing\n/* block /* nested */ still */ + 2");
    write_text(root, "numbers", "select 1_000_000, 0xFF, 0o777, 0b1010, 1.5e-3, .5, 42.");
    write_text(root, "quoted_ident", "select \"MiXeD\", \"with \"\"quote\"\"\" from \"T\"");
    write_text(root, "multi_stmt", "select 1; select 2;  select 3");
    write_text(root, "unterminated", "select * from t where s = 'oo");
    write_text(root, "keywords",
               "with q as (select a, count(*) from t group by a having count(*) > 2 "
               "order by a desc) update u set b = null where exists (select 1 from q)");

    /* MySQL dialect (РМ9): every rule the MySQL lexer branch adds */
    write_text_my(root, "my_comments",
                  "select 1 # line\n-- spaced\n--glued\n/* flat /* not nested */ + 2");
    write_text_my(root, "my_versioned",
                  "insert /*! ignore */ into t values (1), (2) "
                  "/*!80013 on duplicate key update a = 3 */");
    write_text_my(root, "my_strings",
                  "select 'a\\'b', \"double\\\"quoted\", N'nat', _utf8mb4'intro', "
                  "_binary\"raw\", X'ff', B'1010', 0xFF, 0b01");
    write_text_my(root, "my_backtick", "select `From`, `a``b` from `T` where id in (1,2,3)");
    write_text_my(root, "my_unterminated", "select /*!50000 `oo");
}

/* --- pipe seeds: scenarios over the ops format ------------------------------ */

/* Emit one DATA op wrapping the wire bytes currently in wirebuf[wfrom..blen). */
static void sc_data(int slot, enum pipe_op dir_op, unsigned meta, const void *p, size_t n)
{
    if (n > PIPE_DATA_MAX) {
        fprintf(stderr, "gen_seeds: pipe payload too big\n");
        exit(1);
    }
    put_u8(PIPE_OP(dir_op, slot, (unsigned)(n >> 8)));
    put_u8(meta);
    put_u8((unsigned)(n & 0xff));
    put(p, n);
}

/* Capture wire bytes built by the wire_* helpers into a side snapshot. */
static uint8_t snap[4096];
static size_t snaplen;

static void snap_begin(void)
{
    snaplen = blen; /* remember where wire bytes start */
}

static void snap_end(void)
{
    size_t n = blen - snaplen;

    memcpy(snap, buf + snaplen, n);
    blen = snaplen;
    snaplen = n;
}

static void pipe_seeds(const char *root)
{
    unsigned clean = PIPE_DATA_SHAPE(PIPE_SHAPE_CONT);

    /* clean session: open, startup, auth, one query, close */
    put_u8(PIPE_OP(PIPE_OP_OPEN, 0, 0));
    snap_begin();
    wire_startup();
    snap_end();
    sc_data(0, PIPE_OP_RECV, clean, snap, snaplen);
    snap_begin();
    wire_auth_ok();
    wire_param("server_version", "16.3");
    wire_ready('I');
    snap_end();
    sc_data(0, PIPE_OP_SEND, clean, snap, snaplen);
    snap_begin();
    wire_query("select 1");
    snap_end();
    sc_data(0, PIPE_OP_RECV, clean, snap, snaplen);
    snap_begin();
    wire_row_desc();
    wire_data_row("1");
    wire_complete("SELECT 1");
    wire_ready('I');
    snap_end();
    sc_data(0, PIPE_OP_SEND, clean, snap, snaplen);
    put_u8(PIPE_OP(PIPE_OP_CLOSE, 0, 0));
    write_seed(root, "pipe", "clean_session");

    /* loss and recovery: a seq gap dirties both directions, the backend
     * resyncs on the Z anchor, the frontend on a call boundary (Р10/Р19) */
    put_u8(PIPE_OP(PIPE_OP_OPEN, 1, 0));
    snap_begin();
    wire_startup();
    wire_query("select 1");
    snap_end();
    sc_data(1, PIPE_OP_RECV, clean, snap, snaplen);
    snap_begin();
    wire_ready('I'); /* the anchor the resync scan hunts for */
    wire_row_desc();
    wire_data_row("1");
    wire_complete("SELECT 1");
    wire_ready('I');
    snap_end();
    sc_data(1, PIPE_OP_SEND, clean | PIPE_DATA_GAP, snap, snaplen);
    snap_begin();
    wire_query("select 2"); /* call boundary: frontend resync anchor */
    snap_end();
    sc_data(1, PIPE_OP_RECV, clean, snap, snaplen);
    put_u8(PIPE_OP(PIPE_OP_CLOSE, 1, 0));
    write_seed(root, "pipe", "gap_resync");

    /* TLS flip: SSLRequest + 'S', then the whole session again decrypted (Р38) */
    put_u8(PIPE_OP(PIPE_OP_OPEN, 2, 0));
    snap_begin();
    be32(8);
    be32(80877103);
    snap_end();
    sc_data(2, PIPE_OP_RECV, clean, snap, snaplen);
    sc_data(2, PIPE_OP_SEND, clean, "S", 1);
    snap_begin();
    wire_startup();
    snap_end();
    sc_data(2, PIPE_OP_RECV, clean | PIPE_DATA_DECRYPTED, snap, snaplen);
    snap_begin();
    wire_auth_ok();
    wire_ready('I');
    snap_end();
    sc_data(2, PIPE_OP_SEND, clean | PIPE_DATA_DECRYPTED, snap, snaplen);
    snap_begin();
    wire_query("select 'tls'");
    snap_end();
    sc_data(2, PIPE_OP_RECV, clean | PIPE_DATA_DECRYPTED, snap, snaplen);
    snap_begin();
    wire_row_desc();
    wire_data_row("tls");
    wire_complete("SELECT 1");
    wire_ready('I');
    snap_end();
    sc_data(2, PIPE_OP_SEND, clean | PIPE_DATA_DECRYPTED, snap, snaplen);
    put_u8(PIPE_OP(PIPE_OP_CLOSE, 2, 0));
    write_seed(root, "pipe", "tls_flip");

    /* churn: fresh cookies leak old entries, sweep and the LRU ceiling collect
     * them; a synthetic open joins mid-session via resync */
    for (int i = 0; i < 6; i++) {
        put_u8(PIPE_OP(PIPE_OP_OPEN, 3, PIPE_OPEN_FRESH));
        snap_begin();
        wire_query("select 3");
        snap_end();
        sc_data(3, PIPE_OP_RECV, clean, snap, snaplen);
    }
    put_u8(PIPE_OP(PIPE_OP_SWEEP, 0, 7));
    put_u8(PIPE_OP(PIPE_OP_OPEN, 3, PIPE_OPEN_FRESH | PIPE_OPEN_SYNTHETIC));
    snap_begin();
    wire_ready('I');
    wire_row_desc();
    snap_end();
    sc_data(3, PIPE_OP_SEND, clean, snap, snaplen);
    put_u8(PIPE_OP(PIPE_OP_CLOSE, 3, 0));
    write_seed(root, "pipe", "churn_sweep");

    /* capture holes: budget-cut tails and an intra-call hole over a big body */
    put_u8(PIPE_OP(PIPE_OP_OPEN, 0, 0));
    snap_begin();
    wire_startup();
    snap_end();
    sc_data(0, PIPE_OP_RECV, clean, snap, snaplen);
    snap_begin();
    wire_query("select repeat('x', 100000)");
    snap_end();
    /* tail sel 3 = 4096 uncaptured bytes after the payload */
    sc_data(0, PIPE_OP_RECV, PIPE_DATA_SHAPE(PIPE_SHAPE_NEW_TAIL) | PIPE_DATA_TAIL(3), snap,
            snaplen);
    sc_data(0, PIPE_OP_RECV, PIPE_DATA_SHAPE(PIPE_SHAPE_CONT_HOLE) | PIPE_DATA_TAIL(2), "zzzz", 4);
    put_u8(PIPE_OP(PIPE_OP_CLOSE, 0, 0));
    write_seed(root, "pipe", "capture_holes");

    /* raw records into decode: short, unknown type, and a data record whose
     * dir byte is garbage — corrupt-replay-file paths (LK_DEC_SHORT/UNKNOWN) */
    put_u8(PIPE_OP(PIPE_OP_RAW, 0, 0));
    put_u8(4);
    put("\x00\x01\x02\x03", 4); /* shorter than lk_ev_hdr */
    put_u8(PIPE_OP(PIPE_OP_RAW, 0, 0));
    put_u8(24);
    {
        /* full lk_ev_hdr with an unknown type byte */
        uint8_t hdr[24] = {0};

        hdr[0] = 0x34;
        hdr[1] = 0x12;  /* conn_id */
        hdr[20] = 0x77; /* type: unknown */
        put(hdr, sizeof(hdr));
    }
    put_u8(PIPE_OP(PIPE_OP_RAW, 0, 0));
    put_u8(44);
    {
        /* lk_ev_data-shaped record with dir = 0xEE: must be rejected, not
         * routed into frame[dir] (regression for the decode dir check) */
        uint8_t rec[44] = {0};

        rec[3] = 0xC0;  /* conn_id ~ slot 0 base (little-endian u64) */
        rec[20] = 0;    /* type: LK_EV_DATA */
        rec[21] = 0xEE; /* dir: garbage */
        rec[24] = 4;    /* total_len */
        rec[32] = 4;    /* cap_len */
        memcpy(rec + 40, "Q\0\0\0", 4);
        put(rec, sizeof(rec));
    }
    write_seed(root, "pipe", "raw_records");
}

/* --- mysql seeds: whole classic-protocol sessions (MYSQL.md М7) -------------
 * Raw wire bytes for fuzz_my (fed to both directions). Little-endian ints and
 * length-encoded scalars, one packet = len(u24) + seq(u8) + payload. */

static uint8_t mybody[4096];
static size_t myblen;

static void mb(unsigned v)
{
    mybody[myblen++] = (uint8_t)v;
}

static void mb_str(const char *s)
{
    while (*s)
        mybody[myblen++] = (uint8_t)*s++;
}

static void mb_lenstr(const char *s)
{
    size_t n = strlen(s);

    mb(n); /* lenenc length (< 251) */
    mb_str(s);
}

/* Emit the accumulated mybody as one packet with the given seq, reset it. */
static void mypkt(unsigned seq)
{
    put_u8(myblen);
    put_u8(myblen >> 8);
    put_u8(myblen >> 16);
    put_u8(seq);
    put(mybody, myblen);
    myblen = 0;
}

static void my_greeting(void)
{
    mb(10);          /* protocol version */
    mb_str("8.4.0");
    mb(0);           /* version NUL */
    for (int i = 0; i < 4; i++)
        mb(1);       /* thread id */
    for (int i = 0; i < 27; i++)
        mb(0);       /* auth data + caps + status + plugin-data-2 filler */
    mb_str("caching_sha2_password");
    mb(0);
    mypkt(0);
}

static void my_handshake_response(unsigned caps)
{
    mb(caps);
    mb(caps >> 8);
    mb(caps >> 16);
    mb(caps >> 24);
    for (int i = 0; i < 4; i++)
        mb(0);       /* max_packet */
    mb(0xff);        /* charset */
    for (int i = 0; i < 23; i++)
        mb(0);       /* filler */
    mb_str("root");
    mb(0);
    mb(0);           /* auth response length 0 */
    mb_str("test");
    mb(0);
    mb_str("caching_sha2_password");
    mb(0);
    mypkt(1);
}

static void mb16(unsigned v)
{
    mb(v);
    mb(v >> 8);
}

static void my_ok(unsigned seq, unsigned affected, unsigned status)
{
    mb(0x00);
    mb(affected);
    mb(0);           /* last_insert_id */
    mb16(status);
    mb16(0);         /* warnings */
    mypkt(seq);
}

static void my_seeds(const char *root)
{
    unsigned caps = 0x01192209u; /* PROTOCOL_41|CONNECT_WITH_DB|PLUGIN_AUTH|
                                  * DEPRECATE_EOF|... (fixtures_gen MY_FX_CAPS) */

    /* A full simple-query session: handshake, COM_QUERY, 1-row resultset. */
    my_greeting();
    my_handshake_response(caps);
    my_ok(2, 0, 0x0002);
    mb(0x03);
    mb_str("SELECT 1"); /* COM_QUERY */
    mypkt(0);
    mb(1);
    mypkt(1); /* column count = 1 */
    mb_lenstr("def");
    mb_lenstr("");
    mb_lenstr("");
    mb_lenstr("");
    mb_lenstr("c");
    mb_lenstr("");
    mb(0x0c);
    mb16(0x3f);
    for (int i = 0; i < 10; i++)
        mb(0);
    mypkt(2); /* column definition */
    mb_lenstr("1");
    mypkt(3); /* row */
    mb(0xfe);
    mb(0);
    mb(0);
    mb16(0x0002);
    mb16(0);
    mypkt(4); /* OK-0xFE terminator */
    write_seed(root, "my", "simple_session");

    /* An error reply to a query. */
    my_greeting();
    my_handshake_response(caps);
    my_ok(2, 0, 0x0002);
    mb(0x03);
    mb_str("SELECT * FROM missing");
    mypkt(0);
    mb(0xff);
    mb16(1146);
    mb('#');
    mb_str("42S02");
    mb_str("no such table");
    mypkt(1);
    write_seed(root, "my", "error_reply");

    /* A prepared-statement round-trip. */
    my_greeting();
    my_handshake_response(caps);
    my_ok(2, 0, 0x0002);
    mb(0x16);
    mb_str("SELECT ?"); /* COM_STMT_PREPARE */
    mypkt(0);
    mb(0x00);
    for (int i = 0; i < 4; i++)
        mb(i == 0 ? 1 : 0); /* stmt_id = 1 */
    mb16(1);               /* num_columns */
    mb16(1);               /* num_params */
    mb(0);
    mb16(0);
    mypkt(1); /* PREPARE_OK */
    mb(0x17);
    for (int i = 0; i < 4; i++)
        mb(i == 0 ? 1 : 0); /* COM_STMT_EXECUTE stmt_id 1 */
    mb(0);
    for (int i = 0; i < 4; i++)
        mb(i == 0 ? 1 : 0);
    mypkt(0);
    write_seed(root, "my", "prepared");

    /* A compressed / SSL handshake shape (framer blind-zone + TLS flip bits). */
    my_greeting();
    my_handshake_response(caps | 0x0020); /* CLIENT_COMPRESS */
    my_ok(2, 0, 0x0002);
    write_seed(root, "my", "compressed_handshake");

    my_greeting();
    my_handshake_response(caps | 0x0800); /* CLIENT_SSL */
    write_seed(root, "my", "ssl_request");
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: gen_seeds <corpus-root>  (writes into pg/ my/ norm/ pipe/)\n");
        return 1;
    }
    pg_seeds(argv[1]);
    my_seeds(argv[1]);
    norm_seeds(argv[1]);
    pipe_seeds(argv[1]);
    return 0;
}
