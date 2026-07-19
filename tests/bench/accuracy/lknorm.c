// SPDX-License-Identifier: GPL-2.0
/* lknorm (MYSQL.md М7): a thin CLI over the agent's own lk_norm_sql, so an
 * accuracy stand can normalise a reference view's statement text through the
 * EXACT normaliser the agent links — same fingerprint, same canonical label —
 * without reimplementing the lexer in the join script. The MySQL accuracy
 * stand (run-mysql.sh) feeds it the performance_schema DIGEST_TEXT so a server
 * digest lands on the agent series that counted the same statements; the PG
 * accuracy join does the same in-process in logjoin.
 *
 *   lknorm [-m]           read SQL statements from stdin, one per line; print
 *                         one TSV line per input: "<fp-hex>\t<canonical text>".
 *                         -m selects the MySQL dialect (default: pg).
 *
 * Empty input lines pass through as an empty canonical text (fp of no tokens),
 * so line numbering is preserved for a paste-alongside join. */
#include <stdio.h>
#include <string.h>

#include "norm_sql.h"

int main(int argc, char **argv)
{
    enum lk_sql_dialect dialect = LK_SQL_PG;
    char line[8192];

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-m"))
            dialect = LK_SQL_MYSQL;
        else {
            fprintf(stderr, "usage: %s [-m] < statements\n", argv[0]);
            return 2;
        }
    }

    while (fgets(line, sizeof(line), stdin)) {
        struct lk_norm_out out;
        size_t n = strlen(line);

        if (n && line[n - 1] == '\n')
            line[--n] = '\0';
        lk_norm_sql(line, n, dialect, &out);
        printf("%016llx\t%s\n", (unsigned long long)out.fp, out.text);
    }
    return 0;
}
