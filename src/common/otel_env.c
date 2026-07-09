// SPDX-License-Identifier: GPL-2.0
/* See otel_env.h. */
#include "otel_env.h"

#include <stdlib.h>
#include <string.h>

#define LK_MAX_PAIRS 64

char **lk_split_pairs(const char *s, int *n)
{
    char **arr;
    int count = 0;

    *n = 0;
    if (!s || !s[0])
        return NULL;
    arr = calloc(LK_MAX_PAIRS, sizeof(*arr));
    if (!arr)
        return NULL;

    while (*s && count < LK_MAX_PAIRS) {
        const char *comma = strchr(s, ',');
        const char *end = comma ? comma : s + strlen(s);
        const char *b = s, *e = end;
        size_t len;
        char *item;

        while (b < e && (*b == ' ' || *b == '\t'))
            b++;
        while (e > b && (e[-1] == ' ' || e[-1] == '\t'))
            e--;
        len = (size_t)(e - b);
        if (len && memchr(b, '=', len)) { /* keep only well-formed "k=v" */
            item = malloc(len + 1);
            if (item) {
                memcpy(item, b, len);
                item[len] = '\0';
                arr[count++] = item;
            }
        }
        if (!comma)
            break;
        s = comma + 1;
    }
    if (!count) {
        free(arr);
        return NULL;
    }
    *n = count;
    return arr;
}

void lk_free_pairs(char **arr, int n)
{
    if (!arr)
        return;
    for (int i = 0; i < n; i++)
        free(arr[i]);
    free(arr);
}
