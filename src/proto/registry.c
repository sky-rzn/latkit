// SPDX-License-Identifier: GPL-2.0
/* Protocol registry (РМ1) and the handler-base accessors shared by every
 * protocol. */
#include "proto.h"

#include <stdlib.h>
#include <string.h>

const struct lk_proto_ops *const lk_proto_registry[] = {
    &lk_proto_pg_ops, /* index 0 is the default (РМ2: a bare --port N is pg) */
    &lk_proto_my_ops, /* MySQL classic (М2): `--port 3306=mysql` */
};
const unsigned lk_proto_nregistry = sizeof(lk_proto_registry) / sizeof(lk_proto_registry[0]);

const struct lk_proto_ops *lk_proto_find(const char *name, size_t name_len)
{
    for (unsigned i = 0; i < lk_proto_nregistry; i++) {
        const char *n = lk_proto_registry[i]->name;

        if (strlen(n) == name_len && !memcmp(n, name, name_len))
            return lk_proto_registry[i];
    }
    return NULL;
}

/* --- shared handler-base accessors (Р15) ----------------------------------
 * A handler's own state lives in lk_conn.proto_state; the object itself is the
 * protocol-independent base (proto.h), so these need no per-protocol code. */

const struct lk_msg_sink *lk_proto_sink(struct lk_proto *p)
{
    return &p->msink;
}

const struct lk_proto_stats *lk_proto_stats(const struct lk_proto *p)
{
    return &p->st;
}

void lk_proto_free(struct lk_proto *p)
{
    free(p);
}
