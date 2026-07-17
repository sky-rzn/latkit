#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
# М0 trace-corpus client: mysql-connector-python in pure-python mode (a wire
# implementation distinct from libmysqlclient/libmariadb used by the CLI and
# from Connector/J). One scenario per invocation:
#
#   scenarios.py HOST SCENARIO [CSV_PATH]
#
# prepared/cursor traffic here is the *binary* protocol (COM_STMT_PREPARE /
# COM_STMT_EXECUTE) — the mysql CLI's PREPARE ... FROM is textual COM_QUERY.
import sys

import mysql.connector

HOST, SCENARIO = sys.argv[1], sys.argv[2]
CSV = sys.argv[3] if len(sys.argv) > 3 else None

kw = dict(
    host=HOST,
    port=3306,
    user="root",
    password="secret",
    database="test",
    use_pure=True,
    connection_timeout=10,
)
if SCENARIO == "tls":
    kw["ssl_disabled"] = False
    kw["ssl_verify_cert"] = False
else:
    kw["ssl_disabled"] = True
if SCENARIO == "load-data":
    kw["allow_local_infile"] = True

conn = mysql.connector.connect(**kw)

if SCENARIO in ("simple", "tls"):
    cur = conn.cursor()
    cur.execute("SELECT * FROM t")
    cur.fetchall()
    cur.execute("SELECT id, s FROM t WHERE id > 2")
    cur.fetchall()
    cur.close()
elif SCENARIO == "prepared":
    cur = conn.cursor(prepared=True)
    cur.execute("SELECT * FROM t WHERE id = %s", (3,))
    cur.fetchall()
    cur.execute("SELECT * FROM t WHERE id = %s", (1,))  # re-execute, same stmt
    cur.fetchall()
    cur.execute("INSERT INTO t VALUES (%s, %s)", (100, "py-prep"))
    cur.execute("DELETE FROM t WHERE id = %s", (100,))
    conn.commit()
    cur.close()
elif SCENARIO == "error":
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM no_such_table")
    except mysql.connector.Error as e:
        print(f"expected error: {e.errno} {e.sqlstate}")
    cur.close()
elif SCENARIO == "transaction":
    conn.autocommit = False
    cur = conn.cursor()
    cur.execute("INSERT INTO t VALUES (200, 'txn-rollback')")
    conn.rollback()
    cur.execute("INSERT INTO t VALUES (201, 'txn-commit')")
    cur.execute("UPDATE t SET s = 'txn-upd' WHERE id = 201")
    conn.commit()
    cur.execute("DELETE FROM t WHERE id = 201")
    conn.commit()
    cur.close()
elif SCENARIO == "load-data":
    cur = conn.cursor()
    cur.execute(
        f"LOAD DATA LOCAL INFILE '{CSV}' INTO TABLE t_load "
        "FIELDS TERMINATED BY '\\t'"
    )
    conn.commit()
    cur.execute("SELECT COUNT(*) FROM t_load")
    print("loaded:", cur.fetchall())
    cur.execute("DELETE FROM t_load")
    conn.commit()
    cur.close()
elif SCENARIO == "multi":
    # Multi-statement in one COM_QUERY. Connector 9.2+ drains the result sets
    # with fetchsets(); older versions need execute(..., multi=True).
    cur = conn.cursor()
    op = "SELECT 1; SELECT * FROM t; DO SLEEP(0)"
    if hasattr(cur, "fetchsets"):
        cur.execute(op)
        cur.fetchsets()
        conn.consume_results()  # 9.x leaves the tail set pending on close
    else:
        for r in cur.execute(op, multi=True):
            if r.with_rows:
                r.fetchall()
    cur.close()
else:
    sys.exit(f"unknown scenario {SCENARIO}")

conn.close()
print(f"ok {SCENARIO}")
