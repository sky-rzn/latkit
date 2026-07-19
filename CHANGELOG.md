# Changelog

All notable changes to latkit are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the metric
nomenclature is treated as a public API, so any change to a metric name or its
label set is called out explicitly.

## [Unreleased]

### Added

- **MySQL / MariaDB support (classic protocol).** latkit now observes MySQL 5.7
  / 8.x and MariaDB 10.6+ to the same depth as PostgreSQL: simple and prepared
  statements, sessions, multi-statements and multi-resultsets, `LOAD DATA LOCAL
  INFILE`, transactions, and errors (errno + SQLSTATE), plaintext and over TLS
  via the same libssl uprobe channel. Select a port's wire protocol with
  `--port 3306=mysql` (a bare port number still defaults to `pg`); one agent can
  watch a 5432 and a 3306 at once. See
  [docs/notes-myproto.md](docs/notes-myproto.md) and the design plan in
  `MYSQL.md`.
- MySQL deploy stacks: [`deploy/demo-mysql`](deploy/demo-mysql) (the two-minute
  demo, plaintext + TLS profiles) and
  [`deploy/existing-mysql`](deploy/existing-mysql) (monitoring-only, for a
  MySQL/MariaDB you already run).
- Dashboards gained a **`proto`** template variable; all four work under
  `proto="pg"` and `proto="mysql"`.
- Accuracy validation extended with a MySQL track against
  `performance_schema.events_statements_summary_by_digest`
  ([docs/accuracy.md](docs/accuracy.md)).

### Changed

- **Metric label set: every query-family series now carries a
  `proto="pg"|"mysql"` label** (`latkit_query_duration_seconds`,
  `latkit_queries_total`, `latkit_query_errors_total`, `latkit_query_rows_total`
  and the transaction/first-row series). This is the only visible change for
  existing PostgreSQL users — the label is *added*, no metric is renamed or
  removed, and existing PromQL keeps working (an un-grouped query now simply
  spans both protocols). Grouping or joining by the full label set should add
  `proto`. Bundled dashboards and alerts are updated; a minor version, no major
  bump.
- `--tls auto` default `/proc` scan set is now `{postgres, mysqld, mariadbd}`
  (was `postgres`). `--tls-comm` still narrows it to a single comm.

### Notes

- **MySQL blind zones** (recognised and honestly counted, not parsed): the X
  Protocol (port 33060), the compressed protocol (`CLIENT_COMPRESS`), and
  replication streams (`COM_BINLOG_DUMP`). MariaDB builds linking bundled
  wolfSSL/GnuTLS instead of OpenSSL cannot have their TLS decrypted (detected
  and dropped-and-counted). See [README](README.md) "Known limitations".
