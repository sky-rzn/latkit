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

- **HTTP metric families and the `latkit-http` dashboard** (PLAN-HTTP.md М5).
  Observations from an `--port 8080=http` port are reported under their own
  family set rather than borrowed database ones:
  `latkit_http_requests_total{route,method,host,user,proto,status}`,
  `latkit_http_request_duration_seconds{…,code}`, `latkit_http_ttfb_seconds`,
  `latkit_http_request_upload_seconds`,
  `latkit_http_errors_total{code,host,user,proto}`,
  `latkit_http_bytes_total{…,direction}` and
  `latkit_http_response_size_bytes` (an octave grid, 64 B … 1 GiB, separate from
  the latency one). `route` is the *template*, bounded by the same top-K
  dictionary the `query` label uses; the share of `route="other"` is on the
  dashboard as the honesty signal for how well the templater is doing.
  The four timings of РH5 are visible here: duration and TTFB both start at the
  *end of the request*, so a slow upload is not reported as a slow server, and
  the upload interval is its own family.
- `latkit_ignored_conns_total{reason}` gained `h2`, `upgrade` and `connect` —
  the HTTP blind zones, split by what the connection switched to (they replace
  the single `blind` reason introduced during the HTTP track's development).

### Changed

- **Renamed self-metric: `latkit_http_requests_total` →
  `latkit_exporter_requests_total`** (labels `{path,code}` unchanged). The old
  name described the agent's *own* `/metrics` server; with HTTP observation it
  would have collided with the traffic being observed. This is the one breaking
  change of the HTTP track: alerts or dashboards referring to the agent's
  exporter request count must be updated. The bundled dashboards already are.
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
