# latkit — план разработки

eBPF-агент (C + libbpf) для наблюдения за PostgreSQL: перехват трафика на уровне сокетов, парсинг wire-протокола v3, метрики latency по запросам, экспорт в Prometheus и OpenTelemetry. Без собственного бэкенда — данные читает Grafana из Prometheus / OTel-совместимого хранилища.

---

## 1. Общая архитектура

```
                 ядро                                userspace (агент, C)
┌─────────────────────────────────┐   ringbuf   ┌──────────────────────────────┐
│ BPF-программы:                  │ ──────────▶ │ event loop (epoll)           │
│  fentry/fexit tcp_sendmsg/      │  события    │  └ reassembler (по соединению)│
│  tcp_recvmsg (+ sockops для     │  {conn_id,  │  └ парсер протокола PG v3     │
│  трекинга соединений)           │   ts, dir,  │  └ нормализация запросов      │
│  uprobes SSL_read/SSL_write     │   payload}  │  └ агрегатор метрик           │
│  (для TLS)                      │             │     (гистограммы latency)     │
└─────────────────────────────────┘             └───────┬──────────────┬───────┘
                                                        │              │
                                                 HTTP /metrics    OTLP/gRPC|HTTP
                                                        │              │
                                                  Prometheus     OTel Collector
                                                        └──────┬───────┘
                                                            Grafana
```

Ключевой принцип разделения: **в ядре — минимум** (фильтрация по порту/процессу, захват сырых фрагментов payload с таймстемпами и id соединения), **в userspace — всё остальное** (сборка TCP-потока, разбор сообщений протокола, нормализация SQL, агрегация). Парсить протокол в BPF нельзя всерьёз: сообщения рвутся по сегментам TCP, verifier ограничивает циклы и размер программы.

### Модель latency

Агент ставится на хост с PostgreSQL и измеряет **серверное** время обработки:

- simple query: от прихода `Query ('Q')` до `ReadyForQuery ('Z')`;
- extended protocol: от `Bind/Execute` до `ReadyForQuery` после `Sync` (учесть pipelining — очередь незакрытых Execute на соединение);
- дополнительно: время до первой строки (`DataRow`), число строк из `CommandComplete`, ошибки из `ErrorResponse` (код SQLSTATE).

---

## 2. Технологический стек

| Компонент | Выбор | Обоснование |
|---|---|---|
| BPF loader | libbpf + CO-RE (BTF, `vmlinux.h`) | один бинарник на разные ядра, без зависимости от clang в рантайме |
| Захват | `fentry/fexit` на `tcp_sendmsg`/`tcp_recvmsg` (fallback: kprobes для ядер без BTF-trampoline) | видно payload и sock* в одной точке |
| TLS | uprobes на `SSL_read`/`SSL_write`/`SSL_read_ex`/`SSL_write_ex` в libssl процесса postgres | на уровне сокета TLS-трафик зашифрован |
| Транспорт ядро→юзер | `BPF_MAP_TYPE_RINGBUF` | требование: ядро ≥ 5.8; порядок событий, меньше потерь чем perf buffer |
| Сборка | CMake (или Makefile) + clang для BPF-объектов, `bpftool gen skeleton` | стандартный пайплайн libbpf |
| Prometheus | собственный минимальный HTTP-сервер `/metrics` (text exposition format) | формат тривиален, зависимость не нужна |
| OpenTelemetry | OTLP/HTTP + protobuf (сериализация вручную или через `protobuf-c`) | opentelemetry-cpp тянуть в C-проект не хочется; OTLP/HTTP-схема стабильна |
| Тесты | unit — парсер на записанных дампах; e2e — docker: postgres + pgbench | |
| Минимальное ядро | **5.15+ с BTF** (проверяется матрицей 5.15/6.1/6.8/stable, этап 8) | floor зафиксирован в README и `docs/deploy.md`; ниже 5.15 не тестируется и не обещается, без BTF — внятный отказ, не тихие нули (Р52) |

---

## 3. Структура репозитория

```
latkit/
├── src/
│   ├── bpf/
│   │   ├── latkit.bpf.c        # fentry/fexit tcp_*, sockops, uprobes SSL
│   │   ├── latkit.h            # общие структуры событий (ядро↔юзер)
│   │   └── vmlinux.h           # сгенерированный BTF-хедер
│   ├── agent/
│   │   ├── main.c              # CLI, конфиг, жизненный цикл
│   │   ├── loader.c            # загрузка skeleton, аттач, фильтры
│   │   ├── events.c            # чтение ringbuf, диспетчеризация
│   │   ├── conn_table.c        # таблица соединений, LRU, таймауты
│   │   ├── reassembly.c        # сборка потока сообщений из фрагментов
│   │   └── loop.c              # epoll-петля (HTTP-сервер и OTLP-клиент — там же)
│   ├── export/                 # экспортеры (этап 5): http.c (/metrics,
│   │   │                       #   /healthz), prom.c, pbuf.c, otlp.c, spans.c,
│   │   │                       #   timebase.c — зависят от metrics/ + loop.h,
│   │   │                       #   без libbpf (см. STAGE5.md, отклонение §3)
│   ├── proto/                  # код протоколов, единый API «ядро↔обработчик»
│   │   ├── proto.h             # оба контракта: вниз lk_msg_sink, вверх lk_query_sink
│   │   └── pg/                 # обработчик PostgreSQL v3 (был agent/pgproto.c)
│   │       ├── pg.c            # диспетчер по (направление, фаза, тип)
│   │       ├── pg_session.c    # startup, auth, лейблы сессии
│   │       ├── pg_query.c      # фазовая машина, in-flight очередь, тайминги
│   │       ├── pg_prep.c       # кэш prepared statements
│   │       └── pg_wire.h       # bounded cursor (недоверенный вход)
│   ├── norm/                   # нормализатор SQL (этап 4, было agent/normalize.c)
│   │   └── norm_sql.c/.h       # однопроходный лексер + XXH3-64 fingerprint
│   ├── metrics/                # метрики (этап 4, было agent/metrics.c)
│   │   ├── metrics.c/.h        # фасад, aggregator (lk_query_sink), провайдеры, dump
│   │   ├── registry.c/.h       # реестр рядов, top-K LRU, doorkeeper, other
│   │   ├── hist.c/.h           # экспоненциальная гистограмма (schema=2)
│   │   └── selfstats.c/.h      # process_* (getrusage, /proc/self)
│   └── common/                 # лог, конфиг, утилиты
├── tests/
│   ├── unit/                   # парсер, нормализация, reassembly
│   ├── fixtures/               # pcap/бинарные дампы PG-трафика
│   └── e2e/                    # docker-compose: pg + pgbench + агент + prometheus + grafana
├── dashboards/                 # JSON-дашборды Grafana
├── deploy/                     # systemd unit, Dockerfile, k8s DaemonSet
├── docs/
└── PLAN.md
```

---

## 4. Этапы разработки

### Этап 0 — PoC и обвязка (~1 неделя)
- [ ] Скелет проекта: сборка libbpf-приложения (CMake, clang → `.bpf.o` → skeleton), CI (GitHub Actions: build + clang-format + unit-тесты).
- [ ] PoC: fentry на `tcp_recvmsg`/`tcp_sendmsg`, фильтр по порту 5432, вывод первых байт payload в ringbuf → hexdump в userspace. Цель — убедиться, что видим трафик `psql` в обе стороны.
- [ ] Решить вопрос чтения payload: на send — обход `iov_iter` из `msghdr` (ограниченный unroll, `bpf_probe_read_user`); на recv — fexit, читаем уже скопированные данные по сохранённому в map указателю iov (по паре fentry/fexit через `BPF_MAP_TYPE_HASH` keyed by pid_tgid).
- [ ] Docker-окружение для разработки: postgres + pgbench.

**Выход:** сырые байты протокола PG видны в userspace. Это главный технический риск проекта — снять его первым.

### Этап 1 — слой захвата (BPF) (~1–2 недели)
- [ ] Идентификация соединения: `conn_id = {netns, saddr, sport, daddr, dport}` или указатель на `struct sock` + generation. События `CONN_OPEN`/`CONN_CLOSE` (sockops или `inet_sock_set_state`).
- [ ] Фильтрация в ядре: конфигурируемый порт(ы) через `BPF_MAP_TYPE_HASH`; опционально фильтр по cgroup (k8s) и/или comm `postgres`.
- [ ] Формат события: `{conn_id, ts_ns (bpf_ktime_get_ns), direction, seq, len, truncated_flag, payload[CHUNK]}`; CHUNK ≈ 4 КБ, длинные записи режем на несколько событий с seq.
- [ ] Обработка потерь: счётчик drop'ов ringbuf → метрика агента; при потере фрагмента соединение помечается «грязным» и парсер ресинхронизируется (см. этап 3).
- [ ] Бюджет захвата: лимит байт на сообщение (для latency достаточно заголовков и первых N байт `Q`/`P`; `DataRow` можно не копировать целиком — только тип и длину). Это резко снижает overhead.

### Этап 2 — userspace-пайплайн (~1 неделя)
- [ ] Event loop: `ring_buffer__poll` + epoll (HTTP-сервер, таймеры) в одном потоке; агрегация lock-free или под одним мьютексом — профилировать позже.
- [ ] Таблица соединений: hash map conn_id → state; LRU-вытеснение, таймаут неактивных, корректная очистка по `CONN_CLOSE`.
- [ ] Reassembly: на соединение — по буферу на направление; склейка фрагментов, выделение целых сообщений `тип(1) + len(4) + body`. Ресинхронизация после потерь: ждать `ReadyForQuery`-границу / новое соединение.

### Этап 3 — парсер протокола PostgreSQL v3 (~1–2 недели) — детализация в [STAGE3.md](STAGE3.md)
- [x] Выделение кода парсинга протокола PostgreSQL в отдельный модуль: в дальнейшем предполагается парсить и другие протоколы, код работы с ними должен лежать в отдельном каталоге, а API между ядром и обработчиками протоколов единым и четким. → `src/proto/` (контракты в `proto.h`), обработчик PG — `src/proto/pg/`.
- [x] Startup-фаза: `StartupMessage` (без байта типа!), `SSLRequest`/`GSSENCRequest` (ответ 'S' → соединение помечается TLS, socket-события по нему игнорируем — ждём uprobe-канал), `AuthenticationOk`, параметры `user`/`database` → лейблы.
- [x] Frontend: `Q` (simple), `P` (Parse: имя стейтмента + SQL), `B` (Bind), `E` (Execute), `S` (Sync), `X` (Terminate), `C` (Close), `D` (Describe), `F` (FunctionCall), `d/c/f` (COPY).
- [x] Backend: `Z` (ReadyForQuery + статус транзакции), `C` (CommandComplete + тег → число строк), `T`, `D` (считаем, не парсим), `E` (ErrorResponse → SQLSTATE), `N`, `A` (NOTIFY), `s` (portal suspended).
- [x] State machine per connection: очередь in-flight запросов (extended protocol с pipelining), сопоставление ответов запросам, привязка prepared statement name → SQL из `Parse` (кэш на соединение + учёт unnamed statement).
- [x] Крайние случаи: COPY-режим, длинные запросы (обрезанные по бюджету захвата — фингерпринт по префиксу с пометкой), multi-statement `Q` (`select 1; select 2`), отмена запроса (CancelRequest — отдельное соединение).
- [x] Unit-тесты на дампах: детерминированные фикстуры из `tests/replay/fixtures_gen.c` (`tests/fixtures/*.lkt`); покрыты simple, extended, pipeline, ошибки, COPY, multi-statement, cancel, обрыв соединения; fuzz-харнесс `bytes → lk_msg → парсер` (`tests/fuzz`, ASAN/UBSAN).

### Этап 4 — нормализация запросов и метрики (~1 неделя) — детализация в [STAGE4.md](STAGE4.md), заметки [docs/notes-metrics.md](docs/notes-metrics.md)
- [x] Нормализация SQL (как pg_stat_statements, но без парсера PG): лексер-токенизатор — литералы/числа → `?`, схлопывание списков `IN (...)`, нижний регистр ключевых слов, схлопывание whitespace; fingerprint = 64-bit hash (xxhash). → `src/norm/`, `$N` тоже сворачивается в `?` (осознанное отклонение, Р22).
- [x] Контроль кардинальности: LRU top-K нормализованных запросов (конфигурируемый K, по умолчанию 500), остальное — в bucket `other`; плюс doorkeeper (допуск со 2-го появления) и лимиты на `(db,user)` и SQLSTATE (Р23). Это критично для Prometheus.
- [x] Метрики (нативные гистограммы + классические бакеты, лог-шкала 0.1ms…60s, `src/metrics/`):
  - `latkit_query_duration_seconds{query, db, user, code}` — histogram (`code`=ok|error, Р23);
  - `latkit_query_rows_total`, `latkit_queries_total`, `latkit_query_errors_total{sqlstate}`;
  - `latkit_connections_active`, `latkit_connections_opened_total`;
  - `latkit_txn_duration_seconds` (по статусу из `ReadyForQuery`: T→I ok / E→I aborted);
  - self-метрики через провайдеры (Р27): `latkit_ringbuf_dropped_total`, `latkit_parse_errors_total`, `latkit_resync_total`, `latkit_queries_dropped_total{reason}`, `process_*` (CPU/mem агента).
- [x] Лейбл `query` — нормализованный текст, усечённый до N символов (`--query-label-len`); полный текст — только в OTel-спаны/exemplars (этап 5), не в Prometheus.
- [x] Валидация M2: replay-ассерты по дампу для каждой фикстуры этапа 3 (число рядов, count/sum, ноль наблюдений через разрыв — Р19); стресс кардинальности (`test_cardinality_ceiling`); дамп — валидный exposition (`--dump-metrics`, промтул/ручная проверка).

### Этап 5 — экспортеры (~1 неделя) — детализация в [STAGE5.md](STAGE5.md), заметки [docs/notes-export.md](docs/notes-export.md)
- [x] Prometheus: HTTP-сервер `/metrics` (text format), `/healthz` (`src/export/http.c`, `prom.c`); классические `le`-бакеты; exemplars (trace_id) — отложены (шов есть, Р30/Р32).
- [x] OpenTelemetry: OTLP/HTTP protobuf в Collector — метрики (`Sum`/`Gauge`/`ExponentialHistogram`, ручной `pbuf.c`), спаны на сэмплированные запросы (точные тайминги + полный SQL, `spans.c`). Конфиг: endpoint, headers, интервал, resource-атрибуты, ratio/slow-ms.
- [x] Оба экспортера независимо включаемы; конфиг — **флаги + env** (`LATKIT_*` + стандартные `OTEL_*`, приоритет флаг > env > дефолт); **YAML отложен** (Р34, по реальному спросу).

### Этап 6 — TLS (~1–2 недели) — детализация в [STAGE6.md](STAGE6.md), заметки [docs/notes-tls.md](docs/notes-tls.md)
- [x] uprobes на `SSL_read/SSL_write(_ex)` в `libssl.so` (путь автодетектом через `/proc/<pid>/maps` процессов postgres); сопоставление SSL* ↔ fd ↔ conn_id (`SSL_set_fd`-walk `fd→sock→cookie` как основной мост + nested-syscall корреляция в `tcp_*` как fallback, Р37); плейнтекст едет через тот же framer→парсер→метрики без правок `src/proto|norm|metrics|export`.
- [x] Дедупликация: если соединение TLS — источник данных только uprobes (`LK_F_DECRYPTED`), ciphertext socket-события отбрасываются и считаются (`latkit_tls_socket_events_dropped_total`); флаг `LK_CONN_TLS` ставится при виде ответа 'S'/'G'; раздельные seq-пространства (Р38), сброс framer'а в startup внутри TLS (Р36).
- [x] Автодетект libssl и жизненный цикл (`--tls auto|off`, `--libssl`, `--tls-comm`, +env; контейнеры через `/proc/<pid>/root`; ре-скан новых путей; `pid=-1` покрывает fork'и); self-метрики Р41; e2e `ssl=on`+`sslmode=require` (`tests/e2e/verify-tls.sh`).
- [x] Ограничения зафиксированы в docs (`docs/notes-tls.md` §6, README): статически слинкованный OpenSSL, не-OpenSSL (GnuTLS/NSS), BoringSSL (untested), GSSENC — вне scope v1, с явным поведением «детект TLS + drop-and-count», не тихая порча.

### Этап 7 — Grafana, упаковка, документация (~1 неделя) — детализация в [STAGE7.md](STAGE7.md)
- [x] Дашборды (JSON в `dashboards/`): обзор (QPS, p50/p95/p99, error rate, соединения), top-N запросов по p99/времени/частоте, детализация по db/user, health агента. Datasource — переменная (Prometheus/Mimir). → четыре дашборда с фиксированными uid (Р42), top-N только через `topk()`; `dashboards/lint.sh` в CI сверяет имена метрик из `expr` с живым реестром.
- [x] `docker-compose` demo-стек: postgres + pgbench + latkit + prometheus + grafana с provisioned-дашбордами — «увидеть ценность за 5 минут». → `deploy/demo/` (Р43), профиль `tls` включает демонстрацию этапа 6 одной строчкой; требования и хронометраж — в `deploy/demo/README.md`.
- [x] Упаковка: статический бинарник (musl или glibc + static libbpf/libelf/zlib); Dockerfile (privileged либо `CAP_BPF+CAP_PERFMON+CAP_SYS_RESOURCE`, hostPID для uprobes); systemd unit; k8s DaemonSet. → musl full-static (Р45, glibc-fallback не понадобился), scratch-образ ≈4 МБ (Р46), unit с песочницей + DaemonSet (Р47); минимальный CAP-набор измерен опытным путём (uprobes требуют `CAP_SYS_ADMIN` — см. `docs/deploy.md`); релиз по тегу `v*` — `release.yml` (тарбол + ghcr.io).
- [x] Фильтр захвата по cgroup — отложен из этапа 1 (задача 1.3): нужен для k8s (несколько postgres на хосте, порты совпадают); в v1 фильтр — локальный порт + опционально comm. → закрыт (Р48): карта cgroup id + глоб-пути + ре-резолв 30 с; «и»-семантика с портом/comm; требует cgroup v2 (v1-хост — фатальная ошибка); подтверждён на kind с двумя postgres-подами на одном порту.
- [x] README: требования к ядру, capabilities, конфигурация, ограничения, security-замечание (агент видит текст SQL — маскирование литералов включено по умолчанию). → переписан по Р44 (quickstart, установка ×4, модель измерения, security, консолидированные ограничения v1); таблица флагов/env сверяется с `--help` тестом `tests/unit/readme_flags.sh` — расхождение красит CI.

### Этап 8 — hardening и производительность (~1–2 недели) — детализация в [STAGE8.md](STAGE8.md)
- [x] Нагрузочное тестирование: pgbench (TPC-B и select-only, 100+ соединений), измерить overhead на TPS/латентность БД с агентом и без. Бюджет: <3% TPS, <1 CPU core на ~50k qps. → закрыт (Р49, задача 8.1): ΔTPS ±0.2% (< 3%) на plaintext и TLS обеих нагрузок; агент 0.31 (plaintext) / 0.45 (TLS) cores / 50k qps (< 1); методика ABAB, ворота валидны только при нулевых потерях — правило поймало три реальных бага TLS-захвата. Числа, условия, профили — [docs/perf.md](docs/perf.md).
- [x] Валидация точности: сравнить p50/p95 агента с `pg_stat_statements.mean_exec_time` и `log_min_duration_statement` на контролируемой нагрузке; расхождение задокументировать (агент видит время «сеть-до-сети», PG — только execute). → закрыт (Р50, задача 8.2): join через собственный нормализатор по csvlog; count точно (34 804 стейтмента, 0 потерь), p50/p95 adj ≤0.01% на ≥1 мс; смещение +9.0 мкс simple / +22.5 мкс extended (взвешенно) задокументировано как характеристика модели измерения — [docs/accuracy.md](docs/accuracy.md).
- [x] Fuzzing парсера (libFuzzer на `src/proto/pg/` + `normalize.c`) — вход недоверенный; харнесс и корпус заложены в этапе 3 (`tests/fuzz`, `lk_pg_fuzz_one`). → закрыт (Р51, задача 8.3): три таргета — fuzz_pg, fuzz_norm и структурный fuzz_pipe (сценарий событий через decode+conn_table+framer+парсер+нормализатор); инварианты Р51 assert'ами (включая сквозной Р19: после потери первое сообщение — только AFTER_RESYNC); кампания 32 CPU-часа чисто на финальной ревизии; минимизированный корпус и pg.dict в репо; CI — corpus-регрессия + 60 с/таргет на PR, nightly 15 мин/таргет. Находка в продукте одна: decode не валидировал `dir` битой записи (OOB `frame[dir]` с повреждённой `--record`-трассы) — исправлено.
- [x] Матрица ядер: проверка на 5.15 / 6.1 / 6.8+ (vmtest или qemu в CI); graceful degradation без BTF. → закрыт (Р52, задача 8.4): vmtest + ядра `cilium/ci-kernels`, plaintext+TLS-smoke, `iter_unsupported=0` на всех четырёх (5.15.210/6.1.176/6.8.10/7.1.1); CO-RE-ветки iov/__iov/ubuf + перенумерованный `iter_type` + арность `tcp_recvmsg` — в `latkit.bpf.c`/`docs/notes-iov.md`; no-BTF → «kernel 5.15+ with BTF required», не сегфолт.
- [x] Утечки: valgrind/ASAN в CI; long-run тест 24h с чурном соединений. → закрыт (Р53, задача 8.5): nightly valgrind memcheck на replay (чист); 10-ч soak с чурном+индуцированными потерями+рестартами — `VERDICT: PASS` (RSS-плато 21.9 MiB разброс 0.07%, fd 163→163, все 532 resync только в recovery-окнах, карты байт-в-байт). Находка (лог-спам под TLS-чурном) фикснута. Числа — [docs/perf.md](docs/perf.md).
- [x] Оптимизации по данным (Р54, задача 8.6): каждая заготовка этапов 2–6 получила решение go/v1.1/drop — **0 go, 3 v1.1, 5 drop** (ни один профиль не дал ≥10%-концентрации, ворота пройдены 2×). Ни одна отложенная оптимизация не висит без обоснования — таблица в [docs/perf.md](docs/perf.md).

---

## 5. Риски и открытые вопросы

| Риск | Митигция |
|---|---|
| Чтение `iov_iter` в BPF хрупко между версиями ядра | CO-RE + `bpf_core_field_exists`; fallback-вариант на sockmap/sk_msg; снять риск в PoC (этап 0) |
| Потери событий ringbuf под нагрузкой → битые измерения | бюджет захвата (только заголовки + префиксы), счётчики drop, ресинхронизация парсера, метрика честности данных; **измерено (этап 8)**: на цели 50k qps — ноль потерь; потолок пайплайна ~150–200k qps/core, за ним потери *считаются, не молчат* (saturation probe); 10-ч soak — ноль потерь вне индуцированных окон ([docs/perf.md](docs/perf.md)) |
| Взрыв кардинальности метрик | нормализация + top-K LRU + `other`; лимит на длину лейбла; со стороны потребителя — дашборды строятся только на `topk()` поверх агрегатов, ни одной панели с неограниченным множеством рядов (Р42) |
| TLS повсеместен в проде | ✅ этап 6 закрыт: uprobes на `libssl` (`--tls auto`, host+контейнер), плейнтекст через тот же пайплайн; ограничения (статик OpenSSL / GnuTLS / BoringSSL / GSSENC) документированы с явным «детект+drop» ([docs/notes-tls.md](docs/notes-tls.md)) |
| Unix domain sockets (локальные клиенты идут через `unix_stream_sendmsg`, не tcp_*) | **known gap v1.1**: отдельные хуки на `unix_stream_sendmsg/recvmsg` |
| GSSENC (ответ `'G'`, Kerberos-шифрование через libgssapi) | **known gap v1.1**: детектится (флаг TLS ставится и на `'G'`), ciphertext дропается и считается; uprobe-путь для libgssapi отложен |
| Точность: измеряем на сервере, но в тайминг входит ядро/сеть до userspace PG | честно описать модель измерения; **измерено (этап 8, Р50)**: агент ≥ лог систематически, смещение +9.0 мкс simple / +22.5 мкс extended на loopback; count точно, p50/p95 adj ≤0.01% на ≥1 мс ([docs/accuracy.md](docs/accuracy.md)) |

## 6. Вехи

- **M1 (конец этапа 1):** сырой захват PG-трафика стабилен, потери учитываются. ✅
- **M2 (конец этапа 4):** `psql`/pgbench-нагрузка → корректные latency-гистограммы по нормализованным запросам (plaintext). ✅ — дамп реестра (`--dump-metrics`) — валидный Prometheus text exposition; имена рядов зафиксированы как публичный API (см. [docs/notes-metrics.md](docs/notes-metrics.md)).
- **M3 (конец этапа 5):** метрики в Prometheus и OTel Collector, читаются Grafana. ✅ — оба экспортера работают одновременно; e2e-стенд ([tests/e2e/](tests/e2e)) подтверждает pull (`/metrics`) и push (OTLP: `Sum`/`ExponentialHistogram` + спаны), значения сходятся; живой Collector — строгий валидатор protobuf (поймал `fixed64` wire-type в `ExponentialHistogramDataPoint`).
- **v1.0 (конец этапа 8):** TLS, демо-стек, дашборды, подтверждённый overhead <3%, документация. ✅ — бюджет подтверждён числами (ΔTPS ±0.2%, агент < 0.5 core / 50k qps, [docs/perf.md](docs/perf.md)); точность измерена и записана ([docs/accuracy.md](docs/accuracy.md)); три фазз-таргета чисты на 32 CPU-часах; матрица ядер 5.15/6.1/6.8/stable зелёная (plaintext+TLS); 10-ч soak по критериям Р53 без вмешательства; заготовки Р54 закрыты решениями (0 go). Floor — 5.15+BTF.

Суммарная оценка: **8–11 недель** одним разработчиком.
