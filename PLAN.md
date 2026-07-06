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
| Минимальное ядро | 5.8+ (ringbuf), целимся в 5.15+/6.x | зафиксировать в README |

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
│   │   ├── normalize.c         # фингерпринт SQL (литералы → $N)
│   │   ├── metrics.c           # гистограммы, счётчики, top-N
│   │   ├── prom.c              # HTTP /metrics
│   │   └── otlp.c              # экспорт OTLP
│   ├── proto/                  # код протоколов, единый API «ядро↔обработчик»
│   │   ├── proto.h             # оба контракта: вниз lk_msg_sink, вверх lk_query_sink
│   │   └── pg/                 # обработчик PostgreSQL v3 (был agent/pgproto.c)
│   │       ├── pg.c            # диспетчер по (направление, фаза, тип)
│   │       ├── pg_session.c    # startup, auth, лейблы сессии
│   │       ├── pg_query.c      # фазовая машина, in-flight очередь, тайминги
│   │       ├── pg_prep.c       # кэш prepared statements
│   │       └── pg_wire.h       # bounded cursor (недоверенный вход)
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

### Этап 4 — нормализация запросов и метрики (~1 неделя)
- [ ] Нормализация SQL (как pg_stat_statements, но без парсера PG): лексер-токенизатор — литералы/числа → `?`, схлопывание списков `IN (...)`, нижний регистр ключевых слов, схлопывание whitespace; fingerprint = 64-bit hash (xxhash).
- [ ] Контроль кардинальности: LRU top-K нормализованных запросов (конфигурируемый K, по умолчанию ~500), остальное — в bucket `other`. Это критично для Prometheus.
- [ ] Метрики (нативные гистограммы + классические бакеты, лог-шкала 0.1ms…60s):
  - `latkit_query_duration_seconds{query, db, user, code}` — histogram;
  - `latkit_query_rows_total`, `latkit_queries_total`, `latkit_query_errors_total{sqlstate}`;
  - `latkit_connections_active`, `latkit_connections_opened_total`;
  - `latkit_txn_duration_seconds` (по статусу из `ReadyForQuery`: I/T/E);
  - self-метрики: `latkit_ringbuf_dropped_total`, `latkit_parse_errors_total`, `latkit_resync_total`, CPU/mem агента.
- [ ] Лейбл `query` — нормализованный текст, усечённый до N символов; полный текст — только в OTel-спаны/exemplars (не в Prometheus).

### Этап 5 — экспортеры (~1 неделя)
- [ ] Prometheus: HTTP-сервер `/metrics` (text format), `/healthz`; сериализация гистограмм; exemplars (trace_id) — опционально.
- [ ] OpenTelemetry: OTLP/HTTP protobuf в Collector — метрики (те же), опционально спаны на каждый запрос (sampling), которые дают точные тайминги и полный SQL. Конфиг: endpoint, headers, интервал, resource-атрибуты.
- [ ] Оба экспортера независимо включаемы; конфиг — YAML/флаги/env.

### Этап 6 — TLS (~1–2 недели)
- [ ] uprobes на `SSL_read/SSL_write(_ex)` в `libssl.so` (путь автодетектом через `/proc/<pid>/maps` процессов postgres); сопоставление SSL* ↔ fd ↔ conn_id (uprobe на `SSL_set_fd` или чтение fd из `BIO`).
- [ ] Дедупликация: если соединение TLS — источник данных только uprobes, socket-события отбрасываются (флаг ставится при виде ответа 'S' на SSLRequest).
- [ ] Ограничение зафиксировать в docs: статически слинкованный TLS и не-OpenSSL (GnuTLS) — вне scope v1.

### Этап 7 — Grafana, упаковка, документация (~1 неделя)
- [ ] Дашборды (JSON в `dashboards/`): обзор (QPS, p50/p95/p99, error rate, соединения), top-N запросов по p99/времени/частоте, детализация по db/user, health агента. Datasource — переменная (Prometheus/Mimir).
- [ ] `docker-compose` demo-стек: postgres + pgbench + latkit + prometheus + grafana с provisioned-дашбордами — «увидеть ценность за 5 минут».
- [ ] Упаковка: статический бинарник (musl или glibc + static libbpf/libelf/zlib); Dockerfile (privileged либо `CAP_BPF+CAP_PERFMON+CAP_SYS_RESOURCE`, hostPID для uprobes); systemd unit; k8s DaemonSet.
- [ ] Фильтр захвата по cgroup — отложен из этапа 1 (задача 1.3): нужен для k8s (несколько postgres на хосте, порты совпадают); в v1 фильтр — локальный порт + опционально comm.
- [ ] README: требования к ядру, capabilities, конфигурация, ограничения, security-замечание (агент видит текст SQL — маскирование литералов включено по умолчанию).

### Этап 8 — hardening и производительность (~1–2 недели)
- [ ] Нагрузочное тестирование: pgbench (TPC-B и select-only, 100+ соединений), измерить overhead на TPS/латентность БД с агентом и без. Бюджет: <3% TPS, <1 CPU core на ~50k qps.
- [ ] Валидация точности: сравнить p50/p95 агента с `pg_stat_statements.mean_exec_time` и `log_min_duration_statement` на контролируемой нагрузке; расхождение задокументировать (агент видит время «сеть-до-сети», PG — только execute).
- [ ] Fuzzing парсера (libFuzzer на `src/proto/pg/` + `normalize.c`) — вход недоверенный; харнесс и корпус заложены в этапе 3 (`tests/fuzz`, `lk_pg_fuzz_one`).
- [ ] Матрица ядер: проверка на 5.15 / 6.1 / 6.8+ (vmtest или qemu в CI); graceful degradation без BTF.
- [ ] Утечки: valgrind/ASAN в CI; long-run тест 24h с чурном соединений.

---

## 5. Риски и открытые вопросы

| Риск | Митигция |
|---|---|
| Чтение `iov_iter` в BPF хрупко между версиями ядра | CO-RE + `bpf_core_field_exists`; fallback-вариант на sockmap/sk_msg; снять риск в PoC (этап 0) |
| Потери событий ringbuf под нагрузкой → битые измерения | бюджет захвата (только заголовки + префиксы), счётчики drop, ресинхронизация парсера, метрика честности данных |
| Взрыв кардинальности метрик | нормализация + top-K LRU + `other`; лимит на длину лейбла |
| TLS повсеместен в проде | этап 6 обязателен для v1.0; ограничения документируем |
| Unix domain sockets (локальные клиенты идут через `unix_stream_sendmsg`, не tcp_*) | v1.1: отдельные хуки на `unix_stream_sendmsg/recvmsg`; зафиксировать как known gap |
| Точность: измеряем на сервере, но в тайминг входит ядро/сеть до userspace PG | честно описать модель измерения; сравнение с pg_stat_statements в этапе 8 |

## 6. Вехи

- **M1 (конец этапа 1):** сырой захват PG-трафика стабилен, потери учитываются.
- **M2 (конец этапа 4):** `psql`/pgbench-нагрузка → корректные latency-гистограммы по нормализованным запросам (plaintext).
- **M3 (конец этапа 5):** метрики в Prometheus и OTel Collector, читаются Grafana.
- **v1.0 (конец этапа 8):** TLS, демо-стек, дашборды, подтверждённый overhead <3%, документация.

Суммарная оценка: **8–11 недель** одним разработчиком.
