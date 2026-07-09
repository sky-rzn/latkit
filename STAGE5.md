# Этап 5 — экспортеры: Prometheus и OTLP

Детализация этапа 5 из [PLAN.md](PLAN.md) (§4). Оценка: **~1–1,5 недели**
(6–8 рабочих дней; OTLP с ручной сериализацией protobuf — основной объём).

**Цель:** вывести реестр метрик этапа 4 наружу двумя независимыми путями —
**pull** (HTTP `/metrics`, Prometheus text exposition format) и **push**
(OTLP/HTTP protobuf в OTel Collector), плюс опциональные спаны на
сэмплированные запросы с точными таймингами и полным SQL. Это веха **M3**
(PLAN.md §6): метрики в Prometheus и OTel Collector, читаются Grafana.

**Не входит в этап:** дашборды Grafana и demo-compose «за 5 минут»
(этап 7 — здесь только e2e-стенд для проверки M3); TLS-захват (этап 6);
TLS/https на *своих* эндпоинтах агента (задокументированное ограничение
v1 — см. Р29/Р31); OTLP/gRPC (только OTLP/HTTP — Collector принимает оба,
gRPC не даёт ничего, кроме зависимости); Prometheus protobuf exposition
для native histograms (отложено, см. Р30); parsing `traceparent` из
SQL-комментариев (sqlcommenter) — кандидат v1.1; нагрузочный бюджет и
профилирование сериализации всерьёз (этап 8 — здесь только замер и
фиксация цифр).

**Долги этапа 4, закрываемые здесь** (застолблены в STAGE4.md):

- контракт Р26 «`lk_metrics_dump` пишет валидный text format — этап 5
  оборачивает его в HTTP, ничего не пересчитывая» — исполняется; флаг
  `--dump-metrics` остаётся отладочным;
- Р24 обещал native/exponential-экспорт «представление совместимо по
  построению» — OTLP ExponentialHistogram (scale=2) берёт сетку `2^(k/4)`
  как есть;
- Р28: **сырой** SQL, который не попадает в реестр, наконец получает
  легальный выход — OTel-спаны (и exemplars как опция);
- Р13/этап 2: «в стенные часы конвертирует этап 4/5 при экспорте» —
  конвертация CLOCK_MONOTONIC → wall clock появляется здесь (Р33);
- задел Р8: event loop писался «чтобы серверный fd воткнулся без
  переделки» — listen-fd HTTP-сервера встаёт в тот же epoll.

**Отклонение от PLAN.md §3:** вместо `src/agent/prom.c` и
`src/agent/otlp.c` — каталог `src/export/` (в логике этапов 3–4:
`src/agent/` — «BPF, события, framing», экспортеры же зависят только от
`src/metrics/` и `src/proto/proto.h`). PLAN.md поправить в задаче 5.4.

---

## Ключевые проектные решения

Нумерация продолжает Р1–Р28 из [STAGE1.md](STAGE1.md) …
[STAGE4.md](STAGE4.md).

### Р29. HTTP-сервер: свой минимальный, в том же epoll-цикле

Как решено в PLAN.md §2: формат тривиален, зависимость (libmicrohttpd,
civetweb) не нужна. Сервер — маленькая state machine на неблокирующих
сокетах, живущая в петле `lk_loop` (Р8):

- listen-fd регистрируется через `lk_loop_add_fd`; accept'нутые
  соединения — туда же. Петле нужны два расширения (задача 5.1):
  `lk_loop_del_fd` (клиентские fd приходят и уходят — сейчас контракт
  «fd stays registered until the loop is freed») и интерес на запись
  (`EPOLLOUT`) — ответ `/metrics` может не влезть в socket buffer,
  дописывается по готовности;
- **подмножество HTTP/1.1**: только `GET` (и `HEAD`), разбор
  request-line + заголовки до `\r\n\r\n` (содержимое заголовков
  игнорируется), ответ с `Content-Length` и `Connection: close` —
  соединение закрывается после ответа. Keep-alive не делаем: Prometheus
  переоткрывает соединение без жалоб, а у нас исчезает половина state
  machine. Роуты: `/metrics`, `/healthz`, остальное — 404;
- **ответ строится целиком в памяти**: `open_memstream` +
  `lk_metrics_dump(m, f)` — реестр сериализуется между событиями ringbuf
  в единственном потоке, поэтому ни локов, ни снапшотов (контракт Р26);
  дальше буфер отдаётся по EPOLLOUT сколько влезает. Стоимость дампа
  (~сотни КиБ при полном K×dims) — миллисекунды; блокировка пайплайна на
  это время покрыта запасом ringbuf, цифру замеряем и фиксируем в 5.1;
- **защита от медленных/злых клиентов**: лимит одновременных соединений
  (8), таймаут на чтение запроса и на дописывание ответа (5 с, sweep
  раз в секунду через `lk_loop_every`), потолок размера запроса (2 КиБ),
  мусор в request-line → 400 и close. Агент смотрит в сеть — вход
  недоверенный, как у парсера (Р18);
- **bind по умолчанию `127.0.0.1:9752`** (`--prom-listen ADDR:PORT`;
  порт сверить со списком default port allocations Prometheus перед
  фиксацией в README). Для скрейпа извне/из докера пользователь явно
  открывает `0.0.0.0` — консервативный дефолт, security-замечание в
  README. TLS/auth на эндпоинте — вне scope v1 (reverse proxy, если
  нужно), задокументировать.

`/healthz` — 200 и короткое текстовое тело (uptime, events_total,
ringbuf_dropped_total): «жив» = петля крутится и отвечает; деградация
(потери, ресинки) — это метрики, а не health. 503 не возвращаем никогда:
частичная деградация захвата не повод снимать агент с эндпоинта.

### Р30. Prometheus v1 — text format с классическими бакетами

Из двух представлений Р24 text format получает **классические `le`-бакеты**
(каждая четвёртая граница сетки, ~20 значений — уже реализовано в
`lk_metrics_dump` этапа 4). Prometheus **native histograms** требуют
protobuf exposition format — это второй сериализатор ради данных, которые
тот же Prometheus умеет принимать по OTLP (`otlp-write-receiver`), а наш
OTLP-путь и так отдаёт exponential histogram без потерь. Решение:
**protobuf exposition не делаем**; в docs — рецепт «нужны native
histograms в Prometheus → включи OTLP-экспорт в него напрямую или через
Collector». Пересмотр — если появится спрос (этап 8+).

Exemplars в text format требуют OpenMetrics-формата — идут вместе со
спанами (Р32), за флагом: при `Accept: application/openmetrics-text`
дамп переключается в OpenMetrics (`# EOF`, `_total`-суффиксация уже
соблюдена в номенклатуре этапа 4) и к бакетам духовых гистограмм
подклеиваются `# {trace_id="...",span_id="..."} value ts` последних
сэмплированных запросов. Это опциональный хвост задачи 5.3, не критерий
M3.

### Р31. OTLP/HTTP: ручной protobuf-writer, cumulative, push без очереди

Как выбрано в PLAN.md §2 — protobuf вручную, без opentelemetry-cpp и без
protobuf-c (wire format proto3 — это varint + length-delimited, нужный
поднабор схемы OTLP невелик и стабилен):

- `pbuf.c` — append-only writer: `pb_varint`, `pb_tag`, вложенные
  сообщения через «резерв длины»: submessage пишется в хвост буфера,
  длина известна по факту, префикс вставляется memmove'ом (сообщения
  мелкие — десятки байт сдвига) либо через двухпроходный размер для
  верхних уровней. Корректность — golden-тесты: байты против эталонов,
  сгенерированных офлайн настоящим protoc (фикстуры в репо), плюс
  живая валидация Collector'ом (он отвергает битый protobuf с 400);
- **маппинг реестра**: counters → `Sum{is_monotonic, cumulative}`,
  gauges → `Gauge`, гистограммы → `ExponentialHistogram{scale=2}` —
  сетка `2^(k/4)` идёт как есть: `offset = -53`, `bucket_counts` —
  плоский массив Р24; underflow-бакет → `zero_count` с
  `zero_threshold = 2^(-53/4)`; overflow при экспорте складывается в
  верхний бакет (искажение только для >60 с, задокументировать).
  Для structured-доступа реестр получает read-only итератор
  `lk_metrics_iter` (см. «API») — text-дамп и OTLP-сериализатор ходят
  по одним рядам, ничего не пересчитывая;
- **temporality — cumulative**, `time_unix_nano` — момент экспорта,
  `start_time_unix_nano` — **время создания ряда** (`created_ns`
  добавляется в ряд реестра — маленькая правка `registry.c`): вытеснённый
  и вернувшийся fingerprint (Р23) начинает новый stream с новым start —
  это корректный reset по спецификации OTLP, а не «убывший cumulative»;
- **доставка**: POST `<endpoint>/v1/metrics`,
  `Content-Type: application/x-protobuf`, интервал `--otlp-interval`
  (дефолт 15 с). **Очереди и ретраев нет**: не доставилось (таймаут,
  не-2xx, connect refused) — батч выброшен, счётчик
  `latkit_otlp_exports_total{result="error"}`; cumulative-температура
  делает потерю безобидной — следующий push несёт полное состояние.
  429/503 с `Retry-After` уважаем единственным способом — пропуском
  тиков до указанного времени;
- **клиент — неблокирующий, в той же петле**: state machine
  connect → write → read status line, таймаут на всю операцию (5 с),
  **один экспорт в полёте** — если тик интервала пришёл, а прошлый не
  завершился, тик пропускается со счётчиком. `getaddrinfo` блокирующий —
  резолвим на старте и кэшируем, перерезолв — при ошибках соединения
  (фоновая деградация, не блокировка пайплайна на каждый push);
- endpoint только `http://` в v1 (Collector-sidecar рядом — штатная
  топология OTel); https — задокументированное ограничение;
  `--otlp-header K=V` (повторяемый) — для auth-заголовков менеджед-бэкендов;
- **resource-атрибуты**: `service.name=latkit`,
  `service.version=<версия>`, `host.name=<gethostname>`; добавить свои —
  `--otlp-resource K=V`. Scope — `latkit`, версия агента.

OTLP-экспорт включается **наличием endpoint'а** (`--otlp-endpoint` или
стандартный `OTEL_EXPORTER_OTLP_ENDPOINT`), Prometheus-сервер включён по
умолчанию (выключается `--prom-listen none`) — «оба экспортера независимо
включаемы» из PLAN.md.

### Р32. Спаны: сэмплированные, с полным SQL; отдельный потребитель sink'а

Спаны дают то, чего принципиально нет в метриках: точные тайминги
конкретного выполнения и **сырой** текст запроса (Р28 хранит в реестре
только нормализованный). Дизайн:

- **коллектор спанов — ещё одна реализация `lk_query_sink`**, встаёт в
  tee-цепочку `proto_pg → (metrics | spans | --queries)` — парсер и
  агрегатор не знают о его существовании. Tee из этапа 4 обобщается до
  списка sink'ов (задача 5.3);
- **сэмплинг решается в `on_query`**, два независимых предиката
  (`--otlp-spans RATIO` и/или `--otlp-spans-slow-ms N`): вероятностный —
  «представительный срез», порог по длительности — «все медленные».
  Запрос сэмплирован, если сработал любой. По умолчанию спаны
  **выключены**;
- сэмплированный запрос копируется в **кольцевой буфер спанов**
  (`LK_SPAN_BUF = 2048`; текст — копия сырого SQL с потолком
  `--otlp-span-text-max`, дефолт 4 КиБ — текст из `lk_query_obs` живёт
  только на время колбэка, Р16). Буфер полон → новый спан выбрасывается,
  `latkit_spans_dropped_total`. Отправка — POST `/v1/traces` тем же
  клиентом Р31, вместе с тиком метрик либо при заполнении буфера на 3/4;
- **идентификаторы**: trace_id (16 байт) и span_id (8 байт) — из
  `getrandom(2)`; трейс «одиночный» — родителя нет, контекст клиента нам
  не виден (sqlcommenter-`traceparent` из SQL-комментария — кандидат
  v1.1, зафиксировать в docs). Тайминги: `start = ts_start_ns`,
  `end = ts_complete_ns` (точная пер-запросная модель — спанам не нужен
  компромисс Р25), конвертация в wall clock — Р33;
- **атрибуты** — по OTel semconv для databases: `db.system.name=
  "postgresql"`, `db.query.text` (сырой SQL; при `NO_TEXT` — атрибут
  опускается), `db.namespace` (database), `db.user`, `db.response.
  returned_rows`; имя спана — нормализованный текст, усечённый до 64
  символов (нормализатор Р22 дёргается только для сэмплированных —
  стоимость ничтожна); ошибка → `otel.status = ERROR` +
  `db.response.status_code = SQLSTATE`;
- **безопасность**: спаны — единственное место, где сырой SQL (с
  литералами!) покидает агент. По умолчанию выключены; флаг
  `--otlp-span-masked` заменяет `db.query.text` на нормализованный
  текст — для сред, где литералы утекать не должны, но спаны нужны.
  Жирное security-замечание в README (PLAN.md §7);
- **exemplars** (опция, хвост 5.3): последние сэмплированные
  `{trace_id, span_id, value}` подкладываются в соответствующий ряд
  гистограммы (кольцо на 4 exemplar'а на ряд) — выходят в OpenMetrics
  (Р30) и в поле `exemplars` OTLP-гистограммы. Метрики ↔ спаны
  связываются в Grafana. Не критерий M3.

### Р33. Время: один модуль конвертации mono → wall

Все таймстемпы пайплайна — `bpf_ktime_get_ns` (CLOCK_MONOTONIC, Р13).
Наружу нужны стенные часы (OTLP `*_unix_nano`; text format Prometheus
таймстемпов **не** несёт — и не должен). `timebase.c`:

- `offset = clock_gettime(REALTIME) − clock_gettime(MONOTONIC)`,
  семплируется **на каждом тике экспорта** (не кэшируется навечно):
  NTP-степы двигают REALTIME, offset обязан следовать;
- `lk_wall_ns(mono_ns)` — единственная функция конвертации, ей
  пользуются OTLP-метрики (время экспорта, created_ns рядов) и спаны
  (start/end);
- `process_start_time_seconds` (уже в self-метриках Р27) обязан быть
  согласован с `start_time_unix_nano` дефолтных рядов — один источник.

### Р34. Конфиг: флаги + env, без YAML в v1

PLAN.md допускает «YAML/флаги/env» — фиксируем минимум без новых
зависимостей:

- у **каждого** флага агента появляется env-эквивалент
  `LATKIT_<UPPER_SNAKE>` (`--otlp-endpoint` ↔ `LATKIT_OTLP_ENDPOINT`);
  приоритет: флаг > env > дефолт. Механически — таблица флагов в
  `main.c` и так одна, env-проход поверх неё (в `src/common/`);
- стандартные OTel-переменные **уважаются** как дефолты для своих
  флагов: `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`,
  `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_SERVICE_NAME` — агент, задеплоенный
  рядом с другими OTel-инструментами, подхватывает окружение без своей
  конфигурации;
- YAML-файл конфигурации — **не делаем**: парсер YAML — это зависимость
  или боль, а systemd unit/DaemonSet (этап 7) прекрасно живут на
  env+флагах. Пересмотр — по реальному спросу; PLAN.md §4 поправить
  («конфиг — флаги/env, YAML отложен»).

Новые флаги этапа: `--prom-listen ADDR:PORT|none`, `--otlp-endpoint URL`,
`--otlp-interval SEC`, `--otlp-header K=V`*, `--otlp-resource K=V`*,
`--otlp-spans RATIO`, `--otlp-spans-slow-ms N`, `--otlp-span-text-max N`,
`--otlp-span-masked`.

---

## Структура модулей

Целевой срез после этапа:

```
src/
├── agent/                  # events.c: tee расширяется списком sink'ов (Р32)
├── proto/                  # не трогаем
├── norm/                   # не трогаем
├── metrics/
│   └── registry.c          # + created_ns ряда, + lk_metrics_iter (Р31)
├── export/
│   ├── http.c/.h           # мини-HTTP сервер: listener, conn state machine,
│   │                       #   лимиты/таймауты (Р29); роуты — колбэками
│   ├── prom.c/.h           # /metrics (memstream + lk_metrics_dump),
│   │                       #   /healthz; OpenMetrics+exemplars (опция, Р30)
│   ├── pbuf.c/.h           # protobuf-writer (Р31), без I/O
│   ├── otlp.c/.h           # маппинг реестра → OTLP, спаны → OTLP,
│   │                       #   async-клиент, расписание пушей (Р31)
│   ├── spans.c/.h          # sink-коллектор: сэмплинг, кольцо спанов (Р32)
│   └── timebase.c/.h       # mono → wall (Р33)
└── common/                 # + env-слой конфига (Р34)
tests/
├── unit/                   # + test_http.c, test_pbuf.c, test_otlp_enc.c,
│   │                       #   test_spans.c
├── replay/                 # + ассерты на OTLP-энкодинг поверх фикстур
└── e2e/                    # docker-compose: pg + pgbench + latkit +
                            #   prometheus + otel-collector (задача 5.4)
```

Зависимости: `export` → `metrics`, `proto/proto.h`, `loop.h`; **не**
включает libbpf и заголовков `src/agent/` кроме `loop.h` (петля — общая
инфраструктура; при желании чистоты `loop.c/.h` переезжает в
`src/common/` — решить по месту в 5.1). `pbuf.c` и `spans.c` — чистые,
тестируются без сети; сетевые `http.c`/`otlp.c` тестируются на
socketpair/loopback без BPF.

## API между модулями (эскиз)

```c
/* src/metrics/metrics.h — дополнение этапа 5 (Р31) */
enum lk_metric_type { LK_MT_COUNTER, LK_MT_GAUGE, LK_MT_HIST };

struct lk_metric_view {
    const char *name;
    enum lk_metric_type type;
    const struct lk_label *labels; __u32 nlabels;
    __u64 created_ns;             /* mono; создание ряда (Р31) */
    union {
        double val;               /* counter/gauge */
        const struct lk_hist *hist; /* сетка Р24 как есть */
    };
};

/* Обход всех рядов между событиями ringbuf; порядок стабилен (как dump). */
typedef void (*lk_metrics_iter_fn)(void *ctx, const struct lk_metric_view *v);
void lk_metrics_iter(struct lk_metrics *m, lk_metrics_iter_fn fn, void *ctx);
```

```c
/* src/export/http.c — роуты колбэками, сервер не знает про метрики */
struct lk_http_route {
    const char *path;                    /* точное совпадение */
    /* Заполнить body (malloc'ится обработчиком, сервер освобождает),
     * вернуть HTTP-код. accept_hdr — для OpenMetrics-переговоров (Р30). */
    int (*handle)(void *ctx, const char *accept_hdr,
                  char **body, size_t *body_len, const char **content_type);
    void *ctx;
};
struct lk_http *lk_http_new(struct lk_loop *loop, const char *bind_addr,
                            const struct lk_http_route *routes, int nroutes);

/* src/export/otlp.c */
struct lk_otlp_cfg {
    const char *endpoint;         /* http://host:4318 */
    unsigned interval_sec;        /* 15 */
    /* headers, resource k=v, span-настройки Р32 ... */
};
struct lk_otlp *lk_otlp_new(struct lk_loop *loop, struct lk_metrics *m,
                            const struct lk_otlp_cfg *cfg);
/* sink спанов для tee (NULL, если спаны выключены) */
const struct lk_query_sink *lk_otlp_span_sink(struct lk_otlp *o);
```

Self-метрики этапа (в номенклатуру STAGE4.md, через провайдеры Р27):
`latkit_http_requests_total{path,code}`,
`latkit_scrape_duration_seconds` (gauge, последний дамп),
`latkit_otlp_exports_total{signal,result}` (signal=metrics|traces),
`latkit_otlp_export_ticks_skipped_total`,
`latkit_spans_sampled_total`, `latkit_spans_dropped_total`.

---

## Задачи

Разбивка соответствует будущим коммитам (`Stage 5.x: ...`).

### 5.1 Мини-HTTP сервер: /metrics, /healthz (~2 дня)

- [x] Расширить `loop.c`: `lk_loop_del_fd`, интерес EPOLLIN|EPOLLOUT
      (`lk_loop_mod_fd`) — обратная совместимость с текущими
      пользователями петли (слоты в фикс. массиве + generation-guard на
      переиспользование внутри батча; `lk_loop_poll` для кооперативных
      тестов).
- [x] `http.c` (Р29): listener (bind/listen, `SO_REUSEADDR`,
      неблокирующий accept), state machine соединения
      (READ_REQ → WRITE_RESP → close), лимиты: 8 соединений, 2 КиБ на
      запрос, 5 с таймаут (sweep через `lk_loop_every(1)`), 400/404/405
      на мусор, `HEAD` без тела. `send(MSG_NOSIGNAL)` вместо write.
- [x] `prom.c`: `/metrics` — `open_memstream` + `lk_metrics_dump`;
      `/healthz` — uptime/события/дропы; регистрация роутов и self-метрик
      (`http_requests_total{path,code}`, `scrape_duration_seconds`).
- [x] `main.c`: `--prom-listen` (дефолт `127.0.0.1:9752`, `none` —
      выключить). Порт 9752 из плана оставлен; README — задача 5.4.
- [x] `test_http.c` на loopback (кооперативная петля через
      `lk_loop_poll`): разбор запроса по байту (torn request-line),
      запрос больше лимита, медленный клиент → таймаут при живом
      соседнем скрейпе, частичная запись ответа (маленький SO_RCVBUF),
      два параллельных скрейпа, 404/405, HEAD. ASAN/UBSAN чисто.
- [x] Замер: длительность дампа при заполненном реестре (516 рядов,
      ~2,75 МБ) — **~6,3 мс**, зафиксировано в
      [docs/notes-export.md](docs/notes-export.md); пауза ≪ запаса
      ringbuf (8 МиБ).

**Готово, когда:** `curl :9752/metrics` под pgbench-нагрузкой отдаёт дамп,
`promtool check metrics` чист; Prometheus из docker скрейпит агента и
рисует `rate(latkit_queries_total[1m])`; «клиент» из `nc`, приславший
полбайта и уснувший, отваливается по таймауту, не задев ни скрейпы, ни
пайплайн; unit-тесты зелёные.

### 5.2 pbuf, timebase, OTLP-метрики (~2–2,5 дня)

- [x] `timebase.c` (Р33): offset REALTIME−MONOTONIC, семпл на каждом
      экспорте; согласован с `process_start_time_seconds` (оба берутся на
      старте — расхождение в пределах джиттера конструкции, задокументировано).
- [x] `registry.c`: `created_ns` ряда (Р31) + `created_ns` реестра для
      фиксированных семейств; `lk_metrics_iter`/`lk_reg_iter` — стабильный
      обход, тот же порядок, что dump; ряды как `struct lk_metric_view`.
- [x] `pbuf.c`: varint/tag/len-delimited, вложенность через
      резерв+memmove (LIFO-закрытие), sticky OOM; `test_pbuf.c` — golden-байты
      (выведены из спеки proto3, совпадают с каноническими примерами),
      многобайтовый префикс длины, вложенность. protoc недоступен офлайн —
      строгий валидатор схемы это живой Collector (5.4).
- [x] `otlp.c`, энкодер: Resource/Scope, Sum/Gauge/ExponentialHistogram
      (scale=2, offset −53, underflow→zero_count+zero_threshold,
      overflow→верхний бакет), cumulative + start_time из `created_ns`;
      `test_otlp_enc.c` — декодирует свой вывод и проверяет OTLP-структуру и
      маппинг сетки на детерминированном timebase (offset=0).
- [x] `otlp.c`, клиент (Р31): async connect/write/read-status в петле,
      один в полёте, таймаут 5 с, drop-and-count, Retry-After, кэш
      резолва + перерезолв при ошибках соединения; тик по `lk_loop_every`;
      `test_otlp_client.c` — сквозной прогон по loopback (200→ok, 503→error).
- [x] Флаги/env: `--otlp-endpoint`/`--otlp-interval`/`--otlp-header`/
      `--otlp-resource` + `OTEL_EXPORTER_OTLP_*`/`OTEL_SERVICE_NAME`/
      `OTEL_RESOURCE_ATTRIBUTES` как дефолты, приоритет флаг > `LATKIT_*` >
      `OTEL_*` > дефолт (Р34, механика env-слоя в `src/common/otel_env.c`;
      полная таблица — 5.4).

**Готово, когда:** otel-collector (docker, `debug`-exporter) печатает
латкитовские Sum'ы и ExponentialHistogram'ы с правдоподобными значениями,
сходящимися с `/metrics` тех же секунд; `kill` коллектора на минуту →
агент жив, `otlp_exports_total{result="error"}` растёт, после рестарта
коллектора данные идут без перезапуска агента; вытеснение ряда (стресс
top-K) не рождает «убывающий cumulative» — start_time нового stream'а
свежий.

### 5.3 Спаны и exemplars (~1,5 дня)

- [ ] Tee в `events.c`/`pipeline.c`: список `lk_query_sink`-потребителей
      (metrics, spans, `--queries`) вместо пары этапа 4.
- [ ] `spans.c` (Р32): предикаты сэмплинга (ratio через xorshift от
      ts+cookie — без rand(3); порог slow-ms), кольцо `LK_SPAN_BUF`,
      копия текста ≤ `--otlp-span-text-max`, счётчики sampled/dropped;
      `test_spans.c` — сэмплинг детерминирован сидом, переполнение
      кольца, NO_TEXT-запросы.
- [ ] OTLP traces: энкодер Span (semconv-атрибуты Р32, статус из
      LK_QO_ERROR + sqlstate), отправка `/v1/traces` тем же клиентом,
      флаш по тику и по 3/4 заполнения; `--otlp-span-masked`.
- [ ] Опционально (не критерий M3): exemplars — кольцо 4 шт. на ряд
      гистограммы, выдача в OTLP `exemplars` и в OpenMetrics-вариант
      дампа по `Accept` (Р30).
- [ ] Replay-фикстуры этапа 3 через spans-sink: ассерты на число
      сэмплированных при ratio=1.0, тексты, статусы ошибок.

**Готово, когда:** `--otlp-spans 1.0` на psql-сессии доводит спаны до
collector'а (debug-exporter показывает имя, тайминги, `db.query.text`);
`--otlp-spans-slow-ms 100` ловит `pg_sleep(0.2)` и не ловит `select 1`;
длительность спана сходится с гистограммой; при `--otlp-span-masked`
литералов в атрибутах нет.

### 5.4 Конфиг, e2e-стенд, документация, M3 (~1–1,5 дня)

- [ ] Env-слой (Р34): `LATKIT_*` для всех флагов, приоритет
      флаг > env > дефолт; таблица в README; unit-тест приоритетов.
- [ ] `tests/e2e/`: docker-compose — postgres + pgbench + latkit +
      prometheus + otel-collector; скрипт-проверка: подождать скрейпы,
      спросить Prometheus API (`query=latkit_queries_total`), ассерты —
      ряды есть, count растёт, p95 из `histogram_quantile` в разумных
      пределах против отчёта pgbench; спаны в collector-логе. (Помнить
      стенд: захват по IP контейнера, не через docker-proxy/localhost.)
- [ ] Прогон вехи M3: pgbench 3 режима × оба экспортера одновременно;
      сверка `/metrics` и OTLP-значений между собой; потери
      (`pkill -STOP`) → self-метрики согласованы в обоих каналах.
- [ ] `docs/notes-export.md`: подмножество HTTP (Р29), маппинг OTLP
      (Р31: temporality, start_time/reset, overflow-оговорка), модель
      спанов и сэмплинга (Р32), безопасность (bind-дефолт, сырой SQL в
      спанах, `--otlp-span-masked`), ограничения v1 (no https, no gRPC,
      no native-histogram exposition — с рецептом через OTLP).
- [ ] README: новые флаги + env-таблица, quickstart с Prometheus и с
      Collector; security-замечание PLAN.md §7 дополнено спанами.
- [ ] PLAN.md: §3 (`prom.c`/`otlp.c` → `src/export/`), §4 — отметить
      выполненное, «конфиг — флаги/env, YAML отложен»; зафиксировать M3.

**Готово, когда:** чек-лист выхода ниже проходит целиком; `docker compose
up` в `tests/e2e` + один скрипт дают зелёный прогон локально и в CI
(e2e — опционально в CI, если runner без BPF-привилегий — пометить
manual).

---

## Чек-лист выхода этапа (веха M3)

PLAN.md §6: «метрики в Prometheus и OTel Collector, читаются Grafana».
Плюс локальный критерий — «этапу 7 есть что рисовать»: номенклатура
STAGE4.md доступна снаружи обоими путями, поведение под сбоями экспорта
честное.

- [ ] Prometheus скрейпит агента под pgbench-нагрузкой ≥ 30 мин без
      единой failed-скрейп-попытки; `promtool check metrics` чист;
      `histogram_quantile(0.95, ...)` даёт правдоподобный p95.
- [ ] OTel Collector получает те же метрики (значения сходятся с
      `/metrics` в пределах интервала экспорта) как
      ExponentialHistogram/Sum; временное отсутствие collector'а не
      влияет на пайплайн и на Prometheus-путь.
- [ ] Grafana (вручную поднятая на e2e-стенде) рисует QPS и p95 из
      Prometheus — smoke, дашборды — этап 7.
- [ ] Спаны: сэмплированные запросы с точными таймингами и полным SQL
      видны в collector'е; slow-порог работает; masked-режим не содержит
      литералов; при выключенных спанах сырой SQL не покидает агент
      нигде (grep по трафику стенда).
- [ ] Злой клиент HTTP (slowloris, мусор, оверсайз) не влияет на захват:
      счётчики пайплайна ровные, скрейпы соседей проходят.
- [ ] Вытеснение/возврат рядов top-K не ломает ни `rate()` в Prometheus,
      ни cumulative-семантику OTLP (start_time обновлён).
- [ ] Unit-тесты (http, pbuf, otlp-энкодер, spans) в CI зелёные без
      привилегий/BPF; ASAN/UBSAN чисты, включая обрывы соединений на
      каждом состоянии клиентской/серверной state machine.
- [ ] `src/export/` не тянет libbpf; блокирующих вызовов (getaddrinfo на
      горячем пути, connect без O_NONBLOCK, write в полный буфер) нет —
      проверено ревью + strace на нагрузке.
- [ ] Документация (`notes-export.md`, README, env-таблица) сверена с
      фактическим поведением; PLAN.md обновлён, M3 зафиксирована.

## Риски этапа

| Риск | Митигция |
|---|---|
| Сериализация большого реестра в один присест блокирует пайплайн → потери ringbuf на всплеске | замер в 5.1 с зафиксированной цифрой; потолок рядов уже ограничен Р23; запас ringbuf; если цифра плохая — инкрементальный дамп кусками между событиями (этап 8, шов — `lk_metrics_iter`) |
| Свой HTTP-сервер на недоверенном входе — OOB/зависания | подмножество протокола микроскопично (GET + два роута), лимиты/таймауты с первого дня, unit-тесты на порванные и злые запросы, ASAN/UBSAN; bind-дефолт 127.0.0.1 |
| Ручной protobuf разойдётся со схемой OTLP (поля, номера, вложенность) | golden-фикстуры от настоящего protoc в репо; живой Collector в тестах как строгий валидатор (400 на битое); используемое подмножество схемы зафиксировано в notes-export.md |
| Cumulative + вытеснение рядов top-K → «убывающие» значения ломают OTLP-потребителей | `created_ns` → `start_time_unix_nano` per stream (Р31): reset легален по спецификации; тест на вытеснение в 5.2 |
| Недоступный/медленный collector тормозит агент | async-клиент, один в полёте, таймаут 5 с, drop без очереди (cumulative прощает), пропуск тиков со счётчиком; DNS кэширован |
| Сырой SQL в спанах — утечка чувствительных данных | спаны выключены по умолчанию; `--otlp-span-masked`; security-раздел README; потолок текста; exemplars несут только id'ы |
| Часы: NTP-степ между семплами offset'а сдвигает таймстемпы спанов | offset на каждом тике экспорта (Р33); сдвиг внутри одного интервала ≤ степа — для 15-секундных интервалов приемлемо, задокументировать; длительности не страдают (monotonic) |
| Порт по умолчанию конфликтует с чужим экспортером на хосте | сверка со списком port allocations до фиксации; ошибка bind — явная и фатальная на старте (не тихий фолбэк) |
| Расширение `loop.c` (del_fd, EPOLLOUT) заденет существующих пользователей петли | отдельный механический коммит в начале 5.1 с прогоном replay/unit-тестов этапов 2–4 до содержательных правок (приём этапа 2, задача 2.1) |
