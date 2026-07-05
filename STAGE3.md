# Этап 3 — парсер протокола PostgreSQL v3

Детализация этапа 3 из [PLAN.md](PLAN.md) (§4). Оценка: **~1,5–2 недели**
(8–10 рабочих дней; extended protocol с pipelining — самая объёмная часть).

**Цель:** превратить поток целых сообщений (`lk_msg`, выход framer'а этапа 2)
в поток **наблюдений о запросах** — протокол-независимых записей
`{тайминги, текст SQL, строки, SQLSTATE, лейблы сессии}`, которые этап 4
нормализует и агрегирует в метрики. Код протокола при этом выезжает из
`src/agent/` в отдельный каталог `src/proto/` с единым API «ядро ↔
обработчик протокола»: PG — первый обработчик, но не последний
(MySQL/redis-протоколы — кандидаты после v1).

**Не входит в этап:** нормализация SQL и фингерпринт (этап 4 — здесь текст
отдаётся как есть, префиксом); гистограммы и кардинальность (этап 4);
HTTP `/metrics` и OTLP (этап 5); расшифровка TLS (этап 6 — TLS-соединения
по-прежнему детектятся и отбрасываются); fuzzing парсера (этап 8 — но
харнесс закладывается здесь, п. 3.6).

**Долги этапа 2, закрываемые здесь** (помечены в коде):

- гонка read-modify-write в `set_cap_headers` (`events.c`): userspace
  делает lookup+update целиком по `struct lk_conn_state`, затирая
  конкурентные инкременты `seq`/`dropped` из ядра — закрывается вместе с
  реальной политикой `capture_mode` (Р21);
- sink `--messages` в `events.c` («stage 3 replaces it with pgproto») —
  остаётся отладочным флагом, но штатным потребителем framer'а становится
  обработчик протокола;
- `LK_MSG_AFTER_RESYNC` и `on_resync` наконец обретают потребителя,
  который понимает, *что именно* потеряно (in-flight запросы).

**Отклонение от PLAN.md §3:** вместо `src/agent/pgproto.c` — каталог
`src/proto/pg/` (уточнённое требование этапа 3: код протоколов в отдельном
каталоге, API — единый). PLAN.md поправить в рамках задачи 3.6.

---

## Ключевые проектные решения

Нумерация продолжает Р1–Р14 из [STAGE1.md](STAGE1.md) / [STAGE2.md](STAGE2.md).

### Р15. Обработчик протокола — плагин с двумя контрактами

Граница «ядро ↔ протокол» — это ровно два контракта, оба в
`src/proto/proto.h`:

- **вниз** (ядро → обработчик): уже существующий `struct lk_msg_sink`
  (`reassembly.h`) — сообщения, open/close, resync. Обработчик протокола —
  это реализация `lk_msg_sink`, ничего нового изобретать не нужно:
  framer не знает, кто его слушает, `--messages`-логгер и PG-парсер
  подключаются одинаково;
- **вверх** (обработчик → потребитель): новый `struct lk_query_sink` —
  протокол-независимые наблюдения `lk_query_obs` (см. «API»). Потребитель
  этапа 3 — логгер `--queries`; этап 4 заменит его агрегатором, не трогая
  парсер.

Пер-соединённое состояние парсера живёт в `lk_conn.proto_state`
(`void *`, владелец — обработчик): аллоцируется лениво при первом
сообщении соединения, освобождается в `on_conn_close`. Таблица соединений
обязана дёргать close-hook на **всех** путях удаления записи — CONN_CLOSE,
LRU-вытеснение, idle sweep (проверить и закрыть дыру, если вытеснение
сейчас минует sink — иначе утечка `proto_state`).

**Осознанный долг:** сам framer (Р10) остаётся PG-aware — рамки
`тип+len`, startup-фрейминг и якорь 'Z' зашиты в `reassembly.c`.
Обобщение фрейминга (пер-протокольные framer-ops) откладывается до второго
реального протокола: абстракция по одному экземпляру — гадание. Шов
задокументирован в `proto.h`.

### Р16. Единица учёта — query unit; очередь in-flight

Состояние соединения — фазовая машина + **очередь незакрытых запросов**
(кольцо на `LK_PG_MAX_INFLIGHT = 64` элементов — pipelining libpq/драйверов
реально даёт десятки):

```
фазы: STARTUP → AUTH → READY ⇄ (COPY_IN | COPY_OUT | SKIP_TO_SYNC) ; IGNORE
```

- **simple**: `Q` открывает unit (kind=SIMPLE, текст = тело `Q`);
  закрывает его `Z` (ReadyForQuery). `CommandComplete`'ы между ними
  считаются: >1 → флаг `MULTI_STMT`, строки суммируются
  (текст `select 1; select 2` не режем — это работа нормализатора этапа 4);
  `EmptyQueryResponse ('I')` → unit с флагом `EMPTY`.
- **extended**: `Parse ('P')` пишет в кэш prepared statements (Р17) и unit
  не открывает; `Bind ('B')` открывает unit (kind=EXTENDED, текст — из
  кэша по имени стейтмента); `Execute ('E')` помечает старт исполнения;
  `Sync ('S')` закрывает батч. Ответы закрывают unit'ы по одному:
  `CommandComplete ('C')`, `ErrorResponse ('E')`,
  `PortalSuspended ('s')` (флаг `SUSPENDED` — Execute с row limit;
  следующий Execute того же портала откроет новый unit с тем же текстом —
  задокументированное упрощение), `EmptyQueryResponse`.
- **тайминги** (все — `ts_ns` сообщений, точность = границы syscall'ов,
  Р13): `ts_start` — первое frontend-сообщение unit'а (`Q` / `B`);
  `ts_first_row` — первый `DataRow ('D')` unit'а; `ts_complete` —
  закрывшее unit backend-сообщение; `ts_ready` — ближайший последующий
  `Z`. Наблюдение несёт **все четыре**: модель latency PLAN.md (§1) — это
  `ts_ready − ts_start`, но при pipelining батч делит один `Z`, и честная
  пер-запросная длительность — `ts_complete − ts_start`; выбор и
  комбинации — решение этапа 4, парсер не решает за него.
- **ошибки**: из `ErrorResponse` извлекаются поля `C` (SQLSTATE) и `S`
  (severity); в extended-режиме после ошибки backend игнорирует всё до
  `Sync` — остальные unit'ы батча закрываются с флагом `ABORTED` (без
  таймингов исполнения), фаза `SKIP_TO_SYNC` до `Z`.
- **строки**: тег `CommandComplete` (`"SELECT 42"`, `"INSERT 0 5"`,
  `"UPDATE 7"`, `"COPY 100"`, …) — число = последний токен; тег без числа
  (`"BEGIN"`, `"SET"`, …) → rows=0. `DataRow`/`RowDescription` — только
  счётчик (тела не парсим, PLAN.md).
- **транзакции**: статус из `Z` (`I`/`T`/`E`); переход `I→T` запоминает
  старт, `T|E→I` эмитит `on_txn` (материал для
  `latkit_txn_duration_seconds` этапа 4).
- **переполнение очереди**: unit'ы сверх `LK_PG_MAX_INFLIGHT` не
  открываются (счётчик `inflight_overflow`, соединение помечается
  `LOSSY` до ближайшего `Z` — наблюдения по нему не эмитятся, чтобы не
  сопоставить ответы не тем запросам).

Startup-фаза: `StartupMessage` (уже отфреймлен этапом 2 с
`LK_MSG_STARTUP`) → параметры `user`, `database`, `application_name` в
`lk_session` (усечённые копии, см. «API»); `AuthenticationOk` (`'R'`,
code 0) → фаза READY, эмиссия `on_session`. Прочие `'R'`-коды (MD5, SASL,
…) — просто ждём. **Тело `PasswordMessage`/SASL (`'p'`) не читается и не
копируется вообще** — там пароль; это инвариант безопасности, а не
оптимизация. `CancelRequest` framer уже пометил (`LK_CONN_CANCEL`) —
парсер эмитит наблюдение kind=CANCEL без таймингов.

### Р17. Prepared statements: пер-соединённый LRU-кэш имя → текст

`Parse` кладёт `{имя стейтмента → префикс SQL, флаг TRUNC}`;
unnamed statement (`""`) перезаписывается каждым `Parse`;
`Close ('C', frontend)` вида `'S'` удаляет запись. Кэш ограничен:
`LK_PG_PREP_CACHE = 256` записей на соединение, LRU-вытеснение со
счётчиком (драйверы с server-side prepared statements держат десятки,
не тысячи).

`Bind` на имя, которого в кэше нет (агент стартовал позже `Parse`,
synthetic-соединение, вытеснение) → unit с флагом `NO_TEXT`: латентность
честная, текст пуст — этап 4 положит такие в bucket по имени стейтмента
или `other`. То же для `FunctionCall ('F')` — kind=FUNCTION, `NO_TEXT`
(тела не разбираем).

Память: тексты в кэше — префиксы ≤ `LK_MSG_BODY_MAX` (16 КиБ, Р11), но
реально ≤ бюджета захвата (8 КиБ на вызов); worst case на соединение
256 × 16 КиБ = 4 МиБ — недостижим на практике, но потолок явный.
Unit хранит **ссылку** на запись кэша + generation (не копию); вытеснение
записи с живыми ссылками копирует текст в unit — редкий путь, копия
префикса, не утечка.

### Р18. Вход недоверенный: bounded cursor, «обрезано» ≠ «битое»

Всё чтение полей — через курсор `pg_wire` (`src/proto/pg/pg_wire.h`):
`{p, end}` + `get_u8/u32/cstring/skip`, каждый вызов проверяет границу,
выход за `body_cap` невозможен по построению. Два разных исхода:

- курсор упёрся в `body_cap`, а сообщение несёт `LK_MSG_BODY_TRUNC` —
  это **усечение бюджетом захвата**, не ошибка: поле помечается
  truncated (для текста SQL — флаг `TEXT_TRUNC`, фингерпринт по префиксу —
  принятое решение PLAN.md), недостающие поля — unknown;
- курсор упёрся в конец **полного** тела (или поле противоречит `len`) —
  это **повреждение**: счётчик `parse_errors`
  (имя метрики этапа 4 — `latkit_parse_errors_total`), текущий unit
  дропается, семантика соединения сбрасывается до ближайшего `Z`
  (фрейминг при этом **не** трогаем — рамки сообщений валидны, битым
  оказалось содержимое).

Неизвестный тип сообщения — не ошибка протокола (PG добавляет типы):
счётчик `unknown_msgs`, тело пропускается по `len`, синхронизация не
страдает. Шумные, но бесполезные для latency типы
(`NoticeResponse 'N'`, `NotificationResponse 'A'`,
`ParameterStatus 'S'`, `BackendKeyData 'K'`, `ParameterDescription 't'`,
`RowDescription 'T'`, `NoData 'n'`, `BindComplete '2'`,
`ParseComplete '1'`, `CloseComplete '3'`) — считаются и пропускаются
(исключение: из `ParameterStatus` опционально берём `server_version` в
лейблы сессии — дёшево и полезно в дашборде).

### Р19. Потери и ресинк: наблюдение через разрыв не эмитится никогда

Инвариант честности метрик. По `on_resync` либо первому сообщению с
`LK_MSG_AFTER_RESYNC`:

- вся очередь in-flight дропается (счётчик `units_dropped_resync`);
- фаза → READY-degraded: unit'ы не открываются до первого чистого
  `Z` (только он гарантирует границу «между запросами» — сам ресинк
  backend-направления уже заякорен на `Z`, так что обычно это одно и
  то же сообщение); лейблы сессии сохраняются — startup не перечитать;
- то же по `CONN_CLOSE` с непустой очередью (`units_dropped_close`) —
  обрыв соединения посреди запроса наблюдением не становится (известное
  слепое пятно модели, зафиксировать в docs; «запрос, оборванный
  дисконнектом» — кандидат в отдельный счётчик этапа 4).

Synthetic-соединения (`LK_CONN_SYNTHETIC`) проходят тот же путь: парсер
стартует в READY-degraded, startup не виден → `on_session` не эмитится,
лейблы unknown.

### Р20. COPY и репликация

- `CopyInResponse ('G')` / `CopyOutResponse ('H')` → фаза COPY_*:
  `CopyData ('d')` считаем (сообщения + суммарный `len` — байты пролёта),
  тела не смотрим; `CopyDone ('c')` / `CopyFail ('f')`, затем
  `CommandComplete` с тегом `COPY n` закрывают unit
  (kind=COPY_IN/COPY_OUT, rows из тега, bytes в наблюдении).
  Текст unit'а — команда `COPY ...` из открывшего `Q`/`Bind`.
- `CopyBothResponse ('W')` — walsender/репликация: соединение помечается
  IGNORE (наблюдений не будет, только счётчик реплик-соединений) и
  переводится в `LK_CAP_HEADERS` (Р21) — гонять WAL-поток через ringbuf
  незачем.

### Р21. Политика capture_mode; починка гонки RMW

Механизм этапа 1 (`capture_mode` в карте `conns`) получает политику и
безопасную запись:

- **механизм**: `capture_mode` выезжает из `struct lk_conn_state` в
  отдельную карту `capmode` (`BPF_MAP_TYPE_LRU_HASH`, key = cookie,
  value = `__u8`), писатель — **только** userspace, ядро читает
  (fallback FULL при отсутствии записи). RMW-гонка с полем `seq`/`dropped`
  исчезает по построению; `--cap-headers` (тестовый хук) переезжает на ту
  же карту. Записи убираются ядром по LRU / userspace'ом при CONN_CLOSE;
- **политика v1** (консервативная): HEADERS для соединений, чей payload
  заведомо не нужен — TLS (`'S'`-ответ; сейчас это опция в events.c —
  становится дефолтом), CANCEL, реплики (`CopyBoth`), IGNORE;
- **не делаем** (соблазнительно, но рано): динамический флип
  FULL↔HEADERS вокруг COPY и «HEADERS после startup, FULL по `Q`» — при
  pipelining и глубоком ringbuf флип опаздывает на уже сабмиченные
  события, получаем самопорезанные тела. Отложено в этап 8 с
  измерениями; текущий бюджет (8 КиБ/вызов + пропуск тел `DataRow` по
  `len` в userspace) уже держит overhead в рамках.

---

## Структура модулей

Целевой срез после этапа:

```
src/
├── agent/                  # ядро: BPF, события, framing — без семантики
│   ├── events.c            # sink по умолчанию → lk_proto_pg; --messages/--events
│   │                       #   остаются отладочными флагами
│   └── ...                 # остальное без изменений
├── proto/
│   ├── proto.h             # оба контракта (Р15): вниз lk_msg_sink (реэкспорт),
│   │                       #   вверх lk_query_obs / lk_query_sink; реестр
│   │                       #   обработчиков (пока из одного элемента)
│   └── pg/
│       ├── pg.c/.h         # lk_proto_pg_new(); диспетчер сообщений по
│       │                   #   (dir, type, фаза); счётчики; proto_state
│       ├── pg_session.c    # startup-параметры, auth-фаза, lk_session
│       ├── pg_query.c      # фазовая машина Р16: unit'ы, очередь, тайминги,
│       │                   #   CommandComplete-теги, ErrorResponse, COPY
│       ├── pg_prep.c       # кэш prepared statements (Р17)
│       └── pg_wire.h       # bounded cursor (Р18), header-only
└── ...
tests/
├── unit/                   # + test_pg_query.c, test_pg_prep.c, test_pg_wire.c
└── replay/                 # test_replay дополняется query-ассертами
```

`pg_query.c` — сердце этапа; всё в `src/proto/` — чистые функции без I/O
и без libbpf (как decode/conn_table/reassembly): unit-тесты кормят
синтетические `lk_msg`, replay-тесты — фикстуры `.lkt` через общий
`pipeline.c`.

## API между модулями (эскиз)

Восходящий контракт (`src/proto/proto.h`), потребитель — `--queries`
сейчас, агрегатор этапа 4 потом:

```c
enum lk_query_kind {
    LK_Q_SIMPLE, LK_Q_EXTENDED, LK_Q_FUNCTION,
    LK_Q_COPY_IN, LK_Q_COPY_OUT, LK_Q_CANCEL,
};

/* lk_query_obs.flags */
#define LK_QO_ERROR      (1 << 0) /* закрыт ErrorResponse; sqlstate валиден */
#define LK_QO_TEXT_TRUNC (1 << 1) /* текст — префикс (бюджет захвата) */
#define LK_QO_NO_TEXT    (1 << 2) /* текста нет (prepared вне кэша, F, ...) */
#define LK_QO_MULTI_STMT (1 << 3) /* simple Q с несколькими стейтментами */
#define LK_QO_EMPTY      (1 << 4) /* EmptyQueryResponse */
#define LK_QO_SUSPENDED  (1 << 5) /* PortalSuspended: Execute с row limit */
#define LK_QO_ABORTED    (1 << 6) /* extended: отменён ошибкой раньше в батче */
#define LK_QO_PIPELINED  (1 << 7) /* в батче был не один unit */

struct lk_session {
    char user[64], database[64], app[64]; /* усечённые копии; "" = unknown */
    char server_version[16];
    bool complete;                        /* startup виден целиком */
};

struct lk_query_obs {
    __u64 ts_start_ns;     /* первое frontend-сообщение unit'а */
    __u64 ts_first_row_ns; /* первый DataRow; 0 = не было */
    __u64 ts_complete_ns;  /* закрывшее backend-сообщение */
    __u64 ts_ready_ns;     /* ближайший Z после; 0 = ещё не пришёл —
                              для ABORTED/CANCEL */
    const char *text;      /* сырой SQL-префикс, НЕ нормализован; NULL при
                              NO_TEXT; живёт только на время on_query */
    __u32 text_len;
    __u64 rows;            /* из тега CommandComplete; суммa при MULTI_STMT */
    __u64 bytes;           /* COPY: суммарный len CopyData */
    char sqlstate[6];      /* при LK_QO_ERROR, C-строка */
    __u8 kind;             /* enum lk_query_kind */
    char txn_status;       /* I/T/E из закрывшего Z; 0 = unknown */
    __u16 flags;           /* LK_QO_* */
};

struct lk_query_sink {
    void *ctx;
    void (*on_query)(void *ctx, const struct lk_conn *c,
                     const struct lk_session *s, const struct lk_query_obs *o);
    void (*on_session)(void *ctx, const struct lk_conn *c,
                       const struct lk_session *s);       /* AuthenticationOk */
    void (*on_txn)(void *ctx, const struct lk_conn *c,   /* T|E -> I по Z */
                   __u64 start_ns, __u64 end_ns, char final_status);
};

/* Обработчик протокола: реализует lk_msg_sink (вниз), эмитит в out (вверх).
 * Единственная точка сборки в events.c/pipeline-харнессе. */
struct lk_proto;
struct lk_proto *lk_proto_pg_new(const struct lk_query_sink *out);
const struct lk_msg_sink *lk_proto_sink(struct lk_proto *p);
void lk_proto_free(struct lk_proto *p);
```

Счётчики парсера (в 10-секундную строку статистики; имена метрик этапа 4
застолблены): `queries` (эмитировано наблюдений), `errors_sql`
(`LK_QO_ERROR`), `parse_errors` → `latkit_parse_errors_total`,
`unknown_msgs`, `units_dropped_{resync,close,overflow}`,
`prep_evictions`, `sessions`, `replication_conns`.

---

## Задачи

Разбивка соответствует будущим коммитам (`Stage 3.x: ...`).

### 3.1 Каркас src/proto/, контракты, прокладка (~1 день)

- [ ] `src/proto/proto.h`: оба контракта (Р15), `src/proto/pg/pg.c` —
      скелет: `proto_state` аллоцируется/освобождается, сообщения
      диспетчеризуются в заглушки, счётчик по типам.
- [ ] `lk_conn.proto_state` + гарантия close-hook на всех путях удаления
      записи (CLOSE / LRU / idle sweep) — проверить `conn_table.c`,
      закрыть дыру, покрыть unit-тестом «вытеснение освобождает
      proto_state».
- [ ] `pg_wire.h` (Р18) + `test_pg_wire.c`: границы, cstring без
      терминатора, «обрезано ≠ битое».
- [ ] Сборка: `src/proto/**` в CMake отдельной статической целью
      (libbpf-free), линкуется и в агент, и в тесты/replay.
- [ ] Прокладка в `events.c` и `pipeline.c`: PG-обработчик — штатный sink;
      `--messages`/`--events` работают как прежде (сообщения зеркалятся
      в логгер до/помимо парсера).

**Готово, когда:** replay-тесты этапа 2 зелёные без изменений ассертов;
на живом psql агент печатает счётчики типов сообщений от заглушек;
ASAN-прогон unit-тестов чист (proto_state не течёт при вытеснении).

### 3.2 Startup, сессия, auth (~1 день)

- [ ] `pg_session.c`: разбор параметров StartupMessage (пары
      cstring/cstring до двойного нуля) → `lk_session`; усечение полей,
      `complete=false` при `TEXT_TRUNC` тела.
- [ ] Auth-фаза: `'R'` code 0 → READY + `on_session`; прочие коды —
      ожидание; тело `'p'` не читается (Р16, инвариант безопасности —
      закрепить комментарием и тестом «содержимое 'p' не попадает ни в
      одну структуру»).
- [ ] `ParameterStatus`: `server_version` в сессию, остальное — skip.
- [ ] `CancelRequest` → наблюдение kind=CANCEL; TLS/GSSENC-путь не
      трогаем (framer уже отсёк).
- [ ] Unit-тесты: штатный startup (фикстура `simple_query.lkt`);
      обрезанный startup; synthetic-соединение (`synthetic_midsession.lkt`)
      → сессия unknown, `on_session` не эмитится.

**Готово, когда:** на живом psql `--queries` печатает строку сессии с
корректными user/database; replay `ssl_plain.lkt` даёт сессию, `ssl_tls.lkt`
— ноль сессий и ноль наблюдений.

### 3.3 Simple query: Q → Z, строки, ошибки, транзакции (~1,5 дня)

- [ ] `pg_query.c`: unit simple (Р16) — `Q` открывает, `Z` закрывает;
      `ts_first_row` по первому `D`; счёт `D`/`T`.
- [ ] Разбор тега `CommandComplete` → rows (таблица тегов: SELECT/INSERT/
      UPDATE/DELETE/MERGE/FETCH/MOVE/COPY — число; остальные — 0);
      `MULTI_STMT` при >1 `C` до `Z`, rows суммируются.
- [ ] `ErrorResponse`: поля до нулевого байта, извлечение `C`/`S`;
      unit закрывается с `LK_QO_ERROR`; `EmptyQueryResponse`.
- [ ] Транзакции по `Z`-статусу: `I→T` старт, `T|E→I` → `on_txn`.
- [ ] Логгер `--queries`: строка на наблюдение
      (`ts dur kind db user rows sqlstate flags text≤120`), обрезка текста
      только в выводе.
- [ ] Unit-тесты на синтетических `lk_msg` + replay `simple_query.lkt`:
      happy path, ошибка (`select 1/0`), multi-statement, пустой запрос,
      `BEGIN/COMMIT` (txn-событие).

**Готово, когда:** `psql -c "select ...; select ..."` даёт одно наблюдение
MULTI_STMT с правильной суммой строк; `select 1/0` даёт SQLSTATE 22012;
длительности правдоподобны против `\timing` (с поправкой на модель Р13).

### 3.4 Extended protocol: prepared, pipelining (~2–2,5 дня)

- [ ] `pg_prep.c` (Р17): кэш имя→текст, LRU 256, unnamed, `Close 'S'`,
      generation + копия при вытеснении с живыми ссылками;
      `test_pg_prep.c`.
- [ ] Unit extended: `B` открывает (текст из кэша / `NO_TEXT`), `E` —
      старт исполнения, `C`/`s`/`E`/`I` закрывают, `S`+`Z` закрывают
      батч; `PIPELINED` при >1 unit в батче.
- [ ] Ошибка в батче → `SKIP_TO_SYNC`: последующие unit'ы батча —
      `ABORTED`, выход по `Z`.
- [ ] `Describe`/`Flush`/`ParseComplete`/`BindComplete`/`NoData`/
      `ParameterDescription` — skip со счётом; `FunctionCall 'F'` →
      kind=FUNCTION, `NO_TEXT`.
- [ ] Переполнение in-flight (Р16): `LOSSY` до `Z`, счётчик; unit-тест.
- [ ] Новые фикстуры в `fixtures_gen.c`: `-M extended`- и
      `-M prepared`-паттерны pgbench, pipeline-батч с ошибкой посередине,
      Bind на неизвестное имя; replay-ассерты (числа наблюдений, флаги,
      тексты).

**Готово, когда:** `pgbench -M prepared -c 4 -T 30` → число наблюдений
сходится с числом транзакций × стейтментов (±служебные), все с текстом из
кэша; `pgbench -M extended` — то же без `NO_TEXT`; pipeline-фикстура с
ошибкой даёт ровно один `ERROR` + хвост `ABORTED`.

### 3.5 COPY, ресинк, capture_mode (~1,5 дня)

- [ ] COPY (Р20): фазы COPY_IN/COPY_OUT, счёт `d`-сообщений и байт,
      закрытие по `c`/`f` + `C`; kind/rows/bytes в наблюдении;
      `CopyBoth` → IGNORE + счётчик реплик.
- [ ] Ресинк/потери (Р19): дроп очереди по `on_resync`/`AFTER_RESYNC`,
      READY-degraded до чистого `Z`; дроп по `CONN_CLOSE` с непустой
      очередью; unit-тесты + replay `session_gap.lkt` (ассерт: ноль
      наблюдений, пересекающих разрыв).
- [ ] Р21: карта `capmode` в `latkit.bpf.c` (LRU_HASH, читает ядро,
      пишет userspace), выпил `capture_mode` из `lk_conn_state`,
      `set_cap_headers` → запись в новую карту (гонка закрыта);
      политика: TLS/CANCEL/IGNORE → HEADERS; очистка записи при CLOSE.
- [ ] Parse-error путь (Р18): повреждённое поле → дроп unit'а, сброс до
      `Z`, счётчик; unit-тест на битых телах (ручная порча байтов
      фикстуры).

**Готово, когда:** `\copy` в обе стороны даёт по наблюдению с байтами и
rows из тега; replay с gap — ни одного наблюдения через разрыв; на живом
TLS-соединении запись HEADERS появляется в карте, счётчики ядра
показывают срезанный захват; `test_conn_table` и полевой прогон
подтверждают, что `seq`/`dropped` больше не затираются.

### 3.6 Фикстуры, робастность, документация (~1 день)

- [ ] Дополнить набор `.lkt`: ошибки, COPY, pipeline, prepared,
      multi-statement, cancel — детерминированно из `fixtures_gen.c`;
      снять контрольные живые трассы `--record` и сверить replay-логи.
- [ ] Fuzz-харнесс (задел этапа 8): вход `bytes → lk_msg → pg-парсер`
      одной функцией `lk_pg_fuzz_one(const u8 *data, size_t n)`
      (сборка за флагом, в CI — прогон корпуса из фикстур через него под
      ASAN/UBSAN; полноценный libFuzzer — этап 8).
- [ ] README: `--queries`, формат строки, модель таймингов (что именно
      меряем, Р13/Р16); `docs/notes-pgproto.md`: фазовая машина, таблица
      сообщений (тип → действие), слепые пятна (обрыв посреди запроса,
      `NO_TEXT`, SUSPENDED-упрощение).
- [ ] PLAN.md: поправить §3 (`pgproto.c` → `src/proto/pg/`), отметить
      выполненное в §4.

**Готово, когда:** `ctest` гоняет все новые unit/replay-тесты без
привилегий; ASAN/UBSAN-прогон корпуса чист; документация описывает
фактическое поведение (перекрёстная вычитка с кодом).

---

## Чек-лист выхода этапа

Формальной вехи в PLAN.md §6 у этапа 3 нет (M2 — конец этапа 4);
локальный критерий — «этап 4 может начинаться»: наблюдения корректны,
API вверх стабилен.

- [ ] psql-сессия: `--queries` показывает запросы с корректными
      текстами, строками, длительностями; ошибки — с SQLSTATE.
- [ ] `pgbench -c 8 -T 60` во всех трёх режимах (`simple`, `extended`,
      `prepared`): число наблюдений сходится с числом транзакций ×
      стейтментов; `prepared` — без `NO_TEXT`; 0 parse_errors.
- [ ] Pipelining (фикстура + живой тест при наличии libpq-pipeline):
      ответы сопоставлены своим запросам, ошибка в батче не портит
      соседей.
- [ ] Потери (крошечный ringbuf) + чурн `pgbench -C`: ни одного
      наблюдения через разрыв, `units_dropped_*` растут, RSS стабилен,
      после нагрузки таблица и очереди возвращаются к нулю.
- [ ] TLS и репликационные соединения: ноль наблюдений, HEADERS в карте
      `capmode`, гонка RMW устранена (seq/dropped целы).
- [ ] Unit + replay + fuzz-корпус в CI зелёные без привилегий/BPF;
      ASAN чист.
- [ ] `src/proto/` не включает ни одного заголовка из `src/agent/`,
      кроме контрактных (`latkit.h`, `conn_table.h`, `reassembly.h`
      через `proto.h`) — проверить включениями, это и есть «единый и
      чёткий API» из PLAN.md.

## Риски этапа

| Риск | Митигция |
|---|---|
| Pipelining: неверное сопоставление ответов запросам → тихо кривые латентности | очередь строго FIFO по спецификации протокола; `LOSSY` при переполнении вместо угадывания; pipeline-фикстуры с ошибкой посередине; сверка счётчиков запросов/ответов в тестах |
| Модель «extended до Z» vs пер-unit `ts_complete` даст расхождения с ожиданиями PLAN.md | наблюдение несёт оба таймстемпа (Р16), выбор — этап 4; расхождение задокументировано до того, как станет метрикой |
| Кэш prepared разъедется с сервером (агент пропустил Parse/Close при потерях) | `NO_TEXT` — честный fallback, не ошибка; ресинк дропает только in-flight, кэш живёт (Parse вне разрыва валиден); счётчик `NO_TEXT`-наблюдений подскажет масштаб |
| Теги CommandComplete «зоопарк» (расширения, новые версии PG) | неизвестный тег → rows=0 + счётчик, не parse error; таблица тегов — данные, не код |
| Парсер на недоверенном входе — переполнения/OOB | все чтения через `pg_wire` cursor (Р18), запрет прямой арифметики по body в review; fuzz-харнесс с 3.6, ASAN/UBSAN в CI |
| `proto_state`/тексты текут на путях вытеснения | владение зафиксировано (Р15/Р17), close-hook на всех путях удаления — задача 3.1 с ASAN-тестом; long-run чурн в чек-листе |
| Флип capture_mode опоздает к событиям в полёте | динамический флип не делаем (Р21): HEADERS только для соединений, где payload не нужен уже навсегда (TLS/CANCEL/реплика) |
