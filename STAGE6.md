# Этап 6 — TLS: плейнтекст через uprobes на OpenSSL

Детализация этапа 6 из [PLAN.md](PLAN.md) (§4). Оценка: **~1,5–2 недели**
(8–11 рабочих дней; корреляция `SSL*` ↔ соединение и жизненный цикл
attach'а libssl — основной технический риск, снять его первым, как в
этапе 0 сняли чтение `iov_iter`).

**Цель:** для TLS-соединений PostgreSQL получать **тот же поток
plaintext-сообщений протокола v3**, что и для открытых соединений,
подключив его к уже существующему пайплайну (framer → PG-парсер →
метрики/спаны) без единой правки в `src/proto/`, `src/norm/`,
`src/metrics/`, `src/export/`. Источник plaintext — uprobes на
`SSL_read`/`SSL_write`(`_ex`) в `libssl.so` процессов postgres; ciphertext
socket-канал по такому соединению глушится (этап 2 уже помечает
соединение TLS и переводит его в HEADERS). Это закрывает главный риск
таблицы PLAN.md §5 «TLS повсеместен в проде» и делает v1.0 применимым к
реальным инсталляциям.

**Не входит в этап:**
- **не-OpenSSL** (GnuTLS, NSS) — вне scope v1, задокументированное
  ограничение (Р44);
- **статически слинкованный** OpenSSL внутри бинарника postgres — вне
  scope v1; детект символа в самом бинарнике возможен, но откладывается
  (Р44);
- **BoringSSL** — офсет-независимая корреляция (Р37, nested-syscall)
  теоретически работает и на нём, но не тестируется в v1 (пометить как
  «может работать, не гарантируется»);
- **GSSENC** (ответ `'G'` на `GSSENCRequest`) — Kerberos-шифрование через
  libgssapi, отдельный API, редок; v1 его детектит (этап 2, флаг TLS
  ставится и на `'G'`) и **молча теряет** данные — фиксируем как known
  gap, не uprobe'им;
- **дешифровка session keys** (SSLKEYLOGFILE + разбор TLS-рекордов) —
  принципиально другой подход, не нужен: uprobe отдаёт уже расшифрованный
  буфер прикладного уровня;
- нагрузочный бюджет uprobe-оверхеда всерьёз — этап 8 (здесь только замер
  и фиксация цифры).

**Долги/заделы предыдущих этапов, закрываемые здесь:**

- **этап 2, Р10**: «ответ `'S'` → соединение TLS, framing выключается,
  socket-события молча отбрасываются, источником станет uprobe-канал
  этапа 6» — uprobe-канал наконец появляется; флаг `LK_CONN_TLS` и
  `LK_CONN_SSL_REPLY` (`conn_table.h`) переиспользуются как есть;
- **этап 3, Р21**: политика capture_mode «TLS → HEADERS» уже дефолт —
  ciphertext по TLS-соединению не гоняется через ringbuf целиком, только
  заголовки (нужны для корреляции, Р37); эта же карта `capmode`
  переиспользуется;
- **этап 3**: replay-фикстура `ssl_tls.lkt` (STAGE3.md) сейчас даёт «ноль
  наблюдений» — после этапа она обязана давать **полноценную сессию** с
  user/database (реальный `StartupMessage` едет внутри TLS, см. Р36);
- **этап 4/5, лейблы `db`/`user`**: для TLS-соединения они берутся из
  расшифрованного `StartupMessage` — до этого этапа их взять было неоткуда
  (плейнтекст видел только `SSLRequest`, реальный startup зашифрован).

**Отклонение от PLAN.md §3:** uprobe-программы кладутся в существующий
`src/bpf/latkit.bpf.c` (PLAN.md §3 их там и предполагает — «uprobes SSL»);
userspace-обвязка (детект libssl, attach, жизненный цикл) — новый файл
`src/agent/tls_attach.c`, а не разбросана по `loader`/`main`. PLAN.md
править не нужно.

---

## Ключевые проектные решения

Нумерация продолжает Р1–Р34 из [STAGE1.md](STAGE1.md) …
[STAGE5.md](STAGE5.md).

### Р35. Плейнтекст-канал — uprobe entry + uretprobe, буфер по факту длины

Референс приёмов — `libbpf-tools/sslsniff`, `ecapture` (не код, приёмы,
как и договорено в STAGE0.md). Захватываем на границе библиотечных
функций, где данные ещё/уже расшифрованы:

- **`SSL_write(SSL *ssl, const void *buf, int num)`** — прикладной код
  отдаёт **плейнтекст** в OpenSSL. Буфер валиден уже на входе. Но
  реально записанное число байт известно только по возврату (частичная
  запись, `num` — лишь запрос). Схема: **uprobe** сохраняет `{ssl, buf}`
  в карту keyed by `pid_tgid`; **uretprobe** читает `ret = PT_REGS_RC`,
  и при `ret > 0` копирует `min(ret, budget)` байт из `buf`
  (`bpf_probe_read_user`) в data-событие;
- **`SSL_read(SSL *ssl, void *buf, int num)`** — OpenSSL кладёт
  **расшифрованный** плейнтекст в `buf`, но **только к моменту возврата**.
  Значит копировать буфер обязательно в uretprobe (в uprobe там мусор).
  Та же схема: entry сохраняет `{ssl, buf}`, ret копирует `min(ret,
  budget)` при `ret > 0`;
- **`SSL_write_ex`/`SSL_read_ex(SSL*, buf, size_t num, size_t *written)`**
  (OpenSSL ≥ 1.1.1) — возвращают `1/0`, число байт в `*written`. Entry
  дополнительно сохраняет указатель `written`; uretprobe при `ret == 1`
  читает `*written` (`bpf_probe_read_user`) как длину. Аттачим **и**
  классические, **и** `_ex` — приложение может звать любые;
- **направление** (агент на PG-хосте, внутри backend-процесса):
  `SSL_read` = приём от клиента = **frontend-сообщения** (`Q`,`P`,`B`,…)
  → `LK_DIR_RECV`; `SSL_write` = ответ клиенту = **backend-сообщения**
  (`Z`,`C`,`D`,…) → `LK_DIR_SEND`. Ровно та же семантика dir, что у
  socket-канала (`tcp_recvmsg`=recv=frontend), — парсер этапа 3 ничего не
  замечает;
- **формат события — тот же `struct lk_ev_data`** (`latkit.h`), с новым
  флагом `LK_F_DECRYPTED` в `hdr.flags`. Буфер SSL — один непрерывный
  user-указатель (не `iov_iter`!), поэтому чанкование проще, чем в
  socket-пути: переиспользуем эмиттер чанков (`LK_MAX_CHUNKS` ×
  `LK_CHUNK_FULL`, бюджет `--capture-limit`), но без `iter_snapshot` —
  прямой `bpf_probe_read_user` c одним `off`. `total_len = ret`,
  `cap_len` режется бюджетом, `LK_F_TRUNC` при `cap_len < total_len` —
  инвариант «total_len честный» (latkit.h) сохраняется, чтобы
  reassembler этапа 2 знал точный размер дыры;
- **`ret <= 0`** (`SSL_ERROR_WANT_READ/WRITE`, ошибка, EOF) — событие не
  эмитится (нечего): полупустой SSL_read при неблокирующем сокете не
  портит поток;
- **потоки**: postgres backend — процесс на соединение, однопоточный;
  `SSL_read`/`SSL_write` не вложены друг в друга. Ключ `pid_tgid` для
  entry→ret корректен. Многопоточные клиенты нас на серверной стороне не
  касаются (задокументировать допущение).

### Р36. `conn_id` TLS-соединения = тот же socket cookie

Ключевое требование: расшифрованный поток обязан попасть в **ту же**
запись `conn_table`, что socket-путь создал по `CONN_OPEN`, — она несёт
`tuple` (адреса/порты → лейблы) и уже видела `SSLRequest`/`'S'`. Иначе
плейнтекст «повиснет» без адресов и без связи с транзакционной
статистикой. Значит uprobe-события обязаны нести **socket cookie** —
`conn_id`, идентичный socket-каналу (`bpf_get_socket_cookie`, Р1). Но
uprobe видит `SSL*` и регистры userspace, не `struct sock`. Мост —
решение Р37.

Важное следствие: **реальный `StartupMessage` (user/database) едет внутри
TLS.** Plaintext socket-путь по TLS-соединению видит только
`SSLRequest → 'S'`, дальше ciphertext. Значит decrypted-поток должен
начинаться со **startup-фрейминга** (Р10) — как обычное соединение с
самого начала. При переключении соединения на decrypted-источник (Р37)
framer этого направления **сбрасывается в стартовое состояние**
(startup-фрейминг frontend, `startup_done = 0`), чтобы первый `SSL_read`
корректно разобрался как `StartupMessage`. Это единственная правка
состояния — сам `reassembly.c` не трогаем.

### Р37. Мост `SSL*` → cookie: `SSL_set_fd`-walk (основной) + nested-syscall (fallback)

Два независимых способа связать `SSL*` с socket cookie; храним связь в
карте `ssl_to_conn` (`HASH`, key = `SSL*` как `u64`, value = `{cookie,
tuple}`), заполняемой любым из них, читаемой в uretprobe Р35:

- **основной — uprobe на `SSL_set_fd(SSL *ssl, int fd)`** (и
  `SSL_set_rfd`/`SSL_set_wfd`). Postgres backend вызывает ровно
  `SSL_set_fd(port->ssl, port->sock)` в `be_tls_open_server` — до
  handshake, до любых данных. В хуке есть `fd` (аргумент) и `current`;
  CO-RE-обход `task->files->fdt->fd[fd]->private_data` → `struct socket`
  → `sk` → `bpf_get_socket_cookie(sk)` даёт cookie **детерминированно и
  заранее**. Одновременно снимаем `tuple` из `sk` (как в socket-пути).
  Обход fd-таблицы — приём известный (bcc fd→sock), но версионно-хрупкий:
  оборачиваем в `bpf_core_field_exists`, при неудаче — молча в fallback;
- **fallback — nested-syscall корреляция.** Внутри динамического интервала
  `SSL_write`/`SSL_read` (между entry и ret) тот же тред синхронно зовёт
  `tcp_sendmsg`/`tcp_recvmsg` на реальном сокете (postgres backend —
  блокирующие сокеты, синхронный I/O). Наши fentry на `tcp_*` уже
  срабатывают (порт-фильтр совпадает, соединение живо в карте `conns`).
  Схема: entry Р35 ставит `active_ssl[pid_tgid] = ssl`; в `tcp_sendmsg`/
  `tcp_recvmsg`, если `active_ssl[pid_tgid]` есть, пишем
  `ssl_to_conn[ssl] = {cookie, tuple}` из `sk`. Не требует ковыряния в
  структурах OpenSSL — работает и на BoringSSL, и при `SSL_set_bio`
  вместо `SSL_set_fd`. Ограничение: если конкретный `SSL_read` отдал
  данные из внутреннего буфера OpenSSL без свежего `tcp_recvmsg`,
  корреляция в этот вызов не случится — но связь **персистентна** в
  `ssl_to_conn`, достаточно одного коррелирующего вызова (обычно первый
  же `SSL_write`/`SSL_read` дёргает сокет);
- **порядок**: основной способ (`SSL_set_fd`) срабатывает **до** данных,
  поэтому к первому `SSL_read` связь уже есть — покрывает и «первый read
  из буфера». Fallback добирает случаи, где `SSL_set_fd` не поймали
  (BIO-сетап, не-postgres клиент, промах CO-RE-обхода);
- **uretprobe без cookie**: если к возврату `ssl_to_conn[ssl]` всё ещё
  пуст — событие **не эмитим**, счётчик `LK_ST_TLS_CORR_MISS`. Плейнтекст
  без адреса бесполезен; честнее потерять и посчитать, чем слать «в
  никуда»;
- **очистка** `ssl_to_conn`: по uprobe на `SSL_free(SSL*)` (снять запись);
  плюс карта — `LRU_HASH` со своим потолком, чтобы утечка при
  пропущенном `SSL_free` вытеснялась. `active_ssl` — тоже с LRU/малым
  сроком (запись живёт только внутри одного вызова).

### Р38. Слияние потоков и seq-пространство decrypted-канала

TLS-соединение имеет **два физических источника** событий с одним cookie:
ciphertext (socket, `tcp_*`) и plaintext (uprobe). Правила слияния:

- **источник данных для TLS-соединения — только decrypted.** Raw
  socket-события (`LK_F_DECRYPTED` не стоит) по соединению с флагом
  `LK_CONN_TLS` в userspace **отбрасываются до seq-детектора** (сейчас
  events.c их просто скармливает framer'у, который на TLS-соединении
  выключен, — станет явным drop с учётом в `LK_CONN_TLS`-ветке);
- **раздельные seq-пространства.** `hdr.seq` в ядре инкрементится в карте
  `conns` **на каждое** submit'нутое событие соединения — если смешать
  ciphertext и plaintext seq, а половину (ciphertext) выкинуть в
  userspace, seq-детектор увидит ложные дыры. Решение: decrypted-события
  нумеруются из **отдельного per-conn счётчика** (карта `tls_seq`,
  `LRU_HASH` key = cookie), независимого от `conns.seq`. Userspace
  conn_table для TLS-соединения ведёт **decrypted seq-пространство** в
  том же `frame`/hole-детекторе (raw seq для него больше не смотрим).
  Потери честны раздельно: дыра в ciphertext (нам не важен) не марает
  плейнтекст, и наоборот;
- **переключение**: когда userspace впервые видит `LK_CONN_TLS` (ответ
  `'S'`, этап 2) — он (а) переводит соединение в HEADERS через `capmode`
  (уже делает), (б) **сбрасывает framer обоих направлений в стартовое
  состояние** (Р36) и (в) с этого момента кормит framer **только**
  `LK_F_DECRYPTED`-событиями. Гонок нет: ringbuf-порядок глобален, `'S'`
  happens-before любого расшифрованного байта (сначала handshake).

### Р39. Автодетект libssl и жизненный цикл attach'а

`tls_attach.c` — вся возня с процессами и путями, вне BPF-логики:

- **поиск**: перебор `/proc/<pid>` с `comm ∈` фильтру постгреса (тот же
  `cfg_comm_filter`, что в ядре; дефолт `postgres`), в `/proc/<pid>/maps`
  ищем строки `…/libssl.so[.N]`. Уникальные пути дедуплицируются
  (несколько backend'ов → один `libssl`);
- **контейнеры**: путь из `maps` — в mount-неймспейсе цели; открывать его
  надо как `/proc/<pid>/root/<path>`, иначе на хосте файла нет. libbpf
  `bpf_program__attach_uprobe` берёт путь бинарника и резолвит офсет
  символа из его ELF — передаём host-видимый `/proc/<pid>/root/…`. (Стенд:
  идти на IP контейнера, не через docker-proxy — как в заметке о
  тест-стенде.);
- **attach**: один uprobe+uretprobe на функцию на **уникальный путь**
  libssl, `pid = -1` (все процессы, мапящие этот файл, включая будущие
  fork'и backend'ов) + **фильтр по `comm` внутри программы** (отсекаем
  чужие процессы на том же libssl). Символы: `SSL_read`, `SSL_write`,
  `SSL_read_ex`, `SSL_write_ex`, `SSL_set_fd`, `SSL_set_rfd`,
  `SSL_set_wfd`, `SSL_free` — отсутствующие (старый OpenSSL без `_ex`)
  пропускаем без ошибки;
- **ре-скан**: постгрес может подтянуть новый `libssl` (рестарт, обновление,
  второй кластер). Периодический ре-скан (`lk_loop_every`, ~30 с) находит
  новые пути и доаттачивает; уже привязанные — пропускает. Attach на
  `pid=-1` покрывает fork'и без ре-скана — ре-скан нужен только для новых
  **путей**;
- **флаги** (Р34, env-эквиваленты автоматически): `--tls auto|off`
  (дефолт `auto` — детект и attach, если libssl найден; `off` — не
  трогать uprobes), `--libssl PATH` (явный путь, в обход скана — для
  нестандартных сборок/статики-через-указание), `--tls-comm NAME`
  (переопределить comm-фильтр, дефолт наследует общий);
- **привилегии**: uprobes требуют `CAP_BPF`+`CAP_PERFMON` (как fentry) и
  доступа к `/proc/<pid>/(maps|root)` целей → в контейнере **`hostPID`**
  и чтение `/proc` (PLAN.md §7, deploy этапа 7). Зафиксировать в docs;
- **деградация**: libssl не найден при `--tls auto` — **не ошибка**, лог
  «TLS uprobes: libssl not found, TLS connections will be dropped» +
  метрика `latkit_tls_attached{state="none"}`; агент работает по
  plaintext. Явный `--libssl` с несуществующим путём — фатально на старте
  (как bind порта, Р29).

### Р40. Бюджет захвата и оверхед uprobe-канала

- ciphertext по TLS-соединению уже урезан до HEADERS (Р21) — двойного
  прогона данных нет; uprobe-канал несёт плейнтекст с тем же бюджетом
  `--capture-limit`, тела `DataRow` так же пропускаются в userspace по
  `len` (этап 3);
- **плюс к точности**: `SSL_read`/`SSL_write` возвращают целые прикладные
  порции (SSL-рекорды собраны OpenSSL), а не TCP-сегменты, — сообщения
  реже рвутся по границам вызовов, framer'у легче. Дыр (`LK_F_GAP`) в
  decrypted-канале при потере ringbuf-события меньше не станет, но
  «рваных по TCP» ситуаций меньше;
- **оверхед uprobe**: каждый `SSL_read`/`SSL_write` — два trap'а
  (entry+ret) + `bpf_probe_read_user`. Для серверного postgres (десятки
  тысяч qps) это горячий путь; замер overhead — этап 8, но здесь
  фиксируем ожидание и метрику `latkit_tls_uprobe_events_total{fn,dir}`
  для наблюдения. Оптимизация (например, только `SSL_read` для frontend +
  реконструкция таймингов) — не сейчас.

### Р41. Самонаблюдение TLS (в номенклатуру STAGE4.md, провайдеры Р27)

Новые ряды, отдаются обоими экспортёрами этапа 5:

```
latkit_tls_attached{state}                gauge    state=ok|partial|none (1 в активном)
latkit_tls_connections                    gauge    активные TLS-соединения (LK_CONN_TLS)
latkit_tls_connections_total              counter   всего TLS-соединений за время жизни
latkit_tls_uprobe_events_total{fn,dir}    counter   fn=ssl_read|ssl_write|..., по направлению
latkit_tls_decrypted_bytes_total{dir}     counter   расшифрованный плейнтекст (cap_len)
latkit_tls_correlation_misses_total       counter   uretprobe без cookie (Р37)
latkit_tls_socket_events_dropped_total    counter   ciphertext-события, отброшенные (Р38)
```

`LK_ST_TLS_*` добавляются в `enum lk_stat_id` (`latkit.h`) для
per-CPU-счётчиков ядра (`corr_miss`, `uprobe_events`, `decrypted_bytes`),
userspace-счётчики (`tls_connections`, `socket_events_dropped`) — из
conn_table/events, как прочие self-метрики Р27.

---

## Изменения формата события (v1 → v1.1, обратносовместимо)

```c
/* latkit.h — дополнения этапа 6 */

/* hdr.flags */
#define LK_F_DECRYPTED (1 << 3) /* payload из uprobe SSL_*; framing включён
                                   на TLS-соединении именно для таких событий */

enum lk_stat_id {
    /* ... существующие ... */
    LK_ST_TLS_CORR_MISS,       /* uretprobe без известного cookie (Р37) */
    LK_ST_TLS_UPROBE_EVENTS,   /* decrypted-события, submit'нутые */
    LK_ST_TLS_DECRYPTED_BYTES, /* сумма cap_len по decrypted */
    LK_ST_TLS_RESERVE_FAIL,    /* reserve-фейл на decrypted-пути */
    LK_ST_MAX,
};
```

Существующие потребители `lk_ev_data` не ломаются: новый флаг + новые
stat-id добавляются в хвост, размеры структур не меняются. Формат остаётся
«v1» для socket-пути; decrypted — тот же record с флагом.

Новые карты BPF (`latkit.bpf.c`):

```
active_ssl_wr  HASH  pid_tgid -> {u64 ssl, u64 buf, u64 written_ptr}  /* entry SSL_write(_ex) */
active_ssl_rd  HASH  pid_tgid -> {u64 ssl, u64 buf, u64 written_ptr}  /* entry SSL_read(_ex)  */
ssl_to_conn    LRU_HASH  u64 ssl -> {u64 cookie, struct lk_tuple}     /* мост Р37 */
tls_seq        LRU_HASH  u64 cookie -> u32                            /* seq decrypted (Р38) */
```

(`active_ssl_*` раздельны, т.к. read и write различают uretprobe'ы; тред в
одном вызове зараз — коллизий ключа нет.)

---

## Структура модулей

Целевой срез после этапа:

```
src/
├── bpf/
│   └── latkit.bpf.c          # + uprobe/uretprobe SSL_read/write/_ex,
│                             #   SSL_set_fd/rfd/wfd, SSL_free; fd→sock walk
│                             #   (Р37 основной); nested-corr в tcp_* (fallback);
│                             #   новые карты; comm-фильтр в uprobe
├── agent/
│   ├── tls_attach.c/.h       # скан /proc, дедуп путей libssl, attach/детач
│   │                         #   uprobe'ов, ре-скан по таймеру, статус-метрика
│   ├── events.c              # маршрутизация: LK_F_DECRYPTED → framer;
│   │                         #   raw socket-события TLS-соединения → drop+count
│   ├── conn_table.c          # decrypted seq-пространство; сброс framer'а в
│   │                         #   startup при переходе в TLS (Р36/Р38)
│   └── main.c                # --tls, --libssl, --tls-comm (+ env, Р34)
tests/
├── unit/                     # + test_tls_route.c (слияние/seq/drop на
│   │                         #   синтетических событиях), тест сброса framer'а
├── replay/                   # ssl_tls.lkt → полноценная сессия (user/db,
│   │                         #   запросы, латентности) вместо «ноль наблюдений»
└── e2e/                      # docker-compose: postgres ssl=on, клиент
                              #   sslmode=require; ассерты = как plaintext
```

`tls_attach.c` — единственный новый libbpf-зависимый модуль этапа
(скелет/`bpf_program__attach_uprobe`). Логика слияния в `events.c`/
`conn_table.c` остаётся чистой (тестируется синтетическими событиями без
BPF, как этапы 2–4). `src/proto/`, `src/norm/`, `src/metrics/`,
`src/export/` — **не трогаем** (критерий этапа).

---

## API между модулями (эскиз)

```c
/* src/agent/tls_attach.h */
struct lk_tls_cfg {
    enum { LK_TLS_OFF, LK_TLS_AUTO } mode;
    const char *libssl_override;   /* --libssl; NULL => скан */
    const char *comm_filter;       /* --tls-comm; NULL => общий cfg */
    unsigned    rescan_sec;        /* ре-скан новых путей libssl (~30) */
};

struct lk_tls *lk_tls_new(struct latkit_bpf *skel, const struct lk_tls_cfg *cfg);
int  lk_tls_register(struct lk_tls *t, struct lk_loop *loop); /* таймер ре-скана */
void lk_tls_free(struct lk_tls *t);                           /* detach всех линков */

/* Состояние для latkit_tls_attached{state}: none|partial|ok. */
enum lk_tls_state lk_tls_status(const struct lk_tls *t);
```

Маршрутизация в `events.c` (эскиз ветвления в `handle_event`, Р38):

```c
case LK_DEC_DATA:
    if (conn->flags & LK_CONN_TLS) {
        if (!(hdr->flags & LK_F_DECRYPTED)) {
            /* ciphertext по TLS-соединению — молча выкинуть, посчитать */
            e->tls_socket_dropped++;
            break;
        }
        /* decrypted: кормим framer в его собственном seq-пространстве */
    } else if (hdr->flags & LK_F_DECRYPTED) {
        /* decrypted до 'S'? не должно случаться (Р38 порядок) — parse_error */
    }
    /* ... обычный путь framer'а ... */
```

---

## Задачи

Разбивка соответствует будущим коммитам (`Stage 6.x: ...`).

### 6.1 uprobe-канал: сырой плейнтекст в ringbuf (~2–2,5 дня)

- [ ] `latkit.bpf.c`: uprobe/uretprobe `SSL_write`/`SSL_read` (+ `_ex`),
      карты `active_ssl_wr`/`active_ssl_rd`; в uretprobe при `ret>0`
      (или `ret==1` + `*written` для `_ex`) — эмиссия `LK_EV_DATA` с
      `LK_F_DECRYPTED`, направление по функции (Р35), чанкование прямым
      `bpf_probe_read_user` c бюджетом `--capture-limit`; comm-фильтр в
      программе.
- [ ] `tls_attach.c` (минимум для 6.1): `--libssl PATH` (без скана) —
      attach на явный путь; `--tls off` по умолчанию на этом шаге.
- [ ] Проверка: psql `sslmode=require` к dev-postgres с `ssl=on`;
      `--events --hexdump` показывает **читаемый** `StartupMessage`,
      `Query`, `ReadyForQuery` из decrypted-событий (cookie пока может
      быть 0 — мост в 6.2).

**Готово, когда:** на TLS-сессии в ringbuf видны decrypted-события с
осмысленным плейнтекстом протокола v3 в обе стороны; на plaintext-сессии
их нет; `ret<=0`-вызовы не рождают событий.

### 6.2 Мост SSL* → conn_id, seq-пространство (~2 дня)

- [ ] `latkit.bpf.c`: uprobe `SSL_set_fd`/`SSL_set_rfd`/`SSL_set_wfd` —
      CO-RE-обход `fd→sock→cookie` (+`tuple`), запись `ssl_to_conn`
      (Р37 основной), обёрнутый в `bpf_core_field_exists`.
- [ ] Fallback: `active_ssl[pid_tgid]` в entry Р35; в `tcp_sendmsg`/
      `tcp_recvmsg` — при активном `SSL_*` запись `ssl_to_conn` из `sk`.
- [ ] uretprobe 6.1 читает cookie/tuple из `ssl_to_conn`; нет связи →
      drop + `LK_ST_TLS_CORR_MISS`. `SSL_free` → удаление записи;
      `tls_seq` — отдельный per-conn seq для decrypted (Р38).
- [ ] Проверка: decrypted-события несут **тот же cookie**, что
      `CONN_OPEN` этого соединения; `tuple` совпадает с socket-путём;
      `corr_miss` при штатной сессии = 0.

**Готово, когда:** decrypted-поток TLS-соединения сшит с его socket-записью
(cookie/tuple), seq-пространство отдельное, промахов корреляции нет на
чистой psql-сессии.

### 6.3 Автодетект libssl и жизненный цикл (~1,5 дня)

- [ ] `tls_attach.c`: скан `/proc/<pid>/maps` по comm-фильтру, дедуп
      путей libssl, `/proc/<pid>/root/…` для контейнеров, attach
      всех символов на `pid=-1`, отсутствующие символы — пропуск;
      ре-скан по `lk_loop_every(rescan_sec)` для новых путей; detach в
      `lk_tls_free`.
- [ ] `--tls auto|off`, `--libssl`, `--tls-comm` + env (Р34); статус
      `lk_tls_status` → `latkit_tls_attached{state}`. `auto` без libssl —
      не ошибка (лог+метрика); явный `--libssl` битый — фатально.
- [ ] Проверка: старт агента, затем `pg_ctl restart` + новое
      TLS-соединение → ре-скан доаттачивает (или fork покрыт `pid=-1`),
      данные идут; чужой процесс на том же libssl не порождает событий
      (comm-фильтр).

**Готово, когда:** `--tls auto` сам находит libssl постгреса (в т.ч. в
контейнере) и захватывает TLS-трафик; отсутствие libssl деградирует
мягко; статус виден в метрике.

### 6.4 Слияние в пайплайне, ресинк startup (~1,5 дня)

- [ ] `events.c`: ветвление Р38 — decrypted → framer, raw socket по
      `LK_CONN_TLS` → drop+`tls_socket_events_dropped`; decrypted до
      установки TLS → `parse_error` (не должно случаться).
- [ ] `conn_table.c`: при переходе в `LK_CONN_TLS` — сброс `frame[2]` в
      стартовое состояние (startup-фрейминг, Р36); decrypted seq-holes в
      том же hole-детекторе, но по `tls_seq`-пространству.
- [ ] `test_tls_route.c`: синтетические события — (а) TLS-conn: raw
      выкинуты, decrypted во framer; (б) сброс framer'а даёт разбор
      `StartupMessage` из первого decrypted; (в) дыра в decrypted seq
      марает только плейнтекст.
- [ ] Replay `ssl_tls.lkt` (пересоздать фикстуру `--record` на реальной
      TLS-сессии): ассерты — сессия с user/database, запросы, латентности,
      как у plaintext-аналога `ssl_plain.lkt`.

**Готово, когда:** TLS-соединение проходит весь пайплайн (framer → парсер
→ метрики) и даёт наблюдения, неотличимые от plaintext-эквивалента;
ciphertext не попадает во framer; unit- и replay-тесты зелёные.

### 6.5 e2e, метрики, документация, ограничения (~1,5 дня)

- [x] Self-метрики Р41 через провайдеры Р27; сверка с `/metrics` и OTLP
      (`ev_provide_tls_stats` в `events.c`: `latkit_tls_attached{state}`,
      `_connections`, `_connections_total`, `_uprobe_events_total`,
      `_decrypted_bytes_total`, `_correlation_misses_total`,
      `_socket_events_dropped_total`; live-сверка через verify-tls.sh —
      pull `/metrics` и push OTLP сходятся).
- [x] `tests/e2e/`: `docker-compose.tls.yml` (override) с `postgres -c ssl=on`
      (self-signed серт/ключ через init-контейнер), pgbench `sslmode=require`,
      `latkit --tls auto`; `verify-tls.sh` — те же ряды
      `latkit_query_duration_seconds`/`latkit_queries_total`, что в
      plaintext-прогоне, плюс `latkit_tls_connections>0`,
      `latkit_tls_attached{state="ok"}==1`, `corr_miss≈0`. Прогон зелёный.
- [x] `docs/notes-tls.md`: схема захвата (uprobe entry/ret, направления),
      мост `SSL*→conn_id` (SSL_set_fd-walk + nested fallback, допущение о
      блокирующих сокетах postgres), слияние/seq-пространства, автодетект
      и привилегии (`hostPID`, `/proc`), **ограничения v1** (только
      динамический OpenSSL; GnuTLS/статик/BoringSSL/GSSENC — вне scope,
      с явным поведением: детект+drop).
- [x] README: флаги `--tls`/`--libssl`/`--tls-comm` + env, требование
      `hostPID`/CAP для uprobes; security-замечание дополнено: по
      TLS-соединениям агент так же видит текст SQL (маскирование литералов —
      тот же дефолт, спаны с сырым SQL — так же за флагом, Р32).
- [x] PLAN.md §4: этап 6 отмечен выполненным; §5 «TLS повсеместен» —
      митигация закрыта; known gaps зафиксированы (GSSENC, unix-сокеты
      остаются v1.1).

**Готово, когда:** чек-лист выхода ниже проходит целиком; e2e с
`ssl=on` даёт зелёный прогон; ограничения задокументированы.

---

## Чек-лист выхода этапа

Вклад в **v1.0** (PLAN.md §6): «TLS» из критериев v1.0.

- [~] `psql`/pgbench с `sslmode=require` под нагрузкой → корректные
      latency-гистограммы и нормализованные запросы, **совпадающие** с
      plaintext-прогоном; лейблы `db`/`user` присутствуют (из расшифрованного
      `StartupMessage`). Проверено e2e-прогоном (`verify-tls.sh`, 8 клиентов);
      **соак ≥ 30 мин** остаётся для этапа 8 (long-run).
- [x] На TLS-соединении ciphertext не попадает во framer/парсер;
      `corr_miss` ≈ 0 на штатных сессиях. e2e: `tls_drop` считает весь
      ciphertext (дропается до seq-детектора), `corr_miss=0` на чистой
      pgbench-сессии; unit `test_tls_route` фиксирует drop синтетикой.
- [x] `--tls auto` находит libssl постгреса в контейнере (e2e); отсутствие
      libssl → мягкая деградация (метрика `state="none"`, агент жив на
      plaintext); битый `--libssl` → фатально на старте (логика 6.3).
- [ ] Смешанная нагрузка (часть соединений TLS, часть plaintext
      одновременно) → оба типа считаются корректно, seq-пространства не
      мешают друг другу, потери одного канала не марают другой. (не прогнан
      отдельно; раздельность seq-пространств покрыта unit-тестом.)
- [x] Fork backend'ов postgres покрыт (attach `pid=-1`): e2e — 8 backend'ов
      захвачены одним attach (`tls_active=8`). Ре-скан новых путей libssl —
      логика 6.3 (`lk_loop_every`).
- [x] Unit (`test_tls_route`, сброс framer'а) и replay (`ssl_tls.lkt` →
      полная сессия) зелёные без привилегий/BPF; ASAN/UBSAN чисты.
- [x] `src/proto/`, `src/norm/`, `src/metrics/`, `src/export/` не изменены
      (границы контрактов Р15 держат); новый libbpf-код изолирован в
      `tls_attach.c` и `latkit.bpf.c`.
- [x] Документация (`notes-tls.md`, README security-замечание, env-таблица)
      сверена с поведением; PLAN.md обновлён, ограничения зафиксированы.

---

## Риски этапа

| Риск | Митигация |
|---|---|
| Корреляция `SSL*`→cookie не сработает (первый `SSL_read` из внутреннего буфера OpenSSL, BIO вместо fd) | два независимых способа (Р37): `SSL_set_fd`-walk срабатывает до данных (postgres его зовёт), nested-syscall добирает BIO-случаи; связь персистентна — достаточно одного коррелирующего вызова; промах → drop+счётчик, не мусорное наблюдение |
| CO-RE-обход `fd→sock` хрупок между версиями ядра | `bpf_core_field_exists` на каждом шаге, при неудаче — молчаливый fallback на nested-syscall; проверка на матрице ядер (этап 8) |
| Допущение «postgres backend — блокирующие синхронные сокеты» неверно для какой-то сборки | основной путь (`SSL_set_fd`) от этого допущения не зависит; nested-fallback — только страховка; задокументировать |
| uprobe-оверхед на горячем `SSL_read/write` (десятки k qps) | ciphertext уже урезан до HEADERS (двойного прогона нет); бюджет `--capture-limit` + пропуск `DataRow`-тел; замер и решение об оптимизации — этап 8; метрика uprobe-событий для наблюдения |
| Разъезд ciphertext/plaintext seq → ложные дыры | раздельные seq-пространства (Р38): decrypted нумеруется своим счётчиком `tls_seq`, raw socket по TLS-соединению отбрасывается до детектора |
| libssl не найден / нестандартный путь / статика | `--tls auto` деградирует мягко (метрика+лог); `--libssl` для явного пути; статика/GnuTLS/BoringSSL — задокументированные ограничения v1 с явным поведением (детект TLS + drop, не тихая порча) |
| Плейнтекст SQL теперь виден и по TLS — утечка чувствительных данных | тот же режим, что для plaintext: маскирование литералов по умолчанию (этап 4), сырой SQL только в спанах за флагом (Р32, `--otlp-span-masked`); жирное security-замечание в README |
| Attach `pid=-1` на libssl ловит чужие процессы → лишний оверхед и события | comm-фильтр внутри uprobe (дефолт `postgres`); чужой трафик без коррелирующего tracked-conn всё равно отсеется, но фильтр убирает и trap-оверхед |
| Утечка записей `ssl_to_conn`/`active_ssl` при пропущенном `SSL_free`/краше клиента | обе карты — `LRU_HASH` с потолком; `active_ssl` живёт только внутри вызова; `SSL_free`-uprobe как основная очистка |
| GSSENC-соединения (ответ `'G'`) молча теряются | детектятся (флаг TLS ставится и на `'G'`), считаются, помечены known gap v1; uprobe-путь для libgssapi — v1.1 |
