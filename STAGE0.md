# Этап 0 — PoC и обвязка (детальный план)

Развёрнутое описание этапа 0 из [PLAN.md](PLAN.md). Оценка: ~1 неделя.

## Цель этапа

Снять главный технический риск проекта: **убедиться, что из BPF-программ на
`tcp_sendmsg`/`tcp_recvmsg` мы можем прочитать сырые байты wire-протокола
PostgreSQL в обе стороны** и доставить их в userspace через ringbuf. Всё
остальное (скелет сборки, CI, docker-окружение) — обвязка, которая делает этот
эксперимент воспроизводимым и служит фундаментом этапов 1+.

**Критерий выхода:** запускаем `psql -h 127.0.0.1 -c 'select 1'` против
postgres в docker, а агент печатает hexdump фрагментов, в которых глазами видны
`Q…select 1` (frontend) и `T`/`D`/`C`/`Z` (backend), с направлением и
таймстемпами.

## Предусловия (окружение разработки)

Текущая машина уже пригодна, зафиксировано на 2026-07-02:

| Компонент | Требование | Есть локально |
|---|---|---|
| Ядро | ≥ 5.8 (ringbuf), для fentry/fexit — BTF-trampoline | 6.17.0-35-generic |
| BTF | `/sys/kernel/btf/vmlinux` | есть |
| clang | ≥ 12 (target bpf, CO-RE relocations) | 18.1.3 |
| bpftool | для `gen skeleton` и `btf dump` | v7.7.0 (libbpf 1.7) |
| CMake | ≥ 3.16 | 3.28.3 |
| Docker + compose | для dev-окружения postgres | 29.6.1 |

Дополнительно поставить (задача 0.1): `libbpf-dev` (или взять libbpf
git-submodule — см. ниже), `libelf-dev`, `zlib1g-dev`, `clang-format`,
`postgresql-client` (psql для ручных проверок).

Права: PoC запускаем под `sudo`; вопрос минимальных capabilities
(`CAP_BPF+CAP_PERFMON`) откладываем до этапа 7 (упаковка).

---

## Задача 0.1 — Скелет проекта и сборка

### Структура (минимальный срез из PLAN.md §3)

```
latkit/
├── CMakeLists.txt
├── .clang-format               # стиль LLVM или kernel — выбрать и зафиксировать
├── .github/workflows/ci.yml
├── src/
│   ├── bpf/
│   │   ├── latkit.bpf.c        # PoC-программы (задача 0.2)
│   │   ├── latkit.h            # общий хедер ядро↔юзер: struct event
│   │   └── vmlinux.h           # генерируется, в git НЕ коммитим (см. ниже)
│   ├── agent/
│   │   └── main.c              # PoC: load skeleton + attach + poll ringbuf + hexdump
│   └── common/                 # пока пусто, заготовка
├── tests/unit/                 # заготовка + один smoke-тест (чтобы CI-шаг не был пустым)
├── deploy/dev/
│   └── docker-compose.yml      # задача 0.4
└── third_party/libbpf/         # git submodule (вариант A)
```

### libbpf: submodule vs системный

Взять **git submodule `third_party/libbpf` и линковать статически** (вариант A).
Обоснование: в дистрибутивах разъезжаются версии libbpf (0.x vs 1.x, разные
API), а нам в этапе 7 всё равно нужен статический бинарник. Системный libbpf
оставить как fallback-опцию CMake (`-DLATKIT_SYSTEM_LIBBPF=ON`) — пригодится
для пакетирования.

### Пайплайн сборки BPF (CMake custom commands)

Стандартная цепочка libbpf-проекта, три шага:

1. **vmlinux.h** — генерировать на билд-машине, не коммитить:
   ```
   bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
   ```
   CO-RE гарантирует, что бинарник, собранный против свежего vmlinux.h,
   работает на старых ядрах. Для CI без BTF на хосте — положить в репозиторий
   заранее сгенерированный `vmlinux.h` для x86_64 в `src/bpf/generated/`
   (обновляемый вручную) либо качать из btfhub; для этапа 0 достаточно
   закоммиченного снапшота.

2. **latkit.bpf.o**:
   ```
   clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
         -I src/bpf -I third_party/libbpf/src \
         -c src/bpf/latkit.bpf.c -o latkit.bpf.o
   ```
   `-g` обязателен — без DWARF/BTF не будет CO-RE-релокаций; `-O2` обязателен —
   без него verifier не пройдёт.

3. **skeleton**:
   ```
   bpftool gen skeleton latkit.bpf.o > latkit.skel.h
   ```
   `main.c` включает `latkit.skel.h` и получает типизированные
   `latkit_bpf__open/load/attach/destroy`.

Агент: обычная C-цель (`c_std_11` или C17), линкуется с `libbpf.a`, `-lelf -lz`.
Сразу включить `-Wall -Wextra -Werror` — потом дороже.

### CI (GitHub Actions)

Один workflow `ci.yml`, триггер push/PR, три джобы:

- **build** — ubuntu-24.04: поставить clang/bpftool/libelf, `cmake -B build &&
  cmake --build build`. Собрать и BPF-объект, и агент. Артефакт не нужен,
  важен факт компиляции + прохождение verifier'а мы в CI проверить не можем
  (нет привилегий) — только компиляцию и `bpftool gen`.
- **lint** — `clang-format --dry-run --Werror` по `src/`.
- **unit** — сборка и запуск `tests/unit` (пока один тривиальный тест, каркас
  под этап 3). Взять минимальный фреймворк без зависимостей: достаточно
  самодельного `assert`-based main или single-header (например, utest.h),
  чтобы не тянуть GTest в C-проект.

Примечание: запуск самих BPF-программ в CI (vmtest/qemu) — этап 8, здесь не
делаем.

### Definition of done 0.1

- `git clone --recursive && cmake -B build && cmake --build build` даёт бинарник
  `latkit` с нуля на чистой ubuntu 24.04.
- CI зелёный на все три джобы.

---

## Задача 0.2 — PoC: захват трафика порта 5432

### Формат события (`src/bpf/latkit.h`)

Минимум для PoC — без conn_id (это этап 1), идентифицируем по 4-tuple прямо в
событии:

```c
#define POC_CHUNK 256           /* для PoC хватает; 4 КБ — этап 1 */

enum lk_dir { LK_DIR_SEND = 0, LK_DIR_RECV = 1 };

struct lk_event {
    __u64 ts_ns;                /* bpf_ktime_get_ns */
    __u32 pid;
    __u32 saddr, daddr;         /* пока только IPv4; v6 — этап 1 */
    __u16 sport, dport;
    __u8  dir;                  /* enum lk_dir */
    __u8  _pad;
    __u32 total_len;            /* сколько байт было в send/recv всего */
    __u32 cap_len;              /* сколько скопировали в payload */
    __u8  payload[POC_CHUNK];
};
```

### BPF-программы (`latkit.bpf.c`)

- `SEC("fentry/tcp_sendmsg")` — сигнатура
  `tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)`. Данные ещё
  не скопированы в ядро → читать из userspace-буфера (задача 0.3).
- `SEC("fentry/tcp_recvmsg")` + `SEC("fexit/tcp_recvmsg")` — парная схема,
  данные читаем на fexit (задача 0.3).
- Фильтр по порту — прямо в коде, захардкоженный `5432` (`sk->__sk_common.skc_num`
  для локального порта, `skc_dport` — для удалённого; событие интересно, если
  **любой** из двух равен 5432: агент на сервере видит sport=5432, при отладке
  против docker с проброшенным портом может быть иначе). Конфигурируемая map
  портов — этап 1.
- Карты: `BPF_MAP_TYPE_RINGBUF` (`max_entries` = 1 МБ для PoC) + hash map для
  парной схемы recv (задача 0.3).
- Отправка: `bpf_ringbuf_reserve(sizeof(struct lk_event))` → заполнить →
  `bpf_ringbuf_submit`. Не использовать `bpf_ringbuf_output` с буфером на
  стеке — событие больше 512 байт стека не влезет.

### Userspace (`main.c`)

PoC-минимум, без event loop из этапа 2:

1. `latkit_bpf__open_and_load()` + `__attach()`; поднять
   `rlimit MEMLOCK` (для старых ядер; на 5.11+ не нужно, но безвредно).
2. `ring_buffer__new(map_fd, handle_event, ...)` → `ring_buffer__poll(rb, 100)`
   в цикле до SIGINT.
3. `handle_event`: печать
   `ts  dir  pid  src:port -> dst:port  total/captured` + hexdump payload
   (классический формат `xxd`: offset, hex, ASCII — в ASCII-колонке и будут
   видны SQL-строки).
4. Выход по Ctrl-C с корректным `latkit_bpf__destroy` (важно: проверить, что
   fentry-линки детачатся, `bpftool prog list` пуст после выхода).

### Ручная проверка (сценарий приёмки)

```bash
sudo ./build/latkit &
docker compose -f deploy/dev/docker-compose.yml up -d
psql "host=127.0.0.1 port=5432 user=latkit dbname=latkit sslmode=disable" \
     -c "select 'latkit_poc_marker', 42"
```

Ожидаем в выводе агента:
- событие RECV с ASCII `Q....select 'latkit_poc_marker', 42` (плюс перед ним —
  startup-пакет с `user`/`database`);
- события SEND с байтами `T` (RowDescription), `D` (DataRow, внутри маркер),
  `C` (`SELECT 1`), `Z` (ReadyForQuery);
- направления не перепутаны, total_len соответствует реальности,
  `cap_len ≤ POC_CHUNK`.

Обязательно проверить **оба** расположения клиента: psql с хоста в контейнер и
psql изнутри контейнера (`docker exec … psql -h 127.0.0.1`) — во втором случае
трафик идёт через loopback внутри netns контейнера и тоже должен ловиться
(tcp_sendmsg/recvmsg хостового ядра общие для всех netns). Заодно
зафиксировать: соединение через unix-socket (`psql` без `-h`) НЕ видно — это
известный gap из PLAN.md §5, убедиться и записать в docs.

---

## Задача 0.3 — Чтение payload: главный риск

Это исследовательская часть этапа. Две стороны решаются по-разному.

### SEND: обход `iov_iter` из `msghdr` на fentry

На входе в `tcp_sendmsg` данные ещё в userspace, доступны через
`msg->msg_iter`. Проблемы, которые нужно решить и задокументировать:

1. **Тип итератора.** С ядра ~6.0 однобуферный send идёт как `ITER_UBUF`
   (поле `ubuf` — прямой указатель), многосегментный — `ITER_IOVEC`
   (`__iov`/`iov` + `nr_segs`). Читать `msg->msg_iter.iter_type` через CO-RE и
   ветвиться. psql/libpq почти всегда даёт один сегмент → путь UBUF основной,
   IOVEC — цикл с ограниченным unroll (для PoC хватит первых 4 сегментов).
2. **Переименования полей между ядрами.** `iov` → `__iov` (~6.4), появление
   `ubuf` (~6.0), `iov_offset` → `__iov_offset`-подобные сдвиги. Всё читать
   через `BPF_CORE_READ` и `bpf_core_field_exists`, ветки для старых ядер —
   каркас заложить сейчас, наполнение (проверка на 5.15) — этап 8.
3. **Чтение самих данных.** Указатель — userspace, значит
   `bpf_probe_read_user(dst, min(len, POC_CHUNK), base)`. Клиппинг длины
   оформить так, чтобы verifier видел границу (маскирование
   `len & (POC_CHUNK - 1)` или явный `if`).
4. **`iov_offset`** учитывать (обычно 0 на входе в tcp_sendmsg, но не
   полагаться).

Fallback, если чтение iov_iter не взлетит на каком-то ядре: kprobe глубже по
стеку либо sockmap/sk_msg (зафиксировано в PLAN.md §5). В этапе 0 fallback не
реализуем — только убеждаемся, что основной путь работает на 6.x, и оставляем
заметку в docs.

### RECV: парная схема fentry/fexit

На входе в `tcp_recvmsg` буфер пуст; на выходе — заполнен и известен `ret`
(сколько байт скопировано). Тонкость: к моменту fexit `msg_iter` уже
**продвинут** (`iov_iter_advance` в процессе copy_to_user), поэтому указатель
на начало буфера надо сохранить на fentry:

- `BPF_MAP_TYPE_HASH` (`max_entries` ~10k): key = `bpf_get_current_pid_tgid()`,
  value = `{ user_buf_ptr, sock_ptr }`. tcp_recvmsg не переключает контекст
  задачи между входом и выходом → pid_tgid как ключ корректен.
- fentry: если сокет проходит фильтр порта — сохранить базовый указатель
  (из `ubuf` или `iov[0].iov_base`) в map.
- fexit: сигнатура даёт и аргументы, и `ret`. Достать запись из map,
  **обязательно `bpf_map_delete_elem`** (и в ветке ret <= 0 тоже — иначе
  утечка записей), при `ret > 0` прочитать `min(ret, POC_CHUNK)` байт через
  `bpf_probe_read_user` и отправить событие.
- Известное ограничение PoC: если recv раскидан по нескольким iov-сегментам,
  захватываем только первый — для psql это не встречается, отметить в TODO
  этапа 1.

### Мини-эксперименты (чек-лист исследования)

- [ ] `select repeat('x', 100000)` — большой ответ: recv дробится на несколько
      вызовов tcp_recvmsg; убедиться, что события идут последовательно и
      total_len суммируется в ожидаемое.
- [ ] Большой INSERT (многокилобайтный SQL) — большой send, проверить
      total_len > cap_len и корректный префикс.
- [ ] pgbench на 30 сек (`-c 10`) — нет ошибок verifier'а в dmesg, нет паник,
      агент не падает, `bpftool map dump` hash-карты после остановки нагрузки
      пуст (нет утечки записей fentry→fexit).
- [ ] Записать в `docs/notes-iov.md`: какой iter_type наблюдаем на каких
      операциях, какие поля читали, на чём споткнулся verifier — это входные
      данные для этапа 1 и матрицы ядер этапа 8.

### Definition of done 0.3

Оба направления читаются на текущем ядре (6.17); ограничения (multi-iov,
старые ядра) записаны, а не «обнаружатся потом».

---

## Задача 0.4 — Docker-окружение для разработки

`deploy/dev/docker-compose.yml`:

```yaml
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_USER: latkit
      POSTGRES_PASSWORD: latkit
      POSTGRES_DB: latkit
    command: ["postgres", "-c", "ssl=off"]   # TLS — этап 6, здесь явно off
    ports: ["5432:5432"]

  pgbench-init:
    image: postgres:16
    depends_on: [postgres]
    entrypoint: ["pgbench", "-h", "postgres", "-U", "latkit", "-i", "-s", "10", "latkit"]
    environment: { PGPASSWORD: latkit }
    restart: "no"
```

Плюс скрипт-обёртка `deploy/dev/bench.sh` для нагрузки по требованию:
`pgbench -h 127.0.0.1 -U latkit -c 10 -T 30 latkit` (и вариант
`-S` select-only). Агент в этапе 0 в docker **не** заворачиваем — запускается
на хосте под sudo; контейнеризация агента — этап 7.

В `sslmode=disable` для psql-проверок — обязательно: иначе libpq может
согласовать TLS и в socket-канале будет шифрованный мусор (и это, кстати,
полезно один раз увидеть глазами — понять, как выглядит TLS-соединение с точки
зрения socket-хуков, пригодится для флага дедупликации в этапе 6).

---

## Порядок работ по дням (ориентир)

| День | Работа |
|---|---|
| 1 | 0.1: каркас репо, CMake, libbpf submodule, hello-world BPF (fentry без payload) грузится и печатает событие |
| 2 | 0.1: CI + clang-format + каркас unit-тестов; 0.4: docker-compose |
| 3–4 | 0.3/0.2: send-путь (iov_iter/ubuf), hexdump psql-запросов |
| 4–5 | 0.3/0.2: recv-путь (fentry/fexit + hash map), полный двусторонний hexdump |
| 5 | приёмка: сценарий с маркером, pgbench-прогон, notes-iov.md, фиксация ограничений |

Буфер ~1 день заложен на борьбу с verifier'ом — это нормальная статья расходов.

## Риски именно этого этапа

| Риск | Действие |
|---|---|
| Verifier отвергает чтение iov_iter (границы, типы указателей) | маскирование длины, `bpf_core_*`, смотреть готовые реализации (libbpf-tools/sslsniff, ecapture) как референс приёмов, не кода |
| fentry на tcp_* недоступен (нет BTF trampoline) — на чужих машинах | на dev-машине есть; kprobe-fallback зафиксировать как задачу этапа 1, в PoC не делать |
| На fexit tcp_recvmsg буфер уже «уехал» из-за advance | решено схемой «сохранить указатель на fentry» — проверить экспериментом в первый же день recv-работ |
| Loopback/контейнерные пути дают неожиданные функции (напр. обход tcp_sendmsg) | проверка обоих сценариев расположения клиента входит в приёмку 0.2 |

## Что сознательно НЕ делаем в этапе 0

- conn_id, CONN_OPEN/CLOSE, seq и нарезка длинных payload — этап 1;
- конфигурируемые фильтры портов/cgroup — этап 1;
- учёт потерь ringbuf — этап 1 (но `max_entries` уже вынести в константу);
- reassembly и любой парсинг протокола — этапы 2–3 (в PoC смотрим глазами);
- IPv6 и unix sockets — этап 1 / v1.1;
- TLS — этап 6;
- минимальные capabilities вместо sudo — этап 7.
