# Этап 7 — Grafana, упаковка, документация

Детализация этапа 7 из [PLAN.md](PLAN.md) (§4). Оценка: **~1–1,5 недели**
(6–7 рабочих дней; кода в пайплайне почти нет — единственная содержательная
фича этапа — cgroup-фильтр; остальное — дашборды, упаковка и докумен-
тация, где основной риск не «не заработает», а «разъедется с реальностью»).

**Цель:** превратить работающий агент (после этапа 6 — метрики, спаны и
TLS) в **продукт, который чужой человек разворачивает за 5 минут**:
provisioned-дашборды Grafana, demo-стек `docker compose up`, дистрибуция
(статический бинарник, Docker-образ, systemd unit, k8s DaemonSet),
cgroup-фильтр для k8s (долг задачи 1.3) и README, который отвечает на все
вопросы до того, как их задали. Пайплайн `src/proto/`, `src/norm/`,
`src/metrics/`, `src/export/` **не трогаем** (критерий этапа, как в 6);
в `src/agent/`+`src/bpf/` — только cgroup-фильтр.

**Не входит в этап:**
- **нагрузочный бюджет, матрица ядер, fuzzing, long-run** — этап 8 (здесь
  только фиксация требований в README);
- **deb/rpm-пакеты и Helm-chart** — v1.1 по спросу; DaemonSet-манифест и
  тарбол с бинарником покрывают v1;
- **алерты Grafana / recording rules Prometheus** — пример-сниппет в docs,
  как поставляемый артефакт не делаем (пороги зависят от инсталляции);
- **arm64** — сборка возможна (CO-RE не мешает), но тестировать негде:
  релизный артефакт v1 — x86_64; arm64 — v1.1;
- **unix domain sockets** — known gap v1.1 (PLAN.md §5), в README —
  явным ограничением;
- **автодискавери postgres-подов** в k8s (operator-функциональность) —
  v1 конфигурируется руками: порт + comm + cgroup-глоб;
- YAML-конфиг — остаётся отложенным (Р34): systemd/DaemonSat живут на
  env+флагах, этап это докажет на практике.

**Долги предыдущих этапов, закрываемые здесь:**

- **этап 1, задача 1.3**: «фильтр по cgroup — не делаем, зафиксировать
  как задачу этапа 7 (k8s)» — закрывается (Р48);
- **этап 0** (выбор «вариант A», submodule `third_party/libbpf`): «нам в
  этапе 7 всё равно нужен статический бинарник» — исполняется (Р45);
- **этап 5**: e2e-стенд `tests/e2e/` — донор для demo-компоуза (Р43);
  bind-дефолт `127.0.0.1:9752` (Р29) в контейнерных деплоях явно
  переопределяется; env-слой Р34 — основной способ конфигурации
  unit/DaemonSet;
- **этап 6, Р39**: требования uprobes (`hostPID`, доступ к
  `/proc/<pid>/(maps|root)`) — материализуются в Dockerfile и DaemonSet
  (Р46/Р47);
- **этапы 4–6, security-замечания** (маскирование литералов, сырой SQL в
  спанах за флагом, bind-дефолт): собираются в один раздел README (Р44).
  STAGE6.md уже ссылается на **Р44** как на «задокументированное
  ограничение» — номер закрепляется здесь за решением о документации.

**Отклонение от PLAN.md §3:** нет — `dashboards/` и `deploy/` появляются
ровно там, где план их предполагает. Внутри `deploy/` — подкаталоги
`dev/` (существующий стенд), `demo/`, `docker/`, `systemd/`, `k8s/`.
Demo-стек — **отдельный** compose в `deploy/demo/`, а не расширение
`tests/e2e/`: e2e — ассерты для CI, demo — витрина для человека; смешение
превратило бы оба в кашу.

---

## Ключевые проектные решения

Нумерация продолжает Р1–Р41 из [STAGE1.md](STAGE1.md) …
[STAGE6.md](STAGE6.md).

### Р42. Дашборды: четыре JSON, датасорс — переменная, кардинальность под контролем

Четыре дашборда в `dashboards/` с фиксированными `uid` (для стабильных
кросс-ссылок и провижининга):

| uid | Название | Содержимое |
|---|---|---|
| `latkit-overview` | Overview | QPS, p50/p95/p99, error rate, активные/новые соединения, длительность транзакций по статусу (I/T/E), сводка потерь (ringbuf drops, resync) |
| `latkit-queries` | Top queries | top-N нормализованных запросов по p99 / суммарному времени / частоте / ошибкам; таблица с data link на drilldown |
| `latkit-drilldown` | Drilldown | те же метрики в разрезе `$db`/`$user`/`$query`; first-row latency, rows/query, ошибки по SQLSTATE |
| `latkit-health` | Agent health | все self-метрики: `latkit_ringbuf_dropped_total`, `latkit_resync_total`, `latkit_parse_errors_total`, `latkit_queries_dropped_total{reason}`, `latkit_conns_evicted_total{reason}`, `latkit_metric_series`, `latkit_scrape_duration_seconds`, `latkit_otlp_exports_total{result}`, `latkit_tls_attached{state}`, `latkit_tls_correlation_misses_total`, `process_cpu_seconds_total`, `process_resident_memory_bytes` |

Правила построения:

- **датасорс — переменная** `$datasource` (type `datasource`, фильтр
  `prometheus`) — работает с Prometheus/Mimir/VictoriaMetrics без правки
  JSON (требование PLAN.md §4). Никаких захардкоженных uid датасорсов и
  никаких `__inputs`-плейсхолдеров экспорта «for sharing» — дашборды
  кладутся провижинингом as is;
- **квантили — из классических `le`-бакетов** (Р30):
  `histogram_quantile(0.95, sum by (le) (rate(latkit_query_duration_seconds_bucket[$__rate_interval])))`;
  везде `$__rate_interval`, не захардкоженные `[1m]`;
- **top-N — только `topk()` поверх агрегатов**, никогда «все ряды по
  `query` на график»: панели top-N — instant-таблицы
  (`topk($topk, sum by (query) (rate(...)))`) плюс один timeseries по
  выбранному из `$query`. Переменные `$db`, `$user`, `$query` — через
  `label_values(latkit_queries_total, db)` и т.п., `$topk` — custom
  (5/10/20, дефолт 10). Лейбл `query` уже усечён агентом
  (`--query-label-len`, Р28) — дашборд этому доверяет;
- **error rate** — отношение:
  `sum(rate(latkit_query_errors_total[$__rate_interval])) / sum(rate(latkit_queries_total[$__rate_interval]))`,
  и отдельно разбивка по `sqlstate`;
- **честность данных на виду**: панель-аннотация «capture degraded» на
  overview из `rate(latkit_ringbuf_dropped_total[...] ) > 0` или
  `latkit_resync_total` — пользователь обязан видеть, когда цифрам
  нельзя верить (философия Р5/Р27);
- **изготовление и защита от гниения**: JSON выгружается из Grafana UI
  на demo-стенде (руками его не пишем), но в CI появляется
  `dashboards/lint.sh`: (а) `jq` — валидность, фиксированные uid,
  `$datasource` во всех панелях, отсутствие `__inputs`; (б) выгрести все
  `expr` и сверить имена метрик с эталонным списком номенклатуры
  (генерится из реестра: `latkit --dump-metrics` на replay-фикстуре +
  список self-метрик). Переименовали метрику — CI красный;
- Grafana **пин на мажорную версию** (11.x) в demo; schema-версия JSON —
  какую даст экспорт этой версии, ниже не опускаемся.

### Р43. Demo-стек: `deploy/demo`, «ценность за 5 минут», отдельно от e2e

Состав `deploy/demo/docker-compose.yml`:

- **postgres** (официальный образ, 17-alpine) — без published port:
  клиенты ходят по внутренней сети compose напрямую (docker-proxy на
  localhost загрязняет захват loopback-дублями — грабли стенда известны;
  внутри compose-сети прокси не участвует);
- **load** — генератор нагрузки: контейнер с циклом из `pgbench`
  (select-only + TPC-B) **плюс** периодические «спецзапросы» через psql —
  `pg_sleep(0.2…1)` (наполняет хвост p99), заведомые ошибки
  (`select 1/0`, нарушение unique) — чтобы error-панели и SQLSTATE-разбивка
  не были мёртвыми на демо. Нагрузка скромная (демо, не бенчмарк);
- **latkit** — образ из Р46, `pid: host`, `privileged: true` (для демо —
  простота; минимальный CAP-набор — в README и в закомментированном
  варианте `cap_add`), `LATKIT_PROM_LISTEN=0.0.0.0:9752` (дефолт Р29 —
  loopback, в контейнере обязан слушать наружу), `LATKIT_PORT=5432`;
- **prometheus** — scrape `latkit:9752` раз в 5 с (демо должно оживать
  быстро), retention маленький;
- **grafana** — anonymous auth (Viewer), provisioning:
  `datasources/` (Prometheus, `isDefault`) + `dashboards/` — каталог
  `../../dashboards` монтируется read-only, provider с
  `foldersFromFilesStructure`. Дашборды в репозитории — единственный
  источник, никаких копий;
- **профиль `tls`** (`--profile tls`): postgres с `ssl=on` +
  самоподписанный серт, клиент `sslmode=require` — демонстрация этапа 6
  одной строчкой.

UX-контракт: `git clone && cd deploy/demo && docker compose up` → через
≤5 минут на `localhost:3000` живые панели со всеми четырьмя дашбордами.
Требования demo зафиксировать прямо в `deploy/demo/README.md`:
**Linux-хост**, ядро ≥ 5.15 с BTF (`/sys/kernel/btf/vmlinux`); Docker
Desktop (macOS/Windows) — ядро VM, работоспособность не обещаем. Агент на
старте проверяет BTF/ядро и падает с внятным сообщением (уже есть с
этапа 0/1 — сверить текст, чтобы он говорил «kernel 5.15+ with BTF
required», а не голый errno).

`tests/e2e/` остаётся как есть (ассерты CI, этап 5/6); demo от него
берёт приёмы (сеть, IP-адресация), но не общие файлы — их жизненные
циклы разные.

### Р44. Документация: README — пользовательская точка входа, ограничения v1 — одним списком

(Номер закреплён форвард-ссылками из STAGE6.md: «задокументированное
ограничение (Р44)».)

- **README.md** переписывается из «заметок разработчика» в продуктовый:
  1. что это и зачем (одним абзацем + скриншот overview-дашборда из demo);
  2. quickstart = demo-стек (3 команды);
  3. установка: бинарник (release-тарбол), Docker, systemd, k8s — по
     подразделу со ссылками на `deploy/*`;
  4. **требования**: ядро ≥ 5.8 (ringbuf), целевое/тестируемое 5.15+,
     BTF; cgroup v2 для cgroup-фильтра; динамический OpenSSL для TLS;
     capabilities-таблица (Р46);
  5. **конфигурация**: полная таблица флаг ↔ `LATKIT_*` env ↔ дефолт
     (Р34) — генерится сверкой с `--help`, расхождение ловит тест;
  6. **модель измерения** (PLAN.md §1): серверное время «сеть-до-сети»,
     чем отличается от `pg_stat_statements` — управление ожиданиями до
     этапа 8;
  7. **security**: агент видит текст SQL; маскирование литералов включено
     по умолчанию (этап 4); сырой SQL покидает агент только в спанах за
     явным флагом (Р32); bind-дефолт loopback (Р29); что даёт
     `CAP_SYS_PTRACE`+`hostPID` и почему они нужны для TLS (Р39);
  8. **ограничения v1** — один консолидированный список со ссылками:
     unix-сокеты (v1.1), GSSENC (детект+drop), статический/не-OpenSSL TLS,
     нет https/auth на своих эндпоинтах, нет native-histogram exposition
     (рецепт через OTLP, Р30), cgroup-фильтр требует v2, x86_64 only.
- `docs/deploy.md` — подробности деплоя, которым не место в README:
  вывод минимального CAP-набора и его зависимость от LSM, systemd-
  hardening, нюансы k8s (cgroup-глоб, hostPID, runtime-специфика);
  `docs/notes-*.md` остаются инженерными записками — на них README
  ссылается, но не дублирует.
- PLAN.md §4: отметить этап 7; §3 — уже совпадает.

### Р45. Статический бинарник: musl full-static как релизный артефакт, glibc — для разработки

PLAN.md §2 допускает «musl или glibc + static libbpf/libelf/zlib».
Решающий довод за musl: **полностью** статический glibc-бинарник — ловушка
(`getaddrinfo`/NSS требуют динамических `libnss_*` даже при `-static`, а
OTLP-клиент Р31 резолвит endpoint). musl несёт собственный резолвер —
честный `-static` без сюрпризов:

- **релизная сборка** — в Alpine-контейнере (`deploy/docker/Dockerfile`,
  builder-стадия): clang + cmake + `bpftool gen skeleton` как обычно,
  линковка `-static` с musl; libbpf уже статический из
  `third_party/libbpf` (этап 0), `libelf`/`zlib`/`zstd` — статические из
  apk. Результат: `ldd latkit` → «not a dynamic executable», один файл,
  работает на любом дистрибутиве с подходящим ядром (CO-RE);
- **фолбэк**, если статическая связка elfutils+musl окажется болью
  (известная зона турбулентности): glibc-сборка на **старой базе**
  (debian:11) со статическими libbpf/libelf/zlib и динамическими
  libc/libpthread — совместимо со всеми живыми glibc-дистрибутивами.
  Решение зафиксировать по факту в задаче 7.2, README описывает то, что
  получилось;
- **версия — один источник**: `git describe --tags --dirty` → CMake →
  `-DLATKIT_VERSION` → флаг `--version`, строка в `--help`, баннер лога
  при старте и `service.version` в OTLP-ресурсе (Р31 — сейчас там
  заглушка, заменить);
- **релизный пайплайн**: GitHub Actions job по тегу `v*`: сборка
  релизного бинарника, `sha256sum`, тарбол (бинарник + LICENSE +
  дашборды + systemd unit + DaemonSet), публикация в GitHub Release +
  push Docker-образа в ghcr.io с тегами `vX.Y.Z` и `latest`. Никаких
  «ночных» релизов — только теги;
- dev-сборка (обычный `cmake --build`) остаётся динамической glibc — с
  санитайзерами musl-static не дружит, и это не нужно.

### Р46. Docker-образ: scratch + статический бинарник, минимальные capabilities

- **multi-stage Dockerfile** (`deploy/docker/Dockerfile`): builder =
  релизная сборка Р45; финальная стадия — `FROM scratch`, в ней ровно
  `/latkit` (+ `/etc/ssl` не нужен — своих TLS-клиентов у агента нет,
  Р31/Р29). `ENTRYPOINT ["/latkit"]`, конфигурация — env `LATKIT_*`
  (Р34). Размер образа ≈ размер бинарника;
- **запуск** (документированная команда):
  `docker run --pid=host --cap-add BPF --cap-add PERFMON --cap-add SYS_RESOURCE --cap-add SYS_PTRACE -p 9752:9752 ...`.
  Обоснование набора: `CAP_BPF`+`CAP_PERFMON` — программы/карты и
  fentry/uprobes; `CAP_SYS_RESOURCE` — memlock rlimit на ядрах < 5.11
  (на новых — memcg, не помешает); `CAP_SYS_PTRACE` —
  `PTRACE_MODE_READ` для чтения `/proc/<pid>/maps` и открытия
  `/proc/<pid>/root/...` чужих процессов (автодетект libssl, Р39).
  `hostPID` обязателен для того же. **Фактический минимальный набор
  зависит от ядра и LSM** (AppArmor/SELinux могут резать сверх CAP) —
  задача 7.2 проверяет набор опытным путём на стенде и фиксирует в
  `docs/deploy.md`; `--privileged` — документированный fallback, не
  дефолт;
- `hostNetwork` **не нужен**: fentry на `tcp_*` видит все netns хоста
  по определению (захват — не сетевой доступ), `/metrics` публикуется
  обычным портом;
- HEALTHCHECK в образ не кладём (в scratch нет curl, а тащить его ради
  этого — против смысла scratch): compose/k8s проверяют `/healthz`
  снаружи (kubelet `httpGet` умеет сам).

### Р47. systemd unit и k8s DaemonSet: env-конфиг Р34 как единственный интерфейс

**systemd** (`deploy/systemd/latkit.service` + `latkit.env.example`):

- `Type=simple` (лог в stderr → journald, sd_notify не нужен),
  `EnvironmentFile=-/etc/latkit/latkit.env`, `Restart=on-failure`,
  `RestartSec=5`;
- запуск root'ом, но с песочницей:
  `CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_SYS_PTRACE`,
  `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`,
  `PrivateTmp=yes`, `ReadWritePaths=` пусто (агент не пишет на диск,
  кроме `--record` — для него строка-подсказка в комментарии). Non-root +
  `AmbientCapabilities` — заманчиво, но доступ к `/proc/<pid>/root`
  чужих uid из-под non-root требует отдельной проверки — эксперимент
  v1.1, в unit — комментарий;
- установка: `install`-цель в CMake кладёт бинарник в
  `/usr/local/bin`, unit — руками (или из релиз-тарбола) — deb/rpm нет
  (scope).

**k8s** (`deploy/k8s/latkit-daemonset.yaml`, один файл, без Helm):

- `hostPID: true`; `securityContext.capabilities.add: [BPF, PERFMON,
  SYS_RESOURCE, SYS_PTRACE]`, рядом закомментированный
  `privileged: true` fallback (некоторые runtime/ядра не дают тонких CAP);
- volume: `/sys/fs/cgroup` (ro, hostPath) — резолв cgroup-путей для
  фильтра Р48; BTF (`/sys/kernel/btf`) в контейнере виден и так —
  проверить, при необходимости hostPath ro;
- конфигурация — env `LATKIT_*` прямо в манифесте (`LATKIT_PROM_LISTEN=
  0.0.0.0:9752`, `LATKIT_PORT`, `LATKIT_CGROUP=...` — Р48);
- `ports: containerPort 9752` + аннотации `prometheus.io/scrape` (и
  комментарий про PodMonitor для prometheus-operator — сам CRD не
  поставляем); `livenessProbe`/`readinessProbe` — `httpGet /healthz`;
- `resources`: requests `100m/64Mi`, limits `500m/256Mi` — рабочая
  гипотеза, уточняет этап 8 (комментарий в манифесте);
- `tolerations` на control-plane не ставим (postgres там не живёт),
  `nodeSelector` — пример в комментарии;
- проверка — kind/minikube (задача 7.5): postgres-под + pgbench-Job,
  метрики в Prometheus, cgroup-фильтр различает два postgres-пода.

### Р48. cgroup-фильтр: карта id, глоб-пути, периодический ре-резолв

Долг задачи 1.3; сценарий — несколько postgres на хосте (k8s-поды) с
одинаковым портом 5432: портовый фильтр не различает, comm — тоже.

- **ядро**: карта `cgroups` (`BPF_MAP_TYPE_HASH`, key `u64` cgroup id,
  value `u8`, 64 записи). Предикат в send/recv-пути (и только там — как
  comm-фильтр, Р7/1.3): карта непуста → `bpf_get_current_cgroup_id()`
  ∈ `cgroups`. `current` в fentry `tcp_sendmsg`/fexit `tcp_recvmsg` —
  процесс postgres, id корректен. Пустая карта = фильтр выключен —
  ровно как карта `ports`;
- **требование cgroup v2**: `bpf_get_current_cgroup_id()` осмыслен
  только на unified hierarchy. `--cgroup` на чистом v1-хосте — фатальная
  ошибка на старте с внятным текстом (не тихое «ничего не ловится»);
  зафиксировать в README (Р44). В 2026 v2 повсеместен — ограничение
  теоретическое;
- **userspace**: `--cgroup PATTERN` (повторяемый; env `LATKIT_CGROUP`,
  разделитель `,`). PATTERN — путь относительно `/sys/fs/cgroup`
  с **glob** (`fnmatch`, `*` не пересекает `/`, `**` — пересекает):
  в k8s путь пода содержит uid
  (`kubepods.slice/kubepods-burstable.slice/kubepods-*-pod*/...`) —
  без глоба фильтр там бесполезен. Резолв: обход matched-каталогов,
  cgroup id = inode (`name_to_handle_at(2)` — стабильный способ),
  запись в карту;
- **ре-резолв по таймеру** (`lk_loop_every`, 30 с — тот же ритм, что
  ре-скан libssl Р39): под пересоздали — старый id удаляется из карты,
  новый (тот же глоб) добавляется. Гонка «под стартовал между тиками» —
  потеря первых секунд захвата нового пода; для метрик агрегатов
  приемлемо, задокументировать;
- **наблюдаемость**: `latkit_cgroup_filter_paths` (gauge — сколько путей
  сейчас смэтчено; 0 при заданном фильтре — виден мисконфиг) в
  self-метрики через провайдеры Р27; лог на добавление/удаление id;
- **семантика совмещения**: порт И cgroup И comm — все активные фильтры
  соединяются по «и» (как сейчас порт+comm). `--dry-run` (Р34/этап 2)
  печатает итоговую конфигурацию фильтров — сверить, что cgroup туда
  попал.

---

## Структура репозитория (целевой срез)

```
dashboards/
├── latkit-overview.json        # Р42; фиксированные uid, $datasource
├── latkit-queries.json
├── latkit-drilldown.json
├── latkit-health.json
└── lint.sh                     # jq-валидация + сверка метрик (CI)
deploy/
├── dev/                        # как было (стенд разработки)
├── demo/
│   ├── docker-compose.yml      # Р43: pg + load + latkit + prom + grafana
│   ├── README.md               # «5 минут», требования (Linux, BTF)
│   ├── load/                   # скрипт нагрузки: pgbench + spice
│   └── grafana/                # provisioning: datasources, dashboards
├── docker/
│   └── Dockerfile              # Р45/Р46: builder (musl static) + scratch
├── systemd/
│   ├── latkit.service          # Р47
│   └── latkit.env.example      # все LATKIT_* с комментариями
└── k8s/
    └── latkit-daemonset.yaml   # Р47
src/
├── bpf/latkit.bpf.c            # + карта cgroups, предикат в send/recv (Р48)
├── agent/
│   ├── loader.c                # + заполнение cgroups: глоб, name_to_handle_at,
│   │                           #   ре-резолв по таймеру (Р48)
│   └── main.c                  # + --cgroup, --version (Р45/Р48)
.github/workflows/
├── ci.yml                      # + джоба dashboards-lint; + сборка релизного
│                               #   бинарника как smoke (без публикации)
└── release.yml                 # Р45: тег v* → тарбол + ghcr.io
README.md                       # переписан (Р44)
docs/deploy.md                  # CAP-набор, LSM, k8s-нюансы (Р44)
```

---

## Задачи

Разбивка соответствует будущим коммитам (`Stage 7.x: ...`).

### 7.1 cgroup-фильтр (~1 день)

- [ ] `latkit.bpf.c`: карта `cgroups`, предикат
      `bpf_get_current_cgroup_id()` в send/recv-пути при непустой карте;
      как `ports` — пусто значит выключено.
- [ ] `loader.c`: `--cgroup PATTERN` (повторяемый) + `LATKIT_CGROUP`;
      глоб по `/sys/fs/cgroup`, id через `name_to_handle_at`; детект
      cgroup v1 → фатальная ошибка; ре-резолв `lk_loop_every(30)` с
      диффом карты; gauge `latkit_cgroup_filter_paths`; `--dry-run`
      показывает фильтр.
- [ ] Проверка на стенде: **два** postgres-контейнера на 5432 (разные
      cgroup), `--cgroup 'system.slice/docker-<id1>*'` → запросы ко
      второму не рождают наблюдений; пересоздание контейнера →
      после ре-резолва захват возобновляется.
- [ ] Unit: глоб-матчинг и дифф-логика ре-резолва как чистые функции
      (без BPF); тест «фильтр задан, путей 0 → gauge 0 + warn-лог».

**Готово, когда:** на хосте с двумя postgres агент с `--cgroup` видит
только целевой; без флага — оба (регресса нет); пересоздание цели
переживается без рестарта агента; v1-хост с флагом падает внятно.

### 7.2 Статический бинарник, Docker-образ, версия (~1,5 дня)

- [ ] `deploy/docker/Dockerfile`: builder-стадия Alpine (clang, cmake,
      bpftool, статические libelf/zlib) → `-static` musl-бинарник;
      финальная стадия scratch + `/latkit`. Если musl+elfutils
      упрётся — зафиксировать fallback glibc/debian:11 (Р45) и отразить
      в README.
- [ ] Версия: `git describe` → `LATKIT_VERSION` в CMake; `--version`;
      баннер в лог при старте; `service.version` в OTLP-ресурсе
      (заменить заглушку Р31).
- [ ] Проверить бинарник на «чужих» rootfs: контейнеры alpine, debian,
      fedora (хост-ядро одно — интересует userspace-совместимость):
      `--version`, `--dry-run`, полный захват на dev-стенде.
- [ ] Опытный вывод минимального CAP-набора: перебор на стенде
      (plaintext-захват; TLS-захват с uprobes; с/без AppArmor) →
      таблица в `docs/deploy.md`; `--privileged` — документированный
      fallback.
- [ ] `ci.yml`: джоба сборки релизного бинарника (артефакт, без
      публикации) — ловим поломку статической линковки до релиза.

**Готово, когда:** `ldd` показывает статический бинарник (или
задокументированный glibc-fallback); scratch-образ с минимальными CAP
и `--pid=host` захватывает plaintext и TLS на dev-стенде;
`latkit --version` совпадает с git-тегом; CI собирает релизный артефакт.

### 7.3 Дашборды (~1,5 дня)

- [ ] Поднять заготовку demo-стека (без полировки) — среда для
      изготовления дашбордов с живой нагрузкой.
- [ ] Собрать в Grafana UI и выгрузить в `dashboards/` четыре дашборда
      Р42: overview, queries (top-N + data links), drilldown
      (`$db`/`$user`/`$query`), health. Все панели — `$datasource`,
      `$__rate_interval`, квантили из `_bucket`.
- [ ] `dashboards/lint.sh`: jq-валидация (uid, `$datasource`, нет
      `__inputs`) + сверка имён метрик из `expr` с эталонным списком
      (генерация: `--dump-metrics` на replay-фикстурах + self-ряды);
      джоба в `ci.yml`.
- [ ] Ревью кардинальности: ни одной панели, рисующей неограниченное
      множество рядов по `query`; аннотация «capture degraded» на
      overview.
- [ ] Скриншот overview (с живой нагрузкой) → `docs/img/` для README.

**Готово, когда:** на demo-стенде все четыре дашборда живые без единой
«No data»/ошибки запроса; переключение `$datasource` работает; `lint.sh`
зелёный в CI и краснеет от переименованной метрики (проверить нарочно).

### 7.4 Demo-стек «5 минут» (~1 день)

- [ ] `deploy/demo/docker-compose.yml` (Р43): postgres + load + latkit
      (образ 7.2) + prometheus + grafana с полным provisioning из
      `dashboards/`; профиль `tls` с `ssl=on`-постгресом.
- [ ] `load/`: цикл pgbench (select-only + TPC-B) + периодические
      `pg_sleep` и запросы-с-ошибками — все панели демо живые, включая
      p99-хвост и SQLSTATE-разбивку.
- [ ] Сетевая гигиена: нагрузка только по compose-сети (никаких
      published-портов у postgres — docker-proxy/loopback не должен
      попадать в захват); latkit слушает `0.0.0.0:9752` внутри сети.
- [ ] `deploy/demo/README.md`: 3 команды, требования (Linux-хост,
      ядро ≥ 5.15, BTF), что где смотреть, как включить TLS-профиль.
- [ ] Хронометраж на чистой машине (или свежая VM): от `git clone` до
      живых панелей — уложиться в 5 минут (без учёта docker pull на
      медленной сети — оговорка в README).

**Готово, когда:** `docker compose up` на чистом Linux-хосте даёт
работающую Grafana с четырьмя живыми дашбордами ≤ 5 минут; профиль
`tls` показывает TLS-соединения (`latkit_tls_connections > 0`);
`compose down -v` не оставляет мусора.

### 7.5 systemd unit и k8s DaemonSet (~1 день)

- [ ] `deploy/systemd/`: `latkit.service` (Р47: песочница, CAP-set,
      EnvironmentFile) + `latkit.env.example` со **всеми** `LATKIT_*` и
      комментариями; CMake `install`-цель для бинарника.
- [ ] Проверка unit на dev-хосте: `systemctl start` → захват идёт,
      `journalctl` показывает лог, `systemctl restart` чистый, юнит
      переживает `latkit`-краш (Restart=on-failure).
- [ ] `deploy/k8s/latkit-daemonset.yaml` (Р47): hostPID, CAP-set (+
      закомментированный privileged), volume `/sys/fs/cgroup` ro,
      env-конфиг, probes на `/healthz`, prometheus-аннотации, resources.
- [ ] Прогон на kind: latkit DaemonSet + postgres-под + pgbench-Job →
      метрики скрейпятся; **два** postgres-пода + `LATKIT_CGROUP`
      с глобом kubepods → различаются (интеграционная проверка Р48);
      удаление/пересоздание пода — ре-резолв отрабатывает.
- [ ] `docs/deploy.md`: всё, что вылезло в 7.2/7.5 (CAP/LSM, kind-нюансы,
      cgroup-глобы для kubepods, privileged-fallback).

**Готово, когда:** unit и DaemonSet работают на реальных стендах (dev-хост
и kind), cgroup-фильтр подтверждён в k8s-сценарии, все грабли записаны в
`docs/deploy.md`.

### 7.6 README, релиз, финал этапа (~1 день)

- [ ] README.md по структуре Р44: intro + скриншот, quickstart,
      установка ×4, требования, таблица флагов/env (сверка с `--help` —
      маленький тест/скрипт, чтобы не разъезжалось), модель измерения,
      security-раздел, консолидированные ограничения v1.
- [ ] `release.yml`: тег `v*` → сборка (7.2), sha256, тарбол (бинарник +
      LICENSE + dashboards/ + systemd + k8s), GitHub Release, push
      образа в ghcr.io (`vX.Y.Z`, `latest`).
- [ ] Прогнать релизный пайплайн на pre-теге (`v0.9.0-rc1` или тестовый
      тег в форке) — артефакты скачиваются и работают.
- [ ] PLAN.md: §4 — этап 7 выполнен (включая перенесённую задачу 1.3);
      §5 — строка «взрыв кардинальности» дополнена «дашборды строятся
      только на topk» (митигация со стороны потребителя).
- [ ] Пройти чек-лист выхода ниже целиком.

**Готово, когда:** человек со стороны по одному README доходит от нуля до
метрик своим путём (binary/docker/systemd/k8s); релиз собирается тегом
без ручных шагов.

---

## Чек-лист выхода этапа

Вклад в **v1.0** (PLAN.md §6): «демо-стек, дашборды, документация» из
критериев v1.0 (остаётся этап 8: overhead и hardening).

- [ ] **«5 минут»**: чистый Linux-хост, `git clone` → `docker compose up`
      → четыре живых дашборда в Grafana; хронометраж уложился, требования
      написаны там, где их увидят до запуска.
- [ ] Дашборды: все панели работают на demo **и** на e2e-стенде этапа 5;
      `$datasource` переключается; `lint.sh` в CI ловит переименование
      метрики; ни одной панели с неограниченной кардинальностью.
- [ ] Бинарник: один файл, запускается на alpine/debian/fedora rootfs;
      `--version` = git-тег; относительно статичности — либо полный
      static (musl), либо задокументированный glibc-fallback.
- [ ] Docker-образ: scratch, работает с документированным минимальным
      CAP-набором + `--pid=host` (plaintext и TLS); `--privileged` — только
      как задокументированный fallback.
- [ ] systemd unit: старт/стоп/рестарт чистые, песочница включена,
      env-файл — единственное место конфигурации.
- [ ] DaemonSet на kind: метрики скрейпятся, probes зелёные; cgroup-фильтр
      различает два postgres-пода на одном порту; пересоздание пода
      переживается без рестарта агента.
- [ ] cgroup-фильтр: «и»-семантика с портом/comm, `--dry-run` показывает,
      gauge путей в self-метриках; v1-хост падает внятно; unit-тесты
      глоба/диффа зелёные.
- [ ] README: таблица флагов/env механически сверена с `--help`;
      security-раздел и ограничения v1 консолидированы (закрыты ссылки
      Р44 из STAGE6.md); модель измерения описана.
- [ ] Релиз по тегу: тарбол + образ ghcr.io из одного workflow; sha256
      сходятся; артефакт с релиза проходит quickstart.
- [ ] `src/proto/`, `src/norm/`, `src/metrics/`, `src/export/` не
      изменены; ASAN/UBSAN и вся линейка unit/replay-тестов зелёные
      (cgroup-код не задел пайплайн).

---

## Риски этапа

| Риск | Митигация |
|---|---|
| Статическая линковка musl + elfutils/libbpf не соберётся или даст тонкие баги | заранее объявленный fallback (Р45): glibc на старой базе + статические libbpf/libelf/zlib; проверка на трёх rootfs; CI собирает релизный бинарник на каждом push |
| Полный static + glibc `getaddrinfo`/NSS — тихие сюрпризы в рантайме | основной путь — musl (свой резолвер); fallback оставляет libc динамическим — сюрприз исключён конструктивно |
| Дашборды сгниют при переименовании метрик | `dashboards/lint.sh` в CI: сверка `expr` с номенклатурой из живого реестра; e2e-стенд как рендер-проверка |
| Demo не работает на Docker Desktop (macOS/Win): ядро VM без нужного BTF/привилегий | честное требование «Linux-хост» в demo-README; проверка BTF на старте агента с внятным сообщением |
| docker-proxy/loopback загрязняет захват demo | нагрузка только по внутренней compose-сети, у postgres нет published-портов (грабли стенда учтены в Р43) |
| Минимальный CAP-набор различается между ядрами/LSM (AppArmor, SELinux) | набор выводится опытным путём и фиксируется с оговорками в `docs/deploy.md`; privileged — документированный fallback; матрица ядер — этап 8 |
| cgroup id нестабилен в k8s (пересоздание пода) | глоб-паттерны + ре-резолв по таймеру (Р48); окно потери первых секунд нового пода задокументировано; gauge путей ловит мисконфиг |
| Хост на cgroup v1 → фильтр не работает | детект + фатальная ошибка на старте при заданном `--cgroup` (не тихая потеря); ограничение в README |
| kind ≠ прод-k8s (runtime, cgroup-драйвер, пути kubepods) | глоб-паттерн вместо жёсткого пути; известные различия — в `docs/deploy.md`; полная матрица окружений — вне scope v1 |
| Grafana обновится и сломает schema JSON | пин мажорной версии Grafana в demo; дашборды экспортированы под неё; lint ловит структурные регрессии при переэкспорте |
| README разъедется с фактическими флагами | таблица флагов/env сверяется с `--help` автоматически (тест в 7.6) |
| Релизный workflow сломан именно в момент релиза | прогон на rc-теге в 7.6; сборка релизного артефакта в обычном CI на каждый push |
