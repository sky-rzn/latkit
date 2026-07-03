#!/usr/bin/env bash
#
# Нагрузка на dev-postgres по требованию (задача 0.4).
#
# По умолчанию — tpcb-like (read-write), 10 клиентов, 30 секунд:
#   ./bench.sh
# Select-only вариант (только чтения):
#   ./bench.sh -S
# Свои параметры:
#   ./bench.sh -c 8 -T 15
#   ./bench.sh -S -c 20 -T 60
#
# Всё, что после `--`, прокидывается в pgbench как есть:
#   ./bench.sh -- -P 5
#
# Нестандартный порт (стек поднят с PGPORT=5433, см. docker-compose.yml):
#   ./bench.sh -p 5433        # или PGPORT=5433 ./bench.sh
#
# Предполагает поднятый стек (docker compose ... up -d) и проброшенный
# порт (по умолчанию 5432) на 127.0.0.1. Набор данных инициализирует
# pgbench-init из docker-compose.yml.

set -euo pipefail

HOST=127.0.0.1
PORT=${PGPORT:-5432}
DB_USER=latkit
DB_NAME=latkit
export PGPASSWORD=latkit

CLIENTS=10
DURATION=30
SELECT_ONLY=""
PASSTHROUGH=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -S|--select-only)
            SELECT_ONLY="-S"
            shift
            ;;
        -c|--clients)
            CLIENTS="$2"
            shift 2
            ;;
        -T|--time)
            DURATION="$2"
            shift 2
            ;;
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        --)
            shift
            PASSTHROUGH+=("$@")
            break
            ;;
        -h|--help)
            sed -n '2,21p' "$0"
            exit 0
            ;;
        *)
            echo "bench.sh: неизвестный аргумент: $1" >&2
            echo "см. ./bench.sh --help" >&2
            exit 2
            ;;
    esac
done

# Нативный pgbench, если он реально есть (в Ubuntu /usr/bin/pgbench — обёртка
# из postgresql-client-common, которая без серверного пакета postgresql-NN
# падает: pgbench упакован там, а не в postgresql-client-NN). Иначе — pgbench
# из образа postgres:16 в netns хоста, чтобы трафик шёл через 127.0.0.1 как и
# нативный.
if pgbench --version >/dev/null 2>&1; then
    set -x
    exec pgbench \
        -h "$HOST" -p "$PORT" -U "$DB_USER" \
        ${SELECT_ONLY:+$SELECT_ONLY} \
        -c "$CLIENTS" -T "$DURATION" \
        "${PASSTHROUGH[@]}" \
        "$DB_NAME"
fi

echo "bench.sh: нативный pgbench не найден, запускаю из образа postgres:16" >&2
DOCKER=(docker)
docker info >/dev/null 2>&1 || DOCKER=(sudo docker)
set -x
exec "${DOCKER[@]}" run --rm --network host -e PGPASSWORD="$PGPASSWORD" postgres:16 \
    pgbench \
    -h "$HOST" -p "$PORT" -U "$DB_USER" \
    ${SELECT_ONLY:+$SELECT_ONLY} \
    -c "$CLIENTS" -T "$DURATION" \
    "${PASSTHROUGH[@]}" \
    "$DB_NAME"
