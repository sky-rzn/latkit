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
# Предполагает поднятый стек (docker compose ... up -d) и проброшенный
# порт 5432 на 127.0.0.1. Набор данных инициализирует pgbench-init из
# docker-compose.yml.

set -euo pipefail

HOST=127.0.0.1
PORT=5432
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
        --)
            shift
            PASSTHROUGH+=("$@")
            break
            ;;
        -h|--help)
            sed -n '2,20p' "$0"
            exit 0
            ;;
        *)
            echo "bench.sh: неизвестный аргумент: $1" >&2
            echo "см. ./bench.sh --help" >&2
            exit 2
            ;;
    esac
done

if ! command -v pgbench >/dev/null 2>&1; then
    echo "bench.sh: pgbench не найден в PATH (нужен postgresql-client)" >&2
    exit 1
fi

set -x
exec pgbench \
    -h "$HOST" -p "$PORT" -U "$DB_USER" \
    ${SELECT_ONLY:+$SELECT_ONLY} \
    -c "$CLIENTS" -T "$DURATION" \
    "${PASSTHROUGH[@]}" \
    "$DB_NAME"
