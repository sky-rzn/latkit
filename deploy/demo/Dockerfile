# DRAFT demo runtime (task 7.3): just the shared libs latkit needs (libelf/zlib/
# zstd). The agent binary is NOT copied in — it's bind-mounted from the host's
# build/latkit at runtime (see docker-compose.yml), so this works regardless of
# the repo .dockerignore excluding build/. This is the fast path for iterating on
# dashboards; it needs `cmake --build build` on the host first.
#
# Task 7.4 replaces this with the real scratch + musl-static image from
# deploy/docker/Dockerfile (Р46); the compose file has that switch commented in.
FROM ubuntu:24.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends libelf1 zlib1g libzstd1 \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/usr/local/bin/latkit"]
