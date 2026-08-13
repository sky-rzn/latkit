# The demo backend, built in the stack (PLAN-HTTP.md М9) — the demo's only
# requirement is Docker, so no Go toolchain is expected on the host (the e2e
# stand, tests/e2e/docker-compose.http.yml, builds its backend on the host
# instead: there a Go toolchain is already a prerequisite).
#
# CGO off so the binary is static and the runtime stage can be scratch-thin;
# alpine rather than scratch only because a shell in the container is worth
# more than 7 MB when someone is poking at a demo.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /out/backend .

FROM alpine:3.20
COPY --from=build /out/backend /usr/local/bin/backend
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/backend"]
