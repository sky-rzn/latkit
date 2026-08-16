# go-redis — the client every Go service in a k8s cluster carries (МR0, item 2).
FROM golang:1.23-alpine
WORKDIR /app
COPY go.mod main.go /app/
RUN go mod tidy && go build -o /usr/local/bin/goredis .
ENTRYPOINT ["/usr/local/bin/goredis"]
