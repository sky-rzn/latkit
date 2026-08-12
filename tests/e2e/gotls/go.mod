// Minimal module file so the stand's server builds with a bare `go build`
// wherever it is checked out (PLAN-HTTP.md М7). No dependencies on purpose:
// everything the server needs is in the standard library, and the point of the
// stand is crypto/tls itself.
module latkit/tests/e2e/gotls

go 1.21
