// Minimal module file so the stand's backend builds with a bare `go build`
// wherever it is checked out (PLAN-HTTP.md М8). No dependencies on purpose:
// everything it needs is in the standard library.
module latkit/tests/e2e/httpbackend

go 1.21
