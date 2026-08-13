// Minimal module file for the demo backend (PLAN-HTTP.md М9): standard library
// only, no dependencies, so the image build never touches the network for Go
// packages. 1.22 is the floor because the handlers use the method+wildcard
// patterns ServeMux gained in that release.
module latkit/deploy/demo-http/backend

go 1.22
