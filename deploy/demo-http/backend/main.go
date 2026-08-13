// SPDX-License-Identifier: GPL-2.0
//
// The application server of the latkit HTTP demo stack (PLAN-HTTP.md М9).
// Standard library only, one file, built by the compose stack itself — the
// demo must come up on a machine with nothing but Docker installed.
//
// It exists to give every panel of dashboards/latkit-http.json something real
// to show, so the mix is chosen by what the agent has to get right rather than
// by what a web app usually does:
//
//	an id-bearing path per id *shape*   the templater of РH7 meets a number,
//	                                    a UUID, a ULID, a hex digest and a
//	                                    date — and must return five route
//	                                    labels, not five thousand;
//	a query string with junk in it      /api/search?q=… must produce ONE route
//	                                    (the query never reaches a label);
//	a response with no Content-Length   Go chunks it — the framing degradation
//	                                    of РH4, and the common case for Go
//	                                    backends (М0 recon item 2);
//	a body read before the answer       the upload interval of РH5, which is
//	                                    the client's time and not the server's;
//	a deliberately slow route           TTFB and duration are different numbers;
//	a spread of failures                404/429/500/503, so the status-class
//	                                    panel and latkit_http_errors_total have
//	                                    more than one value each — and so the
//	                                    5xx share stays a *share*, since a 404
//	                                    is not an error (РH10).
//
// Every latency here is deliberate and small: the point is a dashboard with
// shape, not a load test (that is tests/bench/run-http.sh).
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"
)

// A tiny helper so the handlers read as "answer this, after roughly this long".
// The jitter is what puts a spread into the histograms; without it every panel
// would be a flat line at one bucket.
func answer(w http.ResponseWriter, status int, body any, minMs, maxMs int) {
	if maxMs > 0 {
		time.Sleep(time.Duration(minMs+rand.Intn(maxMs-minMs+1)) * time.Millisecond)
	}
	buf, _ := json.Marshal(body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(buf, '\n'))
}

func main() {
	addr := os.Getenv("LISTEN")
	if addr == "" {
		addr = ":8081"
	}

	mux := http.NewServeMux()

	// --- the id zoo: one route each, whatever the client puts in the slot ---
	// The wildcard names here are the *server's* truth. latkit never sees them:
	// it templates the path it read off the wire, and the demo is honest only
	// if both arrive at the same answer independently. Point --http-routes at
	// routes.map (see the compose file) to make the agent use this list
	// instead of guessing.
	mux.HandleFunc("GET /api/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		answer(w, 200, map[string]any{"id": r.PathValue("id"), "name": "demo"}, 1, 12)
	})
	mux.HandleFunc("GET /api/users/{id}/orders", func(w http.ResponseWriter, r *http.Request) {
		answer(w, 200, map[string]any{"user": r.PathValue("id"), "orders": []int{1, 2, 3}}, 2, 25)
	})
	mux.HandleFunc("GET /api/orders/{uuid}", func(w http.ResponseWriter, r *http.Request) {
		answer(w, 200, map[string]any{"order": r.PathValue("uuid"), "total": 42}, 1, 18)
	})
	mux.HandleFunc("GET /api/sessions/{ulid}", func(w http.ResponseWriter, r *http.Request) {
		answer(w, 200, map[string]any{"session": r.PathValue("ulid")}, 1, 8)
	})
	mux.HandleFunc("GET /api/blobs/{sha}", func(w http.ResponseWriter, r *http.Request) {
		answer(w, 200, map[string]any{"blob": r.PathValue("sha")}, 1, 9)
	})
	mux.HandleFunc("GET /api/reports/{date}", func(w http.ResponseWriter, r *http.Request) {
		answer(w, 200, map[string]any{"date": r.PathValue("date"), "rows": 128}, 5, 60)
	})

	// The query string is the other half of the cardinality problem: ?q= is
	// unbounded and must not survive into a label. One route, any query.
	mux.HandleFunc("GET /api/search", func(w http.ResponseWriter, r *http.Request) {
		answer(w, 200, map[string]any{"q": r.URL.Query().Get("q"), "hits": rand.Intn(50)}, 3, 40)
	})

	// No Content-Length is set and the body is flushed in pieces, so net/http
	// falls back to Transfer-Encoding: chunked (РH4). This is the default shape
	// of a Go response whose length is not known in advance, which is why the
	// demo has one.
	mux.HandleFunc("GET /api/events", func(w http.ResponseWriter, r *http.Request) {
		fl, _ := w.(http.Flusher)
		w.Header().Set("Content-Type", "application/x-ndjson")
		for i := 0; i < 5; i++ {
			fmt.Fprintf(w, "{\"event\":%d}\n", i)
			if fl != nil {
				fl.Flush()
			}
			time.Sleep(3 * time.Millisecond)
		}
	})

	// The body is drained before the answer, so the client's upload time falls
	// inside the request/response interval — and РH5 keeps it out of the
	// server's duration. The "Request upload time" panel is fed from here.
	upload := func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		answer(w, 201, map[string]any{"stored": n}, 1, 10)
	}
	mux.HandleFunc("POST /api/orders", upload)
	mux.HandleFunc("PUT /api/uploads/{id}", upload)

	// DELETE on a path that also serves GET: the method is part of the route's
	// identity (РH7 — the fingerprint is XXH3(method, template)), so these are
	// two dictionary entries and two histograms, not one.
	mux.HandleFunc("DELETE /api/orders/{uuid}", func(w http.ResponseWriter, r *http.Request) {
		answer(w, 204, nil, 1, 6)
	})

	// The p99 tail. Sleeping *before* the first byte is what makes TTFB and
	// duration disagree, which is the whole reason both are exported.
	mux.HandleFunc("GET /api/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Duration(120+rand.Intn(400)) * time.Millisecond)
		answer(w, 200, map[string]any{"slow": true}, 0, 0)
	})

	// Failures, spread across classes so the dashboard shows a distribution
	// rather than a single spike: mostly fine, sometimes 500, sometimes 503,
	// sometimes 429. Only the 5xx count as errors.
	mux.HandleFunc("GET /api/flaky", func(w http.ResponseWriter, r *http.Request) {
		switch n := rand.Intn(100); {
		case n < 8:
			answer(w, 500, map[string]any{"error": "internal"}, 1, 5)
		case n < 12:
			answer(w, 503, map[string]any{"error": "unavailable"}, 1, 5)
		case n < 20:
			answer(w, 429, map[string]any{"error": "slow down"}, 0, 0)
		default:
			answer(w, 200, map[string]any{"ok": true}, 1, 7)
		}
	})

	// A permanent 500 and a permanent redirect: fixed points the README can
	// tell you to look for.
	mux.HandleFunc("GET /api/boom", func(w http.ResponseWriter, r *http.Request) {
		answer(w, 500, map[string]any{"error": "boom"}, 1, 4)
	})
	mux.HandleFunc("GET /api/legacy", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/api/search?q=demo", http.StatusFound)
	})

	// Health, and the catch-all 404. Go's mux would answer 404 by itself, but
	// then the response would carry no body worth counting.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			answer(w, 404, map[string]any{"error": "no such thing"}, 0, 0)
			return
		}
		answer(w, 404, map[string]any{"error": "not found"}, 0, 0)
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("demo backend: HTTP/1.1 on %s", addr)
	log.Fatal(srv.ListenAndServe())
}
