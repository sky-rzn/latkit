// SPDX-License-Identifier: GPL-2.0
//
// The application server of the plaintext HTTP e2e stand (PLAN-HTTP.md М8).
// One file, no module dependencies, so the stand builds it with nothing but a
// Go toolchain (verify-http.sh builds it on the host, as the Go-TLS stand
// builds its own server).
//
// It is a Go server on purpose rather than a second nginx. Go's net/http is
// where the М0 reconnaissance found the shapes that stress this agent most:
// a response with no Content-Length is chunked by default (item 2), the
// framing degradation of РH4 that a Content-Length body never reaches. The
// nginx in front of it covers the other half — a static file sent with
// `sendfile on`, and a reverse-proxy leg whose upstream is this process — so
// one stand exercises both legs of a deployment the agent will actually meet.
//
// The routes exist to make specific assertions possible in verify-http.sh:
//
//	/hello        a fixed path, Content-Length body: the base case
//	/json/{id}    an id-bearing path — the label must come back templated
//	/chunked      no Content-Length: Go chunks it (РH4's degradation)
//	/upload       reads a request body: the upload interval of РH5
//	/slow         50 ms before the first byte: TTFB and duration differ
//	/boom         500: an error by РH10
//	anything else 404: counted, and deliberately not an error
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	addr := os.Getenv("LISTEN")
	if addr == "" {
		addr = ":8081"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello")
	})
	mux.HandleFunc("/json/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"ok":true}`)
	})
	// No Content-Length is set and the body is flushed in pieces, so net/http
	// falls back to Transfer-Encoding: chunked — the case where the length is
	// not known in advance and the framer has to read chunk sizes off the wire.
	mux.HandleFunc("/chunked", func(w http.ResponseWriter, r *http.Request) {
		fl, _ := w.(http.Flusher)
		for i := 0; i < 4; i++ {
			fmt.Fprintf(w, "chunk-%d\n", i)
			if fl != nil {
				fl.Flush()
			}
		}
	})
	// The body is read to the end before answering: the interval between the
	// first request byte and the last is the client's, and РH5 keeps it apart
	// from the server's duration.
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "got %d\n", n)
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		fmt.Fprintln(w, "slow")
	})
	mux.HandleFunc("/boom", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})

	srv := &http.Server{Addr: addr, Handler: mux}
	log.Printf("httpbackend: serving plaintext HTTP/1.1 on %s", addr)
	log.Fatal(srv.ListenAndServe())
}
