// SPDX-License-Identifier: GPL-2.0
// М0 trace-corpus backend: Go net/http (stdlib only, no modules to fetch).
//
//	go run ./backends/go -addr :8082
//
// The route set is the contract every corpus backend implements (go, node,
// gunicorn) so a scenario means the same thing on each; the CONNECT tunnel and
// the raw 101 upgrade are Go-only (they need connection hijacking) and back the
// РH4 blind-zone traces.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const filler = "0123456789abcdef"

func main() {
	addr := flag.String("addr", ":8082", "listen address")
	flag.Parse()

	mux := http.NewServeMux()

	// Small 200 with an explicit Content-Length (net/http adds it itself for
	// a single small write that fits the 2 KB sniff buffer).
	hello := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "hello from go, method=%s\n", r.Method)
	}
	mux.HandleFunc("/hello", hello)
	mux.HandleFunc("/hello.txt", hello) // the corpus' static-file name on nginx

	// Numeric/UUID path segments — the material the М4 route templater is
	// measured on; here they only have to exist on the wire.
	mux.HandleFunc("/json/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/json/")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, "{\"id\":%q,\"q\":%q}\n", id, r.URL.RawQuery)
	})

	// Known-length body of arbitrary size: the arithmetic-skip path (РH4).
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		n := intQuery(r, "n", 1<<20)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(n))
		body := strings.Repeat(filler, 1+n/len(filler))[:n]
		io.WriteString(w, body)
	})

	// Reconnaissance item 2: one Write, no explicit Content-Length, no Flush.
	// net/http sets Content-Length itself while the whole body still fits its
	// output buffer and switches to chunked past it — /auto?n= finds the knee.
	mux.HandleFunc("/auto", func(w http.ResponseWriter, r *http.Request) {
		n := intQuery(r, "n", 1024)
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, strings.Repeat(filler, 1+n/len(filler))[:n])
	})

	// No Content-Length + flushes => net/http frames the response chunked.
	// Risk 4 of the plan: for Go backends this is the default, not the corner.
	mux.HandleFunc("/chunked", func(w http.ResponseWriter, r *http.Request) {
		n := intQuery(r, "n", 5)
		w.Header().Set("Content-Type", "text/plain")
		fl, _ := w.(http.Flusher)
		for i := 0; i < n; i++ {
			fmt.Fprintf(w, "chunk %d of %d\n", i, n)
			if fl != nil {
				fl.Flush()
			}
			time.Sleep(5 * time.Millisecond)
		}
	})

	// Request body sink: Content-Length, chunked or 100-continue upload —
	// net/http answers Expect: 100-continue on the first body read.
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "read %d bytes, te=%v\n", n, r.TransferEncoding)
	})

	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/hello", http.StatusFound)
	})

	mux.HandleFunc("/boom", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom\n", http.StatusInternalServerError)
	})

	// Delayed first byte: separates TTFB from duration (РH5).
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Duration(intQuery(r, "ms", 200)) * time.Millisecond)
		io.WriteString(w, "slow ok\n")
	})

	// Announces a Content-Length and then dies mid-body: the "разрыв посреди
	// тела" scenario (unit must not hang waiting for the rest).
	mux.HandleFunc("/truncate", func(w http.ResponseWriter, r *http.Request) {
		n := intQuery(r, "n", 1<<16)
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		fmt.Fprintf(buf, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"+
			"Content-Length: %d\r\n\r\n", n)
		buf.WriteString(strings.Repeat(filler, 64)) // 1 KB of a promised n
		buf.Flush()
		time.Sleep(20 * time.Millisecond)
		conn.Close() // reset in the middle of the body
	})

	// Raw 101 upgrade (websocket shape without a websocket library): after the
	// handshake the bytes are opaque — blind zone by design.
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "expected websocket upgrade", http.StatusBadRequest)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n" +
			"Connection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
		buf.Flush()
		// Echo whatever frames the client sends for a moment, then hang up.
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		io.Copy(conn, buf)
	})

	srv := &http.Server{
		Addr:              *addr,
		ReadHeaderTimeout: 30 * time.Second,
		// 16 KB header blocks are a corpus scenario; the default max is 1 MB
		// for the URL+headers, but be explicit about it.
		MaxHeaderBytes: 1 << 20,
		Handler:        http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				connectTunnel(w, r)
				return
			}
			mux.ServeHTTP(w, r)
		}),
	}
	log.Printf("go backend listening on %s", *addr)
	log.Fatal(srv.ListenAndServe())
}

// CONNECT: a real tunnel, so the corpus has a trace where everything after the
// 200 is opaque bytes on an established HTTP connection (РH4 blind zone).
func connectTunnel(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	up, err := net.DialTimeout("tcp", r.Host, 2*time.Second)
	if err != nil {
		buf.WriteString("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		buf.Flush()
		return
	}
	defer up.Close()
	buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	buf.Flush()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	up.SetDeadline(time.Now().Add(5 * time.Second))
	go io.Copy(up, buf)
	io.Copy(client, up)
}

func intQuery(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return def
}
