// SPDX-License-Identifier: GPL-2.0
//
// The Go server of the Go-TLS e2e stand (PLAN-HTTP.md М7, РH13.3). A whole
// server in one file, with no module dependencies, so the stand can build it
// with nothing but a Go toolchain (verify-http-go-tls.sh builds it on the host,
// exactly as it builds the agent there).
//
// Three properties matter for what it is testing:
//
//   - it terminates TLS itself, through crypto/tls, which is the point: there
//     is no libssl anywhere in this process for the existing channel to find,
//     so anything the agent observes came through the Go uprobes;
//   - HTTP/1.1 only (TLSNextProto is set to an empty map, which disables the
//     h2 negotiation Go turns on by default) — h2 is a declared blind zone, and
//     a stand that measured it would be measuring the wrong counter;
//   - it is built unstripped, so crypto/tls's symbols are in the table. A
//     stripped build is a supported *failure* — the agent says so and stays
//     dark — and the verify script has a case for it.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"
)

// A throwaway self-signed certificate, generated at startup: the stand needs no
// cert volume and no init container for the Go half.
func selfSigned() tls.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "latkit-stand"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"gosrv", "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func main() {
	addr := os.Getenv("LISTEN")
	if addr == "" {
		addr = ":8443"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello")
	})
	// An id-bearing route: the observation must come back as /json/{id}.
	mux.HandleFunc("/json/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"ok":true}`)
	})
	mux.HandleFunc("/boom", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{selfSigned()},
			MinVersion:   tls.VersionTLS12,
		},
		// HTTP/1.1 only — see the file comment.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	log.Printf("gotls: serving HTTPS on %s (HTTP/1.1 only)", addr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
