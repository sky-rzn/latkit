// SPDX-License-Identifier: GPL-2.0
// М0 reconnaissance item 4: what Go's net/http negotiates over TLS. The stock
// transport offers h2 through ALPN whenever TLS is configured, so a Go
// service-to-service call to a TLS endpoint is an h2 connection — i.e. a blind
// zone for this plan (§8). The forced HTTP/1.1 run is the control.
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	url := "https://127.0.0.1:8443/hello"
	if len(os.Args) > 1 {
		url = os.Args[1]
	}
	// A fresh config per probe: enabling h2 rewrites NextProtos in place, so a
	// shared tls.Config would make every later probe offer h2 as well.
	insecure := func() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }

	// What http.DefaultTransport does: ALPN offers h2 and gets it.
	probe("go-default", &http.Transport{
		TLSClientConfig: insecure(), ForceAttemptHTTP2: true}, url)
	// The far more common shape in real services: a custom Transport with a
	// TLSClientConfig and no ForceAttemptHTTP2 — Go then silently does *not*
	// enable h2, and the connection stays HTTP/1.1. Worth knowing before
	// declaring "Go clients are h2".
	probe("go-customtls", &http.Transport{TLSClientConfig: insecure()}, url)
	probe("go-h1", &http.Transport{
		TLSClientConfig:   insecure(),
		ForceAttemptHTTP2: false,
		TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
	}, url)
}

func probe(name string, tr *http.Transport, url string) {
	resp, err := (&http.Client{Transport: tr}).Get(url)
	if err != nil {
		fmt.Printf("%-11s ERROR %v\n", name, err)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	fmt.Printf("%-11s got=%s status=%d\n", name, resp.Proto, resp.StatusCode)
}
