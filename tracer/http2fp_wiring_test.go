package tracer

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// TestH2DecryptedCapture_E2E proves the production wiring: an http.Server whose
// TLSNextProto["h2"] wraps the DECRYPTED *tls.Conn in a TeeConn and runs
// http2.Server.ServeConn on it captures the client's opening h2 flight, and at
// request time the handler can pull that tee from the request context and parse
// the Akamai fingerprint. We drive it with a real curl --http2 and require the
// known curl fingerprint — so this guards the full above-TLS capture path.
func TestH2DecryptedCapture_E2E(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	captured := make(chan string, 1)
	h2 := &http2.Server{}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tc, ok := r.Context().Value(HTTP2TeeConnKey).(*TeeConn); ok {
				if fp, perr := ParseHTTP2Fingerprint(tc.RawBytes()); perr == nil {
					select {
					case captured <- fp.Akamai():
					default:
					}
				}
			}
			w.WriteHeader(http.StatusOK)
		}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}, NextProtos: []string{"h2"}},
	}
	srv.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){
		"h2": func(s *http.Server, c *tls.Conn, h http.Handler) {
			tee := NewTeeConn(c, 16384, HTTP2StopFunc)
			ctx := context.WithValue(context.Background(), HTTP2TeeConnKey, tee)
			h2.ServeConn(tee, &http2.ServeConnOpts{BaseConfig: s, Handler: h, Context: ctx})
		},
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	defer srv.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	_ = exec.Command("curl", "-sk", "--http2", "-o", "/dev/null", fmt.Sprintf("https://127.0.0.1:%d/", port)).Run()

	select {
	case akamai := <-captured:
		const want = "3:100;4:10485760;2:0|1048510465|0|m,s,a,p" // peet.ws, curl 8.5.0
		if akamai != want {
			t.Fatalf("decrypted h2 capture via TLSNextProto:\n  got  %s\n  want %s", akamai, want)
		}
		t.Logf("E2E OK: decrypted h2 first flight captured + parsed = %s", akamai)
	case <-time.After(5 * time.Second):
		t.Fatal("no h2 request handled / fingerprint captured")
	}
}
