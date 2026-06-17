package tracer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31, 0),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestGetConfigForClient_TeeConnRawParse_E2E verifies the production wiring
// assumption end-to-end: in the real srv.ServeTLS(NewTeeListener(...)) path, the
// hello.Conn handed to GetConfigForClient IS a *TeeConn, and its RawBytes() hold
// a ClientHello our parser can read. If the type assertion failed, the http.go
// wiring would silently fall back to the stdlib path (a no-op) with no other test
// catching it — so this guards exactly that.
func TestGetConfigForClient_TeeConnRawParse_E2E(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tee := NewTeeListener(ln, 65536, HTTPStopFunc)

	type res struct {
		teeOK    bool
		ja3, ja4 string
	}
	got := make(chan res, 1)

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{selfSignedCert(t)},
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				r := res{}
				if tc, ok := hello.Conn.(*TeeConn); ok { // the production assertion
					r.teeOK = true
					if pch, perr := ParseClientHello(tc.RawBytes()); perr == nil {
						r.ja3 = pch.JA3Hash()
						r.ja4 = pch.JA4()
					}
				}
				select {
				case got <- r:
				default:
				}
				return nil, nil
			},
		},
	}
	go func() { _ = srv.ServeTLS(tee, "", "") }()
	defer srv.Close()

	conn, derr := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if derr == nil {
		_ = conn.Close()
	}

	select {
	case r := <-got:
		if !r.teeOK {
			t.Fatal("hello.Conn did NOT assert to *TeeConn in the ServeTLS path — the http.go wiring would silently no-op")
		}
		if r.ja3 == "" || r.ja4 == "" {
			t.Fatalf("raw parse from TeeConn.RawBytes() came back empty: ja3=%q ja4=%q", r.ja3, r.ja4)
		}
		t.Logf("E2E OK: TeeConn asserted; canonical raw ja3=%s ja4=%s", r.ja3, r.ja4)
	case <-time.After(3 * time.Second):
		t.Fatal("GetConfigForClient never fired")
	}
}
