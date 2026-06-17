package tracer

import (
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"net"
	"os/exec"
	"testing"
	"time"
)

// captureH2FirstFlight stands up a local TLS + ALPN-h2 sink, runs the given
// client against it, and returns the raw DECRYPTED HTTP/2 first-flight bytes the
// client sent (preface + SETTINGS + WINDOW_UPDATE + HEADERS).
func captureH2FirstFlight(t *testing.T, mkArgs func(url string) []string) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cert := selfSignedCert(t)
	captured := make(chan []byte, 1)

	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
		if herr := tc.Handshake(); herr != nil {
			return
		}
		_, _ = tc.Write([]byte{0, 0, 0, 0x04, 0, 0, 0, 0, 0}) // empty server SETTINGS, so the client proceeds
		_ = tc.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 8192)
		var acc []byte
		for {
			n, rerr := tc.Read(buf)
			if n > 0 {
				acc = append(acc, buf[:n]...)
			}
			if hasH2HeadersFrame(acc) || rerr != nil {
				break
			}
		}
		_ = tc.Close()
		captured <- acc
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	args := mkArgs(fmt.Sprintf("https://127.0.0.1:%d/", port))
	_ = exec.Command(args[0], args[1:]...).Run()

	select {
	case b := <-captured:
		return b
	case <-time.After(6 * time.Second):
		t.Fatal("no h2 first-flight captured")
		return nil
	}
}

func hasH2HeadersFrame(b []byte) bool {
	p := len(http2Preface)
	for p+9 <= len(b) {
		length := int(b[p])<<16 | int(b[p+1])<<8 | int(b[p+2])
		if b[p+3] == 0x01 { // HEADERS
			return true
		}
		p += 9 + length
	}
	return false
}

// TestParseHTTP2Fingerprint_RealCurlVsPeetWS captures a REAL curl --http2 first
// flight on a local sink and requires the parsed Akamai fingerprint to match the
// value peet.ws computed INDEPENDENTLY for curl 8.5.0 (2026-06-17). The h2 frames
// curl emits are client-determined (identical to localhost or peet.ws), so the
// fingerprint matches across destinations.
func TestParseHTTP2Fingerprint_RealCurlVsPeetWS(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	raw := captureH2FirstFlight(t, func(u string) []string {
		return []string{"curl", "-sk", "--http2", "-o", "/dev/null", u}
	})
	fp, err := ParseHTTP2Fingerprint(raw)
	if err != nil {
		t.Fatalf("ParseHTTP2Fingerprint: %v (captured %d bytes)", err, len(raw))
	}

	const wantAkamai = "3:100;4:10485760;2:0|1048510465|0|m,s,a,p" // peet.ws, curl 8.5.0
	if got := fp.Akamai(); got != wantAkamai {
		t.Fatalf("Akamai h2 fingerprint vs peet.ws:\n  got  %s\n  want %s", got, wantAkamai)
	}
	const wantHash = "64a832f547be33249bf4d33e8a46c5dc"
	if got := fmt.Sprintf("%x", md5.Sum([]byte(fp.Akamai()))); got != wantHash {
		t.Errorf("Akamai hash vs peet.ws:\n  got  %s\n  want %s", got, wantHash)
	}
}
