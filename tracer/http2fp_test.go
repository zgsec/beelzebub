package tracer

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"
)

// captureH2FirstFlight stands up a local TLS + ALPN-h2 sink, runs `drive` (which
// must make a request to the passed URL), and returns the raw DECRYPTED HTTP/2
// first-flight bytes the client sent (preface + SETTINGS + WINDOW_UPDATE + HEADERS).
func captureH2FirstFlight(t *testing.T, drive func(url string)) []byte {
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
	drive(fmt.Sprintf("https://127.0.0.1:%d/", port))

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

// TestParseHTTP2Fingerprint_RealCurlVsPeetWS — real curl --http2 vs peet.ws.
func TestParseHTTP2Fingerprint_RealCurlVsPeetWS(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	raw := captureH2FirstFlight(t, func(u string) {
		_ = exec.Command("curl", "-sk", "--http2", "-o", "/dev/null", u).Run()
	})
	fp, err := ParseHTTP2Fingerprint(raw)
	if err != nil {
		t.Fatalf("ParseHTTP2Fingerprint: %v (%d bytes)", err, len(raw))
	}
	const wantAkamai = "3:100;4:10485760;2:0|1048510465|0|m,s,a,p" // peet.ws, curl 8.5.0
	if got := fp.Akamai(); got != wantAkamai {
		t.Fatalf("Akamai vs peet.ws (curl):\n  got  %s\n  want %s", got, wantAkamai)
	}
	if got := fmt.Sprintf("%x", md5.Sum([]byte(fp.Akamai()))); got != "64a832f547be33249bf4d33e8a46c5dc" {
		t.Errorf("Akamai hash mismatch: %s", got)
	}
}

// TestParseHTTP2Fingerprint_RealGoClientVsPeetWS — a SECOND real client (Go
// net/http2, distinct settings + pseudo-order) vs peet.ws, proving the parser is
// not overfit to curl. Go-version-specific (captured on go1.24.2).
func TestParseHTTP2Fingerprint_RealGoClientVsPeetWS(t *testing.T) {
	raw := captureH2FirstFlight(t, func(u string) {
		c := &http.Client{Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: true,
		}}
		if resp, err := c.Get(u); err == nil {
			_ = resp.Body.Close()
		}
	})
	fp, err := ParseHTTP2Fingerprint(raw)
	if err != nil {
		t.Fatalf("ParseHTTP2Fingerprint: %v (%d bytes)", err, len(raw))
	}
	const wantAkamai = "2:0;4:4194304;5:16384;6:10485760|1073741824|0|a,m,p,s" // peet.ws, go1.24.2
	if got := fp.Akamai(); got != wantAkamai {
		t.Fatalf("Akamai vs peet.ws (Go):\n  got  %s\n  want %s", got, wantAkamai)
	}
}

// --- synthetic frame builder: exercises branches no real client here sends -----

func appendH2Frame(b []byte, ftype, flags byte, streamID uint32, payload []byte) []byte {
	n := len(payload)
	b = append(b, byte(n>>16), byte(n>>8), byte(n), ftype, flags,
		byte(streamID>>24), byte(streamID>>16), byte(streamID>>8), byte(streamID))
	return append(b, payload...)
}

func hpackPseudo(order ...string) []byte {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, ph := range order {
		switch ph {
		case "m":
			_ = enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
		case "a":
			_ = enc.WriteField(hpack.HeaderField{Name: ":authority", Value: "x"})
		case "s":
			_ = enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
		case "p":
			_ = enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/"})
		}
	}
	return buf.Bytes()
}

func synthH2(settings [][2]uint32, wu uint32, priority []byte, headerFlags byte, headerBody []byte) []byte {
	b := append([]byte{}, http2Preface...)
	var sp []byte
	for _, kv := range settings {
		sp = append(sp, byte(kv[0]>>8), byte(kv[0]), byte(kv[1]>>24), byte(kv[1]>>16), byte(kv[1]>>8), byte(kv[1]))
	}
	b = appendH2Frame(b, 0x4, 0, 0, sp)
	if wu > 0 {
		b = appendH2Frame(b, 0x8, 0, 0, []byte{byte(wu >> 24), byte(wu >> 16), byte(wu >> 8), byte(wu)})
	}
	if priority != nil {
		b = appendH2Frame(b, 0x2, 0, 1, priority)
	}
	b = appendH2Frame(b, 0x1, headerFlags|0x4, 1, headerBody) // END_HEADERS
	return b
}

// TestParseHTTP2Fingerprint_PriorityFrame exercises PRIORITY parsing (no real
// client in this VM sends one).
func TestParseHTTP2Fingerprint_PriorityFrame(t *testing.T) {
	prio := []byte{0x80, 0x00, 0x00, 0x00, 200} // exclusive=1, dep=0, weight byte 200 -> 201
	raw := synthH2([][2]uint32{{1, 4096}}, 0, prio, 0, hpackPseudo("m", "a", "s", "p"))
	fp, err := ParseHTTP2Fingerprint(raw)
	if err != nil {
		t.Fatal(err)
	}
	const want = "1:4096|0|1:1:0:201|m,a,s,p"
	if got := fp.Akamai(); got != want {
		t.Fatalf("PRIORITY:\n  got  %s\n  want %s", got, want)
	}
}

// TestParseHTTP2Fingerprint_PaddedHeaders exercises the PADDED HEADERS flag and a
// third distinct pseudo-order.
func TestParseHTTP2Fingerprint_PaddedHeaders(t *testing.T) {
	body := append([]byte{4}, hpackPseudo("s", "m", "a", "p")...) // padLen=4 + block
	body = append(body, 0, 0, 0, 0)                               // padding
	raw := synthH2([][2]uint32{{1, 65536}, {2, 0}}, 1234, nil, 0x8, body)
	fp, err := ParseHTTP2Fingerprint(raw)
	if err != nil {
		t.Fatal(err)
	}
	const want = "1:65536;2:0|1234|0|s,m,a,p"
	if got := fp.Akamai(); got != want {
		t.Fatalf("PADDED:\n  got  %s\n  want %s", got, want)
	}
}

// TestParseHTTP2Fingerprint_RejectsMalformed — adversarial/truncated input must
// error, never panic.
func TestParseHTTP2Fingerprint_RejectsMalformed(t *testing.T) {
	good := synthH2([][2]uint32{{1, 4096}}, 0, nil, 0, hpackPseudo("m", "a", "s", "p"))
	cases := map[string][]byte{
		"empty":           {},
		"bad_preface":     append([]byte("NOT-H2-PREFACE-AT-ALL!!!!"), 0x00),
		"preface_only":    append([]byte{}, http2Preface...),
		"no_headers":      good[:len(http2Preface)+9+6], // preface + a SETTINGS frame, no HEADERS
		"truncated_frame": good[:len(good)-3],
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on malformed h2 input: %v", r)
				}
			}()
			if _, err := ParseHTTP2Fingerprint(in); err == nil {
				t.Fatalf("expected error for malformed input")
			}
		})
	}
}
