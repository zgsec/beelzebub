package tracer

import (
	"io"
	"net"
	"testing"
)

// scriptConn is a net.Conn whose Read yields pre-scripted chunks in order,
// then EOF. Only Read is exercised by TeeConn; the embedded nil net.Conn
// satisfies the interface for the unused methods.
type scriptConn struct {
	net.Conn
	chunks [][]byte
	idx    int
}

func (c *scriptConn) Read(p []byte) (int, error) {
	if c.idx >= len(c.chunks) {
		return 0, io.EOF
	}
	n := copy(p, c.chunks[c.idx])
	c.idx++
	return n, nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// On an HTTP keep-alive connection the same TeeConn serves multiple requests.
// After the first request's header block is captured (stopFn fires, done=true),
// Rearm() must reset the buffer AND the stop-func state so the SECOND request's
// headers are captured fresh in wire order — not left stale (returning request
// 1's order) and not unbounded (a stale HTTPStopFunc closure whose prev offset
// points past a fresh buffer would never re-detect \r\n\r\n).
func TestTeeConn_RearmRecapturesNextRequest(t *testing.T) {
	req1 := []byte("GET /a HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8\r\n\r\n")
	req2 := []byte("GET /b HTTP/1.1\r\nHost: x\r\nAccept: */*\r\nUser-Agent: go-http\r\n\r\n")
	conn := &scriptConn{chunks: [][]byte{req1, req2}}

	tc := NewTeeConn(conn, 65536, HTTPStopFunc())
	tc.stopFactory = HTTPStopFunc // factory so Rearm can mint a fresh closure

	buf := make([]byte, 4096)

	// Request 1.
	if _, err := tc.Read(buf); err != nil {
		t.Fatalf("req1 read: %v", err)
	}
	if !tc.Complete() {
		t.Fatalf("req1 capture should be complete")
	}
	order1 := ParseHeaderOrder(tc.RawBytes())
	if want := []string{"host", "user-agent"}; !equalStrings(order1, want) {
		t.Fatalf("req1 header order: want %v, got %v", want, order1)
	}

	// Rearm for the next request on the same connection.
	tc.Rearm()

	// Request 2 — must capture fresh, in its own wire order.
	if _, err := tc.Read(buf); err != nil {
		t.Fatalf("req2 read: %v", err)
	}
	if !tc.Complete() {
		t.Fatalf("req2 capture should be complete after Rearm")
	}
	order2 := ParseHeaderOrder(tc.RawBytes())
	if want := []string{"host", "accept", "user-agent"}; !equalStrings(order2, want) {
		t.Fatalf("req2 header order after Rearm: want %v, got %v", want, order2)
	}
}
