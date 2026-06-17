package tracer

import (
	"bytes"
	"encoding/binary"
	"net"
)

// contextKey is a typed key for storing TeeConn in context.Context or ssh.Context.
type contextKey struct{ name string }

// TeeConnKey is the context key for retrieving the *TeeConn from a request or session context.
var TeeConnKey = &contextKey{"tee-conn"}

// HTTP2TeeConnKey is the context key for the DECRYPTED-layer h2 TeeConn (above
// TLS), used to fingerprint the HTTP/2 opening frames. Distinct from TeeConnKey,
// which is the below-TLS tee (TLS ClientHello / plaintext HTTP).
var HTTP2TeeConnKey = &contextKey{"http2-tee-conn"}

// HTTP2StopFunc stops capture once the client's opening HTTP/2 flight is fully
// buffered — the connection preface plus frames up to and including the first
// complete HEADERS frame. That's everything the Akamai fingerprint needs, so we
// avoid buffering the rest of a (potentially long-lived, multiplexed) connection.
func HTTP2StopFunc(buf []byte) bool {
	pre := len(http2Preface)
	if len(buf) < pre+9 || !bytes.HasPrefix(buf, http2Preface) {
		return false
	}
	for p := pre; p+9 <= len(buf); {
		length := int(buf[p])<<16 | int(buf[p+1])<<8 | int(buf[p+2])
		if buf[p+3] == 0x01 { // HEADERS — stop once its full payload is buffered
			return p+9+length <= len(buf)
		}
		p += 9 + length
	}
	return false
}

// StopFunc inspects captured bytes and returns true when capture should stop.
// Called after each Read() with the full accumulated buffer.
type StopFunc func(buf []byte) bool

// HTTPStopFunc returns a stop function that detects the end of HTTP headers
// (\r\n\r\n). It only searches the newly appended region plus a 3-byte
// overlap to handle the delimiter split across Read() calls — O(n) total
// work instead of O(n²).
func HTTPStopFunc() StopFunc {
	prev := 0
	return func(buf []byte) bool {
		// Search from (previous length - 3) to catch \r\n\r\n split across reads
		start := prev
		if start > 3 {
			start -= 3
		}
		prev = len(buf)
		// Scan only the new region
		for i := start; i+3 < len(buf); i++ {
			if buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n' {
				return true
			}
		}
		return false
	}
}

// SSHStopFunc stops capture after the version string + a complete binary packet.
// Validates that the packet contains SSH_MSG_KEXINIT (type 20). Stateless — the
// SSH KEXINIT is typically delivered in 1-2 Read() calls.
func SSHStopFunc(buf []byte) bool {
	// Find end of version string
	nl := -1
	for i, b := range buf {
		if b == '\n' {
			nl = i
			break
		}
	}
	if nl < 0 {
		return false // version string not yet complete
	}
	rest := buf[nl+1:]
	if len(rest) < 5 {
		return false // packet header not yet received
	}
	pktLen := binary.BigEndian.Uint32(rest[:4])
	if pktLen < 2 || pktLen > 35000 {
		return true // malformed — stop capturing garbage
	}
	needed := 4 + int(pktLen) // header(4) + packet body
	return len(rest) >= needed
}

// TeeConn wraps a net.Conn to capture raw bytes during Read() while passing
// them through unmodified. Capture stops when stopFn returns true or maxCap
// is reached (safety limit). Used by JA4H (HTTP) and HASSH (SSH).
//
// No mutex — Read() and RawBytes() are called sequentially within the same
// goroutine. No replay — bytes flow to the parser normally.
type TeeConn struct {
	net.Conn
	buf      []byte
	maxCap   int
	done     bool
	complete bool // true if stopFn triggered (vs maxCap truncation)
	stopFn   StopFunc
	// stopFactory, when set (by TeeListener), lets Rearm mint a fresh stop
	// function for the next preamble. Required for stateful stop functions
	// like HTTPStopFunc whose captured offset must reset between requests.
	stopFactory StopFuncFactory
}

// NewTeeConn wraps a connection for raw byte capture.
func NewTeeConn(c net.Conn, maxCapture int, stop StopFunc) *TeeConn {
	return &TeeConn{
		Conn:   c,
		buf:    make([]byte, 0, 1024),
		maxCap: maxCapture,
		stopFn: stop,
	}
}

func (c *TeeConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && !c.done {
		if space := c.maxCap - len(c.buf); space > 0 {
			grab := n
			if grab > space {
				grab = space
			}
			c.buf = append(c.buf, p[:grab]...)
		}
		if c.stopFn != nil && c.stopFn(c.buf) {
			c.done = true
			c.complete = true
		} else if len(c.buf) >= c.maxCap {
			c.done = true
			// c.complete stays false — capture was truncated
		}
	}
	return n, err
}

// RawBytes returns the captured bytes. Call after the protocol parser has
// consumed the connection preamble (HTTP headers or SSH KEXINIT).
func (c *TeeConn) RawBytes() []byte { return c.buf }

// Complete reports whether capture finished because the stop function
// triggered (true) or because the safety cap was reached (false).
// Returns false if capture is still in progress.
func (c *TeeConn) Complete() bool { return c.complete }

// Release frees the capture buffer. Call after fingerprint computation
// to avoid pinning memory for the lifetime of long-lived connections.
func (c *TeeConn) Release() {
	c.buf = nil
	c.done = true
}

// Rearm resets the capture buffer and stop-func state so the next Read()
// captures a fresh preamble. Used for HTTP keep-alive: the same TeeConn serves
// every request on a persistent connection, so each request needs its own
// header-order capture. Without this, requests after the first reuse a stale
// (released) buffer and the JA4H falls back to non-spec sorted order.
//
// A fresh stop function is minted from stopFactory when present; HTTPStopFunc
// is stateful (tracks an offset across Read calls) and MUST be reset, or the
// stale offset would point past the new buffer and capture would run to maxCap.
// Stateless stop functions (SSHStopFunc) need no factory and are reused as-is.
func (c *TeeConn) Rearm() {
	c.buf = make([]byte, 0, 1024)
	c.done = false
	c.complete = false
	if c.stopFactory != nil {
		c.stopFn = c.stopFactory()
	}
}

// StopFuncFactory creates a new StopFunc per connection. Required for stateful
// stop functions like HTTPStopFunc that track position across Read() calls.
// Stateless stop functions (like SSHStopFunc) can use StopFuncLiteral.
type StopFuncFactory func() StopFunc

// TeeListener wraps a net.Listener to return TeeConn from Accept().
// Each accepted connection gets its own StopFunc instance from the factory.
type TeeListener struct {
	net.Listener
	MaxCapture int
	NewStopFn  StopFuncFactory
}

// NewTeeListener creates a listener that captures connection preambles.
func NewTeeListener(l net.Listener, maxCapture int, factory StopFuncFactory) *TeeListener {
	return &TeeListener{Listener: l, MaxCapture: maxCapture, NewStopFn: factory}
}

func (l *TeeListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return conn, err
	}
	tc := NewTeeConn(conn, l.MaxCapture, l.NewStopFn())
	tc.stopFactory = l.NewStopFn // enables Rearm() for keep-alive re-capture
	return tc, nil
}
