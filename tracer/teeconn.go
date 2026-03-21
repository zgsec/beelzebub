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

// StopFunc inspects captured bytes and returns true when capture should stop.
// Called after each Read() with the full accumulated buffer.
type StopFunc func(buf []byte) bool

// HTTPStopFunc stops capture after \r\n\r\n (end of HTTP headers).
func HTTPStopFunc(buf []byte) bool {
	return bytes.Contains(buf, []byte("\r\n\r\n"))
}

// SSHStopFunc stops capture after the version string + a complete binary packet.
// Validates that the packet contains SSH_MSG_KEXINIT (type 20).
func SSHStopFunc(buf []byte) bool {
	nl := bytes.IndexByte(buf, '\n')
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
	buf    []byte
	maxCap int
	done   bool
	stopFn StopFunc
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
		// Stop when protocol preamble is complete or safety cap reached
		if (c.stopFn != nil && c.stopFn(c.buf)) || len(c.buf) >= c.maxCap {
			c.done = true
		}
	}
	return n, err
}

// RawBytes returns the captured bytes. Call after the protocol parser has
// consumed the connection preamble (HTTP headers or SSH KEXINIT).
func (c *TeeConn) RawBytes() []byte { return c.buf }

// TeeListener wraps a net.Listener to return TeeConn from Accept().
type TeeListener struct {
	net.Listener
	MaxCapture int
	StopFn     StopFunc
}

// NewTeeListener creates a listener that captures connection preambles.
func NewTeeListener(l net.Listener, maxCapture int, stop StopFunc) *TeeListener {
	return &TeeListener{Listener: l, MaxCapture: maxCapture, StopFn: stop}
}

func (l *TeeListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return conn, err
	}
	return NewTeeConn(conn, l.MaxCapture, l.StopFn), nil
}
