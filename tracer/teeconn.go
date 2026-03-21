package tracer

import "net"

// contextKey is a typed key for storing TeeConn in context.Context or ssh.Context.
type contextKey struct{ name string }

// TeeConnKey is the context key for retrieving the *TeeConn from a request or session context.
var TeeConnKey = &contextKey{"tee-conn"}

// TeeConn wraps a net.Conn to capture the first maxCap bytes of Read() data
// while passing them through unmodified. Used by JA4H (HTTP header order) and
// HASSH (SSH KEXINIT) to access raw protocol bytes that Go's parsers discard.
//
// No mutex — Read() and RawBytes() are called sequentially within the same
// goroutine (HTTP handler or SSH session handler). No replay — bytes flow
// to the parser normally.
type TeeConn struct {
	net.Conn
	buf    []byte
	maxCap int
	done   bool
}

// NewTeeConn wraps a connection for raw byte capture.
func NewTeeConn(c net.Conn, maxCapture int) *TeeConn {
	return &TeeConn{Conn: c, buf: make([]byte, 0, 1024), maxCap: maxCapture}
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
		if len(c.buf) >= c.maxCap {
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
}

// NewTeeListener creates a listener that captures the first maxCapture bytes of each connection.
func NewTeeListener(l net.Listener, maxCapture int) *TeeListener {
	return &TeeListener{Listener: l, MaxCapture: maxCapture}
}

func (l *TeeListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return conn, err
	}
	return NewTeeConn(conn, l.MaxCapture), nil
}
