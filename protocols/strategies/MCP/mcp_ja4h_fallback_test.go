package MCP

import (
	"context"
	"io"
	"net"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/tracer"
)

type oneShotConn struct {
	net.Conn
	data []byte
	done bool
}

func (c *oneShotConn) Read(p []byte) (int, error) {
	if c.done {
		return 0, io.EOF
	}
	c.done = true
	return copy(p, c.data), nil
}

// The MCP HTTP-fallback path previously emitted no JA4H (coverage gap). It must
// now fingerprint like the HTTP strategy: sorted-fallback + flag when no wire
// order is available, wire-order JA4H + HeaderOrder when the TeeConn captured it.
func TestMCP_HTTPFallback_EmitsJA4H(t *testing.T) {
	servConf := parser.BeelzebubServiceConfiguration{
		Address:  ":0",
		Commands: []parser.Command{{Regex: regexp.MustCompile(`^/probe$`), Handler: "ok", StatusCode: 200}},
	}
	s := &MCPStrategy{}

	// No TeeConn → sorted fallback, but JA4H is still emitted and flagged.
	tr := &captureTracer{}
	s.handleHTTPFallback(httptest.NewRecorder(), httptest.NewRequest("GET", "/probe", nil), servConf, tr)
	if tr.last.JA4H == "" {
		t.Fatal("HTTP-fallback emitted empty JA4H")
	}
	if !tr.last.JA4HSorted {
		t.Error("expected JA4HSorted=true without wire order")
	}

	// With TeeConn → wire-order JA4H, HeaderOrder populated, not flagged.
	raw := []byte("GET /probe HTTP/1.1\r\nHost: x\r\nUser-Agent: mcp-client\r\nAccept: */*\r\n\r\n")
	tcn := tracer.NewTeeConn(&oneShotConn{data: raw}, 65536, tracer.HTTPStopFunc())
	if _, err := tcn.Read(make([]byte, 4096)); err != nil {
		t.Fatalf("tee read: %v", err)
	}
	r2 := httptest.NewRequest("GET", "/probe", nil)
	r2 = r2.WithContext(context.WithValue(r2.Context(), tracer.TeeConnKey, tcn))
	tr2 := &captureTracer{}
	s.handleHTTPFallback(httptest.NewRecorder(), r2, servConf, tr2)
	if tr2.last.JA4HSorted {
		t.Error("expected JA4HSorted=false with wire order")
	}
	if tr2.last.HeaderOrder == "" {
		t.Error("expected HeaderOrder populated with wire order")
	}
}
