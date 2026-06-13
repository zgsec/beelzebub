package OLLAMA

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/tracer"
)

// captureTracer records emitted events for assertion.
type captureTracer struct{ events []tracer.Event }

func (c *captureTracer) TraceEvent(e tracer.Event) { c.events = append(c.events, e) }
func (c *captureTracer) last() tracer.Event {
	if len(c.events) == 0 {
		return tracer.Event{}
	}
	return c.events[len(c.events)-1]
}

// oneShotConn returns data on the first Read, then EOF.
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

// Ollama is an HTTP-family LLM lure on a keep-alive connection, so its JA4H is
// subject to the same accuracy contract as the HTTP strategy: flag sorted
// fallbacks and preserve wire order when the TeeConn captured it.
func TestOllamaTraceEvent_JA4HSortedFlag(t *testing.T) {
	servConf := parser.BeelzebubServiceConfiguration{
		Address: ":11434", Description: "ollama", ServiceType: "ollama",
	}

	// Case 1: no TeeConn → sorted fallback, flagged.
	s := newTestStrategy()
	req := httptest.NewRequest(http.MethodPost, "/api/chat", strings.NewReader("{}"))
	req.RemoteAddr = "203.0.113.5:5000"
	tt := &captureTracer{}
	s.traceEvent(req, tt, servConf, "chat", "cmd", "out", "{}")
	got := tt.last()
	if !got.JA4HSorted {
		t.Errorf("expected JA4HSorted=true without wire order")
	}
	if got.HeaderOrder != "" {
		t.Errorf("expected empty HeaderOrder without wire order, got %q", got.HeaderOrder)
	}

	// Case 2: TeeConn supplies wire order → not sorted, HeaderOrder set.
	s2 := newTestStrategy()
	raw := []byte("POST /api/chat HTTP/1.1\r\nHost: x\r\nUser-Agent: ollama\r\nContent-Type: application/json\r\n\r\n")
	tc := tracer.NewTeeConn(&oneShotConn{data: raw}, 65536, tracer.HTTPStopFunc())
	if _, err := tc.Read(make([]byte, 4096)); err != nil {
		t.Fatalf("tee read: %v", err)
	}
	req2 := httptest.NewRequest(http.MethodPost, "/api/chat", strings.NewReader("{}"))
	req2.RemoteAddr = "203.0.113.6:5001"
	req2 = req2.WithContext(context.WithValue(req2.Context(), tracer.TeeConnKey, tc))
	tt2 := &captureTracer{}
	s2.traceEvent(req2, tt2, servConf, "chat", "cmd", "out", "{}")
	got2 := tt2.last()
	if got2.JA4HSorted {
		t.Errorf("expected JA4HSorted=false with wire order")
	}
	if got2.HeaderOrder == "" {
		t.Errorf("expected populated HeaderOrder with wire order")
	}
}
