package MCP

import (
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/tracer"
)

// captureTracer records the most recent event so assertions can inspect
// what TraceEvent received. The opt-in ResponseBody capture lives on the
// tracer.Event payload, so unit-testing the flag means reading that event.
type captureTracer struct {
	last tracer.Event
	seen int
}

func (c *captureTracer) TraceEvent(e tracer.Event) {
	c.last = e
	c.seen++
}

// TestMCP_HTTPFallback_ResponseBody_OptIn verifies the response-capture
// wiring added 2026-05-18 (closes the gap documented in
// vault/architecture/2026-05-18-crestfield-disney-cohesion-plan.md §0).
//
// Before the patch: HTTP-fallback handlers under MCP-protocol services
// (the 38-route mcp-8000.yaml architecture)
// computed respBody for the wire and hashed it into ResponseBodySha256,
// but never persisted the body or status code to the tracer event.
// `sessions.response_summary` in PG stayed null for every HTTP-fallback
// request even when `captureResponseBody: true` was declared in the
// service config.
//
// After the patch: when CaptureResponseBody is set, event.ResponseBody
// carries the substituted body (truncated to ResponseBodyMaxBytes) and
// event.ResponseStatusCode carries the matched command's status code
// (or 200 when unset).
func TestMCP_HTTPFallback_ResponseBody_OptIn(t *testing.T) {
	mkServConf := func(capture bool, maxBytes int, status int, handler string) parser.BeelzebubServiceConfiguration {
		return parser.BeelzebubServiceConfiguration{
			Address:              ":0",
			CaptureResponseBody:  capture,
			ResponseBodyMaxBytes: maxBytes,
			Commands: []parser.Command{
				{
					Regex:      regexp.MustCompile(`^/probe$`),
					Handler:    handler,
					Headers:    []string{"Content-Type: text/plain"},
					StatusCode: status,
				},
			},
		}
	}

	t.Run("flag false leaves ResponseBody empty", func(t *testing.T) {
		servConf := mkServConf(false, 0, 200, "hello world")
		s := &MCPStrategy{}
		tr := &captureTracer{}

		r := httptest.NewRequest("GET", "/probe", nil)
		w := httptest.NewRecorder()
		s.handleHTTPFallback(w, r, servConf, tr)

		if tr.seen != 1 {
			t.Fatalf("expected 1 traced event, got %d", tr.seen)
		}
		if tr.last.ResponseBody != "" {
			t.Errorf("expected empty ResponseBody when CaptureResponseBody=false, got %q", tr.last.ResponseBody)
		}
		// Wire body still emitted regardless of capture flag.
		if got := w.Body.String(); got != "hello world" {
			t.Errorf("wire body should always be written; got %q", got)
		}
	})

	t.Run("flag true captures body and status", func(t *testing.T) {
		servConf := mkServConf(true, 0, 418, "I am a teapot")
		s := &MCPStrategy{}
		tr := &captureTracer{}

		r := httptest.NewRequest("GET", "/probe", nil)
		w := httptest.NewRecorder()
		s.handleHTTPFallback(w, r, servConf, tr)

		if tr.last.ResponseBody != "I am a teapot" {
			t.Errorf("expected captured ResponseBody, got %q", tr.last.ResponseBody)
		}
		if tr.last.ResponseStatusCode != 418 {
			t.Errorf("expected captured ResponseStatusCode=418, got %d", tr.last.ResponseStatusCode)
		}
		if tr.last.ResponseBodySha256 == "" {
			t.Errorf("expected ResponseBodySha256 populated unconditionally")
		}
	})

	t.Run("zero StatusCode records as 200", func(t *testing.T) {
		// matchedCommand.StatusCode==0 means handler did not specify a
		// status; Go's http.ResponseWriter defaults to 200 on the wire.
		// Event should record that observable value, not 0.
		servConf := mkServConf(true, 0, 0, "implicit-200-body")
		s := &MCPStrategy{}
		tr := &captureTracer{}

		r := httptest.NewRequest("GET", "/probe", nil)
		w := httptest.NewRecorder()
		s.handleHTTPFallback(w, r, servConf, tr)

		if tr.last.ResponseStatusCode != 200 {
			t.Errorf("expected ResponseStatusCode=200 when StatusCode unset, got %d", tr.last.ResponseStatusCode)
		}
	})

	t.Run("ResponseBodyMaxBytes truncates", func(t *testing.T) {
		big := strings.Repeat("A", 200)
		servConf := mkServConf(true, 50, 200, big)
		s := &MCPStrategy{}
		tr := &captureTracer{}

		r := httptest.NewRequest("GET", "/probe", nil)
		w := httptest.NewRecorder()
		s.handleHTTPFallback(w, r, servConf, tr)

		if len(tr.last.ResponseBody) != 50 {
			t.Errorf("expected ResponseBody truncated to 50 bytes, got %d", len(tr.last.ResponseBody))
		}
		// Wire response should NOT be truncated — only the captured copy.
		if w.Body.Len() != 200 {
			t.Errorf("wire response should be full 200 bytes, got %d", w.Body.Len())
		}
	})

	t.Run("zero ResponseBodyMaxBytes uses default 64 KiB", func(t *testing.T) {
		// 100 KiB handler body, captureResponseBody true, maxBytes 0.
		// Expected: captured body truncated to defaultMCPResponseBodyMaxBytes
		// (64 KiB). Mirrors HTTP/OLLAMA strategy defaults.
		big := strings.Repeat("X", 100*1024)
		servConf := mkServConf(true, 0, 200, big)
		s := &MCPStrategy{}
		tr := &captureTracer{}

		r := httptest.NewRequest("GET", "/probe", nil)
		w := httptest.NewRecorder()
		s.handleHTTPFallback(w, r, servConf, tr)

		if len(tr.last.ResponseBody) != defaultMCPResponseBodyMaxBytes {
			t.Errorf("expected default-truncated ResponseBody of %d bytes, got %d",
				defaultMCPResponseBodyMaxBytes, len(tr.last.ResponseBody))
		}
	})
}
