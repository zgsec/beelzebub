package MCP

import (
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/tracer"
)

// TestMCP_HTTPFallback_MethodGate verifies that the MCP HTTP-fallback router
// honours the per-command Method field added 2026-05-23.
//
// Before the patch (mcp.go:1062-1068): the matcher picked the first regex
// that matched the request URI, ignoring command.Method. That meant routes
// declared `method: POST` (e.g. /key/generate, the new
// /anthropic/v1/messages) would silently respond to GET as well, breaking
// realism (real LiteLLM/Anthropic gateways return 405 method-not-allowed
// for the wrong verb).
//
// After the patch: the matcher skips routes whose declared Method does not
// match the request verb. Empty Method preserves match-any (no behaviour
// change for existing route definitions that omit Method).
func TestMCP_HTTPFallback_MethodGate(t *testing.T) {
	// Two routes with the same regex but different methods. The 405 route
	// is intentionally listed AFTER the POST route to prove the gate works
	// (without method-awareness the POST route would always win on first
	// regex match).
	mkServConf := func() parser.BeelzebubServiceConfiguration {
		return parser.BeelzebubServiceConfiguration{
			Address:              ":0",
			CaptureResponseBody:  true,
			ResponseBodyMaxBytes: 4096,
			Commands: []parser.Command{
				{
					Name:       "post-handler",
					Regex:      regexp.MustCompile(`^/v1/messages$`),
					Method:     "POST",
					Handler:    `{"ok":true}`,
					Headers:    []string{"Content-Type: application/json"},
					StatusCode: 200,
				},
				{
					Name:       "get-405",
					Regex:      regexp.MustCompile(`^/v1/messages$`),
					Method:     "GET",
					Handler:    `{"type":"error","error":{"type":"not_allowed_error"}}`,
					Headers:    []string{"Content-Type: application/json", "Allow: POST"},
					StatusCode: 405,
				},
			},
		}
	}

	t.Run("POST routes to post-handler", func(t *testing.T) {
		servConf := mkServConf()
		s := &MCPStrategy{}
		tr := &captureTracer{}

		r := httptest.NewRequest("POST", "/v1/messages", nil)
		w := httptest.NewRecorder()
		s.handleHTTPFallback(w, r, servConf, tr)

		if tr.last.Handler != "post-handler" {
			t.Errorf("expected POST → post-handler, got %q", tr.last.Handler)
		}
		if w.Code != 200 {
			t.Errorf("expected status 200, got %d", w.Code)
		}
	})

	t.Run("GET routes to get-405 despite POST route listed first", func(t *testing.T) {
		servConf := mkServConf()
		s := &MCPStrategy{}
		tr := &captureTracer{}

		r := httptest.NewRequest("GET", "/v1/messages", nil)
		w := httptest.NewRecorder()
		s.handleHTTPFallback(w, r, servConf, tr)

		if tr.last.Handler != "get-405" {
			t.Errorf("expected GET → get-405, got %q (would indicate method gate is not respected)", tr.last.Handler)
		}
		if w.Code != 405 {
			t.Errorf("expected status 405, got %d", w.Code)
		}
	})

	t.Run("case-insensitive method match", func(t *testing.T) {
		// net/http normalises Method to uppercase, but defending against the
		// case where a hand-built request slips through with mixed case keeps
		// the gate symmetric with the parser-side declaration.
		servConf := mkServConf()
		s := &MCPStrategy{}
		tr := &captureTracer{}

		r := httptest.NewRequest("POST", "/v1/messages", nil)
		r.Method = "post" // force lowercase to exercise EqualFold
		w := httptest.NewRecorder()
		s.handleHTTPFallback(w, r, servConf, tr)

		if tr.last.Handler != "post-handler" {
			t.Errorf("expected case-insensitive POST match → post-handler, got %q", tr.last.Handler)
		}
	})

	t.Run("empty Method preserves match-any behaviour", func(t *testing.T) {
		// Pre-existing routes that omit `method:` must continue to match
		// every verb. This is the non-regression check for the bulk of the
		// existing mcp-8000.yaml route table.
		servConf := parser.BeelzebubServiceConfiguration{
			Address:              ":0",
			CaptureResponseBody:  true,
			ResponseBodyMaxBytes: 4096,
			Commands: []parser.Command{
				{
					Name:       "any-method",
					Regex:      regexp.MustCompile(`^/health$`),
					Handler:    `{"status":"ok"}`,
					Headers:    []string{"Content-Type: application/json"},
					StatusCode: 200,
				},
			},
		}
		s := &MCPStrategy{}

		for _, m := range []string{"GET", "POST", "PUT", "DELETE", "HEAD"} {
			tr := &captureTracer{}
			r := httptest.NewRequest(m, "/health", nil)
			w := httptest.NewRecorder()
			s.handleHTTPFallback(w, r, servConf, tr)

			if tr.last.Handler != "any-method" {
				t.Errorf("method %s: expected any-method (empty Method should match any verb), got %q", m, tr.last.Handler)
			}
			if w.Code != 200 {
				t.Errorf("method %s: expected status 200, got %d", m, w.Code)
			}
		}
	})

	// Silence unused-import warning for tracer when the test grows; the
	// captureTracer type already pulls it in via mcp_response_capture_test.go.
	_ = tracer.Event{}
}
