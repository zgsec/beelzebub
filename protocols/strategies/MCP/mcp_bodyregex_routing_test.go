package MCP

import (
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/mariocandela/beelzebub/v3/parser"
)

// TestMCP_HTTPFallback_BodyRegexRouting locks in the 2026-06-11 fix: the MCP
// HTTP-fallback must honor each command's BodyRegex (and Method), not just the
// URI regex. Before the fix it matched the first path-matching command for every
// body, so the litellm /mcp-rest/test/* stdio-CVE chain (CVE-2026-42271) — three
// handlers on the same path routed by command name — collapsed to the first one
// (args-required), and python3 (the RCE-vector → 200) and echo (allowlist-422)
// never fired.
func TestMCP_HTTPFallback_BodyRegexRouting(t *testing.T) {
	servConf := parser.BeelzebubServiceConfiguration{
		Address:              ":0",
		CaptureResponseBody:  true,
		ResponseBodyMaxBytes: 4096,
		Commands: []parser.Command{
			{ // 1: empty args only
				Regex:      regexp.MustCompile(`^/mcp-rest/test/connection$`),
				Method:     "POST",
				BodyRegex:  regexp.MustCompile(`"args"\s*:\s*\[\s*\]`),
				Handler:    "ARGS_REQUIRED",
				StatusCode: 422,
			},
			{ // 2: allowlisted interpreter -> 200 (the RCE-vector capture seam)
				Regex:      regexp.MustCompile(`^/mcp-rest/test/connection$`),
				Method:     "POST",
				BodyRegex:  regexp.MustCompile(`"command"\s*:\s*"(python3?|node|npx|uvx|docker|deno)"`),
				Handler:    "RCE_200",
				StatusCode: 200,
			},
			{ // 3: catch-all -> allowlist-422
				Regex:      regexp.MustCompile(`^/mcp-rest/test/connection$`),
				Method:     "POST",
				Handler:    "ALLOWLIST_422",
				StatusCode: 422,
			},
		},
	}

	cases := []struct {
		name, body, wantHandler string
		wantStatus              int
	}{
		{"non-allowlisted cmd with args -> allowlist-422 (NOT args-required)",
			`{"transport":"stdio","command":"echo","args":["x"]}`, "ALLOWLIST_422", 422},
		{"allowlisted cmd -> 200 spawn-fail seam",
			`{"transport":"stdio","command":"python3","args":["-c","print(1)"]}`, "RCE_200", 200},
		{"empty args -> args-required",
			`{"transport":"stdio","command":"echo","args":[]}`, "ARGS_REQUIRED", 422},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &MCPStrategy{}
			tr := &captureTracer{}
			r := httptest.NewRequest("POST", "/mcp-rest/test/connection", strings.NewReader(c.body))
			w := httptest.NewRecorder()
			s.handleHTTPFallback(w, r, servConf, tr)

			if tr.seen != 1 {
				t.Fatalf("expected 1 traced event, got %d", tr.seen)
			}
			if tr.last.ResponseBody != c.wantHandler {
				t.Errorf("routed to wrong handler: got %q want %q", tr.last.ResponseBody, c.wantHandler)
			}
			if tr.last.ResponseStatusCode != c.wantStatus {
				t.Errorf("status: got %d want %d", tr.last.ResponseStatusCode, c.wantStatus)
			}
		})
	}
}
