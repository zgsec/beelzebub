package MCP

import (
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
)

// noopTracer satisfies tracer.Tracer for tests that don't care about events.
type noopTracer struct{}

func (noopTracer) TraceEvent(tracer.Event) {}

// TestMCP_HTTPFallback_AppliesResponseSubstitutions — a persona's
// MCP-on-port-8000 deployment exercised the wire-format gap that
// motivates the responsesubs package. A YAML lure authoring
// "${request.uuid_short}" in matchedCommand.Handler must NOT emit the
// literal template string on the wire — that would be strictly worse
// than the cross-fleet-identical req_a1b2c3d4 leak the substitution
// was introduced to fix (see commit 4cd06db, 2026-05-06 conformance
// test).
func TestMCP_HTTPFallback_AppliesResponseSubstitutions(t *testing.T) {
	servConf := parser.BeelzebubServiceConfiguration{
		Address: ":0",
		Commands: []parser.Command{
			{
				Regex:      regexp.MustCompile(`^/probe$`),
				Handler:    `{"id":"req_${request.uuid_short}","trace":"${request.uuid}"}`,
				Headers:    []string{"X-Request-Id: req_${request.uuid_short}"},
				StatusCode: 200,
			},
		},
	}
	s := &MCPStrategy{}

	r1 := httptest.NewRequest("GET", "/probe", nil)
	w1 := httptest.NewRecorder()
	s.handleHTTPFallback(w1, r1, servConf, noopTracer{})

	body1 := w1.Body.String()
	if strings.Contains(body1, "${request.uuid_short}") || strings.Contains(body1, "${request.uuid}") {
		t.Fatalf("placeholder left in MCP fallback body: %q", body1)
	}
	if got := w1.Header().Get("X-Request-Id"); strings.Contains(got, "${") {
		t.Fatalf("placeholder left in MCP fallback header: %q", got)
	}

	// Second request must produce a different UUID (no caching of the
	// first request's UUID into matchedCommand).
	r2 := httptest.NewRequest("GET", "/probe", nil)
	w2 := httptest.NewRecorder()
	s.handleHTTPFallback(w2, r2, servConf, noopTracer{})
	if w1.Body.String() == w2.Body.String() {
		t.Fatalf("MCP fallback emitted identical body for two requests — UUID was baked into matchedCommand: %q", w1.Body.String())
	}

	// And the original Command struct must be untouched (no in-place
	// mutation of Handler / Headers).
	if servConf.Commands[0].Handler != `{"id":"req_${request.uuid_short}","trace":"${request.uuid}"}` {
		t.Errorf("matchedCommand.Handler mutated: %q", servConf.Commands[0].Handler)
	}
	if servConf.Commands[0].Headers[0] != "X-Request-Id: req_${request.uuid_short}" {
		t.Errorf("matchedCommand.Headers mutated: %q", servConf.Commands[0].Headers[0])
	}
}
