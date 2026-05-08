package OLLAMA

import (
	"strings"
	"testing"

	"github.com/mariocandela/beelzebub/v3/parser"
)

// TestOllama_LLMOfflineResponse_AppliesResponseSubstitutions — YAML-authored
// llmOfflineResponse bodies (BlueSpark's litellm/vllm/ollama lures) must get
// per-request placeholder substitution; otherwise a "${request.uuid_short}"
// in the configured fallback body would leak as a literal string on the
// wire. Mirrors the fix wired into MCP / TCP / TELNET.
func TestOllama_LLMOfflineResponse_AppliesResponseSubstitutions(t *testing.T) {
	fb := &parser.LLMOfflineResponse{
		Status: 503,
		Body:   `{"error":"upstream","trace_id":"${request.uuid}","short":"${request.uuid_short}"}`,
	}
	_, body1 := ollamaLLMOfflineResponse(fb, "aurora-7b")
	if strings.Contains(body1, "${request.uuid}") || strings.Contains(body1, "${request.uuid_short}") {
		t.Fatalf("placeholder left in OLLAMA fallback body: %q", body1)
	}
	// Second call must produce a different body — fresh UUID.
	_, body2 := ollamaLLMOfflineResponse(fb, "aurora-7b")
	if body1 == body2 {
		t.Fatalf("OLLAMA fallback returned identical body for two calls: %q", body1)
	}
	// The configured fallback body must not have been mutated.
	if fb.Body != `{"error":"upstream","trace_id":"${request.uuid}","short":"${request.uuid_short}"}` {
		t.Errorf("LLMOfflineResponse.Body mutated: %q", fb.Body)
	}
}
