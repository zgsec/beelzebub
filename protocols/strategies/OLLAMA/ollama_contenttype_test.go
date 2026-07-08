package OLLAMA

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mariocandela/beelzebub/v3/parser"
)

// Real Ollama 0.31.1 content-type split (verified live):
//   /api/* JSON (success AND error) -> "application/json; charset=utf-8"
//   /v1/* SUCCESS (2xx)             -> "application/json"  (bare; mimics api.openai.com)
//   /v1/* ERROR   (4xx)             -> "application/json; charset=utf-8" (gin default)
func TestContentTypeSplit(t *testing.T) {
	const charset = "application/json; charset=utf-8"
	const bare = "application/json"
	s := newTestStrategy()
	tr := noopTracer()
	conf := parser.BeelzebubServiceConfiguration{}

	ct := func(rec *httptest.ResponseRecorder) string { return rec.Header().Get("Content-Type") }

	// --- /api/* -> charset ---
	rec := httptest.NewRecorder()
	s.handleVersion(rec, httptest.NewRequest("GET", "/api/version", nil), conf, tr)
	if ct(rec) != charset {
		t.Errorf("/api/version ct=%q, want %q", ct(rec), charset)
	}
	rec = httptest.NewRecorder()
	s.writeOllamaNonStreaming(rec, "llama3.1:8b", "hi", 5)
	if ct(rec) != charset {
		t.Errorf("/api generate non-stream ct=%q, want %q", ct(rec), charset)
	}
	rec = httptest.NewRecorder()
	s.writeOllamaChatNonStreaming(rec, "llama3.1:8b", "hi", 5)
	if ct(rec) != charset {
		t.Errorf("/api chat non-stream ct=%q, want %q", ct(rec), charset)
	}
	rec = httptest.NewRecorder()
	s.handleEmbed(rec, httptest.NewRequest("POST", "/api/embed", strings.NewReader(`{"model":"nomic-embed-text","input":"hi"}`)), conf, tr)
	if ct(rec) != charset {
		t.Errorf("/api/embed ct=%q, want %q", ct(rec), charset)
	}

	// --- /v1/* SUCCESS -> bare (must NOT be charset) ---
	rec = httptest.NewRecorder()
	s.writeOpenAINonStreaming(rec, "llama3.1:8b", "hi", 5)
	if ct(rec) != bare {
		t.Errorf("/v1 chat success ct=%q, want %q (bare, mimics OpenAI)", ct(rec), bare)
	}
	rec = httptest.NewRecorder()
	s.writeOpenAITextCompletion(rec, "llama3.1:8b", "hi", 5)
	if ct(rec) != bare {
		t.Errorf("/v1 text-completion success ct=%q, want %q (bare)", ct(rec), bare)
	}

	// --- /v1/* ERRORS -> charset ---
	rec = httptest.NewRecorder()
	s.handleOpenAIChat(rec, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{}`)), conf, tr)
	if rec.Code != 401 {
		t.Fatalf("/v1 no-auth code=%d, want 401", rec.Code)
	}
	if ct(rec) != charset {
		t.Errorf("/v1 401 ct=%q, want %q", ct(rec), charset)
	}
	rec = httptest.NewRecorder()
	badReq := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{bad json`))
	badReq.Header.Set("Authorization", "Bearer sk-test")
	s.handleOpenAIChat(rec, badReq, conf, tr)
	if rec.Code != 400 {
		t.Fatalf("/v1 bad-json code=%d, want 400", rec.Code)
	}
	if ct(rec) != charset {
		t.Errorf("/v1 400 ct=%q, want %q", ct(rec), charset)
	}
}
