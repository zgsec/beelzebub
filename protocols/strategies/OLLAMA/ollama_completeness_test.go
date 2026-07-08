package OLLAMA

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mariocandela/beelzebub/v3/parser"
)

// newTestStrategy's catalog is llama3.1:8b, which HAS baked GGUF metadata
// (modelmeta/llama3.1_8b.json) — so tags + show exercise the faithful path.

func TestTagsCompleteness(t *testing.T) {
	s := newTestStrategy()
	req := httptest.NewRequest("GET", "/api/tags", nil)
	w := httptest.NewRecorder()
	s.handleTags(w, req, parser.BeelzebubServiceConfiguration{}, noopTracer())

	if ct := w.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("content-type=%q, want application/json; charset=utf-8", ct)
	}
	if v := w.Header().Get("Ollama-Version"); v != "" {
		t.Errorf("Ollama-Version header present (%q); real Ollama sends none", v)
	}

	var env struct {
		Models []json.RawMessage `json:"models"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(env.Models) < 1 {
		t.Fatalf("no models: %s", w.Body.String())
	}
	assertKeyOrder(t, topKeys(t, env.Models[0]),
		[]string{"name", "model", "modified_at", "size", "digest", "details", "capabilities"}, "tags entry")

	var m struct {
		Details      json.RawMessage `json:"details"`
		Capabilities []string        `json:"capabilities"`
	}
	json.Unmarshal(env.Models[0], &m)
	assertKeyOrder(t, topKeys(t, m.Details), []string{
		"parent_model", "format", "family", "families", "parameter_size",
		"quantization_level", "context_length", "embedding_length"}, "tags details")

	var d struct {
		ContextLength   int `json:"context_length"`
		EmbeddingLength int `json:"embedding_length"`
	}
	json.Unmarshal(m.Details, &d)
	if d.ContextLength != 131072 {
		t.Errorf("context_length=%d, want 131072 (baked)", d.ContextLength)
	}
	if d.EmbeddingLength != 4096 {
		t.Errorf("embedding_length=%d, want 4096 (baked)", d.EmbeddingLength)
	}
	if len(m.Capabilities) == 0 {
		t.Errorf("capabilities array missing")
	}
}

func TestShowServesBakedComplete(t *testing.T) {
	s := newTestStrategy()
	req := httptest.NewRequest("POST", "/api/show", strings.NewReader(`{"model":"llama3.1:8b"}`))
	w := httptest.NewRecorder()
	s.handleShow(w, req, parser.BeelzebubServiceConfiguration{}, noopTracer())

	if ct := w.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("content-type=%q, want application/json; charset=utf-8", ct)
	}
	if w.Header().Get("Ollama-Version") != "" {
		t.Errorf("Ollama-Version header present; real Ollama sends none")
	}
	assertKeyOrder(t, topKeys(t, w.Body.Bytes()), []string{
		"license", "modelfile", "parameters", "template", "details",
		"model_info", "tensors", "capabilities", "modified_at"}, "show top-level")

	var doc struct {
		Tensors      []json.RawMessage          `json:"tensors"`
		ModelInfo    map[string]json.RawMessage `json:"model_info"`
		ModifiedAt   string                     `json:"modified_at"`
		Capabilities []string                   `json:"capabilities"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Tensors) != 292 {
		t.Errorf("tensors=%d, want 292 (baked GGUF)", len(doc.Tensors))
	}
	if len(doc.ModelInfo) != 28 {
		t.Errorf("model_info keys=%d, want 28 (baked GGUF)", len(doc.ModelInfo))
	}
	if doc.ModifiedAt == "1970-01-01T00:00:00Z" || doc.ModifiedAt == "" {
		t.Errorf("modified_at not patched from placeholder: %q", doc.ModifiedAt)
	}
	if len(doc.Capabilities) == 0 {
		t.Errorf("capabilities missing")
	}
}

// A model NOT in the baked library must still 404 (modelExists gate) — the
// fallback path only applies to advertised models missing their fixture.
func TestShowUnknownModelStill404(t *testing.T) {
	s := newTestStrategy()
	req := httptest.NewRequest("POST", "/api/show", strings.NewReader(`{"model":"nonexistent:99b"}`))
	w := httptest.NewRecorder()
	s.handleShow(w, req, parser.BeelzebubServiceConfiguration{}, noopTracer())
	if w.Code != 404 {
		t.Errorf("status=%d, want 404 for unknown model", w.Code)
	}
}
