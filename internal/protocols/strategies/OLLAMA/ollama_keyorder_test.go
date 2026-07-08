package OLLAMA

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
)

func noopTracer() tracer.Tracer { return tracer.GetInstance(func(tracer.Event) {}) }

// topKeys returns the top-level JSON object keys of raw, IN WIRE ORDER.
// (json.Unmarshal into a map would lose order; the Decoder token stream keeps it.)
func topKeys(t *testing.T, raw []byte) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		t.Fatalf("expected JSON object, got %v (err %v): %s", tok, err, raw)
	}
	var keys []string
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			t.Fatalf("key token: %v", err)
		}
		keys = append(keys, kt.(string))
		skipJSONValue(t, dec)
	}
	return keys
}

// skipJSONValue consumes exactly one value (scalar, object, or array) from dec.
func skipJSONValue(t *testing.T, dec *json.Decoder) {
	t.Helper()
	tok, err := dec.Token()
	if err != nil {
		t.Fatalf("value token: %v", err)
	}
	if d, ok := tok.(json.Delim); ok && (d == '{' || d == '[') {
		depth := 1
		for depth > 0 {
			tk, err := dec.Token()
			if err != nil {
				t.Fatalf("skip token: %v", err)
			}
			if dd, ok := tk.(json.Delim); ok {
				if dd == '{' || dd == '[' {
					depth++
				} else {
					depth--
				}
			}
		}
	}
}

func assertKeyOrder(t *testing.T, got, want []string, label string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s: JSON key order does not match real Ollama\n  got:  %v\n  want: %v", label, got, want)
	}
}

func ndjsonLines(s string) []string {
	var out []string
	for _, ln := range strings.Split(strings.TrimSpace(s), "\n") {
		if strings.TrimSpace(ln) != "" {
			out = append(out, ln)
		}
	}
	return out
}

// Real 0.31.1 wire orders, captured in tools/oracle-diff/ollama-0.31.1/fixtures.
var (
	wantGenerateChunk = []string{"model", "created_at", "response", "done"}
	wantGenerateDone  = []string{"model", "created_at", "response", "done", "done_reason", "context",
		"total_duration", "load_duration", "prompt_eval_count", "prompt_eval_duration", "eval_count", "eval_duration"}
	wantChatChunk = []string{"model", "created_at", "message", "done"}
	wantChatDone  = []string{"model", "created_at", "message", "done", "done_reason",
		"total_duration", "load_duration", "prompt_eval_count", "prompt_eval_duration", "eval_count", "eval_duration"}
)

func TestGenerateStreamKeyOrder(t *testing.T) {
	s := newTestStrategy()
	rec := httptest.NewRecorder()
	s.streamOllamaResponse(rec, "llama3.1:8b", "hi there friend", 12)
	lines := ndjsonLines(rec.Body.String())
	if len(lines) < 2 {
		t.Fatalf("expected >=2 ndjson lines, got %d", len(lines))
	}
	assertKeyOrder(t, topKeys(t, []byte(lines[0])), wantGenerateChunk, "generate stream chunk")
	assertKeyOrder(t, topKeys(t, []byte(lines[len(lines)-1])), wantGenerateDone, "generate stream done")
}

func TestChatStreamKeyOrder(t *testing.T) {
	s := newTestStrategy()
	rec := httptest.NewRecorder()
	s.streamOllamaChatResponse(rec, "llama3.1:8b", "hi there friend", 12)
	lines := ndjsonLines(rec.Body.String())
	if len(lines) < 2 {
		t.Fatalf("expected >=2 ndjson lines, got %d", len(lines))
	}
	assertKeyOrder(t, topKeys(t, []byte(lines[0])), wantChatChunk, "chat stream chunk")
	assertKeyOrder(t, topKeys(t, []byte(lines[len(lines)-1])), wantChatDone, "chat stream done")
}

func TestGenerateNonStreamKeyOrder(t *testing.T) {
	s := newTestStrategy()
	rec := httptest.NewRecorder()
	s.writeOllamaNonStreaming(rec, "llama3.1:8b", "hello world", 12)
	assertKeyOrder(t, topKeys(t, rec.Body.Bytes()), wantGenerateDone, "generate non-stream")
}

func TestChatNonStreamKeyOrder(t *testing.T) {
	s := newTestStrategy()
	rec := httptest.NewRecorder()
	s.writeOllamaChatNonStreaming(rec, "llama3.1:8b", "hello world", 12)
	assertKeyOrder(t, topKeys(t, rec.Body.Bytes()), wantChatDone, "chat non-stream")
}

var (
	wantPsEntry      = []string{"name", "model", "size", "digest", "details", "expires_at", "size_vram", "context_length"}
	wantModelDetails = []string{"parent_model", "format", "family", "families", "parameter_size", "quantization_level"}
	wantEmbed        = []string{"model", "embeddings", "total_duration", "load_duration", "prompt_eval_count"}
	wantPullProgress = []string{"status", "digest", "total", "completed"}
)

func TestPsKeyOrder(t *testing.T) {
	s := newTestStrategy()
	s.lastInferenceAt = time.Now() // mark a model VRAM-resident so /api/ps emits an entry
	req := httptest.NewRequest("GET", "/api/ps", nil)
	w := httptest.NewRecorder()
	s.handlePs(w, req, parser.BeelzebubServiceConfiguration{}, noopTracer())

	var env struct {
		Models []json.RawMessage `json:"models"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(env.Models) < 1 {
		t.Fatalf("expected a resident model, got none: %s", w.Body.String())
	}
	assertKeyOrder(t, topKeys(t, env.Models[0]), wantPsEntry, "ps entry")
	var m struct {
		Details json.RawMessage `json:"details"`
	}
	json.Unmarshal(env.Models[0], &m)
	assertKeyOrder(t, topKeys(t, m.Details), wantModelDetails, "ps details")
}

func TestEmbedKeyOrder(t *testing.T) {
	s := newTestStrategy()
	req := httptest.NewRequest("POST", "/api/embed", strings.NewReader(`{"model":"nomic-embed-text","input":"hi"}`))
	w := httptest.NewRecorder()
	s.handleEmbed(w, req, parser.BeelzebubServiceConfiguration{}, noopTracer())
	assertKeyOrder(t, topKeys(t, w.Body.Bytes()), wantEmbed, "embed")
}

func TestPullKeyOrder(t *testing.T) {
	s := newTestStrategy()
	req := httptest.NewRequest("POST", "/api/pull", strings.NewReader(`{"name":"llama3.1:8b"}`))
	w := httptest.NewRecorder()
	s.handlePull(w, req, parser.BeelzebubServiceConfiguration{}, noopTracer())
	var full []byte
	for _, ln := range ndjsonLines(w.Body.String()) {
		if strings.Contains(ln, "completed") {
			full = []byte(ln)
			break
		}
	}
	if full == nil {
		t.Fatalf("no progress stage with completed: %s", w.Body.String())
	}
	assertKeyOrder(t, topKeys(t, full), wantPullProgress, "pull progress")
}
