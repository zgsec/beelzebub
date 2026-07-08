package OLLAMA

import (
	"embed"
	"encoding/json"
	"regexp"
	"strings"
)

// Baked model-metadata library. Real Ollama /api/show returns the full GGUF
// model_info (28 keys) plus the tensor list (292 entries for llama-8B) BY
// DEFAULT in 0.31.1 — data that cannot be derived from the handful of config
// fields. These files are the byte-exact /api/show reconstructed offline by
// tools/oracle-diff/gguf_oracle.py (validated byte-for-byte vs a real 0.31.1
// instance) with modified_at as a "1970-..." placeholder we patch per deploy.
// They are public registry metadata — safe to embed in the binary. Generate
// one per advertised model at persona-authoring time; the emulator then serves
// a faithful /api/show and a coherent /api/tags for that model.
//
//go:embed modelmeta/*.json
var modelMetaFS embed.FS

// modelMeta is the parsed facts + raw bytes for one baked model.
type modelMeta struct {
	raw             []byte // the full byte-exact /api/show (modified_at = placeholder)
	details         ollamaModelDetails
	capabilities    []string
	contextLength   int
	embeddingLength int
}

var modelMetaByKey = loadModelMeta()

func loadModelMeta() map[string]*modelMeta {
	out := map[string]*modelMeta{}
	entries, err := modelMetaFS.ReadDir("modelmeta")
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := modelMetaFS.ReadFile("modelmeta/" + e.Name())
		if err != nil {
			continue
		}
		m := parseModelMeta(raw)
		if m != nil {
			out[strings.TrimSuffix(e.Name(), ".json")] = m
		}
	}
	return out
}

func parseModelMeta(raw []byte) *modelMeta {
	var doc struct {
		Details      ollamaModelDetails         `json:"details"`
		Capabilities []string                   `json:"capabilities"`
		ModelInfo    map[string]json.RawMessage `json:"model_info"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	m := &modelMeta{raw: raw, details: doc.Details, capabilities: doc.Capabilities}
	// context_length / embedding_length live under the arch prefix
	// (llama.context_length, qwen2.embedding_length, ...) — find by suffix.
	for k, v := range doc.ModelInfo {
		if strings.HasSuffix(k, ".context_length") {
			json.Unmarshal(v, &m.contextLength)
		} else if strings.HasSuffix(k, ".embedding_length") {
			json.Unmarshal(v, &m.embeddingLength)
		}
	}
	return m
}

// modelMetaKey sanitizes a model name ("llama3.1:8b") to its file key
// ("llama3.1_8b").
func modelMetaKey(model string) string {
	return strings.NewReplacer(":", "_", "/", "_").Replace(model)
}

func lookupModelMeta(model string) (*modelMeta, bool) {
	m, ok := modelMetaByKey[modelMetaKey(model)]
	return m, ok
}

var modifiedAtRe = regexp.MustCompile(`"modified_at":"[^"]*"`)

// bakedShow returns the byte-exact /api/show for model with modified_at patched
// to modifiedAt, or (nil,false) when no baked metadata exists for the model.
func bakedShow(model, modifiedAt string) ([]byte, bool) {
	m, ok := lookupModelMeta(model)
	if !ok {
		return nil, false
	}
	return modifiedAtRe.ReplaceAll(m.raw, []byte(`"modified_at":"`+modifiedAt+`"`)), true
}

// --- Fallback per-model derivation (used only when a model has no baked
// metadata; baked GGUF facts are authoritative and preferred). ---

func capabilitiesForModel(name, family string) []string {
	if isEmbeddingModel(name) {
		return []string{"embedding"}
	}
	n := strings.ToLower(name)
	if strings.HasPrefix(n, "deepseek-r1") {
		return []string{"completion", "thinking"}
	}
	switch {
	case strings.HasPrefix(n, "llama3.1"), strings.HasPrefix(n, "llama3.2"),
		strings.HasPrefix(n, "llama3.3"), strings.HasPrefix(n, "qwen2.5"),
		strings.HasPrefix(n, "qwen3"), strings.HasPrefix(n, "mistral-nemo"),
		strings.HasPrefix(n, "phi4"):
		return []string{"completion", "tools"}
	}
	return []string{"completion"}
}

func contextLengthForModel(name, family string) int {
	n := strings.ToLower(name)
	switch {
	case strings.HasPrefix(n, "llama3.1"), strings.HasPrefix(n, "llama3.2"),
		strings.HasPrefix(n, "llama3.3"), strings.HasPrefix(n, "phi4"),
		strings.HasPrefix(n, "deepseek-r1"):
		return 131072
	case strings.HasPrefix(n, "qwen2.5"), strings.HasPrefix(n, "mistral"):
		return 32768
	case strings.HasPrefix(n, "gemma3"):
		return 8192
	case strings.HasPrefix(n, "nomic-embed"):
		return 2048
	}
	return 4096
}

func embeddingLengthForModel(name, family string) int {
	if isEmbeddingModel(name) {
		return embeddingDimsForModel(name)
	}
	return 4096
}
