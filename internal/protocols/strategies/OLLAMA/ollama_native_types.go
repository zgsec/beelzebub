package OLLAMA

import "encoding/json"

// Native /api/* response types. These are DELIBERATE structs (not
// map[string]interface{}) for the same reason the OpenAI /v1/* types are:
// Go marshals a map with keys sorted ALPHABETICALLY, but real Ollama (Go
// structs) emits a FIXED field order. A map-based response is a byte-level
// Censys/Shodan banner signature on every multi-key endpoint. Field order
// here mirrors real Ollama api/types.go, captured byte-exact in the 0.31.1
// oracle (captured offline from a real Ollama 0.31.1 instance).

type ollamaGenerateChunk struct {
	Model     string `json:"model"`
	CreatedAt string `json:"created_at"`
	Response  string `json:"response"`
	Done      bool   `json:"done"`
}

type ollamaGenerateDone struct {
	Model              string `json:"model"`
	CreatedAt          string `json:"created_at"`
	Response           string `json:"response"`
	Done               bool   `json:"done"`
	DoneReason         string `json:"done_reason"`
	Context            []int  `json:"context"`
	TotalDuration      int64  `json:"total_duration"`
	LoadDuration       int64  `json:"load_duration"`
	PromptEvalCount    int    `json:"prompt_eval_count"`
	PromptEvalDuration int64  `json:"prompt_eval_duration"`
	EvalCount          int    `json:"eval_count"`
	EvalDuration       int64  `json:"eval_duration"`
}

type ollamaChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaChatChunk struct {
	Model     string            `json:"model"`
	CreatedAt string            `json:"created_at"`
	Message   ollamaChatMessage `json:"message"`
	Done      bool              `json:"done"`
}

type ollamaChatDone struct {
	Model              string            `json:"model"`
	CreatedAt          string            `json:"created_at"`
	Message            ollamaChatMessage `json:"message"`
	Done               bool              `json:"done"`
	DoneReason         string            `json:"done_reason"`
	TotalDuration      int64             `json:"total_duration"`
	LoadDuration       int64             `json:"load_duration"`
	PromptEvalCount    int               `json:"prompt_eval_count"`
	PromptEvalDuration int64             `json:"prompt_eval_duration"`
	EvalCount          int               `json:"eval_count"`
	EvalDuration       int64             `json:"eval_duration"`
}

// ollamaModelDetails is the /api/ps details block (6 keys). NOTE: /api/tags'
// details carries two MORE keys in 0.31.1 (context_length, embedding_length)
// and each tags model also has a capabilities array — a separate completeness
// gap tracked with /api/show, not this ordering fix.
type ollamaModelDetails struct {
	ParentModel       string   `json:"parent_model"`
	Format            string   `json:"format"`
	Family            string   `json:"family"`
	Families          []string `json:"families"`
	ParameterSize     string   `json:"parameter_size"`
	QuantizationLevel string   `json:"quantization_level"`
}

type ollamaPsModel struct {
	Name          string             `json:"name"`
	Model         string             `json:"model"`
	Size          int64              `json:"size"`
	Digest        string             `json:"digest"`
	Details       ollamaModelDetails `json:"details"`
	ExpiresAt     string             `json:"expires_at"`
	SizeVRAM      int64              `json:"size_vram"`
	ContextLength int                `json:"context_length"`
}

type ollamaPsResponse struct {
	Models []ollamaPsModel `json:"models"`
}

type ollamaEmbedResponse struct {
	Model           string      `json:"model"`
	Embeddings      [][]float32 `json:"embeddings"`
	TotalDuration   int64       `json:"total_duration"`
	LoadDuration    int64       `json:"load_duration"`
	PromptEvalCount int         `json:"prompt_eval_count"`
}

// ollamaPullProgress is one /api/pull NDJSON stage. Status-only stages emit
// just {"status":...}; layer stages add digest/total/completed (omitempty).
type ollamaPullProgress struct {
	Status    string `json:"status"`
	Digest    string `json:"digest,omitempty"`
	Total     int64  `json:"total,omitempty"`
	Completed int64  `json:"completed,omitempty"`
}

// ollamaTagsDetails is the /api/tags details block. Unlike /api/ps (6 keys) it
// carries two MORE keys in 0.31.1: context_length + embedding_length.
type ollamaTagsDetails struct {
	ParentModel       string   `json:"parent_model"`
	Format            string   `json:"format"`
	Family            string   `json:"family"`
	Families          []string `json:"families"`
	ParameterSize     string   `json:"parameter_size"`
	QuantizationLevel string   `json:"quantization_level"`
	ContextLength     int      `json:"context_length"`
	EmbeddingLength   int      `json:"embedding_length"`
}

type ollamaTagsModel struct {
	Name         string            `json:"name"`
	Model        string            `json:"model"`
	ModifiedAt   string            `json:"modified_at"`
	Size         int64             `json:"size"`
	Digest       string            `json:"digest"`
	Details      ollamaTagsDetails `json:"details"`
	Capabilities []string          `json:"capabilities"`
}

type ollamaTagsResponse struct {
	Models []ollamaTagsModel `json:"models"`
}

// ollamaShowResponse is the FALLBACK /api/show shape (used only when a model
// has no baked GGUF metadata — an authoring omission; advertised models should
// always have a modelmeta/*.json). model_info + tensors are json.RawMessage so
// the baked path can pass GGUF bytes through untouched and the fallback can emit
// a derived-but-ordered object. Field order mirrors real Ollama.
type ollamaShowResponse struct {
	License      string             `json:"license"`
	Modelfile    string             `json:"modelfile"`
	Parameters   string             `json:"parameters"`
	Template     string             `json:"template"`
	Details      ollamaModelDetails `json:"details"`
	ModelInfo    json.RawMessage    `json:"model_info"`
	Tensors      json.RawMessage    `json:"tensors"`
	Capabilities []string           `json:"capabilities"`
	ModifiedAt   string             `json:"modified_at"`
}

// ollamaFallbackModelInfo is the minimal ordered model_info for the no-baked-
// metadata fallback (general.* keys only; arch-specific keys need the GGUF).
type ollamaFallbackModelInfo struct {
	Architecture   string `json:"general.architecture"`
	FileType       int    `json:"general.file_type"`
	ParameterCount int64  `json:"general.parameter_count"`
	QuantVersion   int    `json:"general.quantization_version"`
}
