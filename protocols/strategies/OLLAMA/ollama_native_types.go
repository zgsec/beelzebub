package OLLAMA

// Native /api/* response types. These are DELIBERATE structs (not
// map[string]interface{}) for the same reason the OpenAI /v1/* types are:
// Go marshals a map with keys sorted ALPHABETICALLY, but real Ollama (Go
// structs) emits a FIXED field order. A map-based response is a byte-level
// Censys/Shodan banner signature on every multi-key endpoint. Field order
// here mirrors real Ollama api/types.go, captured byte-exact in the 0.31.1
// oracle (tools/oracle-diff/ollama-0.31.1/fixtures).

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
