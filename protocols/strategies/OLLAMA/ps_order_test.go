package OLLAMA

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestPsRealShape locks /api/ps to real Ollama's wire shape: struct field order (real
// Ollama marshals a struct, not a map) and size_vram < size (the VRAM footprint is a
// fraction of the on-disk gguf, never exactly equal). Both were live tells.
func TestPsRealShape(t *testing.T) {
	const size int64 = 42520412811
	m := psModel{
		Name: "crestfield-support:latest", Model: "crestfield-support:latest",
		Size: size, Digest: "deadbeefcafe",
		Details: psDetails{Format: "gguf", Family: "llama", Families: []string{"llama"},
			ParameterSize: "70.6B", QuantizationLevel: "Q4_K_M"},
		ExpiresAt: "2026-06-11T00:00:00Z", SizeVRAM: vramBytes(size), ContextLength: 4096,
	}
	b, _ := json.Marshal(m)
	js := string(b)
	order := []string{`"name"`, `"model"`, `"size"`, `"digest"`, `"details"`, `"expires_at"`, `"size_vram"`, `"context_length"`}
	last := -1
	for _, k := range order {
		i := strings.Index(js, k)
		if i < 0 || i < last {
			t.Fatalf("key %s out of real struct order: %s", k, js)
		}
		last = i
	}
	if m.SizeVRAM >= m.Size {
		t.Fatalf("size_vram (%d) must be < size (%d)", m.SizeVRAM, m.Size)
	}
	// details sub-object must also be struct-ordered (parent_model first, not alphabetical)
	if i, j := strings.Index(js, `"parent_model"`), strings.Index(js, `"families"`); i < 0 || i > j {
		t.Fatalf("details keys not in real struct order: %s", js)
	}
}
