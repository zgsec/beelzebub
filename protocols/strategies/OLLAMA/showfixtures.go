package OLLAMA

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/mariocandela/beelzebub/v3/parser"
)

// Capture-grounded /api/show payloads. Each file is the EXACT wire bytes of a
// real /api/show response captured from a genuine Ollama instance (the lab
// Jetson oracle) for the exact model the lure advertises. The engine serves
// these so model_info + tensors + template + license + parameters are
// byte-faithful to the genuine GGUF instead of fabricated (the historical
// failure mode that outed /api/show). The complex nested structures pass
// through verbatim (json.RawMessage); only the per-host modified_at is
// regenerated and a custom fine-tune's SYSTEM directive (where a credential
// canary naturally lives) is injected from config.
//
//go:embed showdata/*.json
var showDataFS embed.FS

// showFixtureHeaderRe matches the "# FROM <model>" header line in a generated
// Modelfile so it can be rewritten to the advertised model name (a fixture
// captured under one tag is reused for a coherently-named advertised model).
var showFixtureHeaderRe = regexp.MustCompile(`(?m)^# FROM .*$`)

// showResponse mirrors real Ollama's /api/show response type EXACTLY: field
// declaration order == wire key order (license, modelfile, parameters, template,
// [system], details, model_info, tensors, capabilities, modified_at), and the
// nested structures are preserved as raw bytes so numeric formatting / key order
// inside model_info and tensors is byte-identical to the genuine GGUF. System is
// omitempty: absent for a stock model, present for a fine-tune (matches real
// Ollama). Marshaling this struct with encoding/json reproduces the real wire
// bytes (same library, same HTML escaping, same field order).
type showResponse struct {
	License      string          `json:"license"`
	Modelfile    string          `json:"modelfile"`
	Parameters   string          `json:"parameters"`
	Template     string          `json:"template"`
	System       string          `json:"system,omitempty"`
	Details      json.RawMessage `json:"details"`
	ModelInfo    json.RawMessage `json:"model_info"`
	Tensors      json.RawMessage `json:"tensors"`
	Capabilities json.RawMessage `json:"capabilities"`
	ModifiedAt   string          `json:"modified_at"`
}

type showFixtureStore struct {
	bySlug map[string]showResponse
}

func loadShowFixtures() (*showFixtureStore, error) {
	entries, err := showDataFS.ReadDir("showdata")
	if err != nil {
		return nil, err
	}
	store := &showFixtureStore{bySlug: make(map[string]showResponse)}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := showDataFS.ReadFile("showdata/" + e.Name())
		if err != nil {
			return nil, err
		}
		var resp showResponse
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, fmt.Errorf("showdata/%s: %w", e.Name(), err)
		}
		store.bySlug[strings.TrimSuffix(e.Name(), ".json")] = resp
	}
	return store, nil
}

// slugForModel derives a fixture slug from a model name when none is configured.
// ':' and '/' are not valid in embedded filenames; normalize them to '_'.
func slugForModel(name string) string {
	return strings.NewReplacer(":", "_", "/", "_").Replace(name)
}

// showResponseFor builds the /api/show response for an advertised model from its
// captured fixture: regenerates modified_at, rewrites the Modelfile header to the
// advertised name, and — for a custom fine-tune (m.System set) — injects the
// SYSTEM directive into the Modelfile, sets the top-level system field, and
// surfaces details.parent_model (exactly as real Ollama does for a model built
// FROM a base; real Ollama hides parent_model on /api/tags but shows it here).
// Returns the marshaled JSON bytes, or nil if no fixture backs the model.
func (s *showFixtureStore) showResponseFor(m parser.OllamaModel, modelName, modifiedAt string) []byte {
	slug := m.ShowFixture
	if slug == "" {
		slug = slugForModel(modelName)
	}
	base, ok := s.bySlug[slug]
	if !ok {
		return nil
	}
	resp := base // value copy; RawMessage fields still share backing arrays until reassigned

	if modifiedAt != "" {
		resp.ModifiedAt = modifiedAt
	}

	// Rewrite the "# FROM <captured-tag>" comment to the advertised model name.
	resp.Modelfile = showFixtureHeaderRe.ReplaceAllString(resp.Modelfile, "# FROM "+modelName)

	if m.System != "" {
		// A fine-tune's SYSTEM directive sits between the TEMPLATE block and the
		// PARAMETER lines in the generated Modelfile — unquoted, on its own line
		// (oracle-confirmed shape). Insert it before the first PARAMETER line.
		sysLine := "SYSTEM " + m.System + "\n"
		if idx := strings.Index(resp.Modelfile, "\nPARAMETER "); idx >= 0 {
			resp.Modelfile = resp.Modelfile[:idx+1] + sysLine + resp.Modelfile[idx+1:]
		} else {
			resp.Modelfile = strings.TrimRight(resp.Modelfile, "\n") + "\n" + sysLine
		}

		// Top-level system field is populated only for a model with a SYSTEM
		// directive (absent entirely for a stock model — handled by omitempty).
		resp.System = m.System

		// details.parent_model is set on /api/show (but NOT /api/tags) for a model
		// built FROM a base. Patch the preserved-raw details without disturbing the
		// rest of its byte layout. Copy first so the shared fixture is untouched.
		if m.ParentModel != "" {
			det := make([]byte, len(base.Details))
			copy(det, base.Details)
			det = bytes.Replace(det, []byte(`"parent_model":""`), []byte(`"parent_model":"`+m.ParentModel+`"`), 1)
			resp.Details = det
		}
	}

	out, err := json.Marshal(resp)
	if err != nil {
		return nil
	}
	return out
}
