package OLLAMA

import (
	"fmt"

	"github.com/mariocandela/beelzebub/v3/parser"
)

// OllamaValidator checks Ollama honeypot configs. This is a fork-only validator —
// upstream has no Ollama strategy. The service answers /api/tags from
// OllamaConfig.Models and keys per-model digests by name, so an empty model list
// or a nameless model produces a hollow, tell-tale Ollama surface.
type OllamaValidator struct{}

func (v *OllamaValidator) Name() string { return "ollama" }

func (v *OllamaValidator) Validate(config parser.BeelzebubServiceConfiguration) []parser.ValidationIssue {
	if config.Protocol != "ollama" {
		return nil
	}

	var issues []parser.ValidationIssue

	for i, m := range config.OllamaConfig.Models {
		if m.Name == "" {
			issues = append(issues, parser.ValidationIssue{
				Level:   parser.LevelWarning,
				Message: fmt.Sprintf("ollama model[%d] has no name defined", i),
			})
		}
	}

	if len(config.OllamaConfig.Models) == 0 {
		issues = append(issues, parser.ValidationIssue{
			Level:   parser.LevelWarning,
			Message: "ollama service has no models defined — /api/tags will be empty",
		})
	}

	return issues
}

func init() {
	parser.RegisterServiceValidator(&OllamaValidator{})
}
