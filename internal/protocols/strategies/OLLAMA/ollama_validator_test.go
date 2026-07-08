package OLLAMA

import (
	"strings"
	"testing"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/stretchr/testify/assert"
)

func ollamaValHas(issues []parser.ValidationIssue, level, substr string) bool {
	for _, i := range issues {
		if i.Level == level && strings.Contains(i.Message, substr) {
			return true
		}
	}
	return false
}

func TestOllamaValidator_WarnsOnNoModels(t *testing.T) {
	cfg := parser.BeelzebubServiceConfiguration{Protocol: "ollama"}
	assert.True(t, ollamaValHas((&OllamaValidator{}).Validate(cfg), parser.LevelWarning, "no models defined"))
}

func TestOllamaValidator_WarnsOnModelWithoutName(t *testing.T) {
	cfg := parser.BeelzebubServiceConfiguration{
		Protocol:     "ollama",
		OllamaConfig: parser.OllamaConfig{Models: []parser.OllamaModel{{Name: ""}}},
	}
	assert.True(t, ollamaValHas((&OllamaValidator{}).Validate(cfg), parser.LevelWarning, "has no name defined"))
}

func TestOllamaValidator_CleanConfigHasNoIssues(t *testing.T) {
	cfg := parser.BeelzebubServiceConfiguration{
		Protocol:     "ollama",
		OllamaConfig: parser.OllamaConfig{Models: []parser.OllamaModel{{Name: "llama3.1:8b"}}},
	}
	assert.Empty(t, (&OllamaValidator{}).Validate(cfg))
}

func TestOllamaValidator_IgnoresOtherProtocol(t *testing.T) {
	assert.Nil(t, (&OllamaValidator{}).Validate(parser.BeelzebubServiceConfiguration{Protocol: "http"}))
}

func TestOllamaValidator_RegisteredViaInit(t *testing.T) {
	found := false
	for _, v := range parser.GetServiceValidators() {
		if v.Name() == "ollama" {
			found = true
		}
	}
	assert.True(t, found)
}
