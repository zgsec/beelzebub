package parser

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// fakeValidator is a test ServiceValidator that always reports one warning,
// used to prove the registry + Validate driver actually invoke registered
// validators.
type fakeValidator struct{}

func (fakeValidator) Name() string { return "fake" }
func (fakeValidator) Validate(config BeelzebubServiceConfiguration) []ValidationIssue {
	return []ValidationIssue{{Level: LevelWarning, Message: "fake ran"}}
}

func allIssues(r ValidateResult) []ValidationIssue {
	var out []ValidationIssue
	for _, res := range r.Results {
		out = append(out, res.Issues...)
	}
	return out
}

func hasIssueContaining(issues []ValidationIssue, level, substr string) bool {
	for _, i := range issues {
		if i.Level == level && strings.Contains(i.Message, substr) {
			return true
		}
	}
	return false
}

func TestValidate_InvalidProtocolIsError(t *testing.T) {
	res := Validate([]BeelzebubServiceConfiguration{{Protocol: "bogus", Address: ":9999"}}, nil)
	assert.True(t, hasIssueContaining(allIssues(res), LevelError, `invalid protocol "bogus"`))
}

func TestValidate_OllamaProtocolIsValid(t *testing.T) {
	// ollama is a fork-only protocol; the validator must accept it, not flag it.
	res := Validate([]BeelzebubServiceConfiguration{{Protocol: "ollama", Address: ":11434"}}, nil)
	assert.False(t, hasIssueContaining(allIssues(res), LevelError, "invalid protocol"))
}

func TestValidate_RegisteredValidatorRuns(t *testing.T) {
	ResetServiceValidators()
	defer ResetServiceValidators()
	RegisterServiceValidator(fakeValidator{})

	res := Validate([]BeelzebubServiceConfiguration{{Protocol: "http", Address: ":8080"}}, nil)
	assert.True(t, hasIssueContaining(allIssues(res), LevelWarning, "fake ran"))
}

func TestValidateCore_RabbitMQEnabledWithoutURI(t *testing.T) {
	cfg := &BeelzebubCoreConfigurations{}
	cfg.Core.Tracings.RabbitMQ.Enabled = true

	res := ValidateCore(cfg, "core.yaml")
	assert.True(t, hasIssueContaining(allIssues(res), LevelError, "rabbitMQ is enabled but URI is empty"))
}
