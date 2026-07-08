package TELNET

import (
	"strings"
	"testing"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/stretchr/testify/assert"
)

func telnetValHas(issues []parser.ValidationIssue, level, substr string) bool {
	for _, i := range issues {
		if i.Level == level && strings.Contains(i.Message, substr) {
			return true
		}
	}
	return false
}

func TestTELNETValidator_EmptyPasswordRegexIsError(t *testing.T) {
	cfg := parser.BeelzebubServiceConfiguration{Protocol: "telnet"}
	assert.True(t, telnetValHas((&TELNETValidator{}).Validate(cfg), parser.LevelError, "passwordRegex is required"))
}

func TestTELNETValidator_IgnoresOtherProtocol(t *testing.T) {
	assert.Nil(t, (&TELNETValidator{}).Validate(parser.BeelzebubServiceConfiguration{Protocol: "http"}))
}

func TestTELNETValidator_RegisteredViaInit(t *testing.T) {
	found := false
	for _, v := range parser.GetServiceValidators() {
		if v.Name() == "telnet" {
			found = true
		}
	}
	assert.True(t, found)
}
