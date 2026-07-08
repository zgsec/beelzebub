package SSH

import (
	"strings"
	"testing"

	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/stretchr/testify/assert"
)

func sshValHas(issues []parser.ValidationIssue, level, substr string) bool {
	for _, i := range issues {
		if i.Level == level && strings.Contains(i.Message, substr) {
			return true
		}
	}
	return false
}

func TestSSHValidator_EmptyPasswordRegexIsError(t *testing.T) {
	cfg := parser.BeelzebubServiceConfiguration{Protocol: "ssh"}
	assert.True(t, sshValHas((&SSHValidator{}).Validate(cfg), parser.LevelError, "passwordRegex is required"))
}

func TestSSHValidator_IgnoresOtherProtocol(t *testing.T) {
	assert.Nil(t, (&SSHValidator{}).Validate(parser.BeelzebubServiceConfiguration{Protocol: "http"}))
}

func TestSSHValidator_RegisteredViaInit(t *testing.T) {
	found := false
	for _, v := range parser.GetServiceValidators() {
		if v.Name() == "ssh" {
			found = true
		}
	}
	assert.True(t, found)
}
