package TCP

import (
	"strings"
	"testing"

	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/stretchr/testify/assert"
)

func tcpValHas(issues []parser.ValidationIssue, level, substr string) bool {
	for _, i := range issues {
		if i.Level == level && strings.Contains(i.Message, substr) {
			return true
		}
	}
	return false
}

func TestTCPValidator_MismatchedTLSIsError(t *testing.T) {
	cfg := parser.BeelzebubServiceConfiguration{Protocol: "tcp", TLSKeyPath: "/x/key.pem"}
	assert.True(t, tcpValHas((&TCPValidator{}).Validate(cfg), parser.LevelError, "both tlsCertPath and tlsKeyPath"))
}

func TestTCPValidator_IgnoresOtherProtocol(t *testing.T) {
	assert.Nil(t, (&TCPValidator{}).Validate(parser.BeelzebubServiceConfiguration{Protocol: "http"}))
}

func TestTCPValidator_RegisteredViaInit(t *testing.T) {
	found := false
	for _, v := range parser.GetServiceValidators() {
		if v.Name() == "tcp" {
			found = true
		}
	}
	assert.True(t, found)
}
