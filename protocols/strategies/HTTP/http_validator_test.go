package HTTP

import (
	"strings"
	"testing"

	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/stretchr/testify/assert"
)

func httpValHas(issues []parser.ValidationIssue, level, substr string) bool {
	for _, i := range issues {
		if i.Level == level && strings.Contains(i.Message, substr) {
			return true
		}
	}
	return false
}

func TestHTTPValidator_WarnsOnCommandsWithoutFallback(t *testing.T) {
	cfg := parser.BeelzebubServiceConfiguration{
		Protocol: "http",
		Commands: []parser.Command{{RegexStr: ".*", Handler: "hi"}},
	}
	assert.True(t, httpValHas((&HTTPValidator{}).Validate(cfg), parser.LevelWarning, "no fallbackCommand"))
}

func TestHTTPValidator_MismatchedTLSIsError(t *testing.T) {
	cfg := parser.BeelzebubServiceConfiguration{Protocol: "http", TLSCertPath: "/x/cert.pem"}
	assert.True(t, httpValHas((&HTTPValidator{}).Validate(cfg), parser.LevelError, "both tlsCertPath and tlsKeyPath"))
}

func TestHTTPValidator_IgnoresNonHTTP(t *testing.T) {
	assert.Nil(t, (&HTTPValidator{}).Validate(parser.BeelzebubServiceConfiguration{Protocol: "tcp"}))
}
