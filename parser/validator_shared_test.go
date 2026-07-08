package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateTLSConfig_MismatchedPathsIsError(t *testing.T) {
	issues := ValidateTLSConfig("/x/cert.pem", "", "svc.yaml")
	assert.True(t, hasIssueContaining(issues, LevelError, "both tlsCertPath and tlsKeyPath must be set"))
}

func TestValidateTLSConfig_BothEmptyIsClean(t *testing.T) {
	assert.Empty(t, ValidateTLSConfig("", "", "svc.yaml"))
}

func TestValidatePasswordRegex_EmptyIsError(t *testing.T) {
	issues := ValidatePasswordRegex("", "telnet", "svc.yaml")
	assert.True(t, hasIssueContaining(issues, LevelError, "passwordRegex is required for telnet protocol"))
}

func TestValidatePasswordRegex_InvalidRegexIsError(t *testing.T) {
	issues := ValidatePasswordRegex("[unclosed", "telnet", "svc.yaml")
	assert.True(t, hasIssueContaining(issues, LevelError, "passwordRegex is not a valid regex"))
}
