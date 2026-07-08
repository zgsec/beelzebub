package MCP

import (
	"strings"
	"testing"

	"github.com/mariocandela/beelzebub/v3/parser"
)

// requiredCanaryVars mirrors the env vars the MCP canary substitution needs.
var requiredCanaryVars = []string{
	"MCP_CANARY_AWS_KEY", "MCP_CANARY_AWS_SECRET", "MCP_CANARY_DB_PASS",
	"MCP_CANARY_DNS", "MCP_CANARY_WEB_URL", "MCP_CANARY_DD_KEY",
	"MCP_CANARY_VAULT_TOKEN",
}

// Regression guard for F1: a missing MCP_CANARY_* env var must make the MCP
// canary substitution return an ERROR (so Init can propagate it and the
// orchestrator can skip this one service) — it must NOT call log.Fatalf /
// os.Exit, which previously killed the entire sensor process at boot.
func TestSubstituteMCPCanaries_ReturnsErrorOnMissingCanaryEnv(t *testing.T) {
	for _, v := range requiredCanaryVars {
		t.Setenv(v, "canary-test-value")
	}
	t.Setenv("MCP_CANARY_AWS_KEY", "") // exactly one missing

	s := &MCPStrategy{}
	servConf := parser.BeelzebubServiceConfiguration{}

	err := s.substituteMCPCanaries(&servConf)
	if err == nil {
		t.Fatal("expected an error when a required MCP_CANARY_* env var is missing, got nil")
	}
	if !strings.Contains(err.Error(), "MCP_CANARY_AWS_KEY") {
		t.Fatalf("error should name the missing var MCP_CANARY_AWS_KEY, got: %v", err)
	}
}

// The happy path must NOT error when every required canary var is present.
func TestSubstituteMCPCanaries_OKWhenEnvPresent(t *testing.T) {
	for _, v := range requiredCanaryVars {
		t.Setenv(v, "canary-test-value")
	}

	s := &MCPStrategy{}
	servConf := parser.BeelzebubServiceConfiguration{}

	if err := s.substituteMCPCanaries(&servConf); err != nil {
		t.Fatalf("expected no error when all canary env vars are present, got: %v", err)
	}
}
