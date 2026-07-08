package MCP

import (
	"testing"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/stretchr/testify/assert"
)

func containsMsg(issues []parser.ValidationIssue, level, msg string) bool {
	for _, i := range issues {
		if i.Level == level && i.Message == msg {
			return true
		}
	}
	return false
}

func TestMCPValidator_WarnsOnToolWithoutName(t *testing.T) {
	v := &MCPValidator{}
	cfg := parser.BeelzebubServiceConfiguration{
		Protocol: "mcp",
		Tools:    []parser.Tool{{Name: "", Params: []parser.Param{{Name: "x"}}}},
	}
	assert.True(t, containsMsg(v.Validate(cfg), parser.LevelWarning, "tool has no name defined"))
}

func TestMCPValidator_WarnsOnToolWithoutParams(t *testing.T) {
	v := &MCPValidator{}
	cfg := parser.BeelzebubServiceConfiguration{
		Protocol: "mcp",
		Tools:    []parser.Tool{{Name: "list_users"}},
	}
	assert.True(t, containsMsg(v.Validate(cfg), parser.LevelWarning, `tool "list_users" has no parameters defined`))
}

func TestMCPValidator_WarnsOnNoTools(t *testing.T) {
	v := &MCPValidator{}
	assert.True(t, containsMsg(v.Validate(parser.BeelzebubServiceConfiguration{Protocol: "mcp"}),
		parser.LevelWarning, "MCP service has no tools defined"))
}

func TestMCPValidator_IgnoresNonMCPProtocol(t *testing.T) {
	v := &MCPValidator{}
	assert.Nil(t, v.Validate(parser.BeelzebubServiceConfiguration{Protocol: "http"}))
}

func TestMCPValidator_RegisteredViaInit(t *testing.T) {
	found := false
	for _, v := range parser.GetServiceValidators() {
		if v.Name() == "mcp" {
			found = true
		}
	}
	assert.True(t, found, "MCPValidator should self-register via init()")
}
