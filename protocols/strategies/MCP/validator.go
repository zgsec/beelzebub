package MCP

import (
	"fmt"

	"github.com/mariocandela/beelzebub/v3/parser"
)

// MCPValidator checks MCP service configurations for common authoring mistakes.
type MCPValidator struct{}

func (v *MCPValidator) Name() string { return "mcp" }

func (v *MCPValidator) Validate(config parser.BeelzebubServiceConfiguration) []parser.ValidationIssue {
	if config.Protocol != "mcp" {
		return nil
	}

	var issues []parser.ValidationIssue

	for _, tool := range config.Tools {
		if tool.Name == "" {
			issues = append(issues, parser.ValidationIssue{
				Level:   parser.LevelWarning,
				Message: "tool has no name defined",
			})
		}
		if len(tool.Params) == 0 {
			issues = append(issues, parser.ValidationIssue{
				Level:   parser.LevelWarning,
				Message: fmt.Sprintf("tool %q has no parameters defined", tool.Name),
			})
		}
	}

	if len(config.Tools) == 0 {
		issues = append(issues, parser.ValidationIssue{
			Level:   parser.LevelWarning,
			Message: "MCP service has no tools defined",
		})
	}

	return issues
}

func init() {
	parser.RegisterServiceValidator(&MCPValidator{})
}
