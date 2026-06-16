package MCP

import (
	"encoding/json"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

func TestBuildInitEvent_PopulatesHandshakeFields(t *testing.T) {
	req := &mcp.InitializeRequest{}
	req.Params.ProtocolVersion = "2025-06-18"
	req.Params.ClientInfo = mcp.Implementation{Name: "cline", Version: "3.2.0"}
	req.Params.Capabilities = mcp.ClientCapabilities{}

	ev := buildInitEvent("203.0.113.7:51000", "MCP203.0.113.7", "sid-1", 1, req)

	if ev.MCPClientName != "cline" {
		t.Errorf("MCPClientName = %q, want cline", ev.MCPClientName)
	}
	if ev.MCPClientVersion != "3.2.0" {
		t.Errorf("MCPClientVersion = %q, want 3.2.0", ev.MCPClientVersion)
	}
	if ev.MCPProtocolVersion != "2025-06-18" {
		t.Errorf("MCPProtocolVersion = %q, want 2025-06-18", ev.MCPProtocolVersion)
	}
	if ev.SessionKey != "MCP203.0.113.7" {
		t.Errorf("SessionKey = %q, want MCP203.0.113.7", ev.SessionKey)
	}
	if ev.Sequence != 1 {
		t.Errorf("Sequence = %d, want 1", ev.Sequence)
	}
	if !json.Valid([]byte(ev.MCPCapabilities)) {
		t.Errorf("MCPCapabilities is not valid JSON: %q", ev.MCPCapabilities)
	}
}
