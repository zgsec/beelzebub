package MCP

import (
	"strings"
	"sync"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

func initRequest(name, version, title, protocol string) *mcp.InitializeRequest {
	req := &mcp.InitializeRequest{}
	req.Params.ClientInfo.Name = name
	req.Params.ClientInfo.Version = version
	req.Params.ClientInfo.Title = title
	req.Params.ProtocolVersion = protocol
	return req
}

func TestExtractMCPClientInfo_NilRequest(t *testing.T) {
	if got := extractMCPClientInfo(nil); got.present() {
		t.Fatalf("nil request must yield empty client info, got %+v", got)
	}
}

func TestExtractMCPClientInfo_Populated(t *testing.T) {
	req := initRequest("claude-code", "1.4.2", "Claude Code", "2025-06-18")
	got := extractMCPClientInfo(req)

	if got.Name != "claude-code" || got.Version != "1.4.2" ||
		got.Title != "Claude Code" || got.ProtocolVersion != "2025-06-18" {
		t.Fatalf("unexpected extraction: %+v", got)
	}
	if !got.present() {
		t.Fatalf("populated request must be present()")
	}
}

func TestExtractMCPClientInfo_EmptyCapabilitiesAreBlank(t *testing.T) {
	// A default/empty capabilities object marshals to "{}" and must be dropped
	// so it carries no misleading signal.
	got := extractMCPClientInfo(initRequest("x", "1", "", ""))
	if got.Capabilities != "" {
		t.Fatalf("empty capabilities must be blank, got %q", got.Capabilities)
	}
}

func TestExtractMCPClientInfo_NonEmptyCapabilities(t *testing.T) {
	req := initRequest("x", "1", "", "")
	req.Params.Capabilities.Experimental = map[string]any{"sampling": true}
	got := extractMCPClientInfo(req)
	if got.Capabilities == "" || !strings.Contains(got.Capabilities, "experimental") {
		t.Fatalf("expected serialized capabilities, got %q", got.Capabilities)
	}
}

func TestClientInfoStore_SetGetHas(t *testing.T) {
	s := &MCPStrategy{}

	if _, ok := s.getClientInfo("1.2.3.4"); ok {
		t.Fatalf("unknown IP must return ok=false")
	}
	if s.hasClientInfo("1.2.3.4") {
		t.Fatalf("unknown IP must not report hasClientInfo")
	}

	ci := mcpClientInfo{Name: "mcp-python", Version: "0.9.0", ProtocolVersion: "2025-06-18"}
	s.setClientInfo("1.2.3.4", ci)

	got, ok := s.getClientInfo("1.2.3.4")
	if !ok || got != ci {
		t.Fatalf("round-trip mismatch: ok=%v got=%+v want=%+v", ok, got, ci)
	}
	if !s.hasClientInfo("1.2.3.4") {
		t.Fatalf("stored IP must report hasClientInfo")
	}
}

func TestClientInfoStore_EmptyInfoIsNotPresent(t *testing.T) {
	// An empty handshake is recorded but must not count as a positive agent signal.
	s := &MCPStrategy{}
	s.setClientInfo("9.9.9.9", mcpClientInfo{})
	if s.hasClientInfo("9.9.9.9") {
		t.Fatalf("empty client info must not report hasClientInfo")
	}
}

func TestClientInfoStore_ConcurrentAccess(t *testing.T) {
	// Guards against a data race between the initialize hook (writer) and the
	// per-tool event path (reader). Run with -race to be meaningful.
	s := &MCPStrategy{}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(n int) { defer wg.Done(); s.setClientInfo("h", mcpClientInfo{Name: "c", Version: "v"}) }(i)
		go func() { defer wg.Done(); _, _ = s.getClientInfo("h") }()
	}
	wg.Wait()
	if got, ok := s.getClientInfo("h"); !ok || got.Name != "c" {
		t.Fatalf("post-concurrency state wrong: ok=%v got=%+v", ok, got)
	}
}
