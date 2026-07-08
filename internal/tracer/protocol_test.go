package tracer

import "testing"

func TestProtocolFromString(t *testing.T) {
	for s, want := range map[string]Protocol{
		"http": HTTP, "ssh": SSH, "tcp": TCP, "mcp": MCP, "telnet": TELNET,
	} {
		got, ok := ProtocolFromString(s)
		if !ok || got != want {
			t.Errorf("ProtocolFromString(%q) = %v, %v; want %v, true", s, got, ok, want)
		}
	}
	for _, s := range []string{"ollama", "bogus", "HTTP", ""} {
		if _, ok := ProtocolFromString(s); ok {
			t.Errorf("ProtocolFromString(%q) should report ok=false", s)
		}
	}
}
