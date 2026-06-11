package HTTP

import (
	"testing"

	"github.com/mariocandela/beelzebub/v3/parser"
)

func firstMatch(cmds []parser.Command, uri, method, body string) (parser.Command, bool) {
	for _, c := range cmds {
		if commandMatches(c, uri, method, body) {
			return c, true
		}
	}
	return parser.Command{}, false
}

// TestMCPMethodRouting locks the fix for the MCP echo-initialize tell: a single /mcp
// endpoint must route by the in-body JSON-RPC "method" (bodyRegex), not return the
// initialize handshake for every method. Specific methods fire before the fallback.
func TestMCPMethodRouting(t *testing.T) {
	cfg := parser.BeelzebubServiceConfiguration{Commands: []parser.Command{
		{RegexStr: "^/mcp$", BodyRegexStr: `"method"\s*:\s*"tools/list"`, Handler: "TOOLS"},
		{RegexStr: "^/mcp$", BodyRegexStr: `"method"\s*:\s*"notifications/`, Handler: "NOTIF", StatusCode: 202},
		{RegexStr: "^/mcp$", Handler: "INIT"}, // initialize + fallback
	}}
	if err := cfg.CompileCommandRegex(); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ body, want string }{
		{`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`, "TOOLS"},
		{`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, "INIT"},
		{`{"jsonrpc":"2.0","method":"notifications/initialized"}`, "NOTIF"},
		{`{"jsonrpc":"2.0","id":3,"method":"resources/list"}`, "INIT"}, // unknown -> handshake fallback (still routed, not 404)
	}
	for _, c := range cases {
		got, ok := firstMatch(cfg.Commands, "/mcp", "POST", c.body)
		if !ok || got.Handler != c.want {
			t.Errorf("body %q -> %q (ok=%v), want %q", c.body, got.Handler, ok, c.want)
		}
	}
}

// TestCommandMatchesLegacyBodyAgnostic guarantees backward compatibility: a command
// with no BodyRegex matches any request body (existing configs are unaffected).
func TestCommandMatchesLegacyBodyAgnostic(t *testing.T) {
	cfg := parser.BeelzebubServiceConfiguration{Commands: []parser.Command{{RegexStr: "^/x$", Handler: "X"}}}
	if err := cfg.CompileCommandRegex(); err != nil {
		t.Fatal(err)
	}
	if !commandMatches(cfg.Commands[0], "/x", "GET", "any body at all") {
		t.Fatalf("legacy no-bodyRegex command should match any body")
	}
	if commandMatches(cfg.Commands[0], "/y", "GET", "") {
		t.Fatalf("URI regex must still gate")
	}
}
