package responsesubs

import (
	"encoding/json"
	"testing"
)

// The exact LiteLLM /mcp-rest/test/connection allowlist-422 template authored in
// personas/crestfield-data-systems/lures/mcp-8000.yaml (single quotes here are the
// rendered form; YAML doubles them in source). `command`/`args` use ${request.json.*}
// (quoted JSON tokens in value positions); the msg uses ${request.json_str.command}
// (bare, JSON-escaped) so an arbitrary command echoes byte-for-byte.
const allowlist422Tmpl = `{"detail":[{"type":"value_error","loc":["body"],"msg":"Value error, Command '${request.json_str.command}' is not in the allowed commands list for stdio transport. Allowed commands: ['deno', 'docker', 'node', 'npx', 'python', 'python3', 'uvx']","input":{"transport":${request.json.transport},"command":${request.json.command},"args":${request.json.args}},"ctx":{"error":{}}}]}`

// TestJSONStr_FullLiteLLM422_ArbitraryCommand proves the GENERIC path is byte-identical
// to the real product for a command that is NOT in any hardcoded set (tcpdump), which
// is the whole point of bare-inject over per-command handlers.
func TestJSONStr_FullLiteLLM422_ArbitraryCommand(t *testing.T) {
	reqBody := []byte(`{"transport":"stdio","command":"tcpdump","args":["-i","eth0"]}`)
	// Captured ground truth shape (CVE-2026-42271), command substituted:
	want := `{"detail":[{"type":"value_error","loc":["body"],"msg":"Value error, Command 'tcpdump' is not in the allowed commands list for stdio transport. Allowed commands: ['deno', 'docker', 'node', 'npx', 'python', 'python3', 'uvx']","input":{"transport":"stdio","command":"tcpdump","args":["-i","eth0"]},"ctx":{"error":{}}}]}`
	got, _ := Apply(allowlist422Tmpl, nil, nil, reqBody)
	if got != want {
		t.Errorf("not byte-identical to real LiteLLM:\n got=%s\nwant=%s", got, want)
	}
	if !json.Valid([]byte(got)) {
		t.Errorf("rendered response is not valid JSON: %s", got)
	}
}

// TestJSONStr_FullPathCommand — /bin/sh echoes verbatim (captured: Command '/bin/sh').
func TestJSONStr_FullPathCommand(t *testing.T) {
	reqBody := []byte(`{"transport":"stdio","command":"/bin/sh","args":["-c","x"]}`)
	got, _ := Apply(allowlist422Tmpl, nil, nil, reqBody)
	if !contains(got, `Command '/bin/sh' is not in`) {
		t.Errorf("full-path command not echoed verbatim: %s", got)
	}
	if !json.Valid([]byte(got)) {
		t.Errorf("invalid JSON: %s", got)
	}
}

// TestJSONStr_InjectionSafe — a command carrying a double-quote / backslash must be
// JSON-escaped so it cannot break out of the enclosing msg string.
func TestJSONStr_InjectionSafe(t *testing.T) {
	reqBody := []byte(`{"command":"ev\"il\\x"}`)
	got, _ := Apply(`{"msg":"Command '${request.json_str.command}'"}`, nil, nil, reqBody)
	if !json.Valid([]byte(got)) {
		t.Fatalf("escaping broke JSON: %s", got)
	}
	var v struct{ Msg string }
	if err := json.Unmarshal([]byte(got), &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v.Msg != `Command 'ev"il\x'` {
		t.Errorf("decoded value wrong: %q", v.Msg)
	}
}

// TestJSONStr_MissingAndNonString — missing key and non-string (array) → "".
func TestJSONStr_MissingAndNonString(t *testing.T) {
	reqBody := []byte(`{"args":["hi"]}`) // command missing; args is non-string
	got, _ := Apply(`{"a":"${request.json_str.command}","b":"${request.json_str.args}"}`, nil, nil, reqBody)
	want := `{"a":"","b":""}`
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

// TestJSONStr_NoCollisionWithJSON — ${request.json.*} (quoted) and ${request.json_str.*}
// (bare) coexist in one template without cross-matching.
func TestJSONStr_NoCollisionWithJSON(t *testing.T) {
	reqBody := []byte(`{"command":"echo"}`)
	got, _ := Apply(`{"quoted":${request.json.command},"bare":"x${request.json_str.command}x"}`, nil, nil, reqBody)
	want := `{"quoted":"echo","bare":"xechox"}`
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

// TestJSONStr_NoBodyIsSafe — nil request body resolves placeholders to "" (no panic).
func TestJSONStr_NoBodyIsSafe(t *testing.T) {
	got, _ := Apply(`{"a":"${request.json_str.command}"}`, nil, nil, nil)
	if got != `{"a":""}` {
		t.Errorf("nil body: got %q", got)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
