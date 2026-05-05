package shellemulator

import (
	"os"
	"testing"
	"time"

	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/stretchr/testify/assert"
)

// --- Helpers ---

func newTestEmulator(cfg parser.ShellEmulator) (*Emulator, *Session) {
	e := NewEmulator(cfg)
	s := &Session{
		User:        "root",
		CWD:         "/root",
		PIDOffset:   42,
		ShellPID:    3100,
		LoginTime:   time.Now(),
		FileOverlay: make(map[string]string),
		DirOverlay:  make(map[string][]string),
		Deleted:     make(map[string]bool),
	}
	return e, s
}

func defaultEmulator() (*Emulator, *Session) {
	return newTestEmulator(parser.ShellEmulator{Enabled: true})
}

// === Stub Dispatcher Tests ===
// Phase D.2: the handler matrix has been deleted. Every command now returns
// "bash: <cmd>: command not found" until D.3 wires the LLM bridge.

func TestEmptyCommand(t *testing.T) {
	e, s := defaultEmulator()
	out, handled := e.Execute("", s)
	assert.True(t, handled)
	assert.Equal(t, "", out)
}

func TestWhitespaceCommand(t *testing.T) {
	e, s := defaultEmulator()
	out, handled := e.Execute("   ", s)
	assert.True(t, handled)
	assert.Equal(t, "", out)
}

func TestAnyCommandReturnsNotFound(t *testing.T) {
	e, s := defaultEmulator()
	out, handled := e.Execute("ls /root", s)
	assert.True(t, handled, "stub should handle all commands (not fall through)")
	assert.Contains(t, out, "command not found")
	assert.Contains(t, out, "ls")
}

func TestCmdCountIncrements(t *testing.T) {
	e, s := defaultEmulator()
	assert.Equal(t, 0, s.CmdCount)
	e.Execute("whoami", s)
	assert.Equal(t, 1, s.CmdCount)
	e.Execute("ls", s)
	assert.Equal(t, 2, s.CmdCount)
}

func TestFirstWordUsedInNotFound(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("docker ps --format table", s)
	assert.Contains(t, out, "bash: docker: command not found")
}

// === BuildPromptContext Tests ===
// BuildPromptContext is the D.3 entry point — must survive D.2 intact.

func TestBuildPromptContextNotEmpty(t *testing.T) {
	e, _ := defaultEmulator()
	ctx := e.BuildPromptContext()
	assert.Contains(t, ctx, "SYSTEM:")
	assert.Contains(t, ctx, "PROCESSES:")
	assert.Contains(t, ctx, "LISTENERS:")
	assert.Contains(t, ctx, "ENV:")
	assert.Contains(t, ctx, "FILES:")
}

func TestBuildPromptContextNoPlaceholders(t *testing.T) {
	e, _ := defaultEmulator()
	ctx := e.BuildPromptContext()
	assert.NotContains(t, ctx, "{{")
	assert.NotContains(t, ctx, "}}")
	assert.Contains(t, ctx, "prod-web-01")
}

// === Token Resolution Tests ===

func TestResolveTokensMergesDefaults(t *testing.T) {
	tokens := resolveTokens(nil)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", tokens["aws_key"])
}

func TestResolveTokensOverridesDefaults(t *testing.T) {
	tokens := resolveTokens(map[string]string{"aws_key": "CUSTOM_KEY"})
	assert.Equal(t, "CUSTOM_KEY", tokens["aws_key"])
	// Other defaults still present
	assert.NotEmpty(t, tokens["api_key"])
}

func TestSubstituteTokens(t *testing.T) {
	tokens := map[string]string{"aws_key": "TESTKEY", "db_password": "TESTPW"}
	result := substituteTokens("key={{AWS_KEY}} pw={{DB_PASSWORD}} other={{UNKNOWN}}", tokens)
	assert.Contains(t, result, "key=TESTKEY")
	assert.Contains(t, result, "pw=TESTPW")
	assert.Contains(t, result, "other={{UNKNOWN}}", "unresolved placeholders remain")
}

func TestResolveTokensExpandsEnv(t *testing.T) {
	os.Setenv("TEST_RESOLVE_VAR", "resolved_value")
	defer os.Unsetenv("TEST_RESOLVE_VAR")

	tokens := resolveTokens(map[string]string{"aws_key": "${TEST_RESOLVE_VAR}"})
	assert.Equal(t, "resolved_value", tokens["aws_key"])
}
