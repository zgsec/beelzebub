package shellemulator

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// === Token Tests ===

func TestDefaultTokensRendered(t *testing.T) {
	e, s := defaultEmulator()
	out, ok := e.Execute("cat /root/.aws/credentials", s)
	require.True(t, ok)
	assert.Contains(t, out, "AKIAIOSFODNN7EXAMPLE", "default AWS key should be substituted")
	assert.Contains(t, out, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "default AWS secret should be substituted")
	assert.NotContains(t, out, "{{AWS_KEY}}", "placeholders must not remain")
	assert.NotContains(t, out, "{{AWS_SECRET}}")
}

func TestCustomCanaryTokensSubstitute(t *testing.T) {
	e, s := newTestEmulator(parser.ShellEmulator{
		Enabled: true,
		CanaryTokens: map[string]string{
			"aws_key":    "AKIACUSTOMTESTKEY123",
			"aws_secret": "CustomSecret/TestValue+123",
		},
	})
	out, _ := e.Execute("cat /root/.aws/credentials", s)
	assert.Contains(t, out, "AKIACUSTOMTESTKEY123")
	assert.Contains(t, out, "CustomSecret/TestValue+123")
}

func TestEnvVarTokenResolution(t *testing.T) {
	os.Setenv("TEST_CANARY_AWS_KEY", "AKIAENVRESOLVED999")
	defer os.Unsetenv("TEST_CANARY_AWS_KEY")

	e, s := newTestEmulator(parser.ShellEmulator{
		Enabled: true,
		CanaryTokens: map[string]string{
			"aws_key": "${TEST_CANARY_AWS_KEY}",
		},
	})
	out, _ := e.Execute("cat /root/.aws/credentials", s)
	assert.Contains(t, out, "AKIAENVRESOLVED999")
}

func TestTokenSubstitutionInEnvOutput(t *testing.T) {
	e, s := newTestEmulator(parser.ShellEmulator{
		Enabled: true,
		CanaryTokens: map[string]string{
			"db_password": "canary-db-pw-test",
		},
	})
	out, _ := e.Execute("cat /opt/app/.env", s)
	assert.Contains(t, out, "DB_PASSWORD=canary-db-pw-test")
	assert.NotContains(t, out, "{{DB_PASSWORD}}")
}

func TestDockerAuthTokenSubstitution(t *testing.T) {
	e, s := newTestEmulator(parser.ShellEmulator{
		Enabled: true,
		CanaryTokens: map[string]string{
			"docker_auth": "Y3VzdG9tOmRvY2tlci1hdXRo",
		},
	})
	out, _ := e.Execute("cat /root/.docker/config.json", s)
	assert.Contains(t, out, "Y3VzdG9tOmRvY2tlci1hdXRo")
}

func TestBuildPromptContextNoPlaceholders(t *testing.T) {
	e, _ := defaultEmulator()
	ctx := e.BuildPromptContext()
	assert.NotContains(t, ctx, "{{")
	assert.NotContains(t, ctx, "}}")
	assert.Contains(t, ctx, "prod-web-01")
}

func TestCrossProtocolBreadcrumbsInLures(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("cat /opt/app/.env", s)
	assert.Contains(t, out, "OLLAMA_HOST=http://localhost:11434", "Ollama breadcrumb must be present")
	assert.Contains(t, out, "MCP_ENDPOINT=http://localhost:8000/mcp", "MCP breadcrumb must be present")
}

func TestBashHistoryContainsMCPBreadcrumb(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("history", s)
	assert.Contains(t, out, "curl -X POST http://localhost:8000/mcp")
}

// === Consistency Tests ===

func TestHostnameConsistency(t *testing.T) {
	e, s := newTestEmulator(parser.ShellEmulator{
		Enabled:  true,
		Hostname: "test-node-42",
	})

	hostname, _ := e.Execute("hostname", s)
	uname, _ := e.Execute("uname -n", s)
	etcHostname, _ := e.Execute("cat /etc/hostname", s)
	etcHosts, _ := e.Execute("cat /etc/hosts", s)

	assert.Equal(t, "test-node-42", hostname)
	assert.Equal(t, "test-node-42", uname)
	assert.Equal(t, "test-node-42", etcHostname)
	assert.Contains(t, etcHosts, "test-node-42")
}

func TestProcessListenerConsistency(t *testing.T) {
	e, s := defaultEmulator()
	ps, _ := e.Execute("ps aux", s)
	netstat, _ := e.Execute("netstat -tulpn", s)

	// nginx is in both ps and netstat
	assert.Contains(t, ps, "nginx")
	assert.Contains(t, netstat, "nginx")

	// sshd is in both
	assert.Contains(t, ps, "sshd")
	assert.Contains(t, netstat, "sshd")

	// ollama is in both
	assert.Contains(t, ps, "ollama")
	assert.Contains(t, netstat, "ollama")
}

func TestWhoamiMatchesID(t *testing.T) {
	e, s := defaultEmulator()
	whoami, _ := e.Execute("whoami", s)
	id, _ := e.Execute("id", s)
	assert.Equal(t, "root", whoami)
	assert.Contains(t, id, "uid=0(root)")
}

func TestEnvOllamaHostMatchesPersona(t *testing.T) {
	e, s := defaultEmulator()
	env, _ := e.Execute("env", s)
	assert.Contains(t, env, "OLLAMA_HOST=http://localhost:11434")
}

// === Temporal Coherence Tests ===

func TestUptimeNotStatic(t *testing.T) {
	e, s := defaultEmulator()
	out1, _ := e.Execute("uptime", s)
	// Sleep briefly to change the second
	time.Sleep(1100 * time.Millisecond)
	out2, _ := e.Execute("uptime", s)
	// The time portion should differ (different second)
	assert.NotEqual(t, out1, out2, "uptime should change between calls")
}

func TestUptimePrettyDynamic(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("uptime -p", s)
	assert.Contains(t, out, "up ")
	assert.Contains(t, out, "days")
}

func TestDateReturnsRealTime(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("date", s)
	now := time.Now().UTC()
	assert.Contains(t, out, now.Format("2006"), "date should include current year")
}

func TestLsTimestampsNotAllIdentical(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("ls -la /root", s)
	lines := strings.Split(out, "\n")
	// Skip header "total" line
	timestamps := make(map[string]bool)
	for _, line := range lines[1:] {
		if len(line) < 40 {
			continue
		}
		// Extract the timestamp region (roughly columns 35-47 in ls output)
		fields := strings.Fields(line)
		if len(fields) >= 8 {
			ts := fields[5] + " " + fields[6] + " " + fields[7]
			timestamps[ts] = true
		}
	}
	assert.Greater(t, len(timestamps), 1, "ls -la timestamps should not all be identical")
}

func TestPsStartColumnNotStatic(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("ps aux", s)
	assert.NotContains(t, out, "Jan10", "ps START should derive from BootTime, not be static 'Jan10'")
}

func TestTopUptimeDynamic(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("top", s)
	assert.Contains(t, out, "up ")
	// First line contains "top - HH:MM:SS up ..."
	firstLine := strings.SplitN(out, "\n", 2)[0]
	assert.Regexp(t, `top - \d{2}:\d{2}:\d{2} up`, firstLine, "top should show dynamic time in header")
}

func TestWShowsDynamicTime(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("w", s)
	assert.Contains(t, out, "up ")
	// Login time should be from session
	loginStr := s.LoginTime.Format("15:04")
	assert.Contains(t, out, loginStr)
}

func TestLastUsesBootTime(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("last", s)
	assert.Contains(t, out, "still logged in")
	assert.Contains(t, out, "system boot")
	assert.Contains(t, out, "wtmp begins")
	// Should NOT contain hardcoded "Jan 15" from old version
	assert.NotContains(t, out, "Mon Jan 15 14:22")
}

// === Session Tests ===

func TestCWDTracking(t *testing.T) {
	e, s := defaultEmulator()
	e.Execute("cd /tmp", s)
	out, _ := e.Execute("pwd", s)
	assert.Equal(t, "/tmp", out)
}

func TestPIDRandomization(t *testing.T) {
	e := NewEmulator(parser.ShellEmulator{Enabled: true})

	s1 := &Session{User: "root", CWD: "/root", PIDOffset: 42, ShellPID: 3100, LoginTime: time.Now(),
		FileOverlay: make(map[string]string), DirOverlay: make(map[string][]string), Deleted: make(map[string]bool)}
	s2 := &Session{User: "root", CWD: "/root", PIDOffset: 137, ShellPID: 3500, LoginTime: time.Now(),
		FileOverlay: make(map[string]string), DirOverlay: make(map[string][]string), Deleted: make(map[string]bool)}

	ps1, _ := e.Execute("ps aux", s1)
	ps2, _ := e.Execute("ps aux", s2)
	assert.NotEqual(t, ps1, ps2, "different sessions should see different PIDs")
}

func TestSystemPIDsUnaffectedByOffset(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("ps aux", s)
	// PID 1 (init) should always be 1
	assert.Contains(t, out, "    1 ", "PID 1 should not be offset")
}

func TestShellPIDInDefaultPs(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("ps", s)
	assert.Contains(t, out, "3100", "shell PID should appear in default ps output")
}

// === Mutable Filesystem Tests ===

func TestTouchThenLs(t *testing.T) {
	e, s := defaultEmulator()
	e.Execute("touch /tmp/testfile", s)
	out, _ := e.Execute("ls /tmp", s)
	assert.Contains(t, out, "testfile")
}

func TestEchoRedirectThenCat(t *testing.T) {
	e, s := defaultEmulator()
	e.Execute(`echo "hello world" > /tmp/test.txt`, s)
	out, _ := e.Execute("cat /tmp/test.txt", s)
	assert.Equal(t, "hello world", out)
}

func TestEchoAppendRedirect(t *testing.T) {
	e, s := defaultEmulator()
	e.Execute(`echo "line1" > /tmp/append.txt`, s)
	e.Execute(`echo "line2" >> /tmp/append.txt`, s)
	out, _ := e.Execute("cat /tmp/append.txt", s)
	assert.Contains(t, out, "line1")
	assert.Contains(t, out, "line2")
}

func TestRmThenCat(t *testing.T) {
	e, s := defaultEmulator()
	e.Execute("touch /tmp/todelete", s)
	e.Execute("rm /tmp/todelete", s)
	out, _ := e.Execute("cat /tmp/todelete", s)
	assert.Contains(t, out, "No such file or directory")
}

func TestRmThenLsExcludes(t *testing.T) {
	e, s := defaultEmulator()
	e.Execute("touch /tmp/rmtest", s)
	e.Execute("rm /tmp/rmtest", s)
	out, _ := e.Execute("ls /tmp", s)
	assert.NotContains(t, out, "rmtest")
}

func TestMkdirThenCd(t *testing.T) {
	e, s := defaultEmulator()
	e.Execute("mkdir /tmp/newdir", s)
	out, _ := e.Execute("cd /tmp/newdir", s)
	assert.Equal(t, "", out, "cd to newly created dir should succeed")
	pwd, _ := e.Execute("pwd", s)
	assert.Equal(t, "/tmp/newdir", pwd)
}

func TestCpFile(t *testing.T) {
	e, s := defaultEmulator()
	e.Execute(`echo "original" > /tmp/src.txt`, s)
	e.Execute("cp /tmp/src.txt /tmp/dst.txt", s)
	out, _ := e.Execute("cat /tmp/dst.txt", s)
	assert.Equal(t, "original", out)
}

func TestOverlayDoesNotAffectOtherSessions(t *testing.T) {
	e := NewEmulator(parser.ShellEmulator{Enabled: true})
	s1 := &Session{User: "root", CWD: "/root", FileOverlay: make(map[string]string), DirOverlay: make(map[string][]string), Deleted: make(map[string]bool)}
	s2 := &Session{User: "root", CWD: "/root", FileOverlay: make(map[string]string), DirOverlay: make(map[string][]string), Deleted: make(map[string]bool)}

	e.Execute(`echo "s1only" > /tmp/s1file`, s1)
	out, _ := e.Execute("cat /tmp/s1file", s2)
	assert.Contains(t, out, "No such file or directory", "session 2 should not see session 1's files")
}

// === /proc Virtual Filesystem Tests ===

func TestLsProcIncludesPIDs(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("ls /proc", s)
	// PID 1 should always be there
	assert.Contains(t, out, "1")
	// Should also contain some other PIDs from the process table
	assert.Contains(t, out, "587")
}

func TestCatProcPidCmdline(t *testing.T) {
	e, s := defaultEmulator()
	// Use raw PID (init is always 1, unaffected by offset)
	out, _ := e.Execute("cat /proc/1/cmdline", s)
	assert.Contains(t, out, "/sbin/init")
}

func TestCatProcPidStatus(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("cat /proc/1/status", s)
	assert.Contains(t, out, "Name:\tinit")
	assert.Contains(t, out, "Pid:\t1")
}

func TestLsProcPidDir(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("ls /proc/1", s)
	assert.Contains(t, out, "cmdline")
	assert.Contains(t, out, "status")
	assert.Contains(t, out, "exe")
}

func TestProcWithOffsetPID(t *testing.T) {
	e, s := defaultEmulator()
	// PID 587 (sshd) with offset 42 = 629
	out, _ := e.Execute("cat /proc/629/cmdline", s)
	assert.Contains(t, out, "sshd")
}

// === Pipe Tests ===

func TestPsAuxPipeHead(t *testing.T) {
	e, s := defaultEmulator()
	out, ok := e.Execute("ps aux | head -5", s)
	require.True(t, ok)
	lines := strings.Split(out, "\n")
	assert.Equal(t, 5, len(lines))
}

func TestCatPasswdPipeGrepRoot(t *testing.T) {
	e, s := defaultEmulator()
	out, ok := e.Execute("cat /etc/passwd | grep root", s)
	require.True(t, ok)
	assert.Contains(t, out, "root")
	assert.NotContains(t, out, "ubuntu")
}

func TestEnvPipeGrepOllama(t *testing.T) {
	e, s := defaultEmulator()
	out, ok := e.Execute("env | grep OLLAMA", s)
	require.True(t, ok)
	assert.Contains(t, out, "OLLAMA_HOST=http://localhost:11434")
}

func TestPipeSortWc(t *testing.T) {
	e, s := defaultEmulator()
	out, ok := e.Execute("env | sort | wc -l", s)
	require.True(t, ok)
	// Should be a number > 0
	assert.NotEqual(t, "0", strings.TrimSpace(out))
}

// === LLM Fallback Tests ===

func TestUnknownCommandReturnsFalse(t *testing.T) {
	e, s := defaultEmulator()
	out, handled := e.Execute("nonexistentcmd --foo", s)
	assert.False(t, handled)
	assert.Equal(t, "", out)
}

func TestBuildPromptContextNotEmpty(t *testing.T) {
	e, _ := defaultEmulator()
	ctx := e.BuildPromptContext()
	assert.Contains(t, ctx, "SYSTEM:")
	assert.Contains(t, ctx, "PROCESSES:")
	assert.Contains(t, ctx, "LISTENERS:")
	assert.Contains(t, ctx, "ENV:")
	assert.Contains(t, ctx, "FILES:")
}

// === Config Merge Tests ===

func TestCustomHostnameOverridesDefault(t *testing.T) {
	e, s := newTestEmulator(parser.ShellEmulator{
		Enabled:  true,
		Hostname: "custom-host",
	})
	out, _ := e.Execute("hostname", s)
	assert.Equal(t, "custom-host", out)
}

func TestCustomLuresMergeWithDefaults(t *testing.T) {
	e, s := newTestEmulator(parser.ShellEmulator{
		Enabled: true,
		Lures: map[string]string{
			"/tmp/custom.txt": "custom content",
		},
	})
	// Custom lure
	out1, _ := e.Execute("cat /tmp/custom.txt", s)
	assert.Equal(t, "custom content", out1)
	// Default lure still present
	out2, _ := e.Execute("cat /etc/passwd", s)
	assert.Contains(t, out2, "root:x:0:0")
}

func TestCustomProcessesReplaceDefaults(t *testing.T) {
	e, s := newTestEmulator(parser.ShellEmulator{
		Enabled: true,
		Processes: []parser.EmulatorProcess{
			{PID: 1, User: "root", CPU: "0.0", Mem: "0.1", VSZ: "100K", RSS: "10M", Cmd: "/custom/init", Stat: "Ss", Time: "0:01"},
		},
	})
	out, _ := e.Execute("ps aux", s)
	assert.Contains(t, out, "/custom/init")
	assert.NotContains(t, out, "nginx")
}

func TestUptimeDaysConfig(t *testing.T) {
	e, s := newTestEmulator(parser.ShellEmulator{
		Enabled:    true,
		UptimeDays: 5,
	})
	out, _ := e.Execute("uptime -p", s)
	assert.Contains(t, out, "5 days")
}

// === Edge Cases ===

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

func TestEchoVariableExpansion(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("echo $HOME", s)
	assert.Equal(t, "/root", out)
}

func TestCdHome(t *testing.T) {
	e, s := defaultEmulator()
	e.Execute("cd /tmp", s)
	e.Execute("cd ~", s)
	out, _ := e.Execute("pwd", s)
	assert.Equal(t, "/root", out)
}

func TestCdNonexistent(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("cd /does/not/exist", s)
	assert.Contains(t, out, "No such file or directory")
}

func TestGrepInFile(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("grep root /etc/passwd", s)
	assert.Contains(t, out, "root:x:0:0")
}

func TestFindInRoot(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("find /root -name credentials", s)
	assert.Contains(t, out, "credentials")
}

func TestWcFile(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("wc -l /etc/passwd", s)
	assert.Contains(t, out, "/etc/passwd")
}

func TestHeadFile(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("head -2 /etc/passwd", s)
	lines := strings.Split(out, "\n")
	assert.Equal(t, 2, len(lines))
}

func TestStatDirectory(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("stat /root", s)
	assert.Contains(t, out, "directory")
	assert.NotContains(t, out, "2024-01-15 14:22:00", "stat timestamps should be dynamic")
}

func TestDigShowsDynamicTimestamp(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("dig example.com", s)
	now := time.Now()
	assert.Contains(t, out, now.UTC().Format("2006"))
}

func TestDockerPsShowsDynamicUptime(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("docker ps", s)
	assert.NotContains(t, out, "23 days ago", "docker ps should use dynamic uptime")
	assert.Contains(t, out, "ago")
}

func TestSystemctlStatusDynamic(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("systemctl status nginx", s)
	assert.Contains(t, out, "active (running)")
	assert.NotContains(t, out, "Mon 2024-01-10", "systemctl should use dynamic boot time")
}

// === Resolve/Substitute Unit Tests ===

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

// === Jitter Test ===

func TestJitterDoesNotBreakOutput(t *testing.T) {
	e, s := defaultEmulator()
	// Just verify that Execute returns correct output even with jitter
	out, ok := e.Execute("whoami", s)
	assert.True(t, ok)
	assert.Equal(t, "root", out)
}

// === Network Commands With Session PID Offset ===

func TestNetstatShowsOffsetPIDs(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("netstat -tulpn", s)
	// sshd PID 587 + offset 42 = 629
	assert.Contains(t, out, "629/sshd")
}

func TestSSShowsOffsetPIDs(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("ss -tulpn", s)
	assert.Contains(t, out, "pid=629")
}

func TestLsofShowsOffsetPIDs(t *testing.T) {
	e, s := defaultEmulator()
	out, _ := e.Execute("lsof -i", s)
	assert.Contains(t, out, "  629") // sshd with offset
}

// === File overlay interacting with grep ===

func TestGrepOverlayFile(t *testing.T) {
	e, s := defaultEmulator()
	e.Execute(`echo "secret=abc123" > /tmp/config`, s)
	out, _ := e.Execute("grep secret /tmp/config", s)
	assert.Equal(t, "secret=abc123", out)
}

// === Find includes overlay ===

func TestFindIncludesOverlay(t *testing.T) {
	e, s := defaultEmulator()
	e.Execute("touch /tmp/findme.txt", s)
	out, _ := e.Execute("find /tmp -name findme.txt", s)
	assert.Contains(t, out, "findme.txt")
}

// === CatOverlayBeforeLure ===

func TestCatOverlayOverridesLure(t *testing.T) {
	e, s := defaultEmulator()
	// Write overlay for a lure path
	e.Execute(`echo "overridden" > /etc/passwd`, s)
	out, _ := e.Execute("cat /etc/passwd", s)
	assert.Equal(t, "overridden", out)
}

// === Semicolon and && Chaining Tests ===

func TestSemicolonChaining(t *testing.T) {
	e, s := defaultEmulator()
	out, ok := e.Execute("whoami; hostname", s)
	require.True(t, ok)
	assert.Contains(t, out, "root")
	assert.Contains(t, out, "prod-web-01")
}

func TestSemicolonThreeCommands(t *testing.T) {
	e, s := defaultEmulator()
	out, ok := e.Execute("whoami; pwd; hostname", s)
	require.True(t, ok)
	lines := strings.Split(out, "\n")
	assert.Equal(t, 3, len(lines))
	assert.Equal(t, "root", lines[0])
	assert.Equal(t, "/root", lines[1])
	assert.Equal(t, "prod-web-01", lines[2])
}

func TestSemicolonTrailing(t *testing.T) {
	e, s := defaultEmulator()
	out, ok := e.Execute("whoami;", s)
	require.True(t, ok)
	assert.Equal(t, "root", out)
}

func TestAndChaining(t *testing.T) {
	e, s := defaultEmulator()
	out, ok := e.Execute("whoami && hostname", s)
	require.True(t, ok)
	assert.Contains(t, out, "root")
	assert.Contains(t, out, "prod-web-01")
}

func TestSemicolonUnhandledFallsThrough(t *testing.T) {
	e, s := defaultEmulator()
	_, ok := e.Execute("whoami; fakecmd", s)
	assert.False(t, ok, "unhandled sub-command should cause whole chain to fall through")
}

func TestSemicolonWithRedirect(t *testing.T) {
	e, s := defaultEmulator()
	out, ok := e.Execute(`echo "hello" > /tmp/f; cat /tmp/f`, s)
	require.True(t, ok)
	assert.Equal(t, "hello", out)
}

func TestSemicolonWithCd(t *testing.T) {
	e, s := defaultEmulator()
	out, ok := e.Execute("cd /tmp; pwd", s)
	require.True(t, ok)
	assert.Equal(t, "/tmp", out)
}

func TestSemicolonWithPipe(t *testing.T) {
	e, s := defaultEmulator()
	out, ok := e.Execute("ps aux | head -3; whoami", s)
	require.True(t, ok)
	assert.Contains(t, out, "root")
	// ps aux | head -3 produces 3 lines, plus whoami adds 1 more
	lines := strings.Split(out, "\n")
	assert.Equal(t, 4, len(lines))
}
