package MCP

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExtractFileArg(t *testing.T) {
	cases := map[string]string{
		"cat credentials.bak":                  "credentials.bak",
		"cat credentials.bak 2>&1":             "credentials.bak",
		"cat /app/.env 2>/dev/null":            "/app/.env",
		"head -n 5 config.yaml":                "config.yaml",
		"head -5 /var/log/app.log":             "/var/log/app.log",
		"tail -f logs/app.log":                 "logs/app.log",
		"cat 'deploy-key.pem'":                 "deploy-key.pem",
		"cat /tmp/up_out* 2>/dev/null; ls -la": "/tmp/up_out*",
		"cat":                                  "",
		"cat > /tmp/x":                         "",
		"cat src/index.js | grep secret":       "src/index.js",
	}
	for cmd, want := range cases {
		if got := extractFileArg(cmd); got != want {
			t.Errorf("extractFileArg(%q) = %q, want %q", cmd, got, want)
		}
	}
}

// fileContentForPath must return distinct, path-appropriate content — never a
// single uniform fallback body regardless of path.
func TestFileContentForPath_DistinctPerFile(t *testing.T) {
	ws := NewWorldState(testSeed(), nil)

	creds := ws.fileContentForPath("credentials.bak")
	deployKey := ws.fileContentForPath("deploy-key.pem")
	unknown := ws.fileContentForPath("/tmp/nonsense-xyz")

	if !strings.Contains(creds, "cdf_api_key") {
		t.Errorf("credentials.bak content unexpected: %q", creds)
	}
	if !strings.Contains(deployKey, "BEGIN RSA PRIVATE KEY") {
		t.Errorf("deploy-key.pem content unexpected: %q", deployKey)
	}
	if creds == deployKey || creds == unknown || deployKey == unknown {
		t.Errorf("distinct files returned identical content (creds/deploy/unknown collapsed)")
	}
	// The retired uniform boilerplate must never reappear on any path.
	for _, c := range []string{creds, deployKey, unknown} {
		if strings.Contains(c, "LOG_LEVEL=warn\nDB_POOL_SIZE=20") {
			t.Errorf("uniform boilerplate leaked back into file content: %q", c)
		}
	}
}

// The core coherence invariant: `cat <path>` (execute_command) and read_file
// must return the same body for the same path.
func TestCatMatchesReadFile(t *testing.T) {
	ws := NewWorldState(testSeed(), nil)

	for _, path := range []string{"credentials.bak", "deploy-key.pem", "/app/.env", "README.md", "/tmp/unknown-file"} {
		catStdout := field(t, ws.handleExecuteCommand(map[string]interface{}{"command": "cat " + path + " 2>&1"}), "stdout")
		readContent := field(t, ws.handleReadFile(map[string]interface{}{"path": path}), "content")
		if catStdout != readContent {
			t.Errorf("cat vs read_file diverged for %q:\n cat=%q\n read=%q", path, catStdout, readContent)
		}
		if strings.Contains(catStdout, "LOG_LEVEL=warn\nDB_POOL_SIZE=20") {
			t.Errorf("cat %q returned uniform boilerplate", path)
		}
	}
}

// field parses an MCP JSON envelope and returns a string field.
func field(t *testing.T, jsonStr, key string) string {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &m); err != nil {
		t.Fatalf("bad JSON envelope %q: %v", jsonStr, err)
	}
	s, _ := m[key].(string)
	return s
}
