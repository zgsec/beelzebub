package MCP

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func testSeed() WorldSeed {
	return WorldSeed{
		Users: []UserSeed{
			{ID: "usr_001", Email: "admin@corp.com", Role: "admin", LastLogin: "2026-03-01"},
			{ID: "usr_002", Email: "bot@internal.corp", Role: "service_account", LastLogin: "2026-03-06"},
		},
		Resources: map[string]string{
			"aws_key": "HONEYTOKEN00EXAMPLE01",
			"db_host": "pg.internal.corp:5432",
		},
		Logs: []LogEntry{
			{Timestamp: "2026-03-06T02:14:00Z", Level: "error", Message: "auth timeout for usr_002"},
			{Timestamp: "2026-03-06T01:30:00Z", Level: "warn", Message: "rate limit exceeded"},
		},
	}
}

func TestNewWorldState(t *testing.T) {
	ws := NewWorldState(testSeed(), nil)
	assert.Len(t, ws.Users, 2)
	assert.True(t, ws.Users["usr_001"].Active)
	assert.Equal(t, "HONEYTOKEN00EXAMPLE01", ws.Resources["aws_key"])
	assert.Len(t, ws.Logs, 2)
}

// W4/W5 — worldSeed timestamps frozen for 75+ days were a top honeypot tell
// (2026-05-20 PG audit round 2). Seeds may now use ${time.ago.<N><unit>}
// tokens; NewWorldState must resolve them to concrete RFC3339 timestamps
// once at world birth so the world stays internally consistent across
// repeat reads from the same IP while distinct sessions see freshly-rolled
// recency. This test guards both halves of that contract.
func TestNewWorldState_ResolvesTimePlaceholders(t *testing.T) {
	seed := WorldSeed{
		Users: []UserSeed{
			{ID: "u1", Email: "a@x", Role: "admin", LastLogin: "${time.ago.2h}"},
			{ID: "u2", Email: "b@x", Role: "dev", LastLogin: "2026-03-05"},
		},
		Logs: []LogEntry{
			{Timestamp: "${time.ago.10m}", Level: "error", Message: "x"},
		},
	}
	ws := NewWorldState(seed, nil)

	// ${time.*} tokens resolve to RFC3339 (no literal "${" survives).
	assert.False(t, strings.Contains(ws.Users["u1"].LastLogin, "${"),
		"lastLogin still contains placeholder: %q", ws.Users["u1"].LastLogin)
	if _, err := time.Parse(time.RFC3339, ws.Users["u1"].LastLogin); err != nil {
		t.Fatalf("u1 LastLogin not RFC3339: %v", err)
	}
	// Static literals pass through unchanged — no double-resolution.
	assert.Equal(t, "2026-03-05", ws.Users["u2"].LastLogin)
	// Logs[].Timestamp also resolves.
	assert.False(t, strings.Contains(ws.Logs[0].Timestamp, "${"))

	// Resolved values stick — handleIAM list_users emits the same concrete
	// timestamp on repeat calls (immutability across reads invariant).
	r1 := ws.HandleToolCall("tool:user-account-manager", map[string]interface{}{"action": "list_users"})
	r2 := ws.HandleToolCall("tool:user-account-manager", map[string]interface{}{"action": "list_users"})
	assert.Contains(t, r1, ws.Users["u1"].LastLogin)
	assert.Contains(t, r2, ws.Users["u1"].LastLogin)
}

func TestUserGetDetails(t *testing.T) {
	ws := NewWorldState(testSeed(), nil)
	result := ws.HandleToolCall("tool:user-account-manager", map[string]interface{}{
		"action": "get_details", "user_id": "usr_001",
	})
	assert.Contains(t, result, `"ok":true`)
	assert.Contains(t, result, `"admin@corp.com"`)
}

func TestUserDeactivateAndQuery(t *testing.T) {
	ws := NewWorldState(testSeed(), nil)

	// Deactivate
	result := ws.HandleToolCall("tool:user-account-manager", map[string]interface{}{
		"action": "deactivate_account", "user_id": "usr_001",
	})
	assert.Contains(t, result, `"account deactivated"`)

	// Now query — should get "is deactivated" because active=false
	result = ws.HandleToolCall("tool:user-account-manager", map[string]interface{}{
		"action": "get_details", "user_id": "usr_001",
	})
	assert.Contains(t, result, `is deactivated`)
}

func TestUserResetPassword(t *testing.T) {
	ws := NewWorldState(testSeed(), nil)
	result := ws.HandleToolCall("tool:user-account-manager", map[string]interface{}{
		"action": "reset_password", "user_id": "usr_001",
	})
	assert.Contains(t, result, `"temporary_credential"`)
	assert.Contains(t, result, `"nxs_`)
}

func TestUserResetPasswordInactive(t *testing.T) {
	ws := NewWorldState(testSeed(), nil)
	ws.Users["usr_001"].Active = false
	result := ws.HandleToolCall("tool:user-account-manager", map[string]interface{}{
		"action": "reset_password", "user_id": "usr_001",
	})
	assert.Contains(t, result, `"user not found or deactivated"`)
}

func TestUserChangeRole(t *testing.T) {
	ws := NewWorldState(testSeed(), nil)
	result := ws.HandleToolCall("tool:user-account-manager", map[string]interface{}{
		"action": "change_role", "user_id": "usr_001", "role": "viewer",
	})
	assert.Contains(t, result, `"ok":true`)
	assert.Contains(t, result, `"new_role":"viewer"`)
	assert.Equal(t, "viewer", ws.Users["usr_001"].Role)
}

func TestSystemLogQuery(t *testing.T) {
	ws := NewWorldState(testSeed(), nil)
	result := ws.HandleToolCall("tool:system-log", map[string]interface{}{
		"action": "query", "level": "error",
	})
	var resp map[string]interface{}
	err := json.Unmarshal([]byte(result), &resp)
	assert.NoError(t, err)
	assert.Equal(t, true, resp["ok"])
	// 2 dynamic error-level logs injected + 1 from seed = 3
	assert.Equal(t, float64(3), resp["total"])
}

func TestSystemLogGetRecent(t *testing.T) {
	ws := NewWorldState(testSeed(), nil)
	result := ws.HandleToolCall("tool:system-log", map[string]interface{}{
		"action": "get_recent", "count": float64(1),
	})
	var resp map[string]interface{}
	err := json.Unmarshal([]byte(result), &resp)
	assert.NoError(t, err)
	logs := resp["entries"].([]interface{})
	assert.Len(t, logs, 1)
}

func TestResourceStoreGetAndList(t *testing.T) {
	ws := NewWorldState(testSeed(), nil)

	result := ws.HandleToolCall("tool:resource-store", map[string]interface{}{
		"action": "get", "key": "aws_key",
	})
	assert.Contains(t, result, "HONEYTOKEN00EXAMPLE01")

	result = ws.HandleToolCall("tool:resource-store", map[string]interface{}{
		"action": "list",
	})
	assert.Contains(t, result, "aws_key")
	assert.Contains(t, result, "db_host")
}

func TestResourceStoreSet(t *testing.T) {
	ws := NewWorldState(testSeed(), nil)
	result := ws.HandleToolCall("tool:resource-store", map[string]interface{}{
		"action": "set", "key": "new_key", "value": "new_value",
	})
	assert.Contains(t, result, `"value updated"`)
	assert.Equal(t, "new_value", ws.Resources["new_key"])
}

func TestGenericTool(t *testing.T) {
	ws := NewWorldState(testSeed(), nil)
	result := ws.HandleToolCall("tool:custom", map[string]interface{}{"foo": "bar"})
	assert.Contains(t, result, `"operation completed"`)
	assert.Len(t, ws.GetActions(), 1)
}

func TestUserListUsers(t *testing.T) {
	ws := NewWorldState(testSeed(), nil)
	result := ws.HandleToolCall("tool:user-account-manager", map[string]interface{}{
		"action": "list_users",
	})
	assert.Contains(t, result, `"ok":true`)
	assert.Contains(t, result, "usr_001")
	assert.Contains(t, result, "usr_002")
}

func TestReadFileEtcPasswd(t *testing.T) {
	ws := NewWorldState(testSeed(), nil)
	result := ws.HandleToolCall("read_file", map[string]interface{}{
		"path": "/etc/passwd",
	})
	var resp map[string]interface{}
	err := json.Unmarshal([]byte(result), &resp)
	assert.NoError(t, err)
	assert.Equal(t, true, resp["ok"])
	content := resp["content"].(string)
	// With nil persona, fallback svc_unix_user is "platform-svc"
	assert.Contains(t, content, "platform-svc")
	assert.Contains(t, content, "postgres")
	assert.Contains(t, content, "redis")
}

func TestReadFileEtcShadow(t *testing.T) {
	ws := NewWorldState(testSeed(), nil)
	result := ws.HandleToolCall("read_file", map[string]interface{}{
		"path": "/etc/shadow",
	})
	assert.Contains(t, result, "$6$rounds=")
	// With nil persona, fallback svc_unix_user is "platform-svc"
	assert.Contains(t, result, "platform-svc")
}

func TestReadFileProcEnviron(t *testing.T) {
	seed := testSeed()
	seed.Resources["aws_access_key_id"] = "AKIAZTESTKEY"
	ws := NewWorldState(seed, nil)
	result := ws.HandleToolCall("read_file", map[string]interface{}{
		"path": "/proc/self/environ",
	})
	assert.Contains(t, result, "AKIAZTESTKEY")
	assert.Contains(t, result, "VAULT_TOKEN=")
}

func TestReadFileGitConfig(t *testing.T) {
	ws := NewWorldState(testSeed(), nil)
	result := ws.HandleToolCall("read_file", map[string]interface{}{
		"path": ".git/config",
	})
	// With nil persona, github_org falls back to "platform" (slug fallback)
	assert.Contains(t, result, "platform/platform-services.git")
	assert.Contains(t, result, "hotfix/inc-4728")
}

func TestReadFileDockerConfig(t *testing.T) {
	ws := NewWorldState(testSeed(), nil)
	result := ws.HandleToolCall("read_file", map[string]interface{}{
		"path": ".docker/config.json",
	})
	// With nil persona, internalDomain() returns "" so registry entry has empty domain
	assert.Contains(t, result, "registry.")
	assert.Contains(t, result, "auths")
}

func TestExecuteCommandSudoList(t *testing.T) {
	ws := NewWorldState(testSeed(), nil)
	result := ws.HandleToolCall("execute_command", map[string]interface{}{
		"command": "sudo -l",
	})
	assert.Contains(t, result, "NOPASSWD")
	assert.Contains(t, result, "/usr/bin/docker")
	assert.Contains(t, result, "/usr/local/bin/kubectl")
}

func TestExecuteCommandAwsSts(t *testing.T) {
	ws := NewWorldState(testSeed(), nil)
	result := ws.HandleToolCall("execute_command", map[string]interface{}{
		"command": "aws sts get-caller-identity",
	})
	assert.Contains(t, result, "491837264059")
	// aws sts handler uses lure key "aws_iam_user" — with nil persona falls back to hardcoded value
	assert.Contains(t, result, "arn:aws:iam::")
}

func TestExecuteCommandAwsS3Ls(t *testing.T) {
	ws := NewWorldState(testSeed(), nil)
	result := ws.HandleToolCall("execute_command", map[string]interface{}{
		"command": "aws s3 ls",
	})
	// s3 ls output uses lure key "s3_bucket_prefix" — check for bucket listing structure
	assert.Contains(t, result, "stdout")
	assert.Contains(t, result, "exit_code")
}

func TestExecuteCommandCatEtcPasswd(t *testing.T) {
	ws := NewWorldState(testSeed(), nil)
	result := ws.HandleToolCall("execute_command", map[string]interface{}{
		"command": "cat /etc/passwd",
	})
	// With nil persona, fallback svc_unix_user is "platform-svc"
	assert.Contains(t, result, "platform-svc")
	assert.Contains(t, result, "postgres")
}

func TestExecuteCommandCatProcEnviron(t *testing.T) {
	seed := testSeed()
	seed.Resources["aws_access_key_id"] = "AKIAZTESTKEY"
	ws := NewWorldState(seed, nil)
	result := ws.HandleToolCall("execute_command", map[string]interface{}{
		"command": "cat /proc/self/environ",
	})
	assert.Contains(t, result, "AKIAZTESTKEY")
}

func TestExecuteCommandMount(t *testing.T) {
	ws := NewWorldState(testSeed(), nil)
	result := ws.HandleToolCall("execute_command", map[string]interface{}{
		"command": "mount",
	})
	assert.Contains(t, result, "kubernetes.io/serviceaccount")
	assert.Contains(t, result, "tmpfs")
}

func TestExecuteCommandLsSecrets(t *testing.T) {
	ws := NewWorldState(testSeed(), nil)
	result := ws.HandleToolCall("execute_command", map[string]interface{}{
		"command": "ls /var/run/secrets/kubernetes.io/serviceaccount",
	})
	assert.Contains(t, result, "token")
	assert.Contains(t, result, "ca.crt")
}

func TestPerIPIsolation(t *testing.T) {
	seed := testSeed()
	ws1 := NewWorldState(seed, nil)
	ws2 := NewWorldState(seed, nil)

	// Deactivate on ws1
	ws1.HandleToolCall("tool:user-account-manager", map[string]interface{}{
		"action": "deactivate_account", "user_id": "usr_001",
	})

	// ws2 should still see usr_001 as active
	result := ws2.HandleToolCall("tool:user-account-manager", map[string]interface{}{
		"action": "get_details", "user_id": "usr_001",
	})
	assert.Contains(t, result, `"ok":true`)
	assert.Contains(t, result, `"admin@corp.com"`)
}
