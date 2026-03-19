package MCP

import (
	"encoding/json"
	"testing"

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
	ws := NewWorldState(testSeed())
	assert.Len(t, ws.Users, 2)
	assert.True(t, ws.Users["usr_001"].Active)
	assert.Equal(t, "HONEYTOKEN00EXAMPLE01", ws.Resources["aws_key"])
	assert.Len(t, ws.Logs, 2)
}

func TestUserGetDetails(t *testing.T) {
	ws := NewWorldState(testSeed())
	result := ws.HandleToolCall("tool:user-account-manager", map[string]interface{}{
		"action": "get_details", "user_id": "usr_001",
	})
	assert.Contains(t, result, `"ok":true`)
	assert.Contains(t, result, `"admin@corp.com"`)
}

func TestUserDeactivateAndQuery(t *testing.T) {
	ws := NewWorldState(testSeed())

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
	ws := NewWorldState(testSeed())
	result := ws.HandleToolCall("tool:user-account-manager", map[string]interface{}{
		"action": "reset_password", "user_id": "usr_001",
	})
	assert.Contains(t, result, `"temporary_credential"`)
	assert.Contains(t, result, `"nxs_`)
}

func TestUserResetPasswordInactive(t *testing.T) {
	ws := NewWorldState(testSeed())
	ws.Users["usr_001"].Active = false
	result := ws.HandleToolCall("tool:user-account-manager", map[string]interface{}{
		"action": "reset_password", "user_id": "usr_001",
	})
	assert.Contains(t, result, `"user not found or deactivated"`)
}

func TestUserChangeRole(t *testing.T) {
	ws := NewWorldState(testSeed())
	result := ws.HandleToolCall("tool:user-account-manager", map[string]interface{}{
		"action": "change_role", "user_id": "usr_001", "role": "viewer",
	})
	assert.Contains(t, result, `"ok":true`)
	assert.Contains(t, result, `"new_role":"viewer"`)
	assert.Equal(t, "viewer", ws.Users["usr_001"].Role)
}

func TestSystemLogQuery(t *testing.T) {
	ws := NewWorldState(testSeed())
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
	ws := NewWorldState(testSeed())
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
	ws := NewWorldState(testSeed())

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
	ws := NewWorldState(testSeed())
	result := ws.HandleToolCall("tool:resource-store", map[string]interface{}{
		"action": "set", "key": "new_key", "value": "new_value",
	})
	assert.Contains(t, result, `"value updated"`)
	assert.Equal(t, "new_value", ws.Resources["new_key"])
}

func TestGenericTool(t *testing.T) {
	ws := NewWorldState(testSeed())
	result := ws.HandleToolCall("tool:custom", map[string]interface{}{"foo": "bar"})
	assert.Contains(t, result, `"operation completed"`)
	assert.Len(t, ws.GetActions(), 1)
}

func TestUserListUsers(t *testing.T) {
	ws := NewWorldState(testSeed())
	result := ws.HandleToolCall("tool:user-account-manager", map[string]interface{}{
		"action": "list_users",
	})
	assert.Contains(t, result, `"ok":true`)
	assert.Contains(t, result, "usr_001")
	assert.Contains(t, result, "usr_002")
}

func TestReadFileEtcPasswd(t *testing.T) {
	ws := NewWorldState(testSeed())
	result := ws.HandleToolCall("read_file", map[string]interface{}{
		"path": "/etc/passwd",
	})
	var resp map[string]interface{}
	err := json.Unmarshal([]byte(result), &resp)
	assert.NoError(t, err)
	assert.Equal(t, true, resp["ok"])
	content := resp["content"].(string)
	assert.Contains(t, content, "nexus-svc")
	assert.Contains(t, content, "postgres")
	assert.Contains(t, content, "redis")
}

func TestReadFileEtcShadow(t *testing.T) {
	ws := NewWorldState(testSeed())
	result := ws.HandleToolCall("read_file", map[string]interface{}{
		"path": "/etc/shadow",
	})
	assert.Contains(t, result, "$6$rounds=")
	assert.Contains(t, result, "nexus-svc")
}

func TestReadFileProcEnviron(t *testing.T) {
	seed := testSeed()
	seed.Resources["aws_access_key_id"] = "AKIAZTESTKEY"
	ws := NewWorldState(seed)
	result := ws.HandleToolCall("read_file", map[string]interface{}{
		"path": "/proc/self/environ",
	})
	assert.Contains(t, result, "AKIAZTESTKEY")
	assert.Contains(t, result, "VAULT_TOKEN=")
}

func TestReadFileGitConfig(t *testing.T) {
	ws := NewWorldState(testSeed())
	result := ws.HandleToolCall("read_file", map[string]interface{}{
		"path": ".git/config",
	})
	assert.Contains(t, result, "nexuslogistics/platform-services.git")
	assert.Contains(t, result, "hotfix/inc-4728")
}

func TestReadFileDockerConfig(t *testing.T) {
	ws := NewWorldState(testSeed())
	result := ws.HandleToolCall("read_file", map[string]interface{}{
		"path": ".docker/config.json",
	})
	assert.Contains(t, result, "registry.int.nexuslogistics.io")
}

func TestExecuteCommandSudoList(t *testing.T) {
	ws := NewWorldState(testSeed())
	result := ws.HandleToolCall("execute_command", map[string]interface{}{
		"command": "sudo -l",
	})
	assert.Contains(t, result, "NOPASSWD")
	assert.Contains(t, result, "/usr/bin/docker")
	assert.Contains(t, result, "/usr/local/bin/kubectl")
}

func TestExecuteCommandAwsSts(t *testing.T) {
	ws := NewWorldState(testSeed())
	result := ws.HandleToolCall("execute_command", map[string]interface{}{
		"command": "aws sts get-caller-identity",
	})
	assert.Contains(t, result, "491837264059")
	assert.Contains(t, result, "nexus-svc-prod")
}

func TestExecuteCommandAwsS3Ls(t *testing.T) {
	ws := NewWorldState(testSeed())
	result := ws.HandleToolCall("execute_command", map[string]interface{}{
		"command": "aws s3 ls",
	})
	assert.Contains(t, result, "nexus-prod-backups")
	assert.Contains(t, result, "nexus-internal-configs")
}

func TestExecuteCommandCatEtcPasswd(t *testing.T) {
	ws := NewWorldState(testSeed())
	result := ws.HandleToolCall("execute_command", map[string]interface{}{
		"command": "cat /etc/passwd",
	})
	assert.Contains(t, result, "nexus-svc")
	assert.Contains(t, result, "postgres")
}

func TestExecuteCommandCatProcEnviron(t *testing.T) {
	seed := testSeed()
	seed.Resources["aws_access_key_id"] = "AKIAZTESTKEY"
	ws := NewWorldState(seed)
	result := ws.HandleToolCall("execute_command", map[string]interface{}{
		"command": "cat /proc/self/environ",
	})
	assert.Contains(t, result, "AKIAZTESTKEY")
}

func TestExecuteCommandMount(t *testing.T) {
	ws := NewWorldState(testSeed())
	result := ws.HandleToolCall("execute_command", map[string]interface{}{
		"command": "mount",
	})
	assert.Contains(t, result, "kubernetes.io/serviceaccount")
	assert.Contains(t, result, "tmpfs")
}

func TestExecuteCommandLsSecrets(t *testing.T) {
	ws := NewWorldState(testSeed())
	result := ws.HandleToolCall("execute_command", map[string]interface{}{
		"command": "ls /var/run/secrets/kubernetes.io/serviceaccount",
	})
	assert.Contains(t, result, "token")
	assert.Contains(t, result, "ca.crt")
}

func TestPerIPIsolation(t *testing.T) {
	seed := testSeed()
	ws1 := NewWorldState(seed)
	ws2 := NewWorldState(seed)

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
