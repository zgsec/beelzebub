package MCP

import (
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/mariocandela/beelzebub/v3/parser"
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

// testPersona builds a *parser.Persona with a known public domain so admin
// roster ids (user_id == user_email for humans) are deterministic in assertions.
func testPersona() *parser.Persona {
	return &parser.Persona{
		SchemaVersion: 1,
		Slug:          "crestfield-data-systems",
		DisplayName:   "Crestfield Data Systems",
		Identity: parser.PersonaIdentity{
			PublicDomain:   "crestfielddata.io",
			InternalDomain: "int.crestfielddata.io",
		},
		LureContent: map[string]string{
			"ci_service_handle": "svc-deployer",
		},
	}
}

func TestAdminRoster_SeedAndRead(t *testing.T) {
	ws := NewWorldState(testSeed(), testPersona())
	ws.SeedAdminRoster()

	jpark, ok := ws.AdminUser("jpark@crestfielddata.io")
	assert.True(t, ok)
	assert.Equal(t, "proxy_admin", jpark.UserRole)

	mchen, ok := ws.AdminUser("mchen@crestfielddata.io")
	assert.True(t, ok)
	assert.Equal(t, "internal_user_viewer", mchen.UserRole)

	assert.Len(t, ws.AdminRosterSnapshot(), 5)

	// Idempotent: a second seed must not duplicate or reset.
	ws.SeedAdminRoster()
	assert.Len(t, ws.AdminRosterSnapshot(), 5)
}

func TestAdminRoster_UpdateReflectsOnRead(t *testing.T) {
	ws := NewWorldState(testSeed(), testPersona())
	ws.SeedAdminRoster()

	when := ws.BornAt.Add(90 * time.Minute)
	updated := ws.UpdateAdminUserRole("mchen@crestfielddata.io", "proxy_admin", when)
	assert.NotNil(t, updated)
	assert.Equal(t, "proxy_admin", updated.UserRole)

	// Core read-back-after-write proof: a later read sees the mutation.
	mchen, ok := ws.AdminUser("mchen@crestfielddata.io")
	assert.True(t, ok)
	assert.Equal(t, "proxy_admin", mchen.UserRole)
	assert.Equal(t, when, mchen.UpdatedAt)
}

func TestAdminRoster_UpdateUpsertsUnknownUser(t *testing.T) {
	ws := NewWorldState(testSeed(), testPersona())
	ws.SeedAdminRoster()

	when := ws.BornAt.Add(5 * time.Minute)
	updated := ws.UpdateAdminUserRole("intruder@evil.test", "proxy_admin", when)
	assert.NotNil(t, updated)
	assert.Equal(t, "proxy_admin", updated.UserRole)
	// looks like an email -> UserEmail populated.
	assert.Equal(t, "intruder@evil.test", updated.UserEmail)
	assert.Equal(t, when, updated.CreatedAt)

	got, ok := ws.AdminUser("intruder@evil.test")
	assert.True(t, ok)
	assert.Equal(t, "proxy_admin", got.UserRole)
	assert.Len(t, ws.AdminRosterSnapshot(), 6)
}

func TestAdminRoster_SnapshotIsOrderedAndIsolated(t *testing.T) {
	ws := NewWorldState(testSeed(), testPersona())
	ws.SeedAdminRoster()

	snap := ws.AdminRosterSnapshot()
	ids := make([]string, len(snap))
	for i, u := range snap {
		ids[i] = u.UserID
	}
	sorted := make([]string, len(ids))
	copy(sorted, ids)
	sort.Strings(sorted)
	assert.Equal(t, sorted, ids, "snapshot must be sorted by UserID")

	// Mutating a returned copy must not change subsequent snapshots.
	snap[0].UserRole = "tampered"
	snap2 := ws.AdminRosterSnapshot()
	assert.NotEqual(t, "tampered", snap2[0].UserRole)

	// Two independent WorldState instances do not share roster state.
	ws2 := NewWorldState(testSeed(), testPersona())
	ws2.SeedAdminRoster()
	ws2.UpdateAdminUserRole("mchen@crestfielddata.io", "proxy_admin", ws2.BornAt)
	mchen1, _ := ws.AdminUser("mchen@crestfielddata.io")
	assert.Equal(t, "internal_user_viewer", mchen1.UserRole, "ws roster must be unaffected by ws2 mutation")
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
