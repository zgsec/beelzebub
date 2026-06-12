package MCP

import (
	"encoding/json"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mariocandela/beelzebub/v3/parser"
)

// newAdminWS builds a seeded WorldState for direct (white-box) handler tests,
// mirroring state_test.go conventions. SeedAdminRoster is idempotent; the
// admin handlers also call it, so a double-seed here is harmless.
func newAdminWS() *WorldState {
	ws := NewWorldState(WorldSeed{}, nil)
	ws.SeedAdminRoster()
	return ws
}

// TestAdminHTTP_UserUpdate_UpsertsAndPromotes proves the operator's exact
// payload ({"user_id":"jpark@crestfielddata.io","user_role":"proxy_admin"})
// upserts+promotes jpark and the response envelope reflects the applied role.
func TestAdminHTTP_UserUpdate_UpsertsAndPromotes(t *testing.T) {
	ws := newAdminWS()
	body := []byte(`{"user_id":"jpark@crestfielddata.io","user_role":"proxy_admin"}`)
	respBody, status := adminUserUpdate(ws, httptest.NewRequest("POST", "/user/update", strings.NewReader(string(body))), body)
	if status != 200 {
		t.Fatalf("status: got %d want 200", status)
	}
	var resp struct {
		UserID string                 `json:"user_id"`
		Data   map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal([]byte(respBody), &resp); err != nil {
		t.Fatalf("unmarshal: %v\nbody=%s", err, respBody)
	}
	if resp.UserID != "jpark@crestfielddata.io" {
		t.Errorf("user_id: got %q want jpark@crestfielddata.io", resp.UserID)
	}
	if resp.Data["user_role"] != "proxy_admin" {
		t.Errorf("data.user_role: got %v want proxy_admin", resp.Data["user_role"])
	}
	// user_update.json fidelity: organization_memberships is null in the
	// mutation envelope (vs [] in /user/info).
	if v, present := resp.Data["organization_memberships"]; !present || v != nil {
		t.Errorf("data.organization_memberships: got %v (present=%v) want null", v, present)
	}
}

// TestAdminHTTP_UserList_ReflectsUpdate is the core statefulness proof: after a
// /user/update promotes jpark, a subsequent /user/list shows jpark with the new
// role. This is what the static handler: render could never do.
func TestAdminHTTP_UserList_ReflectsUpdate(t *testing.T) {
	ws := newAdminWS()
	upd := []byte(`{"user_id":"jpark@crestfielddata.io","user_role":"proxy_admin"}`)
	_, _ = adminUserUpdate(ws, httptest.NewRequest("POST", "/user/update", strings.NewReader(string(upd))), upd)

	respBody, status := adminUserList(ws, httptest.NewRequest("GET", "/user/list", nil), nil)
	if status != 200 {
		t.Fatalf("status: got %d want 200", status)
	}
	var resp struct {
		Users      []map[string]interface{} `json:"users"`
		Total      int                      `json:"total"`
		Page       int                      `json:"page"`
		PageSize   int                      `json:"page_size"`
		TotalPages int                      `json:"total_pages"`
	}
	if err := json.Unmarshal([]byte(respBody), &resp); err != nil {
		t.Fatalf("unmarshal: %v\nbody=%s", err, respBody)
	}
	if resp.Page != 1 || resp.PageSize != 25 || resp.TotalPages != 1 {
		t.Errorf("envelope paging: page=%d page_size=%d total_pages=%d", resp.Page, resp.PageSize, resp.TotalPages)
	}
	var jpark map[string]interface{}
	for _, u := range resp.Users {
		if u["user_id"] == "jpark@crestfielddata.io" {
			jpark = u
		}
	}
	if jpark == nil {
		t.Fatalf("jpark not present in user_list after update; body=%s", respBody)
	}
	if jpark["user_role"] != "proxy_admin" {
		t.Errorf("jpark.user_role: got %v want proxy_admin", jpark["user_role"])
	}
	// Oracle field set spot-check: keys that must exist on every user object.
	for _, k := range []string{"user_id", "max_budget", "spend", "model_max_budget", "model_spend",
		"user_email", "user_alias", "models", "tpm_limit", "rpm_limit", "user_role",
		"organization_memberships", "teams", "sso_user_id", "budget_duration", "budget_reset_at",
		"metadata", "created_at", "updated_at", "object_permission", "key_count"} {
		if _, ok := jpark[k]; !ok {
			t.Errorf("user object missing oracle field %q", k)
		}
	}
}

// TestAdminHTTP_UserInfo_DefaultProxyAdmin verifies the bare GET /user/info
// hot path (the 218.157 operator sent no param) returns the default_user_id
// proxy_admin and the nested envelope shape.
func TestAdminHTTP_UserInfo_DefaultProxyAdmin(t *testing.T) {
	ws := newAdminWS()
	respBody, status := adminUserInfo(ws, httptest.NewRequest("GET", "/user/info", nil), nil)
	if status != 200 {
		t.Fatalf("status: got %d want 200", status)
	}
	var resp struct {
		UserID   string                 `json:"user_id"`
		UserInfo map[string]interface{} `json:"user_info"`
		Keys     []interface{}          `json:"keys"`
		Teams    []interface{}          `json:"teams"`
	}
	if err := json.Unmarshal([]byte(respBody), &resp); err != nil {
		t.Fatalf("unmarshal: %v\nbody=%s", err, respBody)
	}
	if resp.UserID != "default_user_id" {
		t.Errorf("user_id: got %q want default_user_id", resp.UserID)
	}
	if resp.UserInfo == nil {
		t.Fatalf("user_info envelope key missing")
	}
	if resp.UserInfo["user_role"] != "proxy_admin" {
		t.Errorf("user_info.user_role: got %v want proxy_admin", resp.UserInfo["user_role"])
	}
	if resp.Keys == nil {
		t.Errorf("keys envelope key missing/null")
	}
	// Oracle fidelity: keys[] must have exactly 2 entries (array-length tell fix).
	if len(resp.Keys) != 2 {
		t.Errorf("keys length: got %d want 2", len(resp.Keys))
	}
	// Second key must match oracle keys[1]: key_alias="deep", max_budget=999999.
	if len(resp.Keys) >= 2 {
		k2, ok := resp.Keys[1].(map[string]interface{})
		if !ok {
			t.Fatalf("keys[1]: unexpected type %T", resp.Keys[1])
		}
		if k2["key_alias"] != "deep" {
			t.Errorf("keys[1].key_alias: got %v want \"deep\"", k2["key_alias"])
		}
		if k2["max_budget"] != float64(999999) {
			t.Errorf("keys[1].max_budget: got %v want 999999", k2["max_budget"])
		}
	}
	// user_info.json fidelity: organization_memberships hydrates to [] (not null).
	if v, ok := resp.UserInfo["organization_memberships"].([]interface{}); !ok || v == nil {
		t.Errorf("user_info.organization_memberships: got %v want [] (empty array)", resp.UserInfo["organization_memberships"])
	}
}

// TestAdminHTTP_UserInfo_ParamReflectsUpdate verifies ?user_id= honoring:
// after promoting jpark, GET /user/info?user_id=jpark@... reflects proxy_admin.
func TestAdminHTTP_UserInfo_ParamReflectsUpdate(t *testing.T) {
	ws := newAdminWS()
	upd := []byte(`{"user_id":"jpark@crestfielddata.io","user_role":"proxy_admin"}`)
	_, _ = adminUserUpdate(ws, httptest.NewRequest("POST", "/user/update", strings.NewReader(string(upd))), upd)

	r := httptest.NewRequest("GET", "/user/info?user_id=jpark@crestfielddata.io", nil)
	respBody, status := adminUserInfo(ws, r, nil)
	if status != 200 {
		t.Fatalf("status: got %d want 200", status)
	}
	var resp struct {
		UserID   string                 `json:"user_id"`
		UserInfo map[string]interface{} `json:"user_info"`
	}
	if err := json.Unmarshal([]byte(respBody), &resp); err != nil {
		t.Fatalf("unmarshal: %v\nbody=%s", err, respBody)
	}
	if resp.UserID != "jpark@crestfielddata.io" {
		t.Errorf("user_id: got %q want jpark@crestfielddata.io", resp.UserID)
	}
	if resp.UserInfo["user_role"] != "proxy_admin" {
		t.Errorf("user_info.user_role: got %v want proxy_admin", resp.UserInfo["user_role"])
	}
}

// TestAdminHTTP_Credentials_OracleExactEmpty locks the exact oracle empty body.
func TestAdminHTTP_Credentials_OracleExactEmpty(t *testing.T) {
	ws := newAdminWS()
	respBody, status := adminCredentials(ws, httptest.NewRequest("GET", "/credentials", nil), nil)
	if status != 200 {
		t.Fatalf("status: got %d want 200", status)
	}
	if respBody != `{"success":true,"credentials":[]}` {
		t.Errorf("credentials body: got %q want %q", respBody, `{"success":true,"credentials":[]}`)
	}
}

// TestAdminHTTP_UserNew_GeneratesAndPersists verifies user_new mints a uuid id,
// adds it to the roster (visible on a later list), and renders a full object.
func TestAdminHTTP_UserNew_GeneratesAndPersists(t *testing.T) {
	ws := newAdminWS()
	body := []byte(`{"user_role":"internal_user"}`)
	respBody, status := adminUserNew(ws, httptest.NewRequest("POST", "/user/new", strings.NewReader(string(body))), body)
	if status != 200 {
		t.Fatalf("status: got %d want 200", status)
	}
	var resp struct {
		UserID string `json:"user_id"`
		Data   struct {
			UserRole string `json:"user_role"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(respBody), &resp); err != nil {
		t.Fatalf("unmarshal: %v\nbody=%s", err, respBody)
	}
	if resp.UserID == "" {
		t.Fatalf("user_new did not generate a user_id; body=%s", respBody)
	}
	if resp.Data.UserRole != "internal_user" {
		t.Errorf("data.user_role: got %q want internal_user", resp.Data.UserRole)
	}
	if _, ok := ws.AdminUser(resp.UserID); !ok {
		t.Errorf("user_new id %q not persisted to roster", resp.UserID)
	}
}

// TestAdminHTTP_UserUpdate_GarbageBody_NoPanic asserts robustness: an empty or
// non-JSON body must still return 200 and never panic / 500.
func TestAdminHTTP_UserUpdate_GarbageBody_NoPanic(t *testing.T) {
	ws := newAdminWS()
	for _, b := range [][]byte{nil, {}, []byte("not json"), []byte("{")} {
		respBody, status := adminUserUpdate(ws, httptest.NewRequest("POST", "/user/update", nil), b)
		if status != 200 {
			t.Errorf("garbage body %q: status got %d want 200", string(b), status)
		}
		if !json.Valid([]byte(respBody)) {
			t.Errorf("garbage body %q: response not valid JSON: %s", string(b), respBody)
		}
	}
}

// --- dispatch hook tests (end-to-end through handleHTTPFallback) ---

func newStateStrategy() *MCPStrategy {
	return &MCPStrategy{
		worldState:    make(map[string]*WorldState),
		toolHistory:   make(map[string][]toolCallRecord),
		agentTimings:  make(map[string][]int64),
		agentLastSeen: make(map[string]time.Time),
	}
}

// TestStateHandler_DispatchHook_UserList routes a Command with
// StateHandler:"user_list" through handleHTTPFallback and asserts the Go-backed
// body + 200 land on the wire/trace.
func TestStateHandler_DispatchHook_UserList(t *testing.T) {
	servConf := parser.BeelzebubServiceConfiguration{
		Address:              ":0",
		CaptureResponseBody:  true,
		ResponseBodyMaxBytes: 8192,
		Commands: []parser.Command{
			{
				Regex:        regexp.MustCompile(`^/user/list$`),
				Method:       "GET",
				Handler:      "STATIC_SHOULD_NOT_RENDER",
				StatusCode:   200,
				Headers:      []string{"Server: uvicorn", "Content-Type: application/json"},
				StateHandler: "user_list",
			},
		},
	}
	s := newStateStrategy()
	tr := &captureTracer{}
	r := httptest.NewRequest("GET", "/user/list", nil)
	r.RemoteAddr = "203.0.113.7:54321"
	w := httptest.NewRecorder()
	s.handleHTTPFallback(w, r, servConf, tr)

	if tr.last.ResponseStatusCode != 200 {
		t.Errorf("status: got %d want 200", tr.last.ResponseStatusCode)
	}
	if strings.Contains(w.Body.String(), "STATIC_SHOULD_NOT_RENDER") {
		t.Errorf("static handler rendered instead of state handler: %s", w.Body.String())
	}
	var resp struct {
		Users    []map[string]interface{} `json:"users"`
		PageSize int                      `json:"page_size"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("dispatched body not oracle JSON: %v\nbody=%s", err, w.Body.String())
	}
	if resp.PageSize != 25 {
		t.Errorf("page_size: got %d want 25", resp.PageSize)
	}
	// agentLastSeen must be set for the host so a stateful HTTP session isn't
	// evicted mid-interaction.
	s.timingMu.RLock()
	_, seen := s.agentLastSeen["203.0.113.7"]
	s.timingMu.RUnlock()
	if !seen {
		t.Errorf("agentLastSeen not updated for stateful HTTP host")
	}
}

// TestStateHandler_DispatchHook_UnknownFallsBack proves an unknown StateHandler
// name does not crash and falls back to the static handler: render.
func TestStateHandler_DispatchHook_UnknownFallsBack(t *testing.T) {
	servConf := parser.BeelzebubServiceConfiguration{
		Address:              ":0",
		CaptureResponseBody:  true,
		ResponseBodyMaxBytes: 4096,
		Commands: []parser.Command{
			{
				Regex:        regexp.MustCompile(`^/user/list$`),
				Method:       "GET",
				Handler:      "STATIC_FALLBACK_BODY",
				StatusCode:   200,
				StateHandler: "does_not_exist",
			},
		},
	}
	s := newStateStrategy()
	tr := &captureTracer{}
	r := httptest.NewRequest("GET", "/user/list", nil)
	r.RemoteAddr = "203.0.113.9:40000"
	w := httptest.NewRecorder()
	s.handleHTTPFallback(w, r, servConf, tr)

	if w.Body.String() != "STATIC_FALLBACK_BODY" {
		t.Errorf("unknown StateHandler should fall back to static handler: got %q", w.Body.String())
	}
	if tr.last.ResponseStatusCode != 200 {
		t.Errorf("status: got %d want 200", tr.last.ResponseStatusCode)
	}
}
