package MCP

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// admin_http.go: Go-backed "state handlers" for the LiteLLM admin write/action
// surface served on the MCP HTTP-fallback path. Each handler reads and/or
// mutates the per-session admin roster (WorldState.AdminRoster, see state.go)
// and renders an oracle-accurate LiteLLM body, so a /user/update write is
// visible on a later /user/list or /user/info read. This kills the 404
// honeypot tell that ACTION endpoints previously exhibited.
//
// Ground truth: tools/oracle-diff/litellm-1.83.6-admin/fixtures/oracle/
// write-surface/{user_list,user_info,user_update,credentials}.json — these
// renderers are byte-faithful to those envelope shapes.
//
// Robustness contract (it's a honeypot — attackers send garbage): a handler
// NEVER panics and NEVER returns a 5xx. Malformed / empty / non-JSON bodies
// are treated as missing fields and still yield a coherent 200 oracle body.

// adminHTTPHandler answers one stateful admin route. ws is the per-session
// world (roster already seeded by the dispatcher). body is the raw request
// body (may be nil/empty/garbage). Returns the response body and HTTP status.
type adminHTTPHandler func(ws *WorldState, r *http.Request, body []byte) (respBody string, statusCode int)

// adminHTTPHandlers is the registry the dispatcher resolves stateHandler: names
// against. An unknown name is treated as static (the caller falls back to the
// normal responsesubs.Apply render) — adding a route is "add a yaml line +
// (optionally) a func here", never a parser change.
var adminHTTPHandlers = map[string]adminHTTPHandler{
	"user_list":   adminUserList,
	"user_info":   adminUserInfo,
	"user_update": adminUserUpdate,
	"user_new":    adminUserNew,
	"credentials": adminCredentials,
}

// litellmTSLayout is the oracle's millisecond ISO timestamp with a trailing Z
// (e.g. "2026-06-12T12:56:56.919000Z"). LiteLLM renders Python datetimes with
// microsecond precision; the user objects carry 6 fractional digits + "Z".
const litellmTSLayout = "2006-01-02T15:04:05.000000Z07:00"

// litellmTS renders t in the oracle's ...Z millisecond/microsecond ISO format.
// Anchored to roster CreatedAt/UpdatedAt so reads are byte-stable across calls.
func litellmTS(t time.Time) string {
	return t.UTC().Format(litellmTSLayout)
}

// nullableFloat returns f when set (>0) else nil, so unset budgets render as
// JSON null (the oracle shows max_budget: null for users without a budget).
// Spend is rendered separately because the oracle always emits spend: 0.0.

// adminUserObject maps an AdminUser to the FULL oracle user-object field set
// from user_list.json. Fields we don't model render as their null/empty oracle
// default. teams is always a (possibly empty) array, never null.
func adminUserObject(u *AdminUser) map[string]interface{} {
	teams := u.Teams
	if teams == nil {
		teams = []string{}
	}
	var userEmail interface{}
	if u.UserEmail != "" {
		userEmail = u.UserEmail
	} // else nil → null
	var userRole interface{}
	if u.UserRole != "" {
		userRole = u.UserRole
	} // else nil → null (oracle shows user_role: null for unscoped users)
	var maxBudget interface{}
	if u.MaxBudget > 0 {
		maxBudget = u.MaxBudget
	} // else nil → null

	return map[string]interface{}{
		"user_id":                  u.UserID,
		"max_budget":               maxBudget,
		"spend":                    u.Spend,
		"model_max_budget":         map[string]interface{}{},
		"model_spend":              map[string]interface{}{},
		"user_email":               userEmail,
		"user_alias":               nil,
		"models":                   []interface{}{},
		"tpm_limit":                nil,
		"rpm_limit":                nil,
		"user_role":                userRole,
		"organization_memberships": nil,
		"teams":                    teams,
		"sso_user_id":              nil,
		"budget_duration":          nil,
		"budget_reset_at":          nil,
		"metadata":                 map[string]interface{}{},
		"created_at":               litellmTS(u.CreatedAt),
		"updated_at":               litellmTS(u.UpdatedAt),
		"object_permission":        nil,
		"key_count":                u.KeyCount,
	}
}

// adminUserInfoObject is the user_info-shaped (richer) object per user_info.json
// / user_update.json. It carries the extra fields LiteLLM's /user/info and
// /user/update return that /user/list omits (team_id, password, policies, …).
//
// orgMemberships toggles the one field where the two fixtures diverge:
// /user/info hydrates organization_memberships as [] (user_info.json), while
// /user/update returns the raw record with null (user_update.json). Passing the
// right value per call keeps both envelopes byte-faithful from one renderer.
func adminUserInfoObject(u *AdminUser, orgMemberships interface{}) map[string]interface{} {
	teams := u.Teams
	if teams == nil {
		teams = []string{}
	}
	var userEmail interface{}
	if u.UserEmail != "" {
		userEmail = u.UserEmail
	}
	var userRole interface{}
	if u.UserRole != "" {
		userRole = u.UserRole
	}
	var maxBudget interface{}
	if u.MaxBudget > 0 {
		maxBudget = u.MaxBudget
	}

	return map[string]interface{}{
		"user_id":                    u.UserID,
		"user_alias":                 nil,
		"team_id":                    nil,
		"sso_user_id":                nil,
		"organization_id":            nil,
		"object_permission_id":       nil,
		"password":                   nil,
		"teams":                      teams,
		"user_role":                  userRole,
		"max_budget":                 maxBudget,
		"spend":                      u.Spend,
		"user_email":                 userEmail,
		"models":                     []interface{}{},
		"metadata":                   map[string]interface{}{},
		"max_parallel_requests":      nil,
		"tpm_limit":                  nil,
		"rpm_limit":                  nil,
		"budget_duration":            nil,
		"budget_reset_at":            nil,
		"allowed_cache_controls":     []interface{}{},
		"policies":                   []interface{}{},
		"model_spend":                map[string]interface{}{},
		"model_max_budget":           map[string]interface{}{},
		"created_at":                 litellmTS(u.CreatedAt),
		"updated_at":                 litellmTS(u.UpdatedAt),
		"litellm_organization_table": nil,
		"organization_memberships":   orgMemberships,
		"invitations_created":        nil,
		"invitations_updated":        nil,
		"invitations_user":           nil,
		"object_permission":          nil,
	}
}

// marshal is a tiny helper: json.Marshal can only fail on unsupported types,
// which our hand-built maps never contain, so an error here is impossible in
// practice — but we still degrade to an empty object rather than ever panic.
func marshal(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// adminUserList → GET /user/list. Renders every roster entry as a full oracle
// user object in stable (sorted) order. A prior /user/update becomes visible
// here — the proof of statefulness.
func adminUserList(ws *WorldState, r *http.Request, body []byte) (string, int) {
	snap := ws.AdminRosterSnapshot()
	users := make([]map[string]interface{}, 0, len(snap))
	for _, u := range snap {
		users = append(users, adminUserObject(u))
	}
	return marshal(map[string]interface{}{
		"users":       users,
		"total":       len(users),
		"page":        1,
		"page_size":   25,
		"total_pages": 1,
	}), http.StatusOK
}

// defaultAdminUserID is LiteLLM's built-in root admin principal. The 218.157
// operator sent a bare GET /user/info (no param) which resolves here. We ensure
// it exists in the roster as proxy_admin so the default read path is coherent
// AND so a prior /user/update to default_user_id is reflected on a later read.
const defaultAdminUserID = "default_user_id"

// ensureDefaultAdminUser guarantees default_user_id exists in the roster.
// SeedAdminRoster does NOT seed it (it seeds the persona roster), so we upsert
// it as proxy_admin on first /user/info if absent. If it already exists (e.g. a
// prior /user/update mutated its role), we leave it untouched so the mutation
// is reflected. Returns a value copy safe to render.
func ensureDefaultAdminUser(ws *WorldState) *AdminUser {
	if u, ok := ws.AdminUser(defaultAdminUserID); ok {
		return u
	}
	// Upsert as proxy_admin. UpdateAdminUserRole returns a value copy and
	// mutates the live roster under the lock so subsequent reads observe it.
	return ws.UpdateAdminUserRole(defaultAdminUserID, "proxy_admin", time.Now().UTC())
}

// adminUserInfo → GET /user/info[?user_id=]. Bare (no param) is the hot path:
// renders default_user_id (proxy_admin). With ?user_id= resolving in the roster
// it renders that user (real LiteLLM honors ?user_id=). The keys[] array is a
// coherent minimal bait set; teams[] is empty per the oracle.
func adminUserInfo(ws *WorldState, r *http.Request, body []byte) (string, int) {
	var u *AdminUser
	if r != nil {
		if q := r.URL.Query().Get("user_id"); q != "" {
			if found, ok := ws.AdminUser(q); ok {
				u = found
			}
		}
	}
	if u == nil {
		u = ensureDefaultAdminUser(ws)
	}

	return marshal(map[string]interface{}{
		"user_id":   u.UserID,
		"user_info": adminUserInfoObject(u, []interface{}{}),
		"keys":      adminBaitKeys(u),
		"teams":     []interface{}{},
	}), http.StatusOK
}

// adminBaitKeys returns a minimal, coherent set of key objects for /user/info.
// Kept intentionally lean (the canary-bearing variant is a follow-up task);
// shape matches user_info.json's keys[] entries.
func adminBaitKeys(u *AdminUser) []map[string]interface{} {
	created := litellmTS(u.CreatedAt)
	// Strip the trailing Z to match the oracle's key created_at (which, unlike
	// the user object, has no Z suffix in the fixture).
	keyTS := created
	if len(keyTS) > 0 && keyTS[len(keyTS)-1] == 'Z' {
		keyTS = keyTS[:len(keyTS)-1]
	}
	return []map[string]interface{}{
		{
			"token":                  "<sha256>",
			"key_name":               "sk-...UoAw",
			"key_alias":              nil,
			"spend":                  0.0,
			"max_budget":             nil,
			"expires":                nil,
			"models":                 []interface{}{},
			"aliases":                map[string]interface{}{},
			"config":                 map[string]interface{}{},
			"user_id":                u.UserID,
			"team_id":                nil,
			"agent_id":               nil,
			"project_id":             nil,
			"max_parallel_requests":  nil,
			"metadata":               map[string]interface{}{},
			"tpm_limit":              nil,
			"rpm_limit":              nil,
			"budget_duration":        nil,
			"budget_reset_at":        nil,
			"allowed_cache_controls": []interface{}{},
			"allowed_routes":         []interface{}{},
			"permissions":            map[string]interface{}{},
			"model_spend":            map[string]interface{}{},
			"model_max_budget":       map[string]interface{}{},
			"soft_budget_cooldown":   false,
			"blocked":                nil,
			"litellm_budget_table":   nil,
			"org_id":                 nil,
			"created_at":             keyTS,
			"created_by":             nil,
			"updated_at":             keyTS,
			"updated_by":             nil,
			"last_active":            nil,
			"object_permission_id":   nil,
			"object_permission":      nil,
			"access_group_ids":       []interface{}{},
			"rotation_count":         0,
			"auto_rotate":            false,
			"rotation_interval":      nil,
			"last_rotation_at":       nil,
			"key_rotation_at":        nil,
			"router_settings":        map[string]interface{}{},
			"team_alias":             "None",
		},
	}
}

// userUpdateBody is the lenient parse target for /user/update and /user/new.
// All fields optional; missing/garbage → zero values, never an error to the
// caller (we swallow the unmarshal error and treat the body as empty).
type userUpdateBody struct {
	UserID   string `json:"user_id"`
	UserRole string `json:"user_role"`
}

// parseUserBody best-effort-parses body. A nil/empty/non-JSON body yields a
// zero-value struct (no error surfaced) so handlers stay 200-only.
func parseUserBody(body []byte) userUpdateBody {
	var b userUpdateBody
	if len(body) == 0 {
		return b
	}
	_ = json.Unmarshal(body, &b) // ignore error: garbage → zero values
	return b
}

// adminUserUpdate → POST /user/update. Applies user_role to user_id (upserting
// an absent user — jpark is not seeded, so this creates+promotes it, exactly
// the 218.157 operator's intent). Renders the oracle mutation envelope
// {"user_id":..,"data":{<full info object, role applied, updated_at advanced>}}.
// Missing user_role → role unchanged, still 200 with the current object.
func adminUserUpdate(ws *WorldState, r *http.Request, body []byte) (string, int) {
	in := parseUserBody(body)
	now := time.Now().UTC()

	var u *AdminUser
	if in.UserRole != "" {
		// Mutating update (upserts if absent).
		u = ws.UpdateAdminUserRole(in.UserID, in.UserRole, now)
	} else {
		// No role change requested. Render the current object if it exists,
		// else upsert with role unchanged (empty) so we still return a coherent
		// 200 object for an unknown id rather than 4xx.
		if found, ok := ws.AdminUser(in.UserID); ok {
			u = found
		} else {
			u = ws.UpdateAdminUserRole(in.UserID, "", now)
		}
	}

	return marshal(map[string]interface{}{
		"user_id": u.UserID,
		"data":    adminUserInfoObject(u, nil),
	}), http.StatusOK
}

// adminUserNew → POST /user/new. Generates a uuid user_id, adds it to the
// roster (role from body or default internal_user), renders the oracle
// mutation envelope (same shape as /user/update).
func adminUserNew(ws *WorldState, r *http.Request, body []byte) (string, int) {
	in := parseUserBody(body)
	role := in.UserRole
	if role == "" {
		role = "internal_user"
	}
	id := in.UserID
	if id == "" {
		id = uuid.New().String()
	}
	u := ws.UpdateAdminUserRole(id, role, time.Now().UTC())
	return marshal(map[string]interface{}{
		"user_id": u.UserID,
		"data":    adminUserInfoObject(u, nil),
	}), http.StatusOK
}

// adminCredentials → GET /credentials. Oracle-exact empty envelope. This kills
// the 404 tell. A FOLLOW-UP canary task populates credentials[] with the bait
// AWS canary; do NOT add an entry here.
func adminCredentials(ws *WorldState, r *http.Request, body []byte) (string, int) {
	return `{"success":true,"credentials":[]}`, http.StatusOK
}
