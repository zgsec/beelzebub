package MCP

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReplay218157 is the regression that locks in the LiteLLM-admin-lure fix
// for the 218.200.187.157 capture (sensor-fra, 2026-06-12). In the ORIGINAL
// capture the operator's read-surface requests returned 200 but the two ACTION
// requests — GET /credentials and POST /user/update — returned 404. That
// read-200/write-404 asymmetry is the honeypot tell: it forfeited the capture
// (operator stopped at the climax), exposed the lure, and missed the canary.
//
// This test replays the ACTUAL admin request chain (sourced from the capture
// jsonl, materialized into testdata/admin_chain_218157.json) through the REAL
// MCP HTTP dispatch (handleHTTPFallback → regex routing → stateHandler →
// per-IP WorldState), against a single strategy + one RemoteAddr (so every
// request shares ONE WorldState — the statefulness substrate), and asserts:
//
//	no-404         every replayed admin request returns NOT 404; specifically
//	               /credentials and /user/update (the two that 404'd in the
//	               capture) now return 200, alongside /user/list, /user/info,
//	               /key/generate.
//	state-reflected POST /user/update {jpark→proxy_admin} echoes the mutation
//	               (data.user_role==proxy_admin), and a SYNTHETIC follow-up GET
//	               /user/list (the real operator never re-read) shows jpark with
//	               user_role==proxy_admin in the roster — proving the mutation
//	               persisted on the shared WorldState.
//	canary-present GET /credentials returns the populated masked bedrock entry
//	               (credential_name==bedrock-prod-creds, aws_access_key_id
//	               masked first2****last2, custom_llm_provider==bedrock).
//
// Vehicle: handleHTTPFallback driven by httptest (the engine used by
// mcp_bodyregex_routing_test.go / admin_http_test.go). This exercises the real
// regex routing + method match + stateHandler dispatch + per-IP WorldState
// statefulness without standing up a full server/DB/tracer — the dependable,
// hermetic choice per the implementation plan.
//
// Corpus sourcing: the request method/uri/body are read from
// testdata/admin_chain_218157.json, which is a verbatim projection of the
// admin-surface requests in
// honeypot-research/research/218.200.187.157.sensor-fra.jsonl (fields
// HTTPMethod→method, RequestURI→uri, Body→body, ResponseStatusCode→
// captured_status). The method field is present and unambiguous in the jsonl
// (HTTPMethod), so it is sourced directly — not hardcoded per path. The
// testdata copy keeps the Go test hermetic (no cross-repo file dependency).

// replayAdminServConf builds the admin-surface servConf inline, mirroring the
// SHIPPED lure personas/crestfield-data-systems/lures/mcp-8000.yaml: the five
// stateHandler commands (names + methods exactly as in the yaml + the registry
// in admin_http.go), the static /key/generate command, and a FallbackCommand
// with statusCode 404 — so any UNMATCHED path 404s, proving the OLD behavior
// (read-200/write-404) is precisely what the stateHandler routes fix.
func replayAdminServConf() parser.BeelzebubServiceConfiguration {
	jsonHdr := []string{"Content-Type: application/json; charset=utf-8", "Server: uvicorn"}
	return parser.BeelzebubServiceConfiguration{
		Address:              ":0",
		Description:          "Crestfield Platform",
		CaptureResponseBody:  true,
		ResponseBodyMaxBytes: 8192,
		Commands: []parser.Command{
			{
				Regex:        regexp.MustCompile(`^/user/list$`),
				Method:       "GET",
				Name:         "litellm-user-list",
				StateHandler: "user_list",
				Headers:      jsonHdr,
				StatusCode:   200,
				Handler:      `{"users":[],"total":0}`, // static fallback (unused: stateHandler resolves)
			},
			{
				Regex:        regexp.MustCompile(`^/user/info$`),
				Method:       "GET",
				Name:         "litellm-user-info",
				StateHandler: "user_info",
				Headers:      jsonHdr,
				StatusCode:   200,
				Handler:      `{"user_id":"default_user_id"}`,
			},
			{
				Regex:        regexp.MustCompile(`^/user/update$`),
				Method:       "POST",
				Name:         "litellm-user-update",
				StateHandler: "user_update",
				Headers:      jsonHdr,
				StatusCode:   200,
				Handler:      `{"user_id":"default_user_id","data":{}}`,
			},
			{
				Regex:        regexp.MustCompile(`^/user/new$`),
				Method:       "POST",
				Name:         "litellm-user-new",
				StateHandler: "user_new",
				Headers:      jsonHdr,
				StatusCode:   200,
				Handler:      `{"user_id":"new_user","user_role":"internal_user"}`,
			},
			{
				Regex:        regexp.MustCompile(`^/credentials$`),
				Method:       "GET",
				Name:         "litellm-credentials",
				StateHandler: "credentials",
				Headers:      jsonHdr,
				StatusCode:   200,
				Handler:      `{"success":true,"credentials":[]}`,
			},
			{
				// /key/generate is a STATIC command in the shipped lure (no
				// stateHandler) — included so the no-404 assertion covers every
				// request the operator sent, not just the stateful ones.
				Regex:      regexp.MustCompile(`^/key/generate$`),
				Method:     "POST",
				Name:       "litellm-key-generate",
				Headers:    jsonHdr,
				StatusCode: 200,
				Handler:    `{"key":"sk-litellm-replayKey","token_id":"litellm-key-replay","models":[],"max_budget":100.0,"user_id":"default_user_id"}`,
			},
		},
		// Default-404: any path that does NOT match a command above falls here.
		// This is the exact shape that produced the original tell — if a route
		// regressed off its stateHandler, the request would land here and 404.
		FallbackCommand: parser.Command{
			Name:       "default-404",
			Headers:    []string{"Content-Type: application/json", "Server: uvicorn"},
			StatusCode: 404,
			Handler:    `{"detail":"Not Found"}`,
		},
	}
}

// replayPersona mirrors testPersona() in state_test.go so the seeded admin
// roster anchors to crestfielddata.io and contains jpark@crestfielddata.io
// (proxy_admin) + the svc-deployer ci_service handle — exactly what the
// operator enumerated.
func replayPersona() *parser.Persona {
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

type replayRequest struct {
	Method         string `json:"method"`
	URI            string `json:"uri"`
	Body           string `json:"body"`
	CapturedStatus int    `json:"captured_status"`
}

type replayCorpus struct {
	Source   string          `json:"_source"`
	Note     string          `json:"_note"`
	Requests []replayRequest `json:"requests"`
}

func loadReplayCorpus(t *testing.T) replayCorpus {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "admin_chain_218157.json"))
	require.NoError(t, err, "read admin replay corpus")
	var c replayCorpus
	require.NoError(t, json.Unmarshal(raw, &c), "parse admin replay corpus")
	require.NotEmpty(t, c.Requests, "corpus must contain admin requests")
	return c
}

// replayOne drives a single captured request through the real dispatch on the
// given strategy. The RemoteAddr is fixed across the chain so every request
// hits the SAME per-IP WorldState (one stateful session).
func replayOne(s *MCPStrategy, servConf parser.BeelzebubServiceConfiguration, method, uri, body string) (int, string) {
	var r = httptest.NewRequest(method, uri, strings.NewReader(body))
	r.RemoteAddr = "218.200.187.157:46926" // the operator's actual src — one session
	w := httptest.NewRecorder()
	tr := &captureTracer{}
	s.handleHTTPFallback(w, r, servConf, tr)
	return tr.last.ResponseStatusCode, w.Body.String()
}

func TestReplay218157(t *testing.T) {
	servConf := replayAdminServConf()
	corpus := loadReplayCorpus(t)

	// One strategy, persona + seed set so getOrCreateWorld seeds the admin
	// roster (jpark@crestfielddata.io == proxy_admin) on first touch.
	s := newStateStrategy()
	s.seedConfig = testSeed()
	s.persona = replayPersona()

	// --- Assertion 1: no-404 — replay the ACTUAL chain, fail listing any 404 ---
	var got404 []string
	statusByPath := map[string]int{} // last-seen status per path (for the spot checks)
	for _, req := range corpus.Requests {
		status, body := replayOne(s, servConf, req.Method, req.URI, req.Body)
		if status == 404 {
			got404 = append(got404, req.Method+" "+req.URI)
		}
		statusByPath[req.URI] = status
		// Sanity: body must be valid JSON on every admin response (no torn render).
		assert.Truef(t, json.Valid([]byte(body)), "%s %s: response not valid JSON: %s", req.Method, req.URI, body)
	}
	assert.Emptyf(t, got404, "no-404 FAILED: these replayed admin requests still 404: %v", got404)

	// Explicit spot checks on the two requests that 404'd in the ORIGINAL
	// capture (the tell) — they MUST now be 200.
	assert.Equalf(t, 200, statusByPath["/credentials"], "GET /credentials moved off 404? got %d", statusByPath["/credentials"])
	assert.Equalf(t, 200, statusByPath["/user/update"], "POST /user/update moved off 404? got %d", statusByPath["/user/update"])
	// And the requests that were already 200 in the capture stay 200.
	assert.Equal(t, 200, statusByPath["/user/list"], "GET /user/list")
	assert.Equal(t, 200, statusByPath["/user/info"], "GET /user/info")
	assert.Equal(t, 200, statusByPath["/key/generate"], "POST /key/generate")
	if !t.Failed() {
		t.Log("PASS no-404")
	}

	// --- Assertion 2: state-reflected ----------------------------------------
	// The capture's /user/update payload is already in the corpus above and has
	// been replayed onto this WorldState. Re-assert the mutation echo from a
	// fresh dispatch (deterministic), then do the SYNTHETIC follow-up read the
	// real operator never sent, on the SAME strategy/RemoteAddr/WorldState.
	updBody := `{"user_id":"jpark@crestfielddata.io","user_role":"proxy_admin"}`
	updStatus, updResp := replayOne(s, servConf, "POST", "/user/update", updBody)
	require.Equal(t, 200, updStatus, "user/update status")
	var upd struct {
		UserID string                 `json:"user_id"`
		Data   map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(updResp), &upd))
	assert.Equal(t, "jpark@crestfielddata.io", upd.UserID, "update echoes the mutated user_id")
	assert.Equal(t, "proxy_admin", upd.Data["user_role"], "update echoes data.user_role==proxy_admin")

	// Synthetic follow-up read on the SAME WorldState — proves statefulness.
	listStatus, listResp := replayOne(s, servConf, "GET", "/user/list", "")
	require.Equal(t, 200, listStatus, "follow-up user/list status")
	var list struct {
		Users []map[string]interface{} `json:"users"`
	}
	require.NoError(t, json.Unmarshal([]byte(listResp), &list))
	var jpark map[string]interface{}
	for _, u := range list.Users {
		if u["user_id"] == "jpark@crestfielddata.io" {
			jpark = u
		}
	}
	require.NotNilf(t, jpark, "jpark not in follow-up user_list: %s", listResp)
	assert.Equal(t, "proxy_admin", jpark["user_role"],
		"state-reflected FAILED: jpark.user_role not proxy_admin on the follow-up read (mutation did not persist on shared WorldState)")
	if !t.Failed() {
		t.Log("PASS state-reflected")
	}

	// --- Assertion 3: canary-present -----------------------------------------
	credStatus, credResp := replayOne(s, servConf, "GET", "/credentials", "")
	require.Equal(t, 200, credStatus, "credentials status")
	var cred struct {
		Success     bool `json:"success"`
		Credentials []struct {
			CredentialName   string            `json:"credential_name"`
			CredentialValues map[string]string `json:"credential_values"`
			CredentialInfo   map[string]string `json:"credential_info"`
		} `json:"credentials"`
	}
	require.NoError(t, json.Unmarshal([]byte(credResp), &cred), "parse credentials")
	require.True(t, cred.Success, "credentials.success")
	require.Lenf(t, cred.Credentials, 1, "credentials must contain the one populated bedrock entry: %s", credResp)
	c := cred.Credentials[0]
	assert.Equal(t, "bedrock-prod-creds", c.CredentialName, "credential_name")
	assert.Equal(t, "bedrock", c.CredentialInfo["custom_llm_provider"], "custom_llm_provider")
	mask := regexp.MustCompile(`^..\*\*\*\*..$`)
	assert.Regexpf(t, mask, c.CredentialValues["aws_access_key_id"],
		"canary-present FAILED: aws_access_key_id %q not masked first2****last2", c.CredentialValues["aws_access_key_id"])
	if !t.Failed() {
		t.Log("PASS canary-present")
	}
}
