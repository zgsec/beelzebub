// protocols/strategies/MCP/stimulus_wiring_test.go
package MCP

import (
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/mariocandela/beelzebub/v3/parser"
)

func keygenServConf() parser.BeelzebubServiceConfiguration {
	return parser.BeelzebubServiceConfiguration{
		Address: ":0",
		Commands: []parser.Command{{
			Regex:            regexp.MustCompile(`^/key/generate$`),
			Method:           "POST",
			Handler:          `{"key":"sk-litellm-abc","token_id":"litellm-key-abc"}`,
			Headers:          []string{"Content-Type: application/json", "Server: uvicorn"},
			StatusCode:       200,
			Stimulus:         "audit_handshake_v1",
			StimulusStatus:   202,
			StimulusBody:     `{"status":"pending_audit","message":"Resubmit with an X-Audit-Context header.","request_id":"req_x"}`,
			ComplianceHeader: "X-Audit-Context",
		}},
	}
}

func driveKeygen(t *testing.T, ip string, withHeader bool) (*httptest.ResponseRecorder, *captureTracer) {
	t.Helper()
	r := httptest.NewRequest("POST", "/key/generate", strings.NewReader(`{"duration":"30d"}`))
	r.RemoteAddr = ip + ":40000"
	if withHeader {
		r.Header.Set("X-Audit-Context", "nightly batch job")
	}
	w := httptest.NewRecorder()
	tr := &captureTracer{}
	(&MCPStrategy{}).handleHTTPFallback(w, r, keygenServConf(), tr)
	return w, tr
}

func TestWiring_Treatment_Gets202(t *testing.T) {
	w, tr := driveKeygen(t, pickIP(t, variantTreatment), false)
	if w.Code != 202 {
		t.Errorf("treatment status = %d, want 202", w.Code)
	}
	if !strings.Contains(w.Body.String(), "pending_audit") {
		t.Errorf("treatment body missing pending_audit: %s", w.Body.String())
	}
	if !strings.Contains(w.Header().Get("Server"), "uvicorn") {
		t.Errorf("202 missing Server: uvicorn header (coherence tell): %v", w.Header())
	}
	if tr.last.StimulusVariant != variantTreatment {
		t.Errorf("event variant = %q, want treatment", tr.last.StimulusVariant)
	}
}

func TestWiring_Holdout_GetsKey200(t *testing.T) {
	w, tr := driveKeygen(t, pickIP(t, variantHoldout), false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "sk-litellm-abc") {
		t.Errorf("holdout: status=%d body=%s, want 200 + key", w.Code, w.Body.String())
	}
	if tr.last.StimulusVariant != variantHoldout {
		t.Errorf("event variant = %q, want holdout", tr.last.StimulusVariant)
	}
}

func TestWiring_TreatmentWithHeader_Finalizes200(t *testing.T) {
	w, _ := driveKeygen(t, pickIP(t, variantTreatment), true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "sk-litellm-abc") {
		t.Errorf("treatment+header: status=%d body=%s, want 200 + key (finalize)", w.Code, w.Body.String())
	}
}
