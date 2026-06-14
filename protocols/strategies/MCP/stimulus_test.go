// protocols/strategies/MCP/stimulus_test.go
package MCP

import (
	"bufio"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/tracer"
)

func loadRealIPs(t *testing.T) []string {
	t.Helper()
	f, err := os.Open("testdata/real_ips.txt")
	if err != nil {
		t.Fatalf("open real_ips.txt (run Task 0): %v", err)
	}
	defer f.Close()
	var ips []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := sc.Text(); line != "" {
			ips = append(ips, line)
		}
	}
	if len(ips) < 500 {
		t.Fatalf("expected >=500 real IPs, got %d", len(ips))
	}
	return ips
}

func TestSplitVariant_DistributionOnRealIPs(t *testing.T) {
	ips := loadRealIPs(t)
	treat := 0
	for _, ip := range ips {
		if splitVariant(ip, "audit_handshake_v1") == variantTreatment {
			treat++
		}
	}
	frac := float64(treat) / float64(len(ips))
	t.Logf("treatment fraction = %.4f (%d/%d)", frac, treat, len(ips))
	if frac < 0.45 || frac > 0.55 {
		t.Errorf("treatment fraction on real IPs = %.3f, want 0.45-0.55", frac)
	}
}

func TestSplitVariant_StableAndKeyedByID(t *testing.T) {
	ips := loadRealIPs(t)
	flips := 0
	for _, ip := range ips {
		a := splitVariant(ip, "audit_handshake_v1")
		if a != splitVariant(ip, "audit_handshake_v1") {
			t.Fatalf("splitVariant not stable for %s", ip)
		}
		if a != splitVariant(ip, "other_stimulus_v1") {
			flips++
		}
	}
	frac := float64(flips) / float64(len(ips))
	t.Logf("cross-id flip fraction = %.4f (%d/%d)", frac, flips, len(ips))
	if frac < 0.3 || frac > 0.7 {
		t.Errorf("cross-id flip fraction = %.3f, want 0.3-0.7 (independence)", frac)
	}
}

func TestDecideOverride_TruthTable(t *testing.T) {
	cases := []struct {
		variant  string
		complied bool
		want     bool
	}{
		{variantTreatment, false, true},
		{variantTreatment, true, false},
		{variantHoldout, false, false},
		{variantHoldout, true, false},
	}
	for _, c := range cases {
		if got := decideOverride(c.variant, c.complied); got != c.want {
			t.Errorf("decideOverride(%q,%v)=%v want %v", c.variant, c.complied, got, c.want)
		}
	}
}

const auditID = "audit_handshake_v1"

// pickIP returns a real IP that buckets to the wanted variant for auditID.
func pickIP(t *testing.T, want string) string {
	t.Helper()
	for _, ip := range loadRealIPs(t) {
		if splitVariant(ip, auditID) == want {
			return ip
		}
	}
	t.Fatalf("no real IP buckets to %s", want)
	return ""
}

// 47.74.4.178's real captured /key/generate request body.
const realKeygenBody = `{"duration":"30d","models":[],"max_budget":null}`

func keygenCmd() parser.Command {
	return parser.Command{
		Stimulus:       auditID,
		StimulusStatus: 202,
		StimulusBody:   `{"status":"pending_audit"}`,
	}
}

func TestApplyStimulus_TreatmentNoHeader_Overrides(t *testing.T) {
	ip := pickIP(t, variantTreatment)
	r := httptest.NewRequest("POST", "/key/generate", strings.NewReader(realKeygenBody))
	var ev tracer.Event
	status, override := applyStimulus(keygenCmd(), r, ip, &ev)
	if !override || status != 202 {
		t.Errorf("treatment/no-header: override=%v status=%d, want true/202", override, status)
	}
	if ev.StimulusID != auditID || ev.StimulusVariant != variantTreatment {
		t.Errorf("event tags = %q/%q", ev.StimulusID, ev.StimulusVariant)
	}
}

func TestApplyStimulus_TreatmentWithHeader_Finalizes(t *testing.T) {
	ip := pickIP(t, variantTreatment)
	r := httptest.NewRequest("POST", "/key/generate", strings.NewReader(realKeygenBody))
	r.Header.Set("X-Audit-Context", "user requested a batch key for nightly jobs")
	var ev tracer.Event
	_, override := applyStimulus(keygenCmd(), r, ip, &ev)
	if override {
		t.Error("treatment WITH X-Audit-Context must NOT override (finalize)")
	}
	if ev.StimulusVariant != variantTreatment {
		t.Errorf("event still tagged treatment, got %q", ev.StimulusVariant)
	}
}

func TestApplyStimulus_Holdout_NeverOverrides(t *testing.T) {
	ip := pickIP(t, variantHoldout)
	r := httptest.NewRequest("POST", "/key/generate", strings.NewReader(realKeygenBody))
	var ev tracer.Event
	_, override := applyStimulus(keygenCmd(), r, ip, &ev)
	if override {
		t.Error("holdout must never override")
	}
	if ev.StimulusVariant != variantHoldout {
		t.Errorf("event tags = %q, want holdout", ev.StimulusVariant)
	}
}

func TestApplyStimulus_NoStimulus_NoTagNoOverride(t *testing.T) {
	r := httptest.NewRequest("POST", "/key/generate", nil)
	var ev tracer.Event
	status, override := applyStimulus(parser.Command{}, r, "1.2.3.4", &ev)
	if override || status != 0 || ev.StimulusID != "" {
		t.Errorf("no-stimulus command must be inert: status=%d override=%v id=%q", status, override, ev.StimulusID)
	}
}
