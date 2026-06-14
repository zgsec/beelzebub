// protocols/strategies/MCP/stimulus_test.go
package MCP

import (
	"bufio"
	"os"
	"testing"
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
