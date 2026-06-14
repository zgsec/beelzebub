// protocols/strategies/MCP/stimulus_capture_test.go
package MCP

import (
	"encoding/json"
	"os"
	"testing"
)

// TestCaptureKeygenEventFixtures is a fixture GENERATOR (not an assertion):
// it emits the real tracer.Event JSON for a treatment and a holdout
// /key/generate request, for Plan B (honeypot.observer collector) to consume.
// Run explicitly: go test ./protocols/strategies/MCP/ -run TestCaptureKeygenEventFixtures
func TestCaptureKeygenEventFixtures(t *testing.T) {
	dir := os.Getenv("OBSERVER_TESTDATA")
	if dir == "" {
		dir = os.Getenv("HOME") + "/projects/honeypot.observer/exporter/testdata"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	write := func(name, ip string, withHeader bool) {
		_, tr := driveKeygen(t, ip, withHeader)
		b, err := json.MarshalIndent(tr.last, "", "  ")
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		// Wrap as the collector reads it: {"event": <tracer.Event>}.
		wrapped := []byte(`{"event": ` + string(b) + `}`)
		if err := os.WriteFile(dir+"/"+name, wrapped, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		if tr.last.StimulusID == "" {
			t.Fatalf("captured event missing StimulusID for %s", name)
		}
		t.Logf("wrote %s/%s (variant=%s)", dir, name, tr.last.StimulusVariant)
	}
	write("event_keygen_treatment.json", pickIP(t, variantTreatment), false)
	write("event_keygen_holdout.json", pickIP(t, variantHoldout), false)
}
