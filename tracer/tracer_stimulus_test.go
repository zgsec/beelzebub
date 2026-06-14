// tracer/tracer_stimulus_test.go
package tracer

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEvent_StimulusFields_Marshal(t *testing.T) {
	e := Event{StimulusID: "audit_handshake_v1", StimulusVariant: "treatment"}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, `"StimulusID":"audit_handshake_v1"`) {
		t.Errorf("StimulusID not in JSON: %s", s)
	}
	if !strings.Contains(s, `"StimulusVariant":"treatment"`) {
		t.Errorf("StimulusVariant not in JSON: %s", s)
	}
	// omitempty: an empty Event must NOT carry the keys.
	b2, _ := json.Marshal(Event{})
	if strings.Contains(string(b2), "Stimulus") {
		t.Errorf("empty event leaked stimulus keys: %s", b2)
	}
}
