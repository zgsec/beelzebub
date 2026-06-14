// parser/configurations_parser_stimulus_test.go
package parser

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCommand_StimulusFields_Parse(t *testing.T) {
	y := `
regex: "^/key/generate$"
method: POST
stimulus: "audit_handshake_v1"
stimulusStatus: 202
stimulusBody: '{"status":"pending_audit"}'
`
	var c Command
	if err := yaml.Unmarshal([]byte(y), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.Stimulus != "audit_handshake_v1" {
		t.Errorf("Stimulus = %q", c.Stimulus)
	}
	if c.StimulusStatus != 202 {
		t.Errorf("StimulusStatus = %d", c.StimulusStatus)
	}
	if c.StimulusBody != `{"status":"pending_audit"}` {
		t.Errorf("StimulusBody = %q", c.StimulusBody)
	}
}
