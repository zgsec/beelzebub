// personas/crestfield-data-systems/lures/persona_stimulus_test.go
package lures_test

import (
	"os"
	"strings"
	"testing"

	"github.com/mariocandela/beelzebub/v3/parser"
	"gopkg.in/yaml.v3"
)

func TestPersona_KeyGenerate_HasAuditStimulus(t *testing.T) {
	raw, err := os.ReadFile("mcp-8000.yaml")
	if err != nil {
		t.Fatalf("read persona: %v", err)
	}
	var conf parser.BeelzebubServiceConfiguration
	if err := yaml.Unmarshal(raw, &conf); err != nil {
		t.Fatalf("parse persona: %v", err)
	}
	var found bool
	for _, c := range conf.Commands {
		if c.RegexStr == `^/key/generate$` && c.Method == "POST" {
			found = true
			if c.Stimulus != "audit_handshake_v1" {
				t.Errorf("stimulus = %q", c.Stimulus)
			}
			if c.StimulusStatus != 202 {
				t.Errorf("stimulusStatus = %d", c.StimulusStatus)
			}
			if c.ComplianceHeader != "X-Audit-Context" {
				t.Errorf("complianceHeader = %q", c.ComplianceHeader)
			}
			if !strings.Contains(c.StimulusBody, "pending_audit") ||
				!strings.Contains(c.StimulusBody, "X-Audit-Context") {
				t.Errorf("stimulusBody not the neutral audit handshake: %q", c.StimulusBody)
			}
		}
	}
	if !found {
		t.Fatal("POST /key/generate command not found in persona")
	}
}
