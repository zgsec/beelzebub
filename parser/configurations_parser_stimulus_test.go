// parser/configurations_parser_stimulus_test.go
package parser

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestCompileCommandRegex_StateHandlerAndStimulus_MutuallyExclusive verifies that
// CompileCommandRegex rejects a command that sets both stateHandler and stimulus
// (a dangerous config: the state handler would mutate WorldState but then be
// silently overwritten by the stimulus override).
func TestCompileCommandRegex_StateHandlerAndStimulus_MutuallyExclusive(t *testing.T) {
	t.Run("both fields set → error mentioning mutually exclusive", func(t *testing.T) {
		conf := BeelzebubServiceConfiguration{
			Commands: []Command{{
				Name:         "bad-command",
				RegexStr:     `^/key/generate$`,
				StateHandler: "userUpdateHandler",
				Stimulus:     "audit_handshake_v1",
				StimulusBody: `{"status":"pending_audit"}`,
			}},
		}
		err := conf.CompileCommandRegex()
		if err == nil {
			t.Fatal("expected an error for stateHandler+stimulus co-occurrence, got nil")
		}
		if !strings.Contains(err.Error(), "mutually exclusive") {
			t.Errorf("error should mention 'mutually exclusive', got: %v", err)
		}
	})

	t.Run("stimulus only (no stateHandler) → no error", func(t *testing.T) {
		conf := BeelzebubServiceConfiguration{
			Commands: []Command{{
				Name:           "ok-command",
				RegexStr:       `^/key/generate$`,
				Stimulus:       "audit_handshake_v1",
				StimulusStatus: 202,
				StimulusBody:   `{"status":"pending_audit"}`,
			}},
		}
		if err := conf.CompileCommandRegex(); err != nil {
			t.Errorf("stimulus-only command should compile without error, got: %v", err)
		}
	})
}

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
