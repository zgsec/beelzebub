// protocols/strategies/MCP/stimulus.go
package MCP

import (
	"hash/crc32"
	"net/http"
	"strings"

	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/tracer"
)

const (
	variantHoldout   = "holdout"
	variantTreatment = "treatment"
)

// splitVariant deterministically assigns a source IP to a cohort for a given
// stimulus. Stable per (ip, stimulusID); keyed by stimulusID so different
// stimuli split independently (no cross-stimulus correlation). ~50/50 over a
// real attacker-IP population (see TestSplitVariant_DistributionOnRealIPs).
func splitVariant(ip, stimulusID string) string {
	if crc32.ChecksumIEEE([]byte(ip+":"+stimulusID))%2 == 0 {
		return variantHoldout
	}
	return variantTreatment
}

// decideOverride: only the treatment cohort that has NOT complied gets the
// stimulus response. Conservative — holdout and complied actors are never
// deviated from the oracle behavior.
func decideOverride(variant string, complied bool) bool {
	return variant == variantTreatment && !complied
}

// compliancePredicates maps a stimulus id to its "has the attacker complied?"
// check. Registry so future stimuli (B/D) slot in. Unknown id => treated as
// complied (fail-safe: never deviate for a stimulus we don't understand).
var compliancePredicates = map[string]func(*http.Request) bool{
	"audit_handshake_v1": func(r *http.Request) bool {
		return strings.TrimSpace(r.Header.Get("X-Audit-Context")) != ""
	},
}

func complied(stimulusID string, r *http.Request) bool {
	pred, ok := compliancePredicates[stimulusID]
	if !ok {
		return true // unknown stimulus -> behave as holdout (no override)
	}
	return pred(r)
}

// applyStimulus tags the event with the stimulus id + cohort (for BOTH cohorts,
// so the holdout is a recorded control), and returns whether to override the
// response (and with what status). Fail-safe: any panic -> no override.
func applyStimulus(cmd parser.Command, r *http.Request, ip string, event *tracer.Event) (status int, override bool) {
	defer func() {
		if rec := recover(); rec != nil {
			status, override = 0, false // never break the lure
		}
	}()
	if cmd.Stimulus == "" {
		return 0, false
	}
	variant := splitVariant(ip, cmd.Stimulus)
	event.StimulusID = cmd.Stimulus
	event.StimulusVariant = variant
	if decideOverride(variant, complied(cmd.Stimulus, r)) {
		return cmd.StimulusStatus, true
	}
	return 0, false
}
