// protocols/strategies/MCP/stimulus.go
package MCP

import (
	"hash/crc32"
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
