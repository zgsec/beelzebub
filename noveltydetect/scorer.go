package noveltydetect

import (
	"fmt"
	"strings"
)

// Signal contains per-session novelty metrics accumulated during event processing.
type Signal struct {
	CommandsNew       int
	CommandsTotal     int
	CredsNew          int
	PathsNew          int
	ToolSequenceNew   bool
	UserAgentNew      bool
	DurationAnomalous bool
	CrossProtocolNew  bool
}

// Verdict is the result of novelty scoring.
type Verdict struct {
	Score    int      // 0-100 (100 = completely novel)
	Category string   // "novel", "variant", "known"
	Signals  []string
}

// Score computes a full session novelty score from accumulated signals.
func Score(sig Signal) Verdict {
	score := 0
	var signals []string

	// Command novelty: up to 40 points
	if sig.CommandsTotal > 0 {
		cmdScore := (sig.CommandsNew * 40) / sig.CommandsTotal
		if cmdScore > 40 {
			cmdScore = 40
		}
		if cmdScore > 0 {
			score += cmdScore
			signals = append(signals, fmt.Sprintf("commands_new(%d/%d)", sig.CommandsNew, sig.CommandsTotal))
		}
	}

	// Credential novelty: up to 20 points (5 per new pair)
	if sig.CredsNew > 0 {
		credScore := sig.CredsNew * 5
		if credScore > 20 {
			credScore = 20
		}
		score += credScore
		signals = append(signals, fmt.Sprintf("creds_new(%d)", sig.CredsNew))
	}

	// Path novelty: up to 20 points (10 per new path)
	if sig.PathsNew > 0 {
		pathScore := sig.PathsNew * 10
		if pathScore > 20 {
			pathScore = 20
		}
		score += pathScore
		signals = append(signals, fmt.Sprintf("paths_new(%d)", sig.PathsNew))
	}

	// Tool sequence novelty: 15 points
	if sig.ToolSequenceNew {
		score += 15
		signals = append(signals, "tool_sequence_new")
	}

	// Duration anomaly: 10 points
	if sig.DurationAnomalous {
		score += 10
		signals = append(signals, "duration_anomalous")
	}

	// Cross-protocol novelty: 10 points
	if sig.CrossProtocolNew {
		score += 10
		signals = append(signals, "cross_protocol_new")
	}

	// User agent novelty: 5 points
	if sig.UserAgentNew {
		score += 5
		signals = append(signals, "user_agent_new")
	}

	// Clamp 0-100
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	category := "known"
	switch {
	case score >= 70:
		category = "novel"
	case score >= 30:
		category = "variant"
	}

	return Verdict{
		Score:    score,
		Category: category,
		Signals:  signals,
	}
}

// IncrementalScore computes a partial score from signals available so far.
// Unlike Score(), it doesn't penalize for missing signals — useful for
// per-event scoring that converges as more data arrives.
func IncrementalScore(sig Signal) Verdict {
	// Same logic as Score — the difference is conceptual: callers pass
	// partial signals and understand the score may increase.
	return Score(sig)
}

// SignalsString formats a Verdict's signals as a comma-separated string.
func (v Verdict) SignalsString() string {
	return strings.Join(v.Signals, ",")
}
