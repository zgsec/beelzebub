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
//
// Weights: commands 40, credentials 20, paths 20, tool sequence 15,
// duration 10, cross-protocol 10, user agent 5. Category thresholds:
// novel >= 70, variant >= 30, known < 30.
func Score(sig Signal) Verdict {
	score := 0
	var signals []string

	if sig.CommandsTotal > 0 {
		cs := (sig.CommandsNew * 40) / sig.CommandsTotal
		if cs > 40 {
			cs = 40
		}
		if cs > 0 {
			score += cs
			signals = append(signals, fmt.Sprintf("commands_new(%d/%d)", sig.CommandsNew, sig.CommandsTotal))
		}
	}

	if sig.CredsNew > 0 {
		cs := sig.CredsNew * 5
		if cs > 20 {
			cs = 20
		}
		score += cs
		signals = append(signals, fmt.Sprintf("creds_new(%d)", sig.CredsNew))
	}

	if sig.PathsNew > 0 {
		ps := sig.PathsNew * 10
		if ps > 20 {
			ps = 20
		}
		score += ps
		signals = append(signals, fmt.Sprintf("paths_new(%d)", sig.PathsNew))
	}

	if sig.ToolSequenceNew {
		score += 15
		signals = append(signals, "tool_sequence_new")
	}
	if sig.DurationAnomalous {
		score += 10
		signals = append(signals, "duration_anomalous")
	}
	if sig.CrossProtocolNew {
		score += 10
		signals = append(signals, "cross_protocol_new")
	}
	if sig.UserAgentNew {
		score += 5
		signals = append(signals, "user_agent_new")
	}

	if score > 100 {
		score = 100
	}

	category := "known"
	if score >= 70 {
		category = "novel"
	} else if score >= 30 {
		category = "variant"
	}

	return Verdict{Score: score, Category: category, Signals: signals}
}

// IncrementalScore is an alias for Score — callers pass partial signals
// and understand the score may increase as more events arrive.
func IncrementalScore(sig Signal) Verdict {
	return Score(sig)
}

// SignalsString formats a Verdict's signals as a comma-separated string.
func (v Verdict) SignalsString() string {
	return strings.Join(v.Signals, ",")
}
