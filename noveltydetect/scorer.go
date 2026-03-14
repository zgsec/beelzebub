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

// Weights controls how much each signal contributes to the novelty score.
// All weights are capped individually, then summed and clamped to 0-100.
// Operators should tune these based on their deployment's traffic profile.
type Weights struct {
	CommandMax      int // max points from command novelty (ratio-scaled)
	CredPerNew      int // points per new credential pair
	CredMax         int // cap on credential points
	PathPerNew      int // points per new path
	PathMax         int // cap on path points
	ToolSequence    int // flat bonus for new tool sequence
	DurationAnomaly int // flat bonus for anomalous duration
	CrossProtocol   int // flat bonus for cross-protocol novelty
	UserAgent       int // flat bonus for new user agent
}

// Config controls scoring behavior. Pass to NewScorer().
type Config struct {
	Weights          Weights
	NovelThreshold   int // score >= this → "novel" (default 70)
	VariantThreshold int // score >= this → "variant" (default 30)
}

// DefaultConfig returns weights balanced across SSH, HTTP, and MCP traffic.
// These are starting points — operators should tune based on their deployment.
func DefaultConfig() Config {
	return Config{
		Weights: Weights{
			CommandMax:      40,
			CredPerNew:      5,
			CredMax:         20,
			PathPerNew:      10,
			PathMax:         20,
			ToolSequence:    15,
			DurationAnomaly: 10,
			CrossProtocol:   10,
			UserAgent:       5,
		},
		NovelThreshold:   70,
		VariantThreshold: 30,
	}
}

// Scorer computes novelty verdicts using configurable weights and thresholds.
type Scorer struct {
	cfg Config
}

// NewScorer creates a Scorer with the given config.
func NewScorer(cfg Config) *Scorer {
	return &Scorer{cfg: cfg}
}

// Score computes a full session novelty score from accumulated signals.
func (s *Scorer) Score(sig Signal) Verdict {
	w := s.cfg.Weights
	score := 0
	var signals []string

	// Command novelty: ratio-scaled up to CommandMax
	if sig.CommandsTotal > 0 && w.CommandMax > 0 {
		cmdScore := (sig.CommandsNew * w.CommandMax) / sig.CommandsTotal
		if cmdScore > w.CommandMax {
			cmdScore = w.CommandMax
		}
		if cmdScore > 0 {
			score += cmdScore
			signals = append(signals, fmt.Sprintf("commands_new(%d/%d)", sig.CommandsNew, sig.CommandsTotal))
		}
	}

	// Credential novelty: per-new with cap
	if sig.CredsNew > 0 && w.CredPerNew > 0 {
		credScore := sig.CredsNew * w.CredPerNew
		if credScore > w.CredMax {
			credScore = w.CredMax
		}
		score += credScore
		signals = append(signals, fmt.Sprintf("creds_new(%d)", sig.CredsNew))
	}

	// Path novelty: per-new with cap
	if sig.PathsNew > 0 && w.PathPerNew > 0 {
		pathScore := sig.PathsNew * w.PathPerNew
		if pathScore > w.PathMax {
			pathScore = w.PathMax
		}
		score += pathScore
		signals = append(signals, fmt.Sprintf("paths_new(%d)", sig.PathsNew))
	}

	// Tool sequence novelty
	if sig.ToolSequenceNew && w.ToolSequence > 0 {
		score += w.ToolSequence
		signals = append(signals, "tool_sequence_new")
	}

	// Duration anomaly
	if sig.DurationAnomalous && w.DurationAnomaly > 0 {
		score += w.DurationAnomaly
		signals = append(signals, "duration_anomalous")
	}

	// Cross-protocol novelty
	if sig.CrossProtocolNew && w.CrossProtocol > 0 {
		score += w.CrossProtocol
		signals = append(signals, "cross_protocol_new")
	}

	// User agent novelty
	if sig.UserAgentNew && w.UserAgent > 0 {
		score += w.UserAgent
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
	case score >= s.cfg.NovelThreshold:
		category = "novel"
	case score >= s.cfg.VariantThreshold:
		category = "variant"
	}

	return Verdict{
		Score:    score,
		Category: category,
		Signals:  signals,
	}
}

// IncrementalScore computes a partial score from signals available so far.
// Same algorithm as Score — callers pass partial signals and understand
// the score may increase as more events arrive.
func (s *Scorer) IncrementalScore(sig Signal) Verdict {
	return s.Score(sig)
}

// --- Package-level convenience functions using DefaultConfig ---

// Score computes a novelty score using default weights.
func Score(sig Signal) Verdict {
	return defaultScorer.Score(sig)
}

// IncrementalScore computes a partial novelty score using default weights.
func IncrementalScore(sig Signal) Verdict {
	return defaultScorer.IncrementalScore(sig)
}

var defaultScorer = NewScorer(DefaultConfig())

// SignalsString formats a Verdict's signals as a comma-separated string.
func (v Verdict) SignalsString() string {
	return strings.Join(v.Signals, ",")
}
