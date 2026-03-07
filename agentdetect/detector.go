package agentdetect

import (
	"fmt"
	"math"
	"strings"
)

// Signal contains session-level metrics for agent classification.
type Signal struct {
	HasMCPInitialize    bool
	ToolChainDepth      int
	InterEventTimingsMs []int64
	HasIdenticalRetries bool
	HasCrossProtocol    bool
	CrossProtocolGapMs  int64
	HasCommandCorrection bool
	HasAIDiscoveryProbe  bool
}

// Verdict is the result of agent classification.
type Verdict struct {
	Score    int
	Category string // "agent", "bot", "human", "unknown"
	Signals  []string
}

// Classify analyzes session signals and produces an agent likelihood verdict.
func Classify(sig Signal) Verdict {
	score := 0
	var signals []string

	// MCP initialize handshake is a strong agent signal
	if sig.HasMCPInitialize {
		score += 40
		signals = append(signals, "mcp_handshake")
	}

	// Mechanical timing: low stddev + low mean
	if len(sig.InterEventTimingsMs) >= 3 {
		mean, stddev := timingStats(sig.InterEventTimingsMs)
		if mean > 0 && mean < 2000 && stddev < 500 {
			score += 25
			signals = append(signals, fmt.Sprintf("mechanical_timing(mean=%.0f,sd=%.0f)", mean, stddev))
		}
	}

	// Cross-protocol pivot within 60 seconds
	if sig.HasCrossProtocol && sig.CrossProtocolGapMs > 0 && sig.CrossProtocolGapMs < 60000 {
		score += 15
		signals = append(signals, "cross_protocol_pivot")
	}

	// Identical retries (agents retry the same command)
	if sig.HasIdenticalRetries {
		score += 15
		signals = append(signals, "identical_retries")
	}

	// AI plugin/MCP discovery probing
	if sig.HasAIDiscoveryProbe {
		score += 20
		signals = append(signals, "ai_discovery_probe")
	}

	// Tool chain depth >= 3 (sequential tool calls showing workflow)
	if sig.ToolChainDepth >= 3 {
		score += 20
		signals = append(signals, fmt.Sprintf("tool_chain_depth(%d)", sig.ToolChainDepth))
	}

	// Command corrections are a human signal
	if sig.HasCommandCorrection {
		score -= 20
		signals = append(signals, "command_correction(-)")
	}

	// Clamp to 0-100
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	category := "unknown"
	switch {
	case score >= 60:
		category = "agent"
	case score >= 30:
		category = "bot"
	case score < 30 && len(sig.InterEventTimingsMs) >= 3:
		category = "human"
	}

	return Verdict{
		Score:    score,
		Category: category,
		Signals:  signals,
	}
}

// SignalsString formats a Verdict's signals as a comma-separated string.
func (v Verdict) SignalsString() string {
	return strings.Join(v.Signals, ",")
}

func timingStats(timings []int64) (mean, stddev float64) {
	if len(timings) < 2 {
		if len(timings) == 1 {
			return float64(timings[0]), 0
		}
		return 0, 0
	}
	var sum float64
	for _, t := range timings {
		sum += float64(t)
	}
	mean = sum / float64(len(timings))

	var sqDiffSum float64
	for _, t := range timings {
		diff := float64(t) - mean
		sqDiffSum += diff * diff
	}
	// Bessel's correction: divide by n-1 for sample stddev.
	// With small samples (3-5 timings), population stddev underestimates
	// variance, inflating false positive agent classifications.
	stddev = math.Sqrt(sqDiffSum / float64(len(timings)-1))
	return
}
