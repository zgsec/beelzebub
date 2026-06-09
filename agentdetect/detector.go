package agentdetect

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// Signal contains session-level metrics for agent classification.
type Signal struct {
	HasMCPInitialize     bool
	ToolChainDepth       int
	InterEventTimingsMs  []int64
	HasIdenticalRetries  bool
	HasCrossProtocol     bool
	CrossProtocolGapMs   int64
	HasCommandCorrection bool
	HasAIDiscoveryProbe  bool
}

// Verdict is the result of agent classification.
type Verdict struct {
	Score    int
	Category string // "agent", "bot", "human", "unknown"
	Signals  []string
}

// accumulate scores the signals present in sig and returns (score, labels).
//
// It is the single source of truth for the additive model, shared by both
// Classify and IncrementalClassify so the two can never drift. Two weights are
// graded rather than thresholded:
//
//   - mechanical timing scores continuously on a robust coefficient of
//     variation (median absolute deviation / median) instead of the old
//     mean<2000 && stddev<500 cliff, so magnitude is preserved and a few
//     burst/idle outliers cannot flip the verdict;
//   - tool-chain depth saturates above the threshold of 3 so a 65-deep chain
//     outscores a 3-deep one instead of both tying at a flat +20.
func accumulate(sig Signal) (int, []string) {
	score := 0
	var signals []string

	// MCP initialize handshake is a strong agent signal.
	if sig.HasMCPInitialize {
		score += 40
		signals = append(signals, "mcp_handshake")
	}

	// Mechanical timing, graded on a robust coefficient of variation.
	// Require >= 3 samples: with 1 sample dispersion is unobservable and with
	// 2 it is fragile. Three is the statistical minimum for meaningful spread.
	if len(sig.InterEventTimingsMs) >= 3 {
		med, rcv := robustTiming(sig.InterEventTimingsMs)
		// fRegular: 1.0 at rcv<=0 (perfectly periodic, machine), ramping to 0
		// at rcv>=0.5 (human-grade cadence variability).
		fRegular := clamp01(1.0 - rcv/0.5)
		if pts := int(math.Round(25 * fRegular)); pts > 0 {
			score += pts
			signals = append(signals, fmt.Sprintf("mechanical_timing(med=%.0f,rcv=%.2f,+%d)", med, rcv, pts))
		}
	}

	// Cross-protocol pivot within 60 seconds.
	if sig.HasCrossProtocol && sig.CrossProtocolGapMs > 0 && sig.CrossProtocolGapMs < 60000 {
		score += 15
		signals = append(signals, "cross_protocol_pivot")
	}

	// Identical retries (agents retry the same command verbatim).
	if sig.HasIdenticalRetries {
		score += 15
		signals = append(signals, "identical_retries")
	}

	// AI plugin / MCP discovery probing.
	if sig.HasAIDiscoveryProbe {
		score += 20
		signals = append(signals, "ai_discovery_probe")
	}

	// Tool-chain depth >= 3, saturating above the threshold.
	// depth 3 -> +12, depth 8 -> ~+17, depth 65 -> ~+20.
	if sig.ToolChainDepth >= 3 {
		pts := int(math.Round(12 + 8*(1-math.Exp(-float64(sig.ToolChainDepth-3)/5.0))))
		score += pts
		signals = append(signals, fmt.Sprintf("tool_chain_depth(%d,+%d)", sig.ToolChainDepth, pts))
	}

	// Command corrections are a human signal.
	if sig.HasCommandCorrection {
		score -= 20
		signals = append(signals, "command_correction(-)")
	}

	// Clamp to 0-100.
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score, signals
}

// Classify analyzes a full session's signals and produces a verdict. It only
// emits "human" when at least 3 inter-event timings were observed, since with
// fewer samples a low score reflects absence of evidence, not human cadence.
func Classify(sig Signal) Verdict {
	score, signals := accumulate(sig)

	category := "unknown"
	switch {
	case score >= 60:
		category = "agent"
	case score >= 30:
		category = "bot"
	case score < 30 && len(sig.InterEventTimingsMs) >= 3:
		category = "human"
	}

	return Verdict{Score: score, Category: category, Signals: signals}
}

// IncrementalClassify produces a verdict from partial signals accumulated so
// far. Unlike Classify it does not require timing evidence to label "human": a
// non-zero but low score from early events reads as human-tier until more
// agent signals arrive and push it up.
func IncrementalClassify(sig Signal) Verdict {
	score, signals := accumulate(sig)

	category := "unknown"
	if score > 0 {
		switch {
		case score >= 60:
			category = "agent"
		case score >= 30:
			category = "bot"
		default:
			category = "human"
		}
	}

	return Verdict{Score: score, Category: category, Signals: signals}
}

// SignalsString formats a Verdict's signals as a comma-separated string.
func (v Verdict) SignalsString() string {
	return strings.Join(v.Signals, ",")
}

func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

// robustTiming returns the median inter-event gap and a robust coefficient of
// variation (median absolute deviation / median). Robust statistics are used in
// place of mean/stddev so that a handful of burst or idle outliers, common in
// real sessions, cannot dominate the dispersion estimate and flip the verdict.
func robustTiming(timings []int64) (median, robustCV float64) {
	n := len(timings)
	if n == 0 {
		return 0, 0
	}
	xs := make([]float64, n)
	for i, t := range timings {
		xs[i] = float64(t)
	}
	median = medianOf(xs)
	if median <= 0 {
		return median, 0
	}
	devs := make([]float64, n)
	for i, x := range xs {
		devs[i] = math.Abs(x - median)
	}
	mad := medianOf(devs)
	return median, mad / median
}

func medianOf(xs []float64) float64 {
	n := len(xs)
	if n == 0 {
		return 0
	}
	c := make([]float64, n)
	copy(c, xs)
	sort.Float64s(c)
	if n%2 == 1 {
		return c[n/2]
	}
	return (c[n/2-1] + c[n/2]) / 2
}
