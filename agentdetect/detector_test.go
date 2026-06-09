package agentdetect

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClassifyAgent_MCPWithFastTiming(t *testing.T) {
	sig := Signal{
		HasMCPInitialize:    true,
		ToolChainDepth:      5,
		InterEventTimingsMs: []int64{100, 120, 110, 105, 115, 108, 112, 107, 103, 118},
		HasIdenticalRetries: false,
	}
	v := Classify(sig)
	assert.GreaterOrEqual(t, v.Score, 60)
	assert.Equal(t, "agent", v.Category)
	assert.Contains(t, v.SignalsString(), "mcp_handshake")
	assert.Contains(t, v.SignalsString(), "mechanical_timing")
	assert.Contains(t, v.SignalsString(), "tool_chain_depth")
}

func TestClassifyHuman_SlowTimingWithCorrections(t *testing.T) {
	sig := Signal{
		HasMCPInitialize:     false,
		ToolChainDepth:       1,
		InterEventTimingsMs:  []int64{3500, 12000, 8000, 5000, 30000},
		HasCommandCorrection: true,
	}
	v := Classify(sig)
	assert.Less(t, v.Score, 30)
	assert.Equal(t, "human", v.Category)
}

func TestClassifyBot_ModerateSignals(t *testing.T) {
	sig := Signal{
		HasMCPInitialize:    false,
		ToolChainDepth:      0,
		InterEventTimingsMs: []int64{100, 100, 100},
		HasIdenticalRetries: true,
	}
	v := Classify(sig)
	assert.GreaterOrEqual(t, v.Score, 30)
	assert.LessOrEqual(t, v.Score, 59)
	assert.Equal(t, "bot", v.Category)
}

func TestClassifyCrossProtocolPivot(t *testing.T) {
	sig := Signal{
		HasCrossProtocol:    true,
		CrossProtocolGapMs:  5000,
		HasMCPInitialize:    true,
		InterEventTimingsMs: []int64{200, 300, 250},
		ToolChainDepth:      3,
	}
	v := Classify(sig)
	assert.Contains(t, v.SignalsString(), "cross_protocol_pivot")
	assert.Equal(t, "agent", v.Category)
}

func TestScoreClampedTo100(t *testing.T) {
	sig := Signal{
		HasMCPInitialize:    true,
		HasIdenticalRetries: true,
		HasCrossProtocol:    true,
		CrossProtocolGapMs:  1000,
		HasAIDiscoveryProbe: true,
		ToolChainDepth:      5,
		InterEventTimingsMs: []int64{100, 100, 100},
	}
	v := Classify(sig)
	assert.LessOrEqual(t, v.Score, 100)
}

func TestScoreClampedTo0(t *testing.T) {
	sig := Signal{
		HasCommandCorrection: true,
		InterEventTimingsMs:  []int64{10000, 20000, 15000},
	}
	v := Classify(sig)
	assert.GreaterOrEqual(t, v.Score, 0)
}

func TestUnknownWithNoTimings(t *testing.T) {
	sig := Signal{}
	v := Classify(sig)
	assert.Equal(t, "unknown", v.Category)
}

// IncrementalClassify tests — verify timing threshold requires 3+ samples

func TestIncrementalClassify_SingleTimingSample_NoMechanicalTiming(t *testing.T) {
	// Production case: SSH bot sends one command, delta=6ms.
	// With 1 sample, stddev is always 0 — no variance observable.
	// mechanical_timing must NOT fire.
	sig := Signal{
		InterEventTimingsMs: []int64{6},
	}
	v := IncrementalClassify(sig)
	assert.Equal(t, 0, v.Score)
	assert.Equal(t, "unknown", v.Category)
	assert.NotContains(t, v.SignalsString(), "mechanical_timing")
}

func TestIncrementalClassify_TwoTimingSamples_NoMechanicalTiming(t *testing.T) {
	// Two samples: Bessel's correction with n-1=1 is fragile.
	// Can't distinguish "consistently fast" from "coincidentally fast".
	sig := Signal{
		InterEventTimingsMs: []int64{100, 110},
	}
	v := IncrementalClassify(sig)
	assert.NotContains(t, v.SignalsString(), "mechanical_timing")
}

func TestIncrementalClassify_ThreeSamples_MechanicalTimingFires(t *testing.T) {
	// Three samples: statistical minimum for meaningful dispersion.
	// Tight clustering should trigger the signal. Timing is now GRADED on a
	// robust coefficient of variation, so near-tight clustering scores close to
	// (but not exactly) the 25-point ceiling: rcv ~= 0.05 here.
	sig := Signal{
		InterEventTimingsMs: []int64{100, 110, 105},
	}
	v := IncrementalClassify(sig)
	assert.Contains(t, v.SignalsString(), "mechanical_timing")
	assert.GreaterOrEqual(t, v.Score, 20)
	assert.LessOrEqual(t, v.Score, 25)
	assert.Equal(t, "human", v.Category) // <30, but score > 0
}

func TestIncrementalClassify_ThreeSamplesHighVariance_NoMechanicalTiming(t *testing.T) {
	// Three samples with high variance — human-like pattern.
	sig := Signal{
		InterEventTimingsMs: []int64{100, 1500, 200},
	}
	v := IncrementalClassify(sig)
	assert.NotContains(t, v.SignalsString(), "mechanical_timing")
}

func TestIncrementalClassify_MCPFirstCall_AgentWithoutTiming(t *testing.T) {
	// MCP first tool call: no timing yet, but mcp_handshake + ai_probe = 60.
	// Exporter takes max score, so this persists as session classification.
	sig := Signal{
		HasMCPInitialize:    true,
		HasAIDiscoveryProbe: true,
	}
	v := IncrementalClassify(sig)
	assert.Equal(t, 60, v.Score)
	assert.Equal(t, "agent", v.Category)
	assert.NotContains(t, v.SignalsString(), "mechanical_timing")
}

// --- v2 scoring: graded depth + robust timing ---------------------------------

func TestSaturatingDepth_DeeperChainScoresHigher(t *testing.T) {
	// Old model: depth 3 and depth 40 both scored a flat +20 and tied. The
	// saturating curve must rank a deep tool chain above a shallow one while
	// both still clear the >=3 threshold.
	base := Signal{HasMCPInitialize: true}
	shallow := base
	shallow.ToolChainDepth = 3
	deep := base
	deep.ToolChainDepth = 40

	vShallow := Classify(shallow)
	vDeep := Classify(deep)

	assert.Greater(t, vDeep.Score, vShallow.Score, "deeper chain must outscore shallow")
	assert.Contains(t, vShallow.SignalsString(), "tool_chain_depth(3")
	assert.Contains(t, vDeep.SignalsString(), "tool_chain_depth(40")
}

func TestGradedTiming_PartialCreditForBorderlineCadence(t *testing.T) {
	// Old model: a hard mean<2000 && stddev<500 cliff gave all-or-nothing. The
	// robust-CV grade must order tight > borderline > irregular cadence.
	base := Signal{HasMCPInitialize: true} // +40 floor so all three are comparable
	tight := base
	tight.InterEventTimingsMs = []int64{100, 100, 100, 100, 100}
	borderline := base
	borderline.InterEventTimingsMs = []int64{200, 800, 300, 900, 250}
	irregular := base
	irregular.InterEventTimingsMs = []int64{100, 9000, 200, 15000}

	st := Classify(tight).Score
	sb := Classify(borderline).Score
	si := Classify(irregular).Score

	assert.Greater(t, st, sb, "tight cadence must outscore borderline")
	assert.Greater(t, sb, si, "borderline cadence must outscore irregular")
}

// --- v2 scoring: confidence + abstention --------------------------------------

func TestConfidence_ThinNonMCPVerdictAbstains(t *testing.T) {
	// 35 points (ai_discovery + identical_retries) but no MCP and no observed
	// timing volume: a strong-looking score on thin evidence must abstain.
	sig := Signal{HasAIDiscoveryProbe: true, HasIdenticalRetries: true}
	v := Classify(sig)
	assert.GreaterOrEqual(t, v.Score, 30)
	assert.Less(t, v.Confidence, abstainThreshold)
	assert.Equal(t, "unknown", v.Category)
}

func TestConfidence_VolumeRescuesVerdict(t *testing.T) {
	// Same signals, but six observed events lift confidence past the bar.
	sig := Signal{
		HasAIDiscoveryProbe: true,
		HasIdenticalRetries: true,
		InterEventTimingsMs: []int64{500, 9000, 600, 12000, 550, 8000},
	}
	v := Classify(sig)
	assert.GreaterOrEqual(t, v.Confidence, abstainThreshold)
	assert.Equal(t, "bot", v.Category)
}

func TestConfidence_MCPExemptFromAbstention(t *testing.T) {
	// One MCP handshake, no timing: thin, but MCP is high-precision, so the
	// verdict is retained rather than abstained.
	sig := Signal{HasMCPInitialize: true}
	v := Classify(sig)
	assert.Less(t, v.Confidence, abstainThreshold)
	assert.Equal(t, "bot", v.Category)
}
