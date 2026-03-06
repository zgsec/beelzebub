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
