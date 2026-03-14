package noveltydetect

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScoreNovelSession(t *testing.T) {
	sig := Signal{
		CommandsNew:       10,
		CommandsTotal:     10,
		CredsNew:          4,
		PathsNew:          2,
		ToolSequenceNew:   true,
		UserAgentNew:      true,
		DurationAnomalous: true,
		CrossProtocolNew:  true,
	}
	v := Score(sig)
	assert.Equal(t, "novel", v.Category)
	assert.GreaterOrEqual(t, v.Score, 70)
	assert.LessOrEqual(t, v.Score, 100)
}

func TestScoreKnownSession(t *testing.T) {
	sig := Signal{
		CommandsNew:   0,
		CommandsTotal: 10,
	}
	v := Score(sig)
	assert.Equal(t, "known", v.Category)
	assert.Less(t, v.Score, 30)
}

func TestScoreVariantSession(t *testing.T) {
	sig := Signal{
		CommandsNew:   5,
		CommandsTotal: 10,
		PathsNew:      1,
	}
	v := Score(sig)
	assert.Equal(t, "variant", v.Category)
	assert.GreaterOrEqual(t, v.Score, 30)
	assert.Less(t, v.Score, 70)
}

func TestScoreClamping(t *testing.T) {
	// Max out all signals — should clamp to 100
	sig := Signal{
		CommandsNew:       100,
		CommandsTotal:     100,
		CredsNew:          10,
		PathsNew:          5,
		ToolSequenceNew:   true,
		UserAgentNew:      true,
		DurationAnomalous: true,
		CrossProtocolNew:  true,
	}
	v := Score(sig)
	assert.Equal(t, 100, v.Score)
}

func TestScoreEmptySignals(t *testing.T) {
	v := Score(Signal{})
	assert.Equal(t, 0, v.Score)
	assert.Equal(t, "known", v.Category)
	assert.Empty(t, v.Signals)
}

func TestCommandNoveltyScaling(t *testing.T) {
	// 5/10 new commands = 20 points
	sig := Signal{CommandsNew: 5, CommandsTotal: 10}
	v := Score(sig)
	assert.Equal(t, 20, v.Score)

	// 1/10 = 4 points
	sig2 := Signal{CommandsNew: 1, CommandsTotal: 10}
	v2 := Score(sig2)
	assert.Equal(t, 4, v2.Score)
}

func TestCredentialNoveltyScaling(t *testing.T) {
	// 1 new = 5, 4 new = 20 (max)
	v1 := Score(Signal{CredsNew: 1})
	assert.Equal(t, 5, v1.Score)

	v4 := Score(Signal{CredsNew: 4})
	assert.Equal(t, 20, v4.Score)

	// 10 new still capped at 20
	v10 := Score(Signal{CredsNew: 10})
	assert.Equal(t, 20, v10.Score)
}

func TestIncrementalScoreConverges(t *testing.T) {
	// Start with partial info
	sig1 := Signal{CommandsNew: 2, CommandsTotal: 2}
	v1 := IncrementalScore(sig1)

	// Add more signals
	sig2 := Signal{CommandsNew: 2, CommandsTotal: 2, PathsNew: 1, UserAgentNew: true}
	v2 := IncrementalScore(sig2)

	assert.Greater(t, v2.Score, v1.Score)
}

func TestSignalsString(t *testing.T) {
	v := Score(Signal{CommandsNew: 5, CommandsTotal: 10, UserAgentNew: true})
	s := v.SignalsString()
	assert.Contains(t, s, "commands_new")
	assert.Contains(t, s, "user_agent_new")
}

func TestCategoryThresholds(t *testing.T) {
	// Exactly 70 = novel
	sig70 := Signal{CommandsNew: 10, CommandsTotal: 10, CredsNew: 4, PathsNew: 1, UserAgentNew: true}
	v70 := Score(sig70)
	assert.Equal(t, "novel", v70.Category)

	// Exactly 30 = variant (30 = 20 cmd + 10 path)
	sig30 := Signal{CommandsNew: 5, CommandsTotal: 10, PathsNew: 1}
	v30 := Score(sig30)
	assert.Equal(t, "variant", v30.Category)
	assert.Equal(t, 30, v30.Score)
}
