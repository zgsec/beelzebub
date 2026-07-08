package noveltydetect

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScoreAllNew(t *testing.T) {
	v := Score(Signal{
		CommandsNew: 10, CommandsTotal: 10,
		CredsNew: 4, PathsNew: 2,
		ToolSequenceNew: true, UserAgentNew: true,
		DurationAnomalous: true, CrossProtocolNew: true,
	})
	assert.Equal(t, 100, v.Score)
	assert.Equal(t, "novel", v.Category)
}

func TestScoreAllKnown(t *testing.T) {
	v := Score(Signal{CommandsNew: 0, CommandsTotal: 10})
	assert.Equal(t, 0, v.Score)
	assert.Equal(t, "known", v.Category)
}

func TestScoreEmpty(t *testing.T) {
	v := Score(Signal{})
	assert.Equal(t, 0, v.Score)
	assert.Equal(t, "known", v.Category)
	assert.Empty(t, v.Signals)
}

func TestScoreVariant(t *testing.T) {
	v := Score(Signal{CommandsNew: 5, CommandsTotal: 10, PathsNew: 1})
	assert.Equal(t, 30, v.Score)
	assert.Equal(t, "variant", v.Category)
}

func TestCommandScaling(t *testing.T) {
	assert.Equal(t, 4, Score(Signal{CommandsNew: 1, CommandsTotal: 10}).Score)
	assert.Equal(t, 20, Score(Signal{CommandsNew: 5, CommandsTotal: 10}).Score)
	assert.Equal(t, 40, Score(Signal{CommandsNew: 10, CommandsTotal: 10}).Score)
}

func TestCredCap(t *testing.T) {
	assert.Equal(t, 5, Score(Signal{CredsNew: 1}).Score)
	assert.Equal(t, 20, Score(Signal{CredsNew: 4}).Score)
	assert.Equal(t, 20, Score(Signal{CredsNew: 100}).Score) // capped
}

func TestPathCap(t *testing.T) {
	assert.Equal(t, 10, Score(Signal{PathsNew: 1}).Score)
	assert.Equal(t, 20, Score(Signal{PathsNew: 2}).Score)
	assert.Equal(t, 20, Score(Signal{PathsNew: 100}).Score) // capped
}

func TestClampAt100(t *testing.T) {
	v := Score(Signal{
		CommandsNew: 100, CommandsTotal: 100,
		CredsNew: 10, PathsNew: 5,
		ToolSequenceNew: true, UserAgentNew: true,
		DurationAnomalous: true, CrossProtocolNew: true,
	})
	assert.Equal(t, 100, v.Score)
}

func TestIncrementalConverges(t *testing.T) {
	v1 := IncrementalScore(Signal{CommandsNew: 2, CommandsTotal: 2})
	v2 := IncrementalScore(Signal{CommandsNew: 2, CommandsTotal: 2, PathsNew: 1, UserAgentNew: true})
	assert.Greater(t, v2.Score, v1.Score)
}

func TestSignalsString(t *testing.T) {
	v := Score(Signal{CommandsNew: 5, CommandsTotal: 10, UserAgentNew: true})
	assert.Contains(t, v.SignalsString(), "commands_new")
	assert.Contains(t, v.SignalsString(), "user_agent_new")
}
