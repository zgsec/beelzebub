package noveltydetect

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// --- Default scorer (package-level functions) ---

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
	sig := Signal{CommandsNew: 5, CommandsTotal: 10}
	v := Score(sig)
	assert.Equal(t, 20, v.Score)

	sig2 := Signal{CommandsNew: 1, CommandsTotal: 10}
	v2 := Score(sig2)
	assert.Equal(t, 4, v2.Score)
}

func TestCredentialNoveltyScaling(t *testing.T) {
	v1 := Score(Signal{CredsNew: 1})
	assert.Equal(t, 5, v1.Score)

	v4 := Score(Signal{CredsNew: 4})
	assert.Equal(t, 20, v4.Score)

	v10 := Score(Signal{CredsNew: 10})
	assert.Equal(t, 20, v10.Score)
}

func TestIncrementalScoreConverges(t *testing.T) {
	sig1 := Signal{CommandsNew: 2, CommandsTotal: 2}
	v1 := IncrementalScore(sig1)

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
	sig70 := Signal{CommandsNew: 10, CommandsTotal: 10, CredsNew: 4, PathsNew: 1, UserAgentNew: true}
	v70 := Score(sig70)
	assert.Equal(t, "novel", v70.Category)

	sig30 := Signal{CommandsNew: 5, CommandsTotal: 10, PathsNew: 1}
	v30 := Score(sig30)
	assert.Equal(t, "variant", v30.Category)
	assert.Equal(t, 30, v30.Score)
}

// --- Custom scorer tests ---

func TestCustomWeights_HTTPOnly(t *testing.T) {
	// Operator running HTTP-only honeypots: boost path and UA, zero out commands/creds
	cfg := Config{
		Weights: Weights{
			CommandMax:   0,
			CredPerNew:   0,
			CredMax:      0,
			PathPerNew:   25,
			PathMax:      60,
			UserAgent:    20,
			ToolSequence: 20,
		},
		NovelThreshold:   70,
		VariantThreshold: 30,
	}
	s := NewScorer(cfg)

	// 3 new paths = 3*25=75, capped at PathMax=60, + UA 20 = 80
	v := s.Score(Signal{PathsNew: 3, UserAgentNew: true})
	assert.Equal(t, "novel", v.Category)
	assert.Equal(t, 80, v.Score)

	// Commands alone produce nothing
	v2 := s.Score(Signal{CommandsNew: 10, CommandsTotal: 10})
	assert.Equal(t, 0, v2.Score)
	assert.Equal(t, "known", v2.Category)
}

func TestCustomWeights_CredHeavy(t *testing.T) {
	// Operator focused on credential novelty (SSH brute-force research)
	cfg := Config{
		Weights: Weights{
			CommandMax: 20,
			CredPerNew: 15,
			CredMax:    60,
			PathPerNew: 5,
			PathMax:    10,
			UserAgent:  10,
		},
		NovelThreshold:   70,
		VariantThreshold: 30,
	}
	s := NewScorer(cfg)

	// 4 new cred pairs = 60 points from creds alone
	v := s.Score(Signal{CredsNew: 4})
	assert.Equal(t, 60, v.Score)
	assert.Equal(t, "variant", v.Category)

	// 5 new cred pairs still capped at 60
	v2 := s.Score(Signal{CredsNew: 5})
	assert.Equal(t, 60, v2.Score)

	// 4 creds + new UA = 70 → novel
	v3 := s.Score(Signal{CredsNew: 4, UserAgentNew: true})
	assert.Equal(t, 70, v3.Score)
	assert.Equal(t, "novel", v3.Category)
}

func TestCustomThresholds(t *testing.T) {
	// Conservative operator: only flag very high novelty
	cfg := DefaultConfig()
	cfg.NovelThreshold = 90
	cfg.VariantThreshold = 50
	s := NewScorer(cfg)

	// Score 70 would be "novel" with defaults, but "variant" here
	sig := Signal{CommandsNew: 10, CommandsTotal: 10, CredsNew: 4, PathsNew: 1, UserAgentNew: true}
	v := s.Score(sig)
	assert.Equal(t, "variant", v.Category)
	assert.GreaterOrEqual(t, v.Score, 70)
}

func TestZeroWeightsProduceZero(t *testing.T) {
	// All weights zero = everything scores 0
	s := NewScorer(Config{Weights: Weights{}, NovelThreshold: 70, VariantThreshold: 30})
	v := s.Score(Signal{
		CommandsNew: 10, CommandsTotal: 10,
		CredsNew: 5, PathsNew: 3,
		ToolSequenceNew: true, UserAgentNew: true,
		DurationAnomalous: true, CrossProtocolNew: true,
	})
	assert.Equal(t, 0, v.Score)
	assert.Equal(t, "known", v.Category)
	assert.Empty(t, v.Signals)
}

func TestDefaultConfigMatchesPackageLevel(t *testing.T) {
	// Ensure NewScorer(DefaultConfig()) produces identical results to Score()
	s := NewScorer(DefaultConfig())
	sig := Signal{CommandsNew: 5, CommandsTotal: 10, PathsNew: 1, CredsNew: 2}
	v1 := Score(sig)
	v2 := s.Score(sig)
	assert.Equal(t, v1.Score, v2.Score)
	assert.Equal(t, v1.Category, v2.Category)
	assert.Equal(t, v1.Signals, v2.Signals)
}
