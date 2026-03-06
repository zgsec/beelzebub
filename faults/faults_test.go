package faults

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDisabledInjectorNeverFaults(t *testing.T) {
	fi := NewInjector(Config{Enabled: false, ErrorRate: 1.0})
	for i := 0; i < 100; i++ {
		assert.False(t, fi.ShouldFault())
	}
}

func TestErrorRate100PercentAlwaysFaults(t *testing.T) {
	fi := NewInjector(Config{Enabled: true, ErrorRate: 1.0})
	for i := 0; i < 100; i++ {
		assert.True(t, fi.ShouldFault())
	}
}

func TestErrorRate0PercentNeverFaults(t *testing.T) {
	fi := NewInjector(Config{Enabled: true, ErrorRate: 0.0})
	for i := 0; i < 100; i++ {
		assert.False(t, fi.ShouldFault())
	}
}

func TestDelayWithNoJitter(t *testing.T) {
	fi := NewInjector(Config{Enabled: true, DelayMs: 10, DelayJitterMs: 0})
	d := fi.Delay()
	assert.Equal(t, int64(10), d.Milliseconds())
}

func TestDelayDisabled(t *testing.T) {
	fi := NewInjector(Config{Enabled: false, DelayMs: 100})
	d := fi.Delay()
	assert.Equal(t, int64(0), d.Milliseconds())
}

func TestErrorResponseDefault(t *testing.T) {
	fi := NewInjector(Config{Enabled: true})
	resp := fi.ErrorResponse()
	assert.Contains(t, resp, "internal_error")
}

func TestErrorResponseFromConfig(t *testing.T) {
	fi := NewInjector(Config{
		Enabled:        true,
		ErrorResponses: []string{`{"error":"rate_limited"}`},
	})
	resp := fi.ErrorResponse()
	assert.Equal(t, `{"error":"rate_limited"}`, resp)
}

func TestApplyDisabled(t *testing.T) {
	fi := NewInjector(Config{Enabled: false})
	_, ft, faulted := fi.Apply()
	assert.False(t, faulted)
	assert.Equal(t, "", ft)
}

func TestApplyErrorOnly(t *testing.T) {
	fi := NewInjector(Config{
		Enabled:        true,
		ErrorRate:      1.0,
		DelayMs:        0,
		DelayJitterMs:  0,
		ErrorResponses: []string{`{"error":"test"}`},
	})
	resp, ft, faulted := fi.Apply()
	assert.True(t, faulted)
	assert.Equal(t, "error", ft)
	assert.Contains(t, resp, "test")
}

func TestHasDelay(t *testing.T) {
	fi := NewInjector(Config{Enabled: true, DelayMs: 0, DelayJitterMs: 0})
	assert.False(t, fi.HasDelay())

	fi2 := NewInjector(Config{Enabled: true, DelayMs: 10})
	assert.True(t, fi2.HasDelay())

	fi3 := NewInjector(Config{Enabled: true, DelayJitterMs: 10})
	assert.True(t, fi3.HasDelay())
}
