package faults

import (
	"math/rand"
	"sync"
	"time"
)

// Config is the YAML-parseable fault injection configuration.
type Config struct {
	Enabled        bool     `yaml:"enabled"`
	ErrorRate      float64  `yaml:"errorRate"`
	DelayMs        int      `yaml:"delayMs"`
	DelayJitterMs  int      `yaml:"delayJitterMs"`
	ErrorResponses []string `yaml:"errorResponses"`
}

// Injector applies fault injection based on configuration.
type Injector struct {
	mu     sync.Mutex
	config Config
	rng    *rand.Rand
}

// NewInjector creates a fault injector from config.
func NewInjector(config Config) *Injector {
	return &Injector{
		config: config,
		rng:    rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// ShouldFault returns true if this request should receive a fault.
func (fi *Injector) ShouldFault() bool {
	if !fi.config.Enabled {
		return false
	}
	fi.mu.Lock()
	r := fi.rng.Float64()
	fi.mu.Unlock()
	return r < fi.config.ErrorRate
}

// Delay returns the configured delay duration (base + jitter).
func (fi *Injector) Delay() time.Duration {
	if !fi.config.Enabled {
		return 0
	}
	base := time.Duration(fi.config.DelayMs) * time.Millisecond
	jitter := time.Duration(0)
	if fi.config.DelayJitterMs > 0 {
		fi.mu.Lock()
		jitter = time.Duration(fi.rng.Intn(fi.config.DelayJitterMs+1)) * time.Millisecond
		fi.mu.Unlock()
	}
	return base + jitter
}

// HasDelay returns true if any delay is configured.
func (fi *Injector) HasDelay() bool {
	return fi.config.Enabled && (fi.config.DelayMs > 0 || fi.config.DelayJitterMs > 0)
}

// ErrorResponse returns a random error response from the configured list.
func (fi *Injector) ErrorResponse() string {
	if len(fi.config.ErrorResponses) == 0 {
		return `{"error":"internal_error"}`
	}
	fi.mu.Lock()
	resp := fi.config.ErrorResponses[fi.rng.Intn(len(fi.config.ErrorResponses))]
	fi.mu.Unlock()
	return resp
}

// Apply checks for faults and returns (response, faultType, faulted).
// If faulted is true, the caller should use response instead of the normal response.
// faultType is "error", "delay", "error+delay", or "" if no fault.
func (fi *Injector) Apply() (response string, faultType string, faulted bool) {
	if !fi.config.Enabled {
		return "", "", false
	}

	hasDelay := fi.HasDelay()
	isError := fi.ShouldFault()

	if hasDelay {
		time.Sleep(fi.Delay())
	}

	if isError && hasDelay {
		return fi.ErrorResponse(), "error+delay", true
	}
	if isError {
		return fi.ErrorResponse(), "error", true
	}
	if hasDelay {
		return "", "delay", false
	}
	return "", "", false
}
