package plugins

import (
	"fmt"
	"testing"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/cache"
	"golang.org/x/time/rate"
)

// newTestLimiterCache returns a fresh limiter cache for the IP-flood
// regression test below. We need a cache with a small cap so the
// assertion is sharp; the package-level cache uses 10k.
func newTestLimiterCache(maxEntries int, maxAge time.Duration) *cache.Map[*rate.Limiter] {
	return cache.New[*rate.Limiter](maxEntries, maxAge)
}

func TestRateLimiting(t *testing.T) {
	config := LLMHoneypot{
		RateLimitEnabled:       true,
		RateLimitRequests:      2,
		RateLimitWindowSeconds: 1,
	}

	honeypot := InitLLMHoneypot(config)
	clientIP := "192.168.1.1"
	// Isolate from prior runs / other tests that share this IP — under
	// `go test -count=N`, the package-global outlives a single test.
	globalRateLimiters.Delete(clientIP)

	if err := honeypot.checkRateLimit(clientIP); err != nil {
		t.Errorf("First request should not be rate limited: %v", err)
	}

	if err := honeypot.checkRateLimit(clientIP); err != nil {
		t.Errorf("Second request should not be rate limited: %v", err)
	}

	if err := honeypot.checkRateLimit(clientIP); err == nil {
		t.Error("Third request should be rate limited")
	}

	time.Sleep(1 * time.Second)

	if err := honeypot.checkRateLimit(clientIP); err != nil {
		t.Errorf("Request after window should not be rate limited: %v", err)
	}
}

func TestRateLimitingDisabled(t *testing.T) {
	config := LLMHoneypot{
		RateLimitEnabled: false,
	}

	honeypot := InitLLMHoneypot(config)

	for i := 0; i < 100; i++ {
		if err := honeypot.checkRateLimit("192.168.1.1"); err != nil {
			t.Errorf("Request %d should not be rate limited when disabled: %v", i, err)
		}
	}
}

func TestRateLimitingPerIP(t *testing.T) {
	config := LLMHoneypot{
		RateLimitEnabled:       true,
		RateLimitRequests:      1,
		RateLimitWindowSeconds: 1,
	}

	honeypot := InitLLMHoneypot(config)
	clientIP1 := "192.168.1.1"
	clientIP2 := "192.168.1.2"
	// Isolate from prior runs / other tests that share these IPs.
	globalRateLimiters.Delete(clientIP1)
	globalRateLimiters.Delete(clientIP2)

	if err := honeypot.checkRateLimit(clientIP1); err != nil {
		t.Errorf("First request from IP1 should not be rate limited: %v", err)
	}

	if err := honeypot.checkRateLimit(clientIP1); err == nil {
		t.Error("Second request from IP1 should be rate limited")
	}

	if err := honeypot.checkRateLimit(clientIP2); err != nil {
		t.Errorf("First request from IP2 should not be rate limited: %v", err)
	}

	if err := honeypot.checkRateLimit(clientIP2); err == nil {
		t.Error("Second request from IP2 should be rate limited")
	}
}

// TestRateLimiter_BoundedUnderIPFlood is the Track-5 regression: an
// attacker rotating source IPs must not be able to grow the global
// limiter map without bound. Pre-fix the map was an unbounded
// map[string]*rate.Limiter; post-fix it's a ttlmap with a hard cap.
func TestRateLimiter_BoundedUnderIPFlood(t *testing.T) {
	// Swap the package-global for a small-cap version so the assertion
	// is sharp; restore afterward so unrelated tests aren't disturbed.
	prev := globalRateLimiters
	defer func() { globalRateLimiters = prev }()

	const cap_ = 256
	globalRateLimiters = newTestLimiterCache(cap_, time.Hour)

	config := LLMHoneypot{
		RateLimitEnabled:       true,
		RateLimitRequests:      10,
		RateLimitWindowSeconds: 1,
	}
	honeypot := InitLLMHoneypot(config)

	// Pound with 50x the cap in unique IPs.
	for i := 0; i < cap_*50; i++ {
		_ = honeypot.checkRateLimit(fmt.Sprintf("10.0.%d.%d", i/256, i%256))
	}

	if got := globalRateLimiters.Len(); got != cap_ {
		t.Errorf("limiter map size = %d, want exactly %d (LRU should fill it)", got, cap_)
	}
}
