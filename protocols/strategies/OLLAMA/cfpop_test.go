package OLLAMA

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Without a GeoIP DB loaded, Resolve must still return a plausible IATA
// 3-letter code for every input — the heuristic fallback path is the
// contract operators see when they haven't wired up MaxMind yet.
func TestPoPResolver_HeuristicFallback(t *testing.T) {
	r := NewPoPResolver()
	// No DB loaded — exercise the registry heuristic only.

	cases := []struct {
		ip          string
		expectPool  []string
		description string
	}{
		{"173.255.226.61", registryPoPs["ARIN"], "Linode NJ (ARIN)"},
		{"100.80.132.52", registryPoPs["ARIN"], "Tailscale CGNAT (ARIN space)"},
		{"8.8.8.8", registryPoPs["ARIN"], "Google (ARIN)"},
		{"46.4.171.113", registryPoPs["RIPE"], "Hetzner DE (RIPE)"},
		{"80.1.2.3", registryPoPs["RIPE"], "UK block (RIPE)"},
		{"203.0.113.1", registryPoPs["APNIC"], "APNIC TEST-NET-3"},
		{"121.168.139.251", registryPoPs["APNIC"], "Korea Telecom (APNIC)"},
		{"187.1.2.3", registryPoPs["LACNIC"], "Brazil block (LACNIC)"},
		{"197.1.2.3", registryPoPs["AFRINIC"], "African block (AFRINIC)"},
	}

	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			got := r.Resolve(c.ip)
			assert.Contains(t, c.expectPool, got, "resolved PoP must be in expected regional pool")
		})
	}
}

// Stickiness is THE primary invariant: real Cloudflare Anycast routes a
// given client to the same PoP request after request. If Resolve returns
// different PoPs for the same IP, we've reintroduced the fingerprint.
func TestPoPResolver_StickyPerIP(t *testing.T) {
	r := NewPoPResolver()
	ip := "173.255.226.61"
	first := r.Resolve(ip)
	for i := 0; i < 50; i++ {
		assert.Equal(t, first, r.Resolve(ip), "same IP must always resolve to same PoP")
	}
}

// Different clients in the same country should sometimes get different
// PoPs (reflecting real load-distribution), but any client consistently
// sees its own single PoP.
func TestPoPResolver_DistributedAcrossClients(t *testing.T) {
	r := NewPoPResolver()
	seen := map[string]bool{}
	// Sample a bunch of ARIN-range IPs; expect to see >1 PoP across them.
	arinIPs := []string{
		"3.1.2.3", "8.8.8.8", "50.2.3.4", "104.5.6.7",
		"173.1.2.3", "199.4.5.6", "216.1.2.3", "45.6.7.8",
	}
	for _, ip := range arinIPs {
		seen[r.Resolve(ip)] = true
	}
	assert.Greater(t, len(seen), 1, "across many ARIN IPs we should pick >1 PoP")
}

// Every PoP string we return must be exactly 3 uppercase letters — that's
// the invariant a Cloudflare-aware fingerprinter would check.
func TestPoPResolver_ValidIATACode(t *testing.T) {
	r := NewPoPResolver()
	for _, ip := range []string{"8.8.8.8", "46.4.171.113", "121.168.139.251", "187.1.2.3", "197.1.2.3", "::1", "garbage"} {
		code := r.Resolve(ip)
		assert.Len(t, code, 3, "code len must be 3")
		for _, c := range code {
			assert.True(t, c >= 'A' && c <= 'Z', "code chars must be uppercase A-Z, got %q", code)
		}
	}
}

// Even an IPv6 address that isn't in our heuristic table must resolve to
// something plausible. defaultPoPs is the ultimate fallback.
func TestPoPResolver_IPv6FallbackNonEmpty(t *testing.T) {
	r := NewPoPResolver()
	got := r.Resolve("2a01:7e01::1")
	assert.NotEmpty(t, got)
	assert.Len(t, got, 3)
}

// Bogus input must not panic and must return a valid code.
func TestPoPResolver_InvalidIP(t *testing.T) {
	r := NewPoPResolver()
	assert.NotEmpty(t, r.Resolve(""))
	assert.NotEmpty(t, r.Resolve("not-an-ip"))
	assert.NotEmpty(t, r.Resolve("999.999.999.999"))
}

// Every country in our cfPoPsByCountry table must have a non-empty PoP
// list. Regression: it's easy to accidentally add a country with an
// empty list which would panic modulo-0 in pickFromPool.
func TestPoPResolver_AllCountryPoolsNonEmpty(t *testing.T) {
	for country, pops := range cfPoPsByCountry {
		assert.NotEmpty(t, pops, "country %s has empty PoP list", country)
	}
}

// Every registry pool must also be non-empty.
func TestPoPResolver_AllRegistryPoolsNonEmpty(t *testing.T) {
	for registry, pops := range registryPoPs {
		assert.NotEmpty(t, pops, "registry %s has empty PoP list", registry)
	}
}
