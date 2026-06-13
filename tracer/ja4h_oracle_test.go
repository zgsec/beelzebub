package tracer

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
)

// foxioSha mirrors FoxIO common.py sha_encode: sha256 of a comma-joined list,
// hex, truncated to 12 chars. An empty list hashes the empty string.
func foxioSha(items ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(items, ",")))
	return hex.EncodeToString(sum[:])[:12]
}

// JA4H oracle test against the FoxIO reference ALGORITHM, transcribed verbatim
// from FoxIO-LLC/ja4 python/ja4h.py + common.py:
//
//	JA4H = a _ sha(header names, wire order, excl. cookie/referer/pseudo)
//	         _ sha(sorted cookie NAMES)
//	         _ sha(cookie "name=value" in name-sorted order)
//
// The hashing primitive (sha256, ","-join, [:12]) is itself oracle-proven by
// TestComputeJA4FromClientHello_ChromiumReference (same sha_encode), so
// reproducing FoxIO's exact part structure here makes our JA4H corpus-
// comparable. This is the test that catches the original part-c defect (it
// hashed header VALUES instead of cookie names) and the part-d empty-default
// (it used twelve zeros instead of the empty-string hash).
func TestComputeJA4H_FoxIOReferenceAlgorithm(t *testing.T) {
	r, _ := http.NewRequest("POST", "http://x/api", nil)
	r.Proto = "HTTP/1.1"
	r.Header.Set("Accept-Language", "en-US,en;q=0.9")
	r.Header.Set("Cookie", "b_cookie=2; a_cookie=1")

	// Cookie is excluded from the header-name hash; names are kept in wire order.
	wireOrder := []string{"host", "user-agent", "accept", "accept-language", "cookie"}

	parts := strings.Split(ComputeJA4H(r, wireOrder), "_")
	if len(parts) != 4 {
		t.Fatalf("want 4 parts, got %d", len(parts))
	}
	if want := foxioSha("host", "user-agent", "accept", "accept-language"); parts[1] != want {
		t.Errorf("part b (header names, wire order): want %s, got %s", want, parts[1])
	}
	if want := foxioSha("a_cookie", "b_cookie"); parts[2] != want {
		t.Errorf("part c (sorted cookie names): want %s, got %s", want, parts[2])
	}
	if want := foxioSha("a_cookie=1", "b_cookie=2"); parts[3] != want {
		t.Errorf("part d (cookie name=value, name-sorted): want %s, got %s", want, parts[3])
	}
}

// No cookies → parts c and d are "000000000000" — FoxIO to_ja4h uses an
// explicit '0'*12 guard, NOT sha_encode([]). (Confirmed by the differential
// oracle against the real to_ja4h.)
func TestComputeJA4H_FoxIONoCookies(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://x/", nil)
	r.Proto = "HTTP/1.1"
	parts := strings.Split(ComputeJA4H(r, []string{"host", "user-agent"}), "_")
	if parts[2] != "000000000000" || parts[3] != "000000000000" {
		t.Errorf("no-cookie parts c/d: want 000000000000, got c=%s d=%s", parts[2], parts[3])
	}
}
