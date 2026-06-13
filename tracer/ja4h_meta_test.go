package tracer

import (
	"net/http"
	"testing"
)

// ComputeJA4HWithMeta returns the same hash as ComputeJA4H but additionally
// reports whether the hash fell back to sorted header order (no wire order
// available). A sorted-fallback hash is NOT comparable to spec wire-order JA4H
// from other corpora (Shodan, JA4+), so downstream pivots must be able to
// exclude them — silently mixing the two families corrupts fingerprint hunts.
func TestComputeJA4HWithMeta_SortedFlag(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com/x", nil)
	r.Header.Set("User-Agent", "curl/8.5.0")
	r.Header.Set("Accept", "*/*")
	r.Proto = "HTTP/1.1"

	// No wire order → sorted fallback, flagged true.
	hash, sorted := ComputeJA4HWithMeta(r, nil)
	if !sorted {
		t.Errorf("expected sorted=true when wireOrder is nil")
	}
	if want := ComputeJA4H(r, nil); hash != want {
		t.Errorf("hash mismatch: want %q, got %q", want, hash)
	}

	// Wire order available → spec order, flagged false.
	raw := []byte("GET /x HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n")
	wireOrder := ParseHeaderOrder(raw)
	hash2, sorted2 := ComputeJA4HWithMeta(r, wireOrder)
	if sorted2 {
		t.Errorf("expected sorted=false when wireOrder present")
	}
	if want := ComputeJA4H(r, wireOrder); hash2 != want {
		t.Errorf("hash mismatch with wire order: want %q, got %q", want, hash2)
	}
}
