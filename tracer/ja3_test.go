package tracer

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"testing"
)

// ja3String must match the canonical Salesforce JA3 wire format exactly, or the
// resulting hash won't match public corpora (Shodan/GreyNoise/VT) and the
// fingerprint is worse than useless. Validated against hand-computed vectors:
// GREASE removed, WIRE ORDER preserved, TLS 1.3 legacy_version pinned to 771,
// ec_point_formats included.
func TestJA3String_CanonicalFormat(t *testing.T) {
	hello := &tls.ClientHelloInfo{
		// 0x0a0a is GREASE and must be dropped; 0x0304 (TLS1.3) must cap to 771.
		SupportedVersions: []uint16{0x0a0a, 0x0304, 0x0303},
		CipherSuites:      []uint16{0x1a1a, 0xc02f, 0xc030}, // GREASE + 49199,49200
		Extensions:        []uint16{0x0a0a, 0, 11, 10, 35},  // GREASE + 0,11,10,35 (wire order)
		SupportedCurves:   []tls.CurveID{0x0a0a, 23, 24},    // GREASE + 23,24
		SupportedPoints:   []uint8{0},
	}
	got := ja3String(hello)
	want := "771,49199-49200,0-11-10-35,23-24,0"
	if got != want {
		t.Fatalf("JA3 string mismatch:\n  want %q\n  got  %q", want, got)
	}
}

func TestComputeJA3_IsMD5OfCanonicalString(t *testing.T) {
	hello := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{0x0303},
		CipherSuites:      []uint16{0xc02f},
		Extensions:        []uint16{0, 11},
		SupportedCurves:   []tls.CurveID{23},
		SupportedPoints:   []uint8{0},
	}
	want := md5.Sum([]byte("771,49199,0-11,23,0"))
	if got := ComputeJA3FromClientHello(hello); got != hex.EncodeToString(want[:]) {
		t.Errorf("JA3 hash mismatch: got %q", got)
	}
}

func TestComputeJA3_NilSafe(t *testing.T) {
	if got := ComputeJA3FromClientHello(nil); got != "" {
		t.Errorf("nil ClientHello should yield empty JA3, got %q", got)
	}
}
