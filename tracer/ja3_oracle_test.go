package tracer

import (
	"crypto/tls"
	"testing"
)

// Oracle vectors from the canonical Salesforce ja3 reference README
// (github.com/salesforce/ja3). These are the AUTHORITATIVE (ClientHello -> JA3)
// pairs — reproducing both the pre-hash string AND the documented MD5 proves our
// JA3 is cross-corpus comparable (Shodan/GreyNoise/VT), not merely
// self-consistent. JA3 keeps GREASE removed, all extensions (incl. SNI=0), wire
// order, and the legacy ClientHello version.
func TestComputeJA3_SalesforceOracleVectors(t *testing.T) {
	cases := []struct {
		name       string
		hello      *tls.ClientHelloInfo
		wantString string
		wantHash   string
	}{
		{
			name: "with extensions",
			hello: &tls.ClientHelloInfo{
				SupportedVersions: []uint16{0x0301}, // 769
				CipherSuites:      []uint16{47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4},
				Extensions:        []uint16{0, 10, 11}, // SNI(0) kept, supported_groups(10), ec_point_formats(11)
				SupportedCurves:   []tls.CurveID{23, 24, 25},
				SupportedPoints:   []uint8{0},
			},
			wantString: "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0",
			wantHash:   "ada70206e40642a3e4461f35503241d5",
		},
		{
			name: "without extensions",
			hello: &tls.ClientHelloInfo{
				SupportedVersions: []uint16{0x0301}, // 769
				CipherSuites:      []uint16{4, 5, 10, 9, 100, 98, 3, 6, 19, 18, 99},
			},
			wantString: "769,4-5-10-9-100-98-3-6-19-18-99,,,",
			wantHash:   "de350869b8c85de67a350c8d186f11e6",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ja3String(tc.hello); got != tc.wantString {
				t.Errorf("ja3 string:\n  want %q\n  got  %q", tc.wantString, got)
			}
			if got := ComputeJA3FromClientHello(tc.hello); got != tc.wantHash {
				t.Errorf("ja3 hash: want %q, got %q", tc.wantHash, got)
			}
		})
	}
}
