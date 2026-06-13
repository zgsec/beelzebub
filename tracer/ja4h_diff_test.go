package tracer

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestComputeJA4H_DifferentialVsFoxIO is the oracle-diff: every vector in
// testdata/ja4h_oracle_vectors.json was produced by FoxIO's REAL to_ja4h()
// reference compute (see tools/fingerprint-oracle/gen_ja4h_oracle.py) over a
// broad corpus. Our ComputeJA4H must reproduce each one exactly — any drift
// from the canonical algorithm fails here. CI needs only Go (reads the JSON);
// regenerating the golden file needs the gitignored FoxIO clone.
func TestComputeJA4H_DifferentialVsFoxIO(t *testing.T) {
	data, err := os.ReadFile("testdata/ja4h_oracle_vectors.json")
	if err != nil {
		t.Fatalf("read oracle vectors: %v", err)
	}
	var vectors []struct {
		Input struct {
			Method         string   `json:"method"`
			Version        string   `json:"version"`
			Headers        []string `json:"headers"`
			AcceptLanguage string   `json:"accept_language"`
			Cookie         string   `json:"cookie"`
		} `json:"input"`
		Expected string `json:"expected"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse oracle vectors: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("no oracle vectors loaded")
	}

	for _, v := range vectors {
		in := v.Input
		t.Run(v.Expected, func(t *testing.T) {
			r := httptest.NewRequest(in.Method, "http://x/", nil)
			r.Proto = in.Version
			if in.AcceptLanguage != "" {
				r.Header.Set("Accept-Language", in.AcceptLanguage)
			}
			if in.Cookie != "" {
				r.Header.Set("Cookie", in.Cookie)
			}
			// FoxIO keys the referer flag on header presence; we key on
			// r.Referer(), so set a value whenever the corpus lists referer.
			for _, h := range in.Headers {
				if strings.EqualFold(h, "referer") {
					r.Header.Set("Referer", "http://ref/")
				}
			}
			if got := ComputeJA4H(r, in.Headers); got != v.Expected {
				t.Errorf("JA4H mismatch vs FoxIO reference:\n  want %s\n  got  %s\n  input %+v", v.Expected, got, in)
			}
		})
	}
}
