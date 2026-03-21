package tracer

import (
	"net/http"
	"strings"
	"testing"
)

func TestComputeJA4H_BasicGET(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com/api/tags", nil)
	r.Header.Set("User-Agent", "python-requests/2.31.0")
	r.Header.Set("Accept", "*/*")
	r.Header.Set("Accept-Encoding", "gzip, deflate")
	r.Header.Set("Connection", "keep-alive")
	r.Proto = "HTTP/1.1"

	ja4h := ComputeJA4H(r)

	// Format: ge11nn04xxxx_xxxxxxxxxxxx_xxxxxxxxxxxx_000000000000
	parts := strings.Split(ja4h, "_")
	if len(parts) != 4 {
		t.Fatalf("expected 4 parts, got %d: %s", len(parts), ja4h)
	}

	// Part a checks
	a := parts[0]
	if !strings.HasPrefix(a, "ge11") {
		t.Errorf("expected prefix ge11, got %s", a[:4])
	}
	// No cookies, no referer
	if a[4] != 'n' {
		t.Errorf("expected no cookie flag 'n', got %c", a[4])
	}
	if a[5] != 'n' {
		t.Errorf("expected no referer flag 'n', got %c", a[5])
	}
	// 4 headers
	if a[6:8] != "04" {
		t.Errorf("expected 04 headers, got %s", a[6:8])
	}
	// No accept-language → 0000
	if a[8:] != "0000" {
		t.Errorf("expected lang 0000, got %s", a[8:])
	}

	// Part d: no cookies → 000000000000
	if parts[3] != "000000000000" {
		t.Errorf("expected empty cookie hash, got %s", parts[3])
	}

	t.Logf("JA4H: %s", ja4h)
}

func TestComputeJA4H_POST_WithCookies(t *testing.T) {
	r, _ := http.NewRequest("POST", "http://example.com/api/generate", strings.NewReader(`{"model":"llama3.1:8b"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", "ollama/0.18.2")
	r.Header.Set("Accept-Language", "en-US,en;q=0.9")
	r.Header.Set("Cookie", "session=abc123")
	r.Proto = "HTTP/1.1"

	ja4h := ComputeJA4H(r)
	parts := strings.Split(ja4h, "_")
	if len(parts) != 4 {
		t.Fatalf("expected 4 parts, got %d: %s", len(parts), ja4h)
	}

	a := parts[0]
	if !strings.HasPrefix(a, "po11") {
		t.Errorf("expected prefix po11, got %s", a[:4])
	}
	// Has cookie
	if a[4] != 'c' {
		t.Errorf("expected cookie flag 'c', got %c", a[4])
	}
	// Accept-Language: en-US → enus
	if !strings.HasSuffix(a, "enus") {
		t.Errorf("expected lang enus, got %s", a[8:])
	}
	// Part d should NOT be all zeros (has cookies)
	if parts[3] == "000000000000" {
		t.Error("expected non-empty cookie hash")
	}

	t.Logf("JA4H: %s", ja4h)
}

func TestComputeJA4H_Nil(t *testing.T) {
	if ja4h := ComputeJA4H(nil); ja4h != "" {
		t.Errorf("expected empty for nil request, got %s", ja4h)
	}
}

func TestComputeJA4H_Deterministic(t *testing.T) {
	makeReq := func() *http.Request {
		r, _ := http.NewRequest("GET", "http://example.com/", nil)
		r.Header.Set("User-Agent", "LLM-Scanner/2.0-Fast")
		r.Header.Set("Accept", "*/*")
		r.Proto = "HTTP/1.1"
		return r
	}

	first := ComputeJA4H(makeReq())
	for i := 0; i < 100; i++ {
		if got := ComputeJA4H(makeReq()); got != first {
			t.Fatalf("non-deterministic: run %d got %s, expected %s", i, got, first)
		}
	}
}

func TestComputeJA4H_DifferentClients(t *testing.T) {
	// python-requests
	r1, _ := http.NewRequest("GET", "http://example.com/api/tags", nil)
	r1.Header.Set("User-Agent", "python-requests/2.31.0")
	r1.Header.Set("Accept", "*/*")
	r1.Header.Set("Accept-Encoding", "gzip, deflate")
	r1.Header.Set("Connection", "keep-alive")
	r1.Proto = "HTTP/1.1"

	// curl
	r2, _ := http.NewRequest("GET", "http://example.com/api/tags", nil)
	r2.Header.Set("User-Agent", "curl/8.5.0")
	r2.Header.Set("Accept", "*/*")
	r2.Proto = "HTTP/1.1"

	ja4h1 := ComputeJA4H(r1)
	ja4h2 := ComputeJA4H(r2)

	if ja4h1 == ja4h2 {
		t.Errorf("different clients produced same fingerprint: %s", ja4h1)
	}

	// Part a should differ (different header counts)
	parts1 := strings.Split(ja4h1, "_")
	parts2 := strings.Split(ja4h2, "_")
	if parts1[0] == parts2[0] {
		t.Logf("warning: part_a identical despite different header sets: %s", parts1[0])
	}

	t.Logf("python-requests: %s", ja4h1)
	t.Logf("curl:            %s", ja4h2)
}
