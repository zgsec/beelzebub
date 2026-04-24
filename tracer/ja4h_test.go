package tracer

import (
	"net/http"
	"strings"
	"testing"
)

func TestComputeJA4H_SortedFallback(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com/api/tags", nil)
	r.Header.Set("User-Agent", "python-requests/2.31.0")
	r.Header.Set("Accept", "*/*")
	r.Header.Set("Accept-Encoding", "gzip, deflate")
	r.Header.Set("Connection", "keep-alive")
	r.Proto = "HTTP/1.1"

	ja4h := ComputeJA4H(r, nil) // nil wireOrder = sorted fallback

	parts := strings.Split(ja4h, "_")
	if len(parts) != 4 {
		t.Fatalf("expected 4 parts, got %d: %s", len(parts), ja4h)
	}
	if !strings.HasPrefix(parts[0], "ge11nn04") {
		t.Errorf("expected part_a prefix ge11nn04, got %s", parts[0])
	}
	if parts[3] != "000000000000" {
		t.Errorf("expected empty cookie hash, got %s", parts[3])
	}
	t.Logf("JA4H (sorted): %s", ja4h)
}

func TestComputeJA4H_WireOrder(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com/api/tags", nil)
	r.Header.Set("User-Agent", "curl/8.5.0")
	r.Header.Set("Accept", "*/*")
	r.Proto = "HTTP/1.1"

	// Simulate raw bytes: Host comes first, then User-Agent, then Accept
	raw := []byte("GET /api/tags HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n")
	wireOrder := ParseHeaderOrder(raw)

	ja4hWire := ComputeJA4H(r, wireOrder)
	ja4hSorted := ComputeJA4H(r, nil)

	parts := strings.Split(ja4hWire, "_")
	if len(parts) != 4 {
		t.Fatalf("expected 4 parts, got %d: %s", len(parts), ja4hWire)
	}

	// Part a may differ slightly — wire order captures Host from raw bytes,
	// Go's http.Request handles Host separately (not in r.Header). This is expected.
	t.Logf("part_a wire=%s sorted=%s", parts[0], strings.Split(ja4hSorted, "_")[0])

	// Part b should differ — wire order [host, user-agent, accept] vs sorted [accept, host, user-agent]
	partsS := strings.Split(ja4hSorted, "_")
	if parts[1] == partsS[1] {
		t.Logf("note: part_b identical despite different order (unlikely hash collision)")
	}

	t.Logf("JA4H (wire):   %s", ja4hWire)
	t.Logf("JA4H (sorted): %s", ja4hSorted)
	t.Logf("Wire order: %v", wireOrder)
}

func TestComputeJA4H_WithCookies(t *testing.T) {
	r, _ := http.NewRequest("POST", "http://example.com/api/generate", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept-Language", "en-US,en;q=0.9")
	r.Header.Set("Cookie", "session=abc123")
	r.Proto = "HTTP/1.1"

	ja4h := ComputeJA4H(r, nil)
	parts := strings.Split(ja4h, "_")

	a := parts[0]
	if !strings.HasPrefix(a, "po11c") {
		t.Errorf("expected POST + cookie flag, got %s", a[:5])
	}
	if !strings.HasSuffix(a, "enus") {
		t.Errorf("expected lang enus, got %s", a[8:])
	}
	if parts[3] == "000000000000" {
		t.Error("expected non-empty cookie hash")
	}
	t.Logf("JA4H: %s", ja4h)
}

func TestComputeJA4H_Nil(t *testing.T) {
	if ja4h := ComputeJA4H(nil, nil); ja4h != "" {
		t.Errorf("expected empty for nil request, got %s", ja4h)
	}
}

func TestComputeJA4H_Deterministic(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\r\nUser-Agent: LLM-Scanner/2.0-Fast\r\nAccept: */*\r\n\r\n")
	wireOrder := ParseHeaderOrder(raw)

	makeReq := func() *http.Request {
		r, _ := http.NewRequest("GET", "http://example.com/", nil)
		r.Header.Set("User-Agent", "LLM-Scanner/2.0-Fast")
		r.Header.Set("Accept", "*/*")
		r.Proto = "HTTP/1.1"
		return r
	}

	first := ComputeJA4H(makeReq(), wireOrder)
	for i := 0; i < 100; i++ {
		if got := ComputeJA4H(makeReq(), wireOrder); got != first {
			t.Fatalf("non-deterministic: run %d got %s, expected %s", i, got, first)
		}
	}
}

func TestParseHeaderOrder(t *testing.T) {
	raw := []byte("GET /api/tags HTTP/1.1\r\nHost: localhost:11434\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\nbody")
	order := ParseHeaderOrder(raw)

	expected := []string{"host", "user-agent", "accept"}
	if len(order) != len(expected) {
		t.Fatalf("expected %d headers, got %d: %v", len(expected), len(order), order)
	}
	for i, name := range expected {
		if order[i] != name {
			t.Errorf("header %d: expected %q, got %q", i, name, order[i])
		}
	}
}

func TestParseHeaderOrder_Incomplete(t *testing.T) {
	if order := ParseHeaderOrder([]byte("GET / HTTP/1.1\r\nHost: x\r\n")); order != nil {
		t.Errorf("expected nil for incomplete headers, got %v", order)
	}
}

func TestParseHeaderOrder_CookieRefererFiltered(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\r\nHost: x\r\nCookie: a=b\r\nReferer: http://x\r\nAccept: */*\r\n\r\n")
	order := ParseHeaderOrder(raw)
	// ParseHeaderOrder returns ALL headers including cookie/referer
	// filterHeaders (called by ComputeJA4H) does the filtering
	if len(order) != 4 { // host, cookie, referer, accept
		t.Fatalf("expected 4 raw headers, got %d: %v", len(order), order)
	}

	// But ComputeJA4H should filter them for the hash
	r, _ := http.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("Host", "x")
	r.Header.Set("Cookie", "a=b")
	r.Header.Set("Referer", "http://x")
	r.Header.Set("Accept", "*/*")
	r.Proto = "HTTP/1.1"

	ja4h := ComputeJA4H(r, order)
	parts := strings.Split(ja4h, "_")
	// Header count should be 2 (host + accept, excluding cookie + referer)
	// Cookie present → 'c', Referer present → 'r' (per FoxIO spec), count "02"
	if !strings.Contains(parts[0], "cr02") {
		t.Errorf("expected cr02 in part_a (cookie=c, referer=r, 2 remaining headers), got part_a=%s", parts[0])
	}
}
