package tracer

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// ComputeJA4H computes a JA4H HTTP client fingerprint from an http.Request.
//
// When wireOrder is non-nil, header names are used in wire order for parts b/c
// (spec-compliant). When nil, falls back to sorted order (deterministic but
// non-spec-compliant — for use when raw bytes are unavailable).
//
// Spec: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.md
func ComputeJA4H(r *http.Request, wireOrder []string) string {
	if r == nil {
		return ""
	}

	// --- Part a: method + version + cookie + referer + count + lang ---
	method := methodCode(r.Method)
	version := versionCode(r.Proto)
	hasCookie := boolFlag(len(r.Cookies()) > 0, "c")
	hasReferer := boolFlag(r.Referer() != "", "r")

	// Filter headers: exclude cookie, referer, pseudo-headers
	filtered := filterHeaders(wireOrder, r.Header)
	numHeaders := fmt.Sprintf("%02d", clamp(len(filtered), 0, 99))
	lang := langCode(r.Header.Get("Accept-Language"))

	partA := method + version + hasCookie + hasReferer + numHeaders + lang

	// --- Part b: truncated SHA256 of header names (wire order or sorted) ---
	partB := truncHash(strings.Join(filtered, ","))

	// --- Parts c/d: cookies, sorted by name (FoxIO JA4H spec) ---
	// c = sha256 of sorted cookie NAMES; d = sha256 of cookie "name=value"
	// pairs in that same name-sorted order. Per FoxIO python/ja4h.py +
	// common.py: sha_encode joins with "," and truncates sha256 to 12 hex; an
	// EMPTY list hashes the empty string (-> e3b0c44298fc), NOT twelve zeros.
	// (Earlier this fork hashed header VALUES into part c, which never matched
	// the FoxIO corpus — see ja4h_oracle_test.go.)
	cookies := r.Cookies()
	sort.Slice(cookies, func(i, j int) bool { return cookies[i].Name < cookies[j].Name })
	names := make([]string, len(cookies))
	pairs := make([]string, len(cookies))
	for i, c := range cookies {
		names[i] = c.Name
		pairs[i] = c.Name + "=" + c.Value
	}
	partC := truncHash(strings.Join(names, ","))
	partD := truncHash(strings.Join(pairs, ","))

	return partA + "_" + partB + "_" + partC + "_" + partD
}

// ComputeJA4HWithMeta computes the JA4H hash and reports whether it used the
// sorted-header fallback (true) instead of spec wire order (false). The sorted
// path runs exactly when wireOrder is nil (see filterHeaders); a sorted hash is
// deterministic but NOT comparable to wire-order JA4H from other corpora, so
// callers persist this flag to keep the two families distinguishable downstream.
func ComputeJA4HWithMeta(r *http.Request, wireOrder []string) (hash string, sorted bool) {
	return ComputeJA4H(r, wireOrder), wireOrder == nil
}

// ParseHeaderOrder extracts HTTP header names in wire order from raw request bytes.
// Returns nil if the header section is incomplete.
func ParseHeaderOrder(raw []byte) []string {
	end := bytes.Index(raw, []byte("\r\n\r\n"))
	if end < 0 {
		return nil
	}
	lines := bytes.Split(raw[:end], []byte("\r\n"))
	if len(lines) < 2 {
		return nil // need at least request line + one header
	}
	names := make([]string, 0, len(lines)-1)
	for _, line := range lines[1:] { // skip request line
		if i := bytes.IndexByte(line, ':'); i > 0 {
			names = append(names, strings.ToLower(string(bytes.TrimSpace(line[:i]))))
		}
	}
	return names
}

// filterHeaders returns header names excluding cookie, referer, and pseudo-headers.
// If wireOrder is non-nil, preserves that order. Otherwise collects from the map and sorts.
func filterHeaders(wireOrder []string, h http.Header) []string {
	var source []string
	if wireOrder != nil {
		source = wireOrder
	} else {
		source = make([]string, 0, len(h))
		for name := range h {
			source = append(source, strings.ToLower(name))
		}
		sort.Strings(source)
	}

	filtered := make([]string, 0, len(source))
	for _, name := range source {
		lower := strings.ToLower(name)
		if lower == "cookie" || lower == "referer" || strings.HasPrefix(lower, ":") {
			continue
		}
		filtered = append(filtered, lower)
	}
	return filtered
}

func methodCode(m string) string {
	switch strings.ToUpper(m) {
	case "GET":
		return "ge"
	case "POST":
		return "po"
	case "PUT":
		return "pu"
	case "DELETE":
		return "de"
	case "PATCH":
		return "pa"
	case "HEAD":
		return "he"
	case "OPTIONS":
		return "op"
	case "CONNECT":
		return "co"
	case "TRACE":
		return "tr"
	default:
		if len(m) >= 2 {
			return strings.ToLower(m[:2])
		}
		return "xx"
	}
}

func versionCode(proto string) string {
	switch proto {
	case "HTTP/1.0":
		return "10"
	case "HTTP/1.1":
		return "11"
	case "HTTP/2.0", "HTTP/2":
		return "20"
	case "HTTP/3.0", "HTTP/3":
		return "30"
	default:
		return "00"
	}
}

// boolFlag returns trueChar if b is true, "n" if false.
// FoxIO JA4H spec: cookie uses "c", referer uses "r" (NOT both "c").
func boolFlag(b bool, trueChar string) string {
	if b {
		return trueChar
	}
	return "n"
}

func langCode(acceptLang string) string {
	if acceptLang == "" {
		return "0000"
	}
	tag := strings.SplitN(acceptLang, ",", 2)[0]
	tag = strings.SplitN(tag, ";", 2)[0]
	tag = strings.TrimSpace(strings.ToLower(tag))
	tag = strings.ReplaceAll(tag, "-", "")
	if len(tag) >= 4 {
		return tag[:4]
	}
	return tag + strings.Repeat("0", 4-len(tag))
}

func truncHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:])[:12]
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
