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
	hasCookie := boolFlag(len(r.Cookies()) > 0)
	hasReferer := boolFlag(r.Referer() != "")

	// Filter headers: exclude cookie, referer, pseudo-headers
	filtered := filterHeaders(wireOrder, r.Header)
	numHeaders := fmt.Sprintf("%02d", clamp(len(filtered), 0, 99))
	lang := langCode(r.Header.Get("Accept-Language"))

	partA := method + version + hasCookie + hasReferer + numHeaders + lang

	// --- Part b: truncated SHA256 of header names (wire order or sorted) ---
	partB := truncHash(strings.Join(filtered, ","))

	// --- Part c: truncated SHA256 of header values in same order ---
	values := make([]string, 0, len(filtered))
	for _, name := range filtered {
		// http.Header stores canonical form; look up case-insensitively
		values = append(values, strings.Join(r.Header.Values(http.CanonicalHeaderKey(name)), ","))
	}
	partC := truncHash(strings.Join(values, ","))

	// --- Part d: truncated SHA256 of sorted cookie key=value pairs ---
	partD := "000000000000"
	if cookies := r.Cookies(); len(cookies) > 0 {
		pairs := make([]string, 0, len(cookies))
		for _, c := range cookies {
			pairs = append(pairs, c.Name+"="+c.Value)
		}
		sort.Strings(pairs)
		partD = truncHash(strings.Join(pairs, ","))
	}

	return partA + "_" + partB + "_" + partC + "_" + partD
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

func boolFlag(b bool) string {
	if b {
		return "c"
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
