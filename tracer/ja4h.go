package tracer

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// ComputeJA4H computes a JA4H HTTP client fingerprint from an http.Request.
//
// JA4H format: {method}{version}{cookie}{referer}{num_headers}{lang}_{header_hash}_{value_hash}_{cookie_hash}
//
// Spec: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.md
//
// Limitation: Go's net/http parses headers into map[string][]string, which does
// not preserve wire order. We sort header names alphabetically as a deterministic
// fallback. This still produces a strong fingerprint — different clients send
// different header SETS even when order is lost.
func ComputeJA4H(r *http.Request) string {
	if r == nil {
		return ""
	}

	// --- Part a: method + version + cookie + referer + count + lang ---
	method := methodCode(r.Method)
	version := versionCode(r.Proto)
	hasCookie := boolChar(len(r.Cookies()) > 0)
	hasReferer := boolChar(r.Referer() != "")

	// Count headers (excluding pseudo-headers, cookie, and referer for the count
	// matches what the client originally sent)
	headerNames := collectHeaderNames(r.Header)
	numHeaders := fmt.Sprintf("%02d", min(len(headerNames), 99))

	lang := langCode(r.Header.Get("Accept-Language"))

	partA := method + version + hasCookie + hasReferer + numHeaders + lang

	// --- Part b: truncated SHA256 of sorted header names ---
	sort.Strings(headerNames)
	partB := truncHash(strings.Join(headerNames, ","))

	// --- Part c: truncated SHA256 of sorted header values ---
	values := make([]string, 0, len(headerNames))
	for _, name := range headerNames {
		values = append(values, strings.Join(r.Header.Values(name), ","))
	}
	partC := truncHash(strings.Join(values, ","))

	// --- Part d: truncated SHA256 of cookie key=value pairs ---
	partD := "000000000000"
	if cookies := r.Cookies(); len(cookies) > 0 {
		cookieParts := make([]string, 0, len(cookies))
		for _, c := range cookies {
			cookieParts = append(cookieParts, c.Name+"="+c.Value)
		}
		sort.Strings(cookieParts)
		partD = truncHash(strings.Join(cookieParts, ","))
	}

	return partA + "_" + partB + "_" + partC + "_" + partD
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
		return strings.ToLower(m[:min(2, len(m))])
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

func boolChar(b bool) string {
	if b {
		return "c"
	}
	return "n"
}

func langCode(acceptLang string) string {
	if acceptLang == "" {
		return "0000"
	}
	// Take first language tag, strip quality, lowercase, pad/truncate to 4
	tag := strings.SplitN(acceptLang, ",", 2)[0]
	tag = strings.SplitN(tag, ";", 2)[0]
	tag = strings.TrimSpace(strings.ToLower(tag))
	tag = strings.ReplaceAll(tag, "-", "")
	if len(tag) >= 4 {
		return tag[:4]
	}
	return tag + strings.Repeat("0", 4-len(tag))
}

func collectHeaderNames(h http.Header) []string {
	names := make([]string, 0, len(h))
	for name := range h {
		lower := strings.ToLower(name)
		// Skip pseudo-headers
		if strings.HasPrefix(lower, ":") {
			continue
		}
		names = append(names, lower)
	}
	return names
}

func truncHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:])[:12]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
