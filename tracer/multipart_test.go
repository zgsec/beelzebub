package tracer

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestSha256Hex_EmptyReturnsEmpty(t *testing.T) {
	// Slice B Q1: empty bodies must not produce a hash.
	if got := Sha256Hex(nil); got != "" {
		t.Errorf("Sha256Hex(nil): want \"\" got %q", got)
	}
	if got := Sha256Hex([]byte{}); got != "" {
		t.Errorf("Sha256Hex(empty): want \"\" got %q", got)
	}
	if got := Sha256HexString(""); got != "" {
		t.Errorf("Sha256HexString(empty): want \"\" got %q", got)
	}
}

func TestSha256Hex_KnownValue(t *testing.T) {
	if got := Sha256HexString("hello"); got != sha("hello") {
		t.Errorf("Sha256HexString hash mismatch: want %q got %q", sha("hello"), got)
	}
}

func TestIsMultipartContentType(t *testing.T) {
	cases := []struct {
		ct   string
		want bool
	}{
		{"multipart/form-data; boundary=abc", true},
		{"MULTIPART/MIXED;boundary=xyz", true},
		{"multipart/related", true}, // no boundary, but type prefix matches
		{"application/json", false},
		{"", false},
		{"garbage", false},
		{"multipart/form-data", true}, // no boundary param, still multipart shape
	}
	for _, c := range cases {
		if got := IsMultipartContentType(c.ct); got != c.want {
			t.Errorf("IsMultipartContentType(%q): want %v got %v", c.ct, c.want, got)
		}
	}
}

func TestParseMultipart_Empty(t *testing.T) {
	if parts := ParseMultipart("", "multipart/form-data; boundary=x"); parts != nil {
		t.Errorf("empty body: want nil, got %v", parts)
	}
	if parts := ParseMultipart("body", ""); parts != nil {
		t.Errorf("empty content-type: want nil, got %v", parts)
	}
	if parts := ParseMultipart("body", "application/json"); parts != nil {
		t.Errorf("non-multipart content-type: want nil, got %v", parts)
	}
	if parts := ParseMultipart("body", "multipart/form-data"); parts != nil {
		t.Errorf("missing boundary: want nil, got %v", parts)
	}
}

func buildMultipart(boundary string, fields []struct {
	name, filename, ct, body string
}) string {
	var b strings.Builder
	for _, f := range fields {
		b.WriteString("--")
		b.WriteString(boundary)
		b.WriteString("\r\n")
		disp := `form-data; name="` + f.name + `"`
		if f.filename != "" {
			disp += `; filename="` + f.filename + `"`
		}
		b.WriteString("Content-Disposition: ")
		b.WriteString(disp)
		b.WriteString("\r\n")
		if f.ct != "" {
			b.WriteString("Content-Type: ")
			b.WriteString(f.ct)
			b.WriteString("\r\n")
		}
		b.WriteString("\r\n")
		b.WriteString(f.body)
		b.WriteString("\r\n")
	}
	b.WriteString("--")
	b.WriteString(boundary)
	b.WriteString("--\r\n")
	return b.String()
}

func TestParseMultipart_TwoFieldsHashed(t *testing.T) {
	body := buildMultipart("XYZ", []struct{ name, filename, ct, body string }{
		{"username", "", "", "alice"},
		{"file", "a.txt", "text/plain", "hello world"},
	})
	parts := ParseMultipart(body, "multipart/form-data; boundary=XYZ")
	if len(parts) != 2 {
		t.Fatalf("want 2 parts, got %d", len(parts))
	}
	if parts[0].Name != "username" || parts[0].Sha256 != sha("alice") {
		t.Errorf("part 0: %+v", parts[0])
	}
	if parts[1].Name != "file" || parts[1].Filename != "a.txt" {
		t.Errorf("part 1 name/filename: %+v", parts[1])
	}
	if parts[1].Sha256 != sha("hello world") {
		t.Errorf("part 1 sha: want %q got %q", sha("hello world"), parts[1].Sha256)
	}
	if parts[1].ContentType != "text/plain" {
		t.Errorf("part 1 ct: want text/plain got %q", parts[1].ContentType)
	}
	if parts[1].Size != int64(len("hello world")) {
		t.Errorf("part 1 size: want %d got %d", len("hello world"), parts[1].Size)
	}
	if parts[1].Truncated {
		t.Errorf("part 1 should not be truncated for 11-byte body")
	}
}

func TestParseMultipart_TruncatesBodyPreviewAtCap(t *testing.T) {
	bigBody := strings.Repeat("A", MultipartPartPreviewMaxBytes+512)
	body := buildMultipart("BIG", []struct{ name, filename, ct, body string }{
		{"upload", "huge.bin", "application/octet-stream", bigBody},
	})
	parts := ParseMultipart(body, "multipart/form-data; boundary=BIG")
	if len(parts) != 1 {
		t.Fatalf("want 1 part, got %d", len(parts))
	}
	p := parts[0]
	if p.Size != int64(len(bigBody)) {
		t.Errorf("size: want %d (full body), got %d", len(bigBody), p.Size)
	}
	if p.Sha256 != sha(bigBody) {
		t.Errorf("sha must cover full body, not preview")
	}
	if len(p.BodyPreview) != MultipartPartPreviewMaxBytes {
		t.Errorf("preview length: want %d got %d", MultipartPartPreviewMaxBytes, len(p.BodyPreview))
	}
	if !p.Truncated {
		t.Errorf("Truncated must be true when preview shorter than size")
	}
}

func TestParseMultipart_PartCountOverflow(t *testing.T) {
	count := MultipartMaxParts + 5
	fields := make([]struct{ name, filename, ct, body string }, count)
	for i := range fields {
		fields[i].name = "f"
		fields[i].body = "x"
	}
	body := buildMultipart("OVF", fields)
	parts := ParseMultipart(body, "multipart/form-data; boundary=OVF")
	// Expect MultipartMaxParts real parts + 1 synthetic overflow record.
	if got := len(parts); got != MultipartMaxParts+1 {
		t.Fatalf("want %d parts (cap + overflow marker), got %d", MultipartMaxParts+1, got)
	}
	if parts[len(parts)-1].Name != "__overflow__" {
		t.Errorf("last part should be __overflow__, got %q", parts[len(parts)-1].Name)
	}
}

func TestParseMultipart_ParseErrorEmitsSynthetic(t *testing.T) {
	// Boundary mismatch — body starts with --GOOD but Content-Type says BAD
	body := "--GOOD\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nhi\r\n--GOOD--\r\n"
	parts := ParseMultipart(body, "multipart/form-data; boundary=BAD")
	if len(parts) != 1 {
		t.Fatalf("want 1 synthetic part, got %d (%+v)", len(parts), parts)
	}
	if parts[0].Name != "__parse_error__" {
		t.Errorf("want __parse_error__ marker, got %q", parts[0].Name)
	}
	if parts[0].Size != int64(len(body)) {
		t.Errorf("synthetic record should carry envelope size, got %d", parts[0].Size)
	}
}

func TestParseMultipart_FilenameIsIOC(t *testing.T) {
	// Filename + content-type are captured even when the body is empty
	// — they're independent IOC signal per the design's principle 7.
	body := buildMultipart("Z", []struct{ name, filename, ct, body string }{
		{"upload", "exploit.elf", "application/x-executable", ""},
	})
	parts := ParseMultipart(body, "multipart/form-data; boundary=Z")
	if len(parts) != 1 {
		t.Fatalf("want 1 part, got %d", len(parts))
	}
	if parts[0].Filename != "exploit.elf" {
		t.Errorf("filename: want exploit.elf got %q", parts[0].Filename)
	}
	if parts[0].ContentType != "application/x-executable" {
		t.Errorf("ct: want application/x-executable got %q", parts[0].ContentType)
	}
	if parts[0].Size != 0 {
		t.Errorf("size for empty part: want 0 got %d", parts[0].Size)
	}
	if parts[0].Sha256 != "" {
		t.Errorf("empty part should produce no sha (Slice B Q1); got %q", parts[0].Sha256)
	}
}
