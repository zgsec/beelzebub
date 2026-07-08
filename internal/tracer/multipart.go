package tracer

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"
)

// MultipartPart is one entry in tracer.Event.RequestBodyParts. Populated by
// ParseMultipart when an HTTP request arrives with a multipart/* Content-Type.
//
// Shape is the same as the Slice B design's schema:
// docs/strategy/2026-05-12-ws4-slice-b-body-capture-design.md (in the
// honeypot-research repo). The exporter forwards this struct verbatim as
// opaque JSON and the aggregator stores it in sessions.multipart_parts JSONB.
type MultipartPart struct {
	Name        string `json:"name,omitempty"`
	Filename    string `json:"filename,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Size        int64  `json:"size"`
	Sha256      string `json:"sha256"`
	BodyPreview string `json:"body_preview,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
}

// MultipartPartPreviewMaxBytes caps the per-part body_preview at 16 KiB.
// Combined with MultipartMaxParts (32) this bounds the worst-case extra
// memory per multipart request at ~512 KiB — Nanode-safe per Slice B Q3.
const MultipartPartPreviewMaxBytes = 16 * 1024

// MultipartMaxParts caps the number of parts emitted from a single body.
// Excess parts are dropped and replaced by a synthetic "__overflow__" record.
const MultipartMaxParts = 32

// IsMultipartContentType reports whether a Content-Type header value indicates
// a multipart body that ParseMultipart can handle. Case-insensitive, tolerant
// of parameters (e.g. "multipart/form-data; boundary=...").
func IsMultipartContentType(contentType string) bool {
	if contentType == "" {
		return false
	}
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		// Tolerate malformed Content-Type by checking the prefix directly.
		return strings.HasPrefix(strings.ToLower(contentType), "multipart/")
	}
	return strings.HasPrefix(mt, "multipart/")
}

// Sha256Hex returns the lowercase-hex sha256 of b, or "" when b is empty.
// Slice B Q1 (operator-approved 2026-05-12): empty bodies must not produce
// a hash — the constant digest would bloat every empty-body row.
func Sha256Hex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Sha256HexString is the string variant for callers that have body as a
// string (typical when bodies come from io.ReadAll → string conversion).
func Sha256HexString(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ParseMultipart breaks a multipart body into MultipartPart records.
//
// Returns nil on:
//   - empty body
//   - non-multipart Content-Type
//   - missing boundary parameter
//
// On any per-part parse error mid-stream, the function emits a synthetic
// "__parse_error__" record holding the envelope size + Content-Type and
// stops. The caller still has the raw body (sha256'd separately).
//
// On part-count overflow (more than MultipartMaxParts), the function emits a
// synthetic "__overflow__" record with the total remaining size and stops.
//
// Caps: per-part body_preview at MultipartPartPreviewMaxBytes. Full part
// bytes are sha256'd (size = full size, not preview size).
func ParseMultipart(body string, contentType string) []MultipartPart {
	if body == "" {
		return nil
	}
	if contentType == "" {
		return nil
	}
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil
	}
	boundary, ok := params["boundary"]
	if !ok || boundary == "" {
		return nil
	}

	mr := multipart.NewReader(strings.NewReader(body), boundary)
	out := make([]MultipartPart, 0, 4)
	for {
		if len(out) >= MultipartMaxParts {
			// Emit one synthetic record indicating the overflow and stop.
			out = append(out, MultipartPart{
				Name:      "__overflow__",
				Size:      int64(len(body)),
				Truncated: true,
			})
			break
		}
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			out = append(out, MultipartPart{
				Name:        "__parse_error__",
				ContentType: contentType,
				Size:        int64(len(body)),
				Sha256:      Sha256HexString(body),
				Truncated:   true,
			})
			break
		}
		rec := MultipartPart{
			Name:        part.FormName(),
			Filename:    part.FileName(),
			ContentType: partContentType(part.Header),
		}
		// Read the full part body so we can hash it. Capped at
		// MultipartMaxParts * 64 KiB by the outer body cap (set in the
		// caller's strategy) so unbounded reads aren't possible.
		partBytes, err := io.ReadAll(part)
		if err != nil {
			// Best-effort: hash what we got, mark truncated.
			rec.Size = int64(len(partBytes))
			rec.Sha256 = Sha256Hex(partBytes)
			rec.Truncated = true
			out = append(out, rec)
			continue
		}
		rec.Size = int64(len(partBytes))
		rec.Sha256 = Sha256Hex(partBytes)
		if len(partBytes) > MultipartPartPreviewMaxBytes {
			rec.BodyPreview = string(partBytes[:MultipartPartPreviewMaxBytes])
			rec.Truncated = true
		} else if len(partBytes) > 0 {
			rec.BodyPreview = string(partBytes)
		}
		out = append(out, rec)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// partContentType returns the Content-Type header value from a multipart
// part, defaulting to "application/octet-stream" per RFC 7578 §4.4 when the
// header is absent (matches Go's stdlib mime/multipart convention).
func partContentType(h textproto.MIMEHeader) string {
	if ct := h.Get("Content-Type"); ct != "" {
		return ct
	}
	return ""
}
