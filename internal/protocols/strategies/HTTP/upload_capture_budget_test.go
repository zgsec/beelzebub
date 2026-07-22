package HTTP

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/artifactstore"
	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/plugins"
)

// buildPluginUploadRequest constructs the S7 upload POST: multipart body with a
// "pluginzip" part carrying payload, targeting the exact route the capture
// branch keys on.
func buildPluginUploadRequest(t *testing.T, payload []byte, remoteAddr string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("pluginzip", "backdoor.zip")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := part.Write(payload); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/wp-admin/update.php?action=upload-plugin", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.RemoteAddr = remoteAddr
	ctx := context.WithValue(req.Context(), http.LocalAddrContextKey,
		net.Addr(&stubAddr{s: "127.0.0.1:8042"}))
	return req.WithContext(ctx)
}

func countBins(t *testing.T, dir string) []string {
	t.Helper()
	bins, err := filepath.Glob(filepath.Join(dir, "*.bin"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	return bins
}

// TestPluginUploadCapturedWhole locks the fidelity fix: a plugin .zip LARGER
// than the default 1 MiB read limit must be captured WHOLE (correct SHA), not
// silently truncated. Before the fix the body was read at a hard 1 MiB cap, so
// any >1 MiB upload was stored as a corrupt fragment under a SHA that matched
// nothing — useless for downstream analysis.
func TestPluginUploadCapturedWhole(t *testing.T) {
	dir := t.TempDir()
	const cap = 8 * 1024 * 1024 // 8 MiB store cap — comfortably above the payload
	store := artifactstore.New(dir, cap)
	chainStore := plugins.NewChainStore(time.Hour, 100)

	// 2 MiB payload — over the old 1 MiB truncation point.
	payload := bytes.Repeat([]byte{0xAB, 0xCD, 0xEF, 0x01}, 512*1024) // 2 MiB
	wantSHA := hex.EncodeToString(func() []byte { s := sha256.Sum256(payload); return s[:] }())

	req := buildPluginUploadRequest(t, payload, "203.0.113.9:5555")
	servConf := parser.BeelzebubServiceConfiguration{ServiceType: "wp"}
	cmd := parser.Command{Handler: "x", StatusCode: 200}

	_, err, _ := buildHTTPResponse(servConf, &captureTracer{}, cmd, req, nil, nil, chainStore, store)
	if err != nil {
		t.Fatalf("buildHTTPResponse: %v", err)
	}

	binPath := filepath.Join(dir, wantSHA+".bin")
	got, statErr := os.ReadFile(binPath)
	if statErr != nil {
		t.Fatalf("whole-zip .bin not stored at %s (truncation regression?): %v", binPath, statErr)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("stored artifact is not the whole zip: got %d bytes, want %d", len(got), len(payload))
	}
}

// TestPluginUploadOversizeNotStored locks the honesty fix: a plugin .zip that
// exceeds the configured cap must NOT be persisted at all — better a logged
// drop than a truncated, corrupt fragment stored under a misleading SHA.
func TestPluginUploadOversizeNotStored(t *testing.T) {
	dir := t.TempDir()
	const cap = 1536 * 1024 // 1.5 MiB cap (> 1 MiB so the read budget expands)
	store := artifactstore.New(dir, cap)
	chainStore := plugins.NewChainStore(time.Hour, 100)

	// 3 MiB payload — larger than the cap even after the read budget.
	payload := bytes.Repeat([]byte{0x11, 0x22, 0x33, 0x44}, 768*1024) // 3 MiB

	req := buildPluginUploadRequest(t, payload, "203.0.113.10:5555")
	servConf := parser.BeelzebubServiceConfiguration{ServiceType: "wp"}
	cmd := parser.Command{Handler: "x", StatusCode: 200}

	_, err, _ := buildHTTPResponse(servConf, &captureTracer{}, cmd, req, nil, nil, chainStore, store)
	if err != nil {
		t.Fatalf("buildHTTPResponse: %v", err)
	}

	if bins := countBins(t, dir); len(bins) != 0 {
		t.Fatalf("oversize upload was persisted (%v) — a truncated fragment must never be stored", bins)
	}
}
