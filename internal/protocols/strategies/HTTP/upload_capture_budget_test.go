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

// buildPluginUploadRequest constructs the S7 upload POST: a multipart body with
// a "pluginzip" part carrying payload, targeting the exact route the capture
// branch keys on. It returns the request AND the full body bytes — the handler
// buffers the body once and hands it to buildHTTPResponse as preBody, so tests
// that call buildHTTPResponse directly must supply the same bytes (otherwise
// buildHTTPResponse's own fallback read is bounded to 1 MiB).
func buildPluginUploadRequest(t *testing.T, payload []byte, remoteAddr string) (*http.Request, []byte) {
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
	bodyBytes := buf.Bytes()
	req := httptest.NewRequest(http.MethodPost, "/wp-admin/update.php?action=upload-plugin", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.RemoteAddr = remoteAddr
	ctx := context.WithValue(req.Context(), http.LocalAddrContextKey,
		net.Addr(&stubAddr{s: "127.0.0.1:8042"}))
	return req.WithContext(ctx), bodyBytes
}

func countBins(t *testing.T, dir string) []string {
	t.Helper()
	bins, err := filepath.Glob(filepath.Join(dir, "*.bin"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	return bins
}

// TestPluginUploadCapturedWhole locks the fidelity fix: given the whole upload
// body (as the handler buffers it), a plugin .zip LARGER than the default 1 MiB
// read limit is captured WHOLE (correct SHA), not truncated into a corrupt
// fragment under a SHA that matches nothing.
func TestPluginUploadCapturedWhole(t *testing.T) {
	dir := t.TempDir()
	const cap = 8 * 1024 * 1024 // 8 MiB store cap — comfortably above the payload
	store := artifactstore.New(dir, cap)
	chainStore := plugins.NewChainStore(time.Hour, 100)

	// 2 MiB payload — over the old 1 MiB truncation point.
	payload := bytes.Repeat([]byte{0xAB, 0xCD, 0xEF, 0x01}, 512*1024) // 2 MiB
	wantSHA := hex.EncodeToString(func() []byte { s := sha256.Sum256(payload); return s[:] }())

	req, body := buildPluginUploadRequest(t, payload, "203.0.113.9:5555")
	servConf := parser.BeelzebubServiceConfiguration{ServiceType: "wp"}
	cmd := parser.Command{Handler: "x", StatusCode: 200}

	_, err, _ := buildHTTPResponse(servConf, &captureTracer{}, cmd, req, nil, nil, chainStore, store, body)
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
	const cap = 1536 * 1024 // 1.5 MiB cap
	store := artifactstore.New(dir, cap)
	chainStore := plugins.NewChainStore(time.Hour, 100)

	// 3 MiB payload — larger than the cap.
	payload := bytes.Repeat([]byte{0x11, 0x22, 0x33, 0x44}, 768*1024) // 3 MiB

	req, body := buildPluginUploadRequest(t, payload, "203.0.113.10:5555")
	servConf := parser.BeelzebubServiceConfiguration{ServiceType: "wp"}
	cmd := parser.Command{Handler: "x", StatusCode: 200}

	_, err, _ := buildHTTPResponse(servConf, &captureTracer{}, cmd, req, nil, nil, chainStore, store, body)
	if err != nil {
		t.Fatalf("buildHTTPResponse: %v", err)
	}

	if bins := countBins(t, dir); len(bins) != 0 {
		t.Fatalf("oversize upload was persisted (%v) — a truncated fragment must never be stored", bins)
	}
}

// TestIsPluginUploadRequest locks the exact request shape that gets the enlarged
// read budget — it must match only the S7 upload POST, so an ordinary GET/other
// POST can't force the memory-amplifying read.
func TestIsPluginUploadRequest(t *testing.T) {
	cases := []struct {
		method, target string
		want           bool
	}{
		{http.MethodPost, "/wp-admin/update.php?action=upload-plugin", true},
		{http.MethodGet, "/wp-admin/update.php?action=upload-plugin", false},
		{http.MethodPost, "/wp-admin/update.php?action=activate", false},
		{http.MethodPost, "/wp-admin/update.php", false},
		{http.MethodPost, "/wp-login.php?action=upload-plugin", false},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.target, nil)
		if got := isPluginUploadRequest(req); got != c.want {
			t.Errorf("isPluginUploadRequest(%s %s) = %v, want %v", c.method, c.target, got, c.want)
		}
	}
}

// TestEnlargedUploadBudget: expands past 1 MiB only when the store cap does.
func TestEnlargedUploadBudget(t *testing.T) {
	if got := enlargedUploadBudget(artifactstore.New(t.TempDir(), 8*1024*1024)); got != 8*1024*1024+multipartFramingHeadroom {
		t.Errorf("budget for 8 MiB cap = %d, want %d", got, 8*1024*1024+multipartFramingHeadroom)
	}
	if got := enlargedUploadBudget(artifactstore.New(t.TempDir(), 0)); got != defaultBodyReadBudget {
		t.Errorf("budget for unbounded cap = %d, want %d (default)", got, defaultBodyReadBudget)
	}
	if got := enlargedUploadBudget(artifactstore.New(t.TempDir(), 512*1024)); got != defaultBodyReadBudget {
		t.Errorf("budget for sub-1MiB cap = %d, want %d (never below default)", got, defaultBodyReadBudget)
	}
}

// TestUploadReadSlotBound proves the concurrency guard hard-caps in-flight
// enlarged reads: exactly maxConcurrentUploadReads slots, no more, and release
// frees a slot. This is the bound that prevents an upload-spray OOM.
func TestUploadReadSlotBound(t *testing.T) {
	var releases []func()
	for i := 0; i < maxConcurrentUploadReads; i++ {
		rel, ok := acquireUploadReadSlot()
		if !ok {
			t.Fatalf("slot %d should be available", i)
		}
		releases = append(releases, rel)
	}
	// Pool is now saturated — the next acquire must fail (fall back to 1 MiB).
	if _, ok := acquireUploadReadSlot(); ok {
		t.Fatal("acquired a slot past the concurrency bound — OOM guard is broken")
	}
	// Releasing one must free exactly one slot.
	releases[0]()
	rel, ok := acquireUploadReadSlot()
	if !ok {
		t.Fatal("slot not freed after release")
	}
	rel()
	for _, r := range releases[1:] {
		r()
	}
}
