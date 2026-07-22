package HTTP

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/artifactstore"
	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/plugins"
)

// readArtifactMeta reads and JSON-decodes the <sha>.meta.json sibling the
// artifact store writes next to every captured <sha>.bin. Provenance lives at
// the top level of that object (artifactstore.Store.Write merges the capture
// map into the enriched meta), so a caller checks stage/src_ip/filename etc.
// as ordinary keys.
func readArtifactMeta(t *testing.T, dir, sha string) map[string]any {
	t.Helper()
	metaPath := filepath.Join(dir, sha+".meta.json")
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("meta.json not found for artifact %s at %s: %v", sha, metaPath, err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("meta.json for %s is not valid JSON: %v", sha, err)
	}
	return m
}

// wantMetaString fails unless meta[key] is present and equals want. Isolating
// the assertion keeps the walk below readable and makes a provenance
// regression name the exact field that drifted.
func wantMetaString(t *testing.T, meta map[string]any, key, want string) {
	t.Helper()
	got, ok := meta[key]
	if !ok {
		t.Fatalf("provenance field %q missing from meta.json (an operator porting this artifact could not attribute it); meta=%v", key, meta)
	}
	if gs, _ := got.(string); gs != want {
		t.Fatalf("provenance field %q = %v, want %q", key, got, want)
	}
}

// TestHTTP_ChainWiring_FullChainWalk_CapturesBothArtifactsWithProvenance walks
// ONE per-source-IP chain session through every stage of the wp2shell gadget
// chain in order — S3 escalation → S4 login → S6 upload-nonce → S7 plugin
// upload → S8 activate → S9 command — against ONE shared chain store and ONE
// shared artifact store, then asserts the store holds EXACTLY the two
// artifacts the chain is designed to bank (the uploaded .zip and the raw S9
// command body), each addressed by its own sha256 AND carrying correct
// provenance in its .meta.json.
//
// Why this exists beyond the per-stage tests already in http_test.go: those
// tests each stand up a fresh session/store and assert one stage's .bin bytes.
// None asserts (a) that the whole sequence advances on a single session so a
// real exploit actually REACHES the capture points, end to end, nor (b) the
// provenance metadata — every existing capture test checks .bin bytes only, so
// an empty src_ip, a mislabeled stage, or a dropped filename would pass every
// test yet leave an operator unable to attribute or triage a captured dropper.
// This is the lock the "manage the zips securely, eventually port them to
// analyze" requirement needs: the capture is only useful if it is attributable.
func TestHTTP_ChainWiring_FullChainWalk_CapturesBothArtifactsWithProvenance(t *testing.T) {
	chainStore := plugins.NewChainStore(time.Hour, 100)
	astoreDir := t.TempDir()
	astore := artifactstore.New(astoreDir, 0 /* no size limit */)
	tt := &captureTracer{}
	servConf := parser.BeelzebubServiceConfiguration{}

	const (
		srcIP    = "203.0.113.200"
		username = "w2s_fullwalk_test"
		zipName  = "sgio-wp2shell-fullwalk.zip"
	)
	zipBytes := []byte("PK\x03\x04-full-chain-walk-synthetic-plugin-zip-bytes")
	// The command a fresh S7 plugin would register a shell route for; captured
	// verbatim (never base64-decoded) at S9. commandStageBody is defined in
	// http_test.go (same package) as `{"c":"aWQK"}`.
	cmdBody := commandStageBody

	fallthrough404 := func(name string) parser.Command {
		return parser.Command{Name: name, StatusCode: 404, Handler: `{"code":"not_found"}`}
	}

	// --- S3: escalation batch mints the fabricated administrator (adminCreated).
	// Reuses the exact captured-shape batch every Task-7/8 test drives.
	escalateChainSession(t, chainStore, tt, servConf, srcIP, username)

	// --- S4: login check — armed session must get ServeAuthStage's 200 +
	// a wordpress_logged_in_* Set-Cookie, not the command's static 404.
	loginReq := newChainTestRequest(t, http.MethodGet, "/wp-login.php", "", srcIP+":4001")
	loginResp, err, _ := buildHTTPResponse(servConf, tt, fallthrough404("wp-login"), loginReq, nil, nil, chainStore, astore, nil)
	if err != nil {
		t.Fatal(err)
	}
	if loginResp.StatusCode != 200 || strings.Contains(loginResp.Body, "not_found") {
		t.Fatalf("S4 login stage did not advance on the armed session: %d %s", loginResp.StatusCode, loginResp.Body)
	}

	// --- S6: plugin-install page — must serve the upload-nonce form (200),
	// proving auth-stage routing reaches the pre-upload step.
	installReq := newChainTestRequest(t, http.MethodGet, "/wp-admin/plugin-install.php?tab=upload", "", srcIP+":4002")
	installResp, err, _ := buildHTTPResponse(servConf, tt, fallthrough404("plugin-install"), installReq, nil, nil, chainStore, astore, nil)
	if err != nil {
		t.Fatal(err)
	}
	if installResp.StatusCode != 200 || strings.Contains(installResp.Body, "not_found") {
		t.Fatalf("S6 plugin-install stage did not advance on the armed session: %d %s", installResp.StatusCode, installResp.Body)
	}

	// --- S7: plugin upload — the .zip must be captured byte-for-byte AND the
	// response must serve the activate-flow illusion (gated on adminCreated).
	contentType, body := buildPluginUploadMultipart(t, zipName, zipBytes)
	uploadReq := newChainTestRequest(t, http.MethodPost, "/wp-admin/update.php?action=upload-plugin", string(body), srcIP+":4003")
	uploadReq.Header.Set("Content-Type", contentType)
	uploadResp, err, _ := buildHTTPResponse(servConf, tt, fallthrough404("wp-admin-update"), uploadReq, nil, nil, chainStore, astore, nil)
	if err != nil {
		t.Fatal(err)
	}
	if uploadResp.StatusCode != 200 || !strings.Contains(uploadResp.Body, "plugins.php?action=activate") {
		t.Fatalf("S7 upload stage did not serve the activate-flow illusion: %d %s", uploadResp.StatusCode, uploadResp.Body)
	}

	// --- S8: activate — proves S7 set uploadOpen (prerequisite for S9).
	activateReq := newChainTestRequest(t, http.MethodGet,
		"/wp-admin/plugins.php?action=activate&plugin=x&_wpnonce=deadbeef00", "", srcIP+":4004")
	activateResp, err, _ := buildHTTPResponse(servConf, tt, fallthrough404("wp-admin-plugins"), activateReq, nil, nil, chainStore, astore, nil)
	if err != nil {
		t.Fatal(err)
	}
	if activateResp.StatusCode != 200 || strings.Contains(activateResp.Body, "not_found") {
		t.Fatalf("S8 activate stage did not advance after upload: %d %s", activateResp.StatusCode, activateResp.Body)
	}

	// --- S9: first command against the fake shell route — the raw body must be
	// captured verbatim AND the canned marker+output JSON served.
	cmdReq := newChainTestRequest(t, http.MethodPost, "/?rest_route=/wp2shell/v1/deadbeef01", cmdBody, srcIP+":4005")
	cmdReq.Header.Set("Content-Type", "application/json")
	cmdResp, err, _ := buildHTTPResponse(servConf, tt, fallthrough404("wp2shell-command"), cmdReq, nil, nil, chainStore, astore, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertCommandStageJSON(t, cmdResp)

	// --- Assertions: exactly the two intended artifacts, each attributable.
	zipSHA := hex.EncodeToString(func() []byte { s := sha256.Sum256(zipBytes); return s[:] }())
	cmdSHA := hex.EncodeToString(func() []byte { s := sha256.Sum256([]byte(cmdBody)); return s[:] }())
	if zipSHA == cmdSHA {
		t.Fatal("test setup error: zip and command bytes collide on sha256")
	}

	if bins := countBins(t, astoreDir); len(bins) != 2 {
		t.Fatalf("expected exactly 2 captured artifacts (S7 zip + S9 command), found %d: %v", len(bins), bins)
	}

	// S7 zip: bytes + provenance (stage/src_ip/filename an operator needs).
	if got, statErr := os.ReadFile(filepath.Join(astoreDir, zipSHA+".bin")); statErr != nil {
		t.Fatalf("S7 zip not captured under its sha %s: %v", zipSHA, statErr)
	} else if string(got) != string(zipBytes) {
		t.Fatalf("S7 zip bytes differ from what was uploaded: got %q, want %q", got, zipBytes)
	}
	zipMeta := readArtifactMeta(t, astoreDir, zipSHA)
	wantMetaString(t, zipMeta, "stage", "plugin_upload")
	wantMetaString(t, zipMeta, "src_ip", srcIP)
	wantMetaString(t, zipMeta, "filename", zipName)
	wantMetaString(t, zipMeta, "sha256", zipSHA)
	if got, _ := zipMeta["size_bytes"].(float64); int(got) != len(zipBytes) {
		t.Fatalf("S7 zip meta size_bytes = %v, want %d", zipMeta["size_bytes"], len(zipBytes))
	}

	// S9 command body: bytes + provenance (stage/src_ip).
	if got, statErr := os.ReadFile(filepath.Join(astoreDir, cmdSHA+".bin")); statErr != nil {
		t.Fatalf("S9 command body not captured under its sha %s: %v", cmdSHA, statErr)
	} else if string(got) != cmdBody {
		t.Fatalf("S9 command bytes differ from what was sent: got %q, want %q", got, cmdBody)
	}
	cmdMeta := readArtifactMeta(t, astoreDir, cmdSHA)
	wantMetaString(t, cmdMeta, "stage", "command")
	wantMetaString(t, cmdMeta, "src_ip", srcIP)
	wantMetaString(t, cmdMeta, "sha256", cmdSHA)
}
