package bridge

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRecordAndHasDiscovery(t *testing.T) {
	b := NewBridge()

	assert.False(t, b.HasDiscovered("1.2.3.4", "aws_key"))

	b.RecordDiscovery("1.2.3.4", "ssh", "aws_key", "AKIA...", "secret...")

	assert.True(t, b.HasDiscovered("1.2.3.4", "aws_key"))
	assert.False(t, b.HasDiscovered("1.2.3.4", "db_password"))
	assert.False(t, b.HasDiscovered("5.6.7.8", "aws_key"))
}

func TestSetAndHasFlag(t *testing.T) {
	b := NewBridge()

	assert.False(t, b.HasFlag("1.2.3.4", "ssh_authenticated"))

	b.SetFlag("1.2.3.4", "ssh_authenticated")

	assert.True(t, b.HasFlag("1.2.3.4", "ssh_authenticated"))
	assert.False(t, b.HasFlag("1.2.3.4", "other_flag"))
	assert.False(t, b.HasFlag("5.6.7.8", "ssh_authenticated"))
}

func TestGetDiscoveries(t *testing.T) {
	b := NewBridge()
	b.RecordDiscovery("1.2.3.4", "ssh", "aws_key", "k1", "v1")
	b.RecordDiscovery("1.2.3.4", "http", "api_token", "k2", "v2")

	creds := b.GetDiscoveries("1.2.3.4")
	assert.Len(t, creds, 2)
}

func TestGetFlags(t *testing.T) {
	b := NewBridge()
	b.SetFlag("1.2.3.4", "a")
	b.SetFlag("1.2.3.4", "b")

	flags := b.GetFlags("1.2.3.4")
	assert.Len(t, flags, 2)
	assert.Contains(t, flags, "a")
	assert.Contains(t, flags, "b")
}

func TestIPIsolation(t *testing.T) {
	b := NewBridge()
	b.RecordDiscovery("1.2.3.4", "ssh", "aws_key", "k", "v")
	b.SetFlag("1.2.3.4", "authenticated")

	assert.False(t, b.HasDiscovered("5.6.7.8", "aws_key"))
	assert.False(t, b.HasFlag("5.6.7.8", "authenticated"))
	assert.Empty(t, b.GetDiscoveries("5.6.7.8"))
	assert.Empty(t, b.GetFlags("5.6.7.8"))
}

// TestRecordDiscovery_CapsPerIPSlice is the Track-5 regression: an
// attacker pounding a single IP with credential-shaped payloads must
// not be able to grow the per-IP discoveredCreds slice without bound.
// Pre-fix the slice grew on every RecordDiscovery call; post-fix it
// stops at maxCredsPerIP and drops oldest-first.
func TestRecordDiscovery_CapsPerIPSlice(t *testing.T) {
	b := NewBridge()
	const ip = "10.0.0.1"

	// Spam well past the cap.
	for i := 0; i < maxCredsPerIP*5; i++ {
		b.RecordDiscovery(ip, "ssh", "aws_key", "k", "v")
	}

	got := len(b.GetDiscoveries(ip))
	if got != maxCredsPerIP {
		t.Errorf("len(discoveries) = %d, want exactly %d", got, maxCredsPerIP)
	}
}

// TestRecordDiscovery_FIFOEviction asserts that the oldest discovery
// is the one dropped when the cap is hit, so the most recent activity
// is always preserved (which is what HasDiscovered/LastActivity rely on).
func TestRecordDiscovery_FIFOEviction(t *testing.T) {
	b := NewBridge()
	const ip = "10.0.0.1"

	// First discovery has a marker we can recognize.
	b.RecordDiscovery(ip, "ssh", "first_marker", "k0", "v0")

	// Spam past the cap with a different type.
	for i := 0; i < maxCredsPerIP+5; i++ {
		b.RecordDiscovery(ip, "http", "filler", "k", "v")
	}

	creds := b.GetDiscoveries(ip)
	if len(creds) != maxCredsPerIP {
		t.Fatalf("len = %d, want %d", len(creds), maxCredsPerIP)
	}
	for _, c := range creds {
		if c.Type == "first_marker" {
			t.Errorf("oldest entry survived eviction; FIFO not honored")
		}
	}
}

func TestCrossProtocolFlow(t *testing.T) {
	b := NewBridge()

	// SSH: attacker discovers AWS credentials
	b.RecordDiscovery("10.0.0.1", "ssh", "aws_key", "AKIA...", "secret...")
	b.SetFlag("10.0.0.1", "discovered_aws_credentials")

	// MCP: gate on bridge flag
	assert.True(t, b.HasFlag("10.0.0.1", "discovered_aws_credentials"))
	assert.True(t, b.HasDiscovered("10.0.0.1", "aws_key"))

	// Different IP has no access
	assert.False(t, b.HasFlag("10.0.0.2", "discovered_aws_credentials"))
}
