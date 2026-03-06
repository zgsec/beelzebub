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
