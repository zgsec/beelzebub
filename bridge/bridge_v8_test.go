package bridge

import (
	"testing"
	"time"
)

// TestSetFlag_StoresTimestamp verifies the v8 bool→time.Time migration.
func TestSetFlag_StoresTimestamp(t *testing.T) {
	b := NewBridge()
	before := time.Now()
	b.SetFlag("1.2.3.4", "test_flag")
	after := time.Now()

	if !b.HasFlag("1.2.3.4", "test_flag") {
		t.Error("HasFlag returned false after SetFlag")
	}

	last := b.LastActivity("1.2.3.4")
	if last.Before(before) || last.After(after) {
		t.Errorf("LastActivity out of range: %v not in [%v, %v]", last, before, after)
	}
}

func TestLastActivity_MultipleFlags(t *testing.T) {
	b := NewBridge()
	b.SetFlag("1.2.3.4", "flag_a")
	time.Sleep(2 * time.Millisecond)
	b.SetFlag("1.2.3.4", "flag_b")

	last := b.LastActivity("1.2.3.4")
	if last.IsZero() {
		t.Fatal("LastActivity is zero")
	}
	flags := b.GetFlags("1.2.3.4")
	if len(flags) != 2 {
		t.Errorf("expected 2 flags, got %d", len(flags))
	}
}

func TestLastActivity_IncludesCredentials(t *testing.T) {
	b := NewBridge()
	b.RecordDiscovery("1.2.3.4", "test", "aws_key", "AKIA...", "secret...")
	last := b.LastActivity("1.2.3.4")
	if last.IsZero() {
		t.Error("LastActivity is zero after RecordDiscovery")
	}
}

func TestLastActivity_NoActivity(t *testing.T) {
	b := NewBridge()
	if !b.LastActivity("9.9.9.9").IsZero() {
		t.Error("expected zero for unknown IP")
	}
}

func TestHasFlag_FalseForMissing(t *testing.T) {
	b := NewBridge()
	b.SetFlag("1.2.3.4", "exists")
	if b.HasFlag("1.2.3.4", "nope") {
		t.Error("true for non-existent flag")
	}
	if b.HasFlag("9.9.9.9", "exists") {
		t.Error("true for non-existent IP")
	}
}

func TestClean_RemovesStaleEntries(t *testing.T) {
	b := NewBridge()
	b.RecordDiscovery("old.ip", "test", "key", "k", "v")
	b.SetFlag("old.ip", "old_flag")
	b.Clean(0)
	if b.HasFlag("old.ip", "old_flag") {
		t.Error("flag survived Clean(0)")
	}
	if len(b.GetDiscoveries("old.ip")) > 0 {
		t.Error("discoveries survived Clean(0)")
	}
}
