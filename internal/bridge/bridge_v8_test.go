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

// TestClean_PrunesFlagOnlyIPs guards a fixed memory leak: pre-fix Clean only
// iterated discoveredCreds, so an IP that set a flag without ever recording
// a credential discovery (the common path — most authenticated sessions
// never trigger checkCredentialDiscovery) was never pruned from sessionFlags.
func TestClean_PrunesFlagOnlyIPs(t *testing.T) {
	b := NewBridge()
	b.SetFlag("flag.only", "authenticated")

	// Backdate the flag so it falls outside the cutoff window.
	b.mu.Lock()
	b.sessionFlags["flag.only"]["authenticated"] = time.Now().Add(-2 * time.Hour)
	b.mu.Unlock()

	b.Clean(1 * time.Hour)

	if b.HasFlag("flag.only", "authenticated") {
		t.Error("flag-only IP should be pruned after Clean")
	}
	b.mu.RLock()
	_, present := b.sessionFlags["flag.only"]
	b.mu.RUnlock()
	if present {
		t.Error("sessionFlags entry for flag-only IP should be removed")
	}
}

// TestClean_RetainsRecentlyActiveIPs ensures the cleaner doesn't over-prune.
func TestClean_RetainsRecentlyActiveIPs(t *testing.T) {
	b := NewBridge()
	b.RecordDiscovery("recent.cred", "test", "aws_key", "k", "v")
	b.SetFlag("recent.flag", "authenticated")

	b.Clean(1 * time.Hour)

	if !b.HasDiscovered("recent.cred", "aws_key") {
		t.Error("recent discovery should survive Clean")
	}
	if !b.HasFlag("recent.flag", "authenticated") {
		t.Error("recent flag should survive Clean")
	}
}
