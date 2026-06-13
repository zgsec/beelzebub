package bridge

import (
	"testing"
	"time"
)

// ActorID is the genuine cross-protocol actor-episode key (replacing the old
// IP-hash correlation_id). It must be:
//   - stable for the same IP within an active window (so SSH+MCP+HTTP from one
//     actor share an id), and
//   - rolled to a NEW id once the IP has been idle past the episode TTL (so a
//     revisit days later is a distinct campaign, not fused with the first), and
//   - distinct across IPs.
func TestProtocolBridge_ActorID(t *testing.T) {
	b := NewBridge()
	t0 := time.Now()

	id1 := b.ActorID("1.2.3.4", t0)
	if id1 == "" {
		t.Fatal("ActorID returned empty")
	}

	// Same IP, still within the window → same episode id.
	if got := b.ActorID("1.2.3.4", t0.Add(30*time.Minute)); got != id1 {
		t.Errorf("actor id should be stable within the window: got %q, want %q", got, id1)
	}

	// Same IP returning after idle > TTL (last activity was t0+30m; +61m later
	// exceeds the 60m episode TTL) → new episode id.
	if got := b.ActorID("1.2.3.4", t0.Add(30*time.Minute).Add(61*time.Minute)); got == id1 {
		t.Errorf("actor id should roll to a new episode after idle past TTL, got same %q", got)
	}

	// Different IP → different id.
	if got := b.ActorID("5.6.7.8", t0); got == id1 {
		t.Errorf("different IPs must get different actor ids")
	}
}
