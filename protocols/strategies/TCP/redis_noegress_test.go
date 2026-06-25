package TCP

import (
	"net"
	"testing"
	"time"
)

// TestRedisReplication_NoEgress is the load-bearing security gate for the
// redisCaptureHook replication path. It stands up a real loopback listener
// (a fake attacker master), drives a SLAVEOF through redisCaptureHook, and
// asserts that the listener accepts NO connection within 300 ms — proving the
// lure never dials the attacker's host. It also asserts the IOC is recorded.
//
// If this test ever FAILS, that is a real security regression: some code path
// opened an outbound socket toward the attacker's master. Do not suppress or
// skip — fix the regression.
func TestRedisReplication_NoEgress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	dialed := make(chan struct{}, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			dialed <- struct{}{}
			c.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	s := &TCPStrategy{} // artifactStore nil is fine; replication path returns before touching it
	captured := map[string]string{}
	s.redisCaptureHook(resp("SLAVEOF", "127.0.0.1", portStr), captured)

	select {
	case <-dialed:
		t.Fatal("SECURITY REGRESSION: lure dialed the attacker's master on SLAVEOF")
	case <-time.After(300 * time.Millisecond):
		// no connection — correct behaviour
	}

	if captured["redis_replication_master"] != "127.0.0.1:"+portStr {
		t.Fatalf("replication IOC not recorded: %v", captured)
	}
}
