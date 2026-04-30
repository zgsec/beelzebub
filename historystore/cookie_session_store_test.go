package historystore

import (
	"testing"
	"time"
)

func TestCookieSession_CreateAndGet(t *testing.T) {
	s := NewCookieSessionStore(30 * time.Minute)
	cs := s.Create("203.0.113.1", "ja4h-x", map[string]string{
		"operator_user": "pwn3d",
		"operator_role": "Administrator",
	})
	if len(cs.Cookie) != 64 {
		t.Fatalf("cookie not 64-hex: %q", cs.Cookie)
	}
	got, ok := s.Get(cs.Cookie)
	if !ok {
		t.Fatal("Get returned !ok")
	}
	if got.Captured["operator_user"] != "pwn3d" {
		t.Fatalf("captures missing: %+v", got.Captured)
	}
}

func TestCookieSession_TTLExpiry(t *testing.T) {
	s := NewCookieSessionStore(10 * time.Millisecond)
	cs := s.Create("1.1.1.1", "x", nil)
	time.Sleep(20 * time.Millisecond)
	if _, ok := s.Get(cs.Cookie); ok {
		t.Fatal("expected TTL expiry, got ok")
	}
}

func TestCookieSession_UnknownCookie(t *testing.T) {
	s := NewCookieSessionStore(time.Hour)
	if _, ok := s.Get("nonexistent"); ok {
		t.Fatal("unknown cookie returned ok")
	}
}

func TestCookieSession_TouchUpdatesLastSeen(t *testing.T) {
	s := NewCookieSessionStore(time.Hour)
	cs := s.Create("1.1.1.1", "x", nil)
	first := cs.LastSeen
	time.Sleep(2 * time.Millisecond)
	got, _ := s.Get(cs.Cookie)
	if !got.LastSeen.After(first) {
		t.Fatal("LastSeen not updated by Get")
	}
}
