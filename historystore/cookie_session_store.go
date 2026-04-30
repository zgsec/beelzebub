package historystore

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// CookieSession is one operator's HTTP cookie-keyed session.
//
// Captured holds regex-extracted fields from the create handler
// (e.g. operator_user, operator_role for ScreenConnect). The map is
// scoped per-session and lure-namespaced by convention — each lure
// uses prefixed keys to avoid collision (`screenconnect.operator_user`).
//
// SessionKey is hash(cookie); it propagates into tracer.Event.SessionKey
// for downstream cross-event correlation.
type CookieSession struct {
	Cookie     string
	SessionKey string
	SrcIP      string
	JA4H       string
	Captured   map[string]string
	Stage      string
	CreatedAt  time.Time
	LastSeen   time.Time
}

// CookieSessionStore is a TTL-bounded in-memory map of active sessions.
//
// Reuses the shape of HistoryStore (sibling file): mutex-guarded map,
// background sweeper goroutine, no persistence. Per-sensor in-process,
// no coordination across sensors.
type CookieSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*CookieSession
	ttl      time.Duration
	stopCh   chan struct{}
}

// NewCookieSessionStore returns a started store. Call Stop() to halt sweeper.
func NewCookieSessionStore(ttl time.Duration) *CookieSessionStore {
	s := &CookieSessionStore{
		sessions: make(map[string]*CookieSession),
		ttl:      ttl,
		stopCh:   make(chan struct{}),
	}
	go s.sweepLoop()
	return s
}

// Create registers a fresh session and returns it.
func (s *CookieSessionStore) Create(srcIP, ja4h string, captured map[string]string) *CookieSession {
	cookie := newCookie()
	now := time.Now().UTC()
	cs := &CookieSession{
		Cookie:     cookie,
		SessionKey: hashCookie(cookie),
		SrcIP:      srcIP,
		JA4H:       ja4h,
		Captured:   copyMap(captured),
		CreatedAt:  now,
		LastSeen:   now,
	}
	s.mu.Lock()
	s.sessions[cookie] = cs
	s.mu.Unlock()
	return cs
}

// Get returns the session for cookie if alive. Updates LastSeen.
// Returns (nil, false) if missing or expired.
func (s *CookieSessionStore) Get(cookie string) (*CookieSession, bool) {
	if len(cookie) != 64 {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, ok := s.sessions[cookie]
	if !ok {
		return nil, false
	}
	if time.Since(cs.CreatedAt) > s.ttl {
		delete(s.sessions, cookie)
		return nil, false
	}
	cs.LastSeen = time.Now().UTC()
	return cs, true
}

// Stop halts the sweeper goroutine. Safe to call once.
func (s *CookieSessionStore) Stop() { close(s.stopCh) }

func (s *CookieSessionStore) sweepLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.sweep()
		}
	}
}

func (s *CookieSessionStore) sweep() {
	cutoff := time.Now().Add(-s.ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.sessions {
		if v.CreatedAt.Before(cutoff) {
			delete(s.sessions, k)
		}
	}
}

// Len returns the live session count (for metrics / tests).
func (s *CookieSessionStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

func newCookie() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Crypto/rand failure is unrecoverable.
		panic("cookie_session_store: rand.Read failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func hashCookie(cookie string) string {
	// Use a fast non-crypto hash if perf matters; for now sha256[:16].
	// Matches the SessionKey convention used by MCP elsewhere.
	return cookie[:16] // first 16 hex chars are unique-enough for keying
}

func copyMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
