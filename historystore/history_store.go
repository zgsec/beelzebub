package historystore

import (
	"sync"
	"time"

	"github.com/mariocandela/beelzebub/v3/plugins"
)

var (
	MaxHistoryAge   = 60 * time.Minute
	CleanerInterval = 1 * time.Minute
)

// HistoryStore is a thread-safe structure for storing Messages used to build LLM Context.
type HistoryStore struct {
	sync.RWMutex
	sessions map[string]HistoryEvent
}

const retryRingSize = 16

// HistoryEvent is a container for storing messages and session metadata.
type HistoryEvent struct {
	LastSeen  time.Time
	Messages  []plugins.Message
	SessionID string
	Sequence  int

	// Ring buffer for retry detection
	recentCommands [retryRingSize]string
	recentCmdIDs   [retryRingSize]string
	ringIdx        int
}

// NewHistoryStore returns a prepared HistoryStore
func NewHistoryStore() *HistoryStore {
	return &HistoryStore{
		sessions: make(map[string]HistoryEvent),
	}
}

// HasKey returns true if the supplied key exists in the map.
func (hs *HistoryStore) HasKey(key string) bool {
	hs.RLock()
	defer hs.RUnlock()
	_, ok := hs.sessions[key]
	return ok
}

// Query returns the value stored at the map
func (hs *HistoryStore) Query(key string) []plugins.Message {
	hs.RLock()
	defer hs.RUnlock()
	return hs.sessions[key].Messages
}

// Append will add the slice of Mesages to the entry for the key.
// If the map has not yet been initalised, then a new map is created.
func (hs *HistoryStore) Append(key string, message ...plugins.Message) {
	hs.Lock()
	defer hs.Unlock()
	// In the unexpected case that the map has not yet been initalised, create it.
	if hs.sessions == nil {
		hs.sessions = make(map[string]HistoryEvent)
	}
	e, ok := hs.sessions[key]
	if !ok {
		e = HistoryEvent{}
	}
	e.LastSeen = time.Now()
	e.Messages = append(e.Messages, message...)
	hs.sessions[key] = e
}

// NextSequence increments and returns the sequence number for a session.
// The caller must hold the HistoryStore lock.
func (hs *HistoryStore) NextSequence(key string) int {
	e := hs.sessions[key]
	e.Sequence++
	e.LastSeen = time.Now()
	hs.sessions[key] = e
	return e.Sequence
}

// SetSessionID sets the session UUID for a key if not already set.
func (hs *HistoryStore) SetSessionID(key, sessionID string) {
	hs.Lock()
	defer hs.Unlock()
	if hs.sessions == nil {
		hs.sessions = make(map[string]HistoryEvent)
	}
	e := hs.sessions[key]
	if e.SessionID == "" {
		e.SessionID = sessionID
	}
	e.LastSeen = time.Now()
	hs.sessions[key] = e
}

// GetSessionID returns the session ID for a key, or empty string if not found.
func (hs *HistoryStore) GetSessionID(key string) string {
	hs.RLock()
	defer hs.RUnlock()
	return hs.sessions[key].SessionID
}

// DetectRetry checks if cmd was recently issued on this session.
// Returns (isRetry, previousEventID). Also records cmd in the ring buffer.
func (hs *HistoryStore) DetectRetry(key, cmd, eventID string) (bool, string) {
	hs.Lock()
	defer hs.Unlock()
	e := hs.sessions[key]

	// Search ring buffer for duplicate
	for i := 0; i < retryRingSize; i++ {
		if e.recentCommands[i] == cmd && e.recentCommands[i] != "" {
			prevID := e.recentCmdIDs[i]
			// Record current entry
			e.recentCommands[e.ringIdx] = cmd
			e.recentCmdIDs[e.ringIdx] = eventID
			e.ringIdx = (e.ringIdx + 1) % retryRingSize
			hs.sessions[key] = e
			return true, prevID
		}
	}

	// Record new entry
	e.recentCommands[e.ringIdx] = cmd
	e.recentCmdIDs[e.ringIdx] = eventID
	e.ringIdx = (e.ringIdx + 1) % retryRingSize
	hs.sessions[key] = e
	return false, ""
}

// HistoryCleaner is a function that will periodically remove records from the HistoryStore
// that are older than MaxHistoryAge.
func (hs *HistoryStore) HistoryCleaner() {
	cleanerTicker := time.NewTicker(CleanerInterval)
	go func() {
		for range cleanerTicker.C {
			hs.Lock()
			for k, v := range hs.sessions {
				if time.Since(v.LastSeen) > MaxHistoryAge {
					delete(hs.sessions, k)
				}
			}
			hs.Unlock()
		}
	}()
}
