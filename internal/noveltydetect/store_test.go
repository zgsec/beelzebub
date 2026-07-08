package noveltydetect

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRecordAndLookupCommand(t *testing.T) {
	s := NewStore()
	assert.False(t, s.IsCommandKnown("uname -a"))
	isNew := s.RecordCommand("uname -a")
	assert.True(t, isNew)
	assert.True(t, s.IsCommandKnown("uname -a"))
	// Case-insensitive
	assert.True(t, s.IsCommandKnown("UNAME -A"))
	// Second record is not new
	isNew = s.RecordCommand("uname -a")
	assert.False(t, isNew)
}

func TestRecordAndLookupCredPair(t *testing.T) {
	s := NewStore()
	assert.False(t, s.IsCredPairKnown("root", "password"))
	isNew := s.RecordCredPair("root", "password")
	assert.True(t, isNew)
	assert.True(t, s.IsCredPairKnown("root", "password"))
	isNew = s.RecordCredPair("root", "password")
	assert.False(t, isNew)
}

func TestRecordAndLookupPath(t *testing.T) {
	s := NewStore()
	assert.False(t, s.IsPathKnown("/api/tags"))
	isNew := s.RecordPath("/api/tags")
	assert.True(t, isNew)
	assert.True(t, s.IsPathKnown("/api/tags"))
	// Case-insensitive
	assert.True(t, s.IsPathKnown("/API/TAGS"))
}

func TestRecordAndLookupToolSequence(t *testing.T) {
	s := NewStore()
	tools := []string{"list_users", "get_logs", "create_resource"}
	assert.False(t, s.IsToolSequenceKnown(tools))
	isNew := s.RecordToolSequence(tools)
	assert.True(t, isNew)
	assert.True(t, s.IsToolSequenceKnown(tools))
	isNew = s.RecordToolSequence(tools)
	assert.False(t, isNew)
	// Different order is different sequence
	assert.False(t, s.IsToolSequenceKnown([]string{"get_logs", "list_users", "create_resource"}))
}

func TestRecordAndLookupUserAgent(t *testing.T) {
	s := NewStore()
	assert.False(t, s.IsUserAgentKnown("curl/7.68.0"))
	isNew := s.RecordUserAgent("curl/7.68.0")
	assert.True(t, isNew)
	assert.True(t, s.IsUserAgentKnown("curl/7.68.0"))
	assert.True(t, s.IsUserAgentKnown("CURL/7.68.0"))
}

func TestCleanTTL(t *testing.T) {
	s := NewStore()
	s.RecordCommand("old-command")
	// Manually backdate the entry
	key := hash(normalizeCommand("old-command"))
	s.mu.Lock()
	s.commands[key] = time.Now().Add(-48 * time.Hour)
	s.mu.Unlock()

	s.RecordCommand("new-command")

	removed := s.Clean(24 * time.Hour)
	assert.Equal(t, 1, removed)
	assert.False(t, s.IsCommandKnown("old-command"))
	assert.True(t, s.IsCommandKnown("new-command"))
}

func TestStats(t *testing.T) {
	s := NewStore()
	s.RecordCommand("cmd1")
	s.RecordCommand("cmd2")
	s.RecordCredPair("root", "pass")
	s.RecordPath("/api")
	s.RecordToolSequence([]string{"a", "b"})
	s.RecordUserAgent("bot/1.0")

	stats := s.Stats()
	assert.Equal(t, 2, stats.Commands)
	assert.Equal(t, 1, stats.CredPairs)
	assert.Equal(t, 1, stats.Paths)
	assert.Equal(t, 1, stats.ToolSeqs)
	assert.Equal(t, 1, stats.UserAgents)
}

func TestConcurrentAccess(t *testing.T) {
	s := NewStore()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s.RecordCommand("cmd")
			s.IsCommandKnown("cmd")
			s.RecordCredPair("user", "pass")
			s.RecordPath("/test")
			s.RecordToolSequence([]string{"a"})
			s.RecordUserAgent("bot")
		}(i)
	}
	wg.Wait()
	// Should not panic or deadlock
	stats := s.Stats()
	assert.Equal(t, 1, stats.Commands) // All same command
}
