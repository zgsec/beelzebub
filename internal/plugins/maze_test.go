package plugins

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func mazeGET(m *MazeHoneypot, path string) MazeResponse {
	r, _ := http.NewRequest("GET", path, nil)
	return m.HandleRequest(r)
}

func TestMazePluginName(t *testing.T) {
	assert.Equal(t, "MazeHoneypot", MazePluginName)
}

func TestMaze_DirectoryPathReturnsListing(t *testing.T) {
	m := &MazeHoneypot{ServerVersion: "Apache/2.4.41 (Ubuntu)"}
	resp := mazeGET(m, "/backup/")

	assert.Equal(t, 200, resp.StatusCode)
	assert.Contains(t, resp.Body, "Index of")
	assert.Contains(t, strings.ToLower(resp.ContentType), "text/html")
}

func TestMaze_DeterministicSameURLSameBody(t *testing.T) {
	m := &MazeHoneypot{ServerVersion: "Apache/2.4.41 (Ubuntu)"}
	a := mazeGET(m, "/data/reports/")
	b := mazeGET(m, "/data/reports/")
	assert.Equal(t, a.Body, b.Body, "same URL must be reproducible (the research payload)")
}

func TestMaze_FilePathReturnsContentNotListing(t *testing.T) {
	m := &MazeHoneypot{ServerVersion: "Apache/2.4.41 (Ubuntu)"}
	resp := mazeGET(m, "/config/database.yaml")

	assert.Equal(t, 200, resp.StatusCode)
	assert.NotEmpty(t, resp.Body)
	assert.NotContains(t, resp.Body, "Index of")
}
