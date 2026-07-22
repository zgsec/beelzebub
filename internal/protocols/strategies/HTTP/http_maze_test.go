package HTTP

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/historystore"
	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/stretchr/testify/assert"
)

func TestBuildHTTPResponse_MazePluginServesDirectoryListing(t *testing.T) {
	cookieStore := historystore.NewCookieSessionStore(time.Hour)
	defer cookieStore.Stop()
	sctx := &sessionContext{cookieStore: cookieStore, cookieName: ".X", ttlSeconds: 1800}

	req := httptest.NewRequest("GET", "/backup/", nil)
	req.RemoteAddr = "203.0.113.5:1234"

	cmd := parser.Command{Plugin: "MazeHoneypot", StatusCode: 200}
	tt := &captureTracer{}
	servConf := parser.BeelzebubServiceConfiguration{ServerVersion: "Apache/2.4.41 (Ubuntu)"}

	resp, err, _ := buildHTTPResponse(servConf, tt, cmd, req, nil, sctx, nil)

	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Contains(t, resp.Body, "Index of")
	assert.Contains(t, strings.Join(resp.Headers, "\n"), "text/html")
}
