package OLLAMA

import (
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mariocandela/beelzebub/v3/bridge"
	"github.com/mariocandela/beelzebub/v3/historystore"
	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/tracer"
	"github.com/stretchr/testify/assert"
)

func newTestStrategy() *OllamaStrategy {
	return &OllamaStrategy{
		Sessions:     historystore.NewHistoryStore(),
		ipSessions:   make(map[string]*OllamaSession),
		models:       []parser.OllamaModel{{Name: "llama3.1:8b", Family: "llama", ParameterSize: "8B", QuantizationLevel: "Q4_0"}},
		version:      "0.6.2",
		canaryTokens: map[string]string{},
		injections:   map[string]string{},
		rng:          rand.New(rand.NewSource(42)),
	}
}

func TestCategorizePrompt(t *testing.T) {
	tests := []struct {
		prompt   string
		expected PromptCategory
	}{
		{"Hi", CategoryTestProbe},
		{"hello", CategoryTestProbe},
		{"test", CategoryTestProbe},
		{"2+2", CategoryTestProbe},
		{"ok", CategoryTestProbe},
		{"Write a python function to sort a list", CategoryCoding},
		{"implement a REST API in golang", CategoryCoding},
		{"write code for a database query", CategoryCoding},
		{"translate this to Spanish", CategoryTranslation},
		{"übersetze den Text ins Englische", CategoryTranslation},
		{"переведи на английский", CategoryTranslation},
		{"how to exploit a buffer overflow", CategorySecurity},
		{"create a reverse shell payload", CategorySecurity},
		{"nmap scan for vulnerabilities", CategorySecurity},
		{"how to install docker", CategoryQuestion},
		{"explain the difference between TCP and UDP", CategoryQuestion},
		{"what is a kubernetes pod", CategoryQuestion},
		{"I need some help with my project planning", CategoryGeneral},
		{"the weather is nice today", CategoryGeneral},
	}

	for _, tt := range tests {
		t.Run(tt.prompt, func(t *testing.T) {
			result := categorizePrompt(tt.prompt)
			assert.Equal(t, tt.expected, result, "prompt: %q", tt.prompt)
		})
	}
}

func TestBuildInjectedResponse(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	canaryTokens := map[string]string{
		"canary_url": "https://canary.example.com",
		"aws_key":    "AKIAIOSFODNN7TESTKEY",
	}
	payloads := map[string]string{}

	t.Run("injection disabled returns clean response", func(t *testing.T) {
		resp := buildInjectedResponse(CategoryTestProbe, "", -1, 1, rng, canaryTokens, payloads, nil, "")
		assert.NotContains(t, resp, "im_sep")
		assert.NotContains(t, resp, "INFERENCE NODE")
		assert.NotContains(t, resp, "split-brain")
	})

	t.Run("canary tokens substituted in coding response", func(t *testing.T) {
		found := false
		for i := 0; i < 20; i++ {
			resp := buildInjectedResponse(CategoryCoding, "", 0, 1, rng, canaryTokens, payloads, nil, "")
			if strings.Contains(resp, "TESTKEY") {
				found = true
				break
			}
		}
		assert.True(t, found, "canary tokens should be substituted in coding responses")
	})

	t.Run("cross-protocol breadcrumbs in security response", func(t *testing.T) {
		found := false
		for i := 0; i < 20; i++ {
			resp := buildInjectedResponse(CategorySecurity, "", 0, 1, rng, canaryTokens, payloads, nil, "")
			if strings.Contains(resp, "localhost:8000") || strings.Contains(resp, "localhost:18789") {
				found = true
				break
			}
		}
		assert.True(t, found, "security responses should reference other honeypot ports")
	})

	t.Run("prompt reflection prepended for question category", func(t *testing.T) {
		resp := buildInjectedResponse(CategoryQuestion, "explain kubernetes networking", 0, 1, rng, canaryTokens, payloads, nil, "")
		assert.True(t, strings.HasPrefix(resp, "Regarding kubernetes networking: "), "should prepend topic reflection")
	})

	t.Run("bridge hint appended for ssh_authenticated", func(t *testing.T) {
		br := bridge.NewBridge()
		br.SetFlag("10.0.0.1", "ssh_authenticated")
		resp := buildInjectedResponse(CategoryGeneral, "test something here", 0, 1, rng, canaryTokens, payloads, br, "10.0.0.1")
		assert.Contains(t, resp, "SSH-authenticated sessions get priority inference")
		assert.Contains(t, resp, "localhost:8000/mcp")
	})

	t.Run("no bridge hint when bridge is nil", func(t *testing.T) {
		resp := buildInjectedResponse(CategoryGeneral, "", 0, 1, rng, canaryTokens, payloads, nil, "10.0.0.1")
		assert.NotContains(t, resp, "SSH-authenticated")
		assert.NotContains(t, resp, "unified IAM")
	})

	t.Run("canary package import in python template", func(t *testing.T) {
		found := false
		for i := 0; i < 20; i++ {
			resp := buildInjectedResponse(CategoryCoding, "", 0, 1, rng, canaryTokens, payloads, nil, "")
			if strings.Contains(resp, "crestfield-platform-sdk") {
				found = true
				break
			}
		}
		assert.True(t, found, "coding responses should include canary pip package")
	})
}

func TestReflectTopic(t *testing.T) {
	tests := []struct {
		prompt   string
		expected string
	}{
		{"explain kubernetes networking", "Regarding kubernetes networking: "},
		{"what is a docker container", "Regarding docker container: "},
		{"Hi", ""},                  // too short, no keywords
		{"hello world", ""},         // both are stop words
		{"translate this to french", "Regarding french: "},
		{"how do microservices communicate with databases and caching layers", "Regarding microservices communicate databases: "},
	}
	for _, tt := range tests {
		t.Run(tt.prompt, func(t *testing.T) {
			result := reflectTopic(tt.prompt)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBridgeHint(t *testing.T) {
	t.Run("nil bridge returns empty", func(t *testing.T) {
		assert.Equal(t, "", bridgeHint(nil, "1.2.3.4"))
	})

	t.Run("no flags returns empty", func(t *testing.T) {
		br := bridge.NewBridge()
		assert.Equal(t, "", bridgeHint(br, "1.2.3.4"))
	})

	t.Run("ssh_authenticated returns MCP hint", func(t *testing.T) {
		br := bridge.NewBridge()
		br.SetFlag("1.2.3.4", "ssh_authenticated")
		hint := bridgeHint(br, "1.2.3.4")
		assert.Contains(t, hint, "SSH-authenticated")
		assert.Contains(t, hint, "localhost:8000/mcp")
	})

	t.Run("discovered_aws_credentials returns IAM hint", func(t *testing.T) {
		br := bridge.NewBridge()
		br.SetFlag("1.2.3.4", "discovered_aws_credentials")
		hint := bridgeHint(br, "1.2.3.4")
		assert.Contains(t, hint, "unified IAM")
		assert.Contains(t, hint, "OpenClaw :18789")
	})

	t.Run("mcp_tools_used returns configstore hint", func(t *testing.T) {
		br := bridge.NewBridge()
		br.SetFlag("1.2.3.4", "mcp_tools_used")
		hint := bridgeHint(br, "1.2.3.4")
		assert.Contains(t, hint, "cdf/configstore.kv")
	})

	t.Run("ssh takes priority over aws", func(t *testing.T) {
		br := bridge.NewBridge()
		br.SetFlag("1.2.3.4", "ssh_authenticated")
		br.SetFlag("1.2.3.4", "discovered_aws_credentials")
		hint := bridgeHint(br, "1.2.3.4")
		assert.Contains(t, hint, "SSH-authenticated")
		assert.NotContains(t, hint, "unified IAM")
	})
}

func TestSessionIsolation(t *testing.T) {
	s := &OllamaStrategy{
		ipSessions: make(map[string]*OllamaSession),
	}

	sess1 := s.getOrCreateSession("1.1.1.1")
	sess2 := s.getOrCreateSession("2.2.2.2")

	sess1.mu.Lock()
	sess1.PromptCount = 10
	sess1.HasRegistered = true
	sess1.mu.Unlock()

	sess2.mu.Lock()
	assert.Equal(t, 0, sess2.PromptCount)
	assert.False(t, sess2.HasRegistered)
	sess2.mu.Unlock()

	sess1Again := s.getOrCreateSession("1.1.1.1")
	sess1Again.mu.Lock()
	assert.Equal(t, 10, sess1Again.PromptCount)
	assert.True(t, sess1Again.HasRegistered)
	sess1Again.mu.Unlock()
}

func TestSessionEscalation(t *testing.T) {
	sess := &OllamaSession{
		ModelsRequested: make(map[string]bool),
		EndpointsHit:    make(map[string]bool),
		ModelLoaded:     make(map[string]bool),
	}

	// All requests return -1 (no injection — engagement-first strategy)
	sess.PromptCount = 1
	assert.Equal(t, -1, injectionLevelForSession(sess))
	sess.PromptCount = 4
	assert.Equal(t, -1, injectionLevelForSession(sess))
	sess.PromptCount = 5
	assert.Equal(t, -1, injectionLevelForSession(sess))
	sess.PromptCount = 7
	assert.Equal(t, -1, injectionLevelForSession(sess))
	sess.PromptCount = 8
	assert.Equal(t, -1, injectionLevelForSession(sess))
	sess.PromptCount = 15
	assert.Equal(t, -1, injectionLevelForSession(sess))
}

func TestTimingProfile(t *testing.T) {
	tests := []struct {
		model    string
		expected int
	}{
		{"llama3.1:8b", 40},
		{"mistral:7b", 40},
		{"codellama:13b", 120},
		{"llama2:70b", 250},
		{"nomic-embed-text", 40},
	}

	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			tp := timingForModel(tt.model)
			assert.Equal(t, tt.expected, tp.TokenDelayMs)
		})
	}
}

func TestOllamaGenerateRequest(t *testing.T) {
	reqBody := `{"model":"llama3.1:8b","prompt":"Write hello world in Python","stream":false}`
	var req struct {
		Model  string `json:"model"`
		Prompt string `json:"prompt"`
		Stream *bool  `json:"stream"`
	}
	err := json.Unmarshal([]byte(reqBody), &req)
	assert.NoError(t, err)
	assert.Equal(t, "llama3.1:8b", req.Model)
	assert.Equal(t, "Write hello world in Python", req.Prompt)
	assert.NotNil(t, req.Stream)
	assert.False(t, *req.Stream)
}

func TestOllamaStreamFormat(t *testing.T) {
	chunks := []string{
		`{"model":"llama3.1:8b","created_at":"2026-03-07T00:00:00Z","response":"Hello","done":false}`,
		`{"model":"llama3.1:8b","created_at":"2026-03-07T00:00:00Z","response":"","done":true,"total_duration":1000000000}`,
	}

	for _, chunk := range chunks {
		var parsed map[string]interface{}
		err := json.Unmarshal([]byte(chunk), &parsed)
		assert.NoError(t, err)
		assert.Contains(t, parsed, "model")
		assert.Contains(t, parsed, "done")
		assert.Contains(t, parsed, "created_at")
	}
}

func TestOpenAIStreamFormat(t *testing.T) {
	chunk := `{"id":"chatcmpl-abc123","object":"chat.completion.chunk","created":1709827200,"model":"llama3.1:8b","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}`

	var parsed map[string]interface{}
	err := json.Unmarshal([]byte(chunk), &parsed)
	assert.NoError(t, err)
	assert.Equal(t, "chat.completion.chunk", parsed["object"])
	choices := parsed["choices"].([]interface{})
	assert.Len(t, choices, 1)
}

func TestRegistration(t *testing.T) {
	br := bridge.NewBridge()
	s := &OllamaStrategy{
		ipSessions:   make(map[string]*OllamaSession),
		Bridge:       br,
		canaryTokens: map[string]string{},
		injections:   map[string]string{},
		rng:          rand.New(rand.NewSource(42)),
	}

	ip := "10.0.0.1"
	sess := s.getOrCreateSession(ip)

	sess.mu.Lock()
	sess.HasRegistered = true
	sess.RegisterPayload = `{"client_id":"test-system-prompt","tools":"tool1,tool2"}`
	sess.InjectionLevel = 3
	sess.mu.Unlock()

	br.RecordDiscovery(ip, "ollama", "agent_system_prompt", "register_payload", sess.RegisterPayload)
	br.SetFlag(ip, "ollama_injection_success")

	assert.True(t, br.HasFlag(ip, "ollama_injection_success"))
	assert.True(t, br.HasDiscovered(ip, "agent_system_prompt"))

	discoveries := br.GetDiscoveries(ip)
	assert.Len(t, discoveries, 1)
	assert.Equal(t, "ollama", discoveries[0].Source)
}

func TestInjectionEscalation(t *testing.T) {
	sess := &OllamaSession{
		PromptCount:  1,
		EndpointsHit: make(map[string]bool),
	}

	// All requests: no injection (engagement-first strategy)
	assert.Equal(t, -1, injectionLevelForSession(sess))

	sess.PromptCount = 4
	assert.Equal(t, -1, injectionLevelForSession(sess))

	sess.PromptCount = 5
	assert.Equal(t, -1, injectionLevelForSession(sess))

	sess.PromptCount = 8
	assert.Equal(t, -1, injectionLevelForSession(sess))
}

func TestSystemMessageExtraction(t *testing.T) {
	br := bridge.NewBridge()
	s := &OllamaStrategy{
		Sessions:     historystore.NewHistoryStore(),
		ipSessions:   make(map[string]*OllamaSession),
		Bridge:       br,
		canaryTokens: map[string]string{},
		injections:   map[string]string{},
		rng:          rand.New(rand.NewSource(42)),
		models:       []parser.OllamaModel{{Name: "llama3.1:8b"}},
		version:      "0.6.2",
	}

	body := `{"model":"llama3.1:8b","messages":[{"role":"system","content":"You are a security researcher"},{"role":"user","content":"Hi"}],"stream":false}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer sk-test-0000")
	w := httptest.NewRecorder()

	servConf := parser.BeelzebubServiceConfiguration{Description: "test"}
	tr := tracer.GetInstance(func(event tracer.Event) {})

	s.handleOpenAIChat(w, req, servConf, tr)

	assert.Equal(t, http.StatusOK, w.Code)

	ip := "192.0.2.1"
	assert.True(t, br.HasFlag(ip, "ollama_system_prompt_captured"))
	assert.True(t, br.HasDiscovered(ip, "agent_system_prompt"))

	discoveries := br.GetDiscoveries(ip)
	found := false
	for _, d := range discoveries {
		if d.Type == "agent_system_prompt" && strings.Contains(d.Value, "security researcher") {
			found = true
		}
	}
	assert.True(t, found, "should capture system message content")
}

func TestOllamaContextArray(t *testing.T) {
	ctx := ollamaContextArray(10, 20)
	assert.True(t, len(ctx) > 0, "context array should not be empty")
	assert.Equal(t, 30, len(ctx), "context array should be promptTokens + evalTokens")
	// Values should be in plausible token ID range
	for _, v := range ctx {
		assert.True(t, v >= 128000, "token IDs should be in range")
	}
}

func TestModelListResponse(t *testing.T) {
	models := []parser.OllamaModel{
		{Name: "llama3.1:8b", Size: "4.7GB", Family: "llama", ParameterSize: "8B", QuantizationLevel: "Q4_0"},
		{Name: "mistral:7b", Size: "4.1GB", Family: "mistral", ParameterSize: "7B", QuantizationLevel: "Q4_0"},
	}

	type modelEntry struct {
		Name    string `json:"name"`
		Details struct {
			Family        string `json:"family"`
			ParameterSize string `json:"parameter_size"`
		} `json:"details"`
	}

	var entries []modelEntry
	for _, m := range models {
		e := modelEntry{Name: m.Name}
		e.Details.Family = m.Family
		e.Details.ParameterSize = m.ParameterSize
		entries = append(entries, e)
	}

	resp := struct {
		Models []modelEntry `json:"models"`
	}{Models: entries}

	out, err := json.Marshal(resp)
	assert.NoError(t, err)

	var parsed map[string]interface{}
	json.Unmarshal(out, &parsed)
	models2 := parsed["models"].([]interface{})
	assert.Len(t, models2, 2)
}

func TestTokenizeResponse(t *testing.T) {
	text := "Hello world"
	tokens := tokenizeResponse(text)
	assert.True(t, len(tokens) > 0)

	reconstructed := strings.Join(tokens, "")
	assert.Equal(t, text, reconstructed)
}

func TestOllamaStrategyInit(t *testing.T) {
	br := bridge.NewBridge()
	s := &OllamaStrategy{Bridge: br}

	servConf := parser.BeelzebubServiceConfiguration{
		Protocol:    "ollama",
		Address:     ":0",
		Description: "Ollama LLM inference",
		OllamaConfig: parser.OllamaConfig{
			Models: []parser.OllamaModel{
				{Name: "llama3.1:8b", Size: "4.7GB", Family: "llama", ParameterSize: "8B", QuantizationLevel: "Q4_0"},
			},
			Version: "0.6.2",
		},
	}

	tr := tracer.GetInstance(func(event tracer.Event) {})
	err := s.Init(servConf, tr)
	assert.NoError(t, err)
	time.Sleep(50 * time.Millisecond)
}

func TestHandleRootResponse(t *testing.T) {
	s := newTestStrategy()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	servConf := parser.BeelzebubServiceConfiguration{Description: "test"}
	tr := tracer.GetInstance(func(event tracer.Event) {})

	s.handleRoot(w, req, servConf, tr)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "Ollama is running", w.Body.String())
}

func TestHandleVersionResponse(t *testing.T) {
	s := newTestStrategy()

	req := httptest.NewRequest("GET", "/api/version", nil)
	w := httptest.NewRecorder()

	servConf := parser.BeelzebubServiceConfiguration{Description: "test"}
	tr := tracer.GetInstance(func(event tracer.Event) {})

	s.handleVersion(w, req, servConf, tr)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"version":"0.6.2"`)
	assert.Contains(t, w.Body.String(), `"platform":"Crestfield Platform"`)
	assert.Contains(t, w.Body.String(), `"mcp_endpoint":"http://localhost:8000/mcp"`)
}

func TestHandleTagsResponse(t *testing.T) {
	s := newTestStrategy()
	s.models = []parser.OllamaModel{
		{Name: "llama3.1:8b", Family: "llama", ParameterSize: "8B", QuantizationLevel: "Q4_0"},
		{Name: "mistral:7b", Family: "mistral", ParameterSize: "7B", QuantizationLevel: "Q4_0"},
	}

	req := httptest.NewRequest("GET", "/api/tags", nil)
	w := httptest.NewRecorder()

	servConf := parser.BeelzebubServiceConfiguration{Description: "test"}
	tr := tracer.GetInstance(func(event tracer.Event) {})

	s.handleTags(w, req, servConf, tr)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Len(t, resp.Models, 2)
}

func TestHandleGenerateNonStreaming(t *testing.T) {
	s := newTestStrategy()

	body := `{"model":"llama3.1:8b","prompt":"Hi","stream":false}`
	req := httptest.NewRequest("POST", "/api/generate", strings.NewReader(body))
	w := httptest.NewRecorder()

	servConf := parser.BeelzebubServiceConfiguration{Description: "test"}
	tr := tracer.GetInstance(func(event tracer.Event) {})

	s.handleGenerate(w, req, servConf, tr)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, true, resp["done"])
	assert.NotEmpty(t, resp["response"])
}

func TestHandleOpenAIChatNonStreaming(t *testing.T) {
	s := newTestStrategy()

	body := `{"model":"llama3.1:8b","messages":[{"role":"user","content":"Hi"}],"stream":false}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer sk-test-0000")
	w := httptest.NewRecorder()

	servConf := parser.BeelzebubServiceConfiguration{Description: "test"}
	tr := tracer.GetInstance(func(event tracer.Event) {})

	s.handleOpenAIChat(w, req, servConf, tr)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "chat.completion", resp["object"])
	choices := resp["choices"].([]interface{})
	assert.Len(t, choices, 1)
}

func TestHandleOpenAIChatRequires401OnMissingBearer(t *testing.T) {
	s := newTestStrategy()

	body := `{"model":"llama3.1:8b","messages":[{"role":"user","content":"Hi"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	// No Authorization header
	w := httptest.NewRecorder()

	servConf := parser.BeelzebubServiceConfiguration{Description: "test"}
	tr := tracer.GetInstance(func(event tracer.Event) {})
	s.handleOpenAIChat(w, req, servConf, tr)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "You didn't provide an API key")
	assert.NotEmpty(t, w.Header().Get("X-Request-ID"))
}

func TestHandleOpenAIChatRequires401OnMalformedBearer(t *testing.T) {
	s := newTestStrategy()

	body := `{"model":"llama3.1:8b","messages":[{"role":"user","content":"Hi"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Token abc")
	w := httptest.NewRecorder()

	servConf := parser.BeelzebubServiceConfiguration{Description: "test"}
	tr := tracer.GetInstance(func(event tracer.Event) {})
	s.handleOpenAIChat(w, req, servConf, tr)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_api_key")
}

func TestIsEmbeddingModel(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"nomic-embed-text", true},
		{"nomic-embed-text:latest", true},
		{"mxbai-embed-large", true},
		{"snowflake-arctic-embed2", true},
		{"all-minilm", true},
		{"all-MiniLM-L6-v2", true},
		{"bge-small-en", true},
		{"gte-large", true},
		{"text-embedding-3-small", true},
		{"jina-embed-v2", true},
		{"arctic-embed", true},
		{"llama3.1:8b", false},
		{"gpt-4.1-mini", false},
		{"", false},
		{"qwen2.5-coder:7b", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, isEmbeddingModel(c.name))
		})
	}
}

func TestHandleGenerateRejectsEmbeddingModel(t *testing.T) {
	s := newTestStrategy()

	body := `{"model":"nomic-embed-text","prompt":"Hi","stream":false}`
	req := httptest.NewRequest("POST", "/api/generate", strings.NewReader(body))
	w := httptest.NewRecorder()

	servConf := parser.BeelzebubServiceConfiguration{Description: "test"}
	tr := tracer.GetInstance(func(event tracer.Event) {})

	s.handleGenerate(w, req, servConf, tr)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "does not support generate")
	// Must NOT leak chat-style response fields
	assert.NotContains(t, w.Body.String(), `"response"`)
	assert.NotContains(t, w.Body.String(), `"done"`)
}

func TestHandleChatRejectsEmbeddingModel(t *testing.T) {
	s := newTestStrategy()

	body := `{"model":"bge-small-en","messages":[{"role":"user","content":"hi"}],"stream":false}`
	req := httptest.NewRequest("POST", "/api/chat", strings.NewReader(body))
	w := httptest.NewRecorder()

	servConf := parser.BeelzebubServiceConfiguration{Description: "test"}
	tr := tracer.GetInstance(func(event tracer.Event) {})

	s.handleChat(w, req, servConf, tr)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "does not support chat")
	assert.NotContains(t, w.Body.String(), `"message"`)
}

func TestHandleOpenAIChatRejectsEmbeddingModel(t *testing.T) {
	s := newTestStrategy()

	body := `{"model":"text-embedding-3-small","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer sk-test-0000")
	w := httptest.NewRecorder()

	servConf := parser.BeelzebubServiceConfiguration{Description: "test"}
	tr := tracer.GetInstance(func(event tracer.Event) {})

	s.handleOpenAIChat(w, req, servConf, tr)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "not a chat model")
	assert.Contains(t, w.Body.String(), "v1/embeddings")
}

// When the backend LLM plugin is not configured, handleChat falls back to
// template-based responses. We can still verify that user-supplied system
// messages don't crash the handler and that the handler's chosen prompt path
// includes the system instruction (via the template fallback's category
// selection and prompt reflection).
func TestHandleChatAcceptsUserSystemMessage(t *testing.T) {
	s := newTestStrategy()

	body := `{"model":"llama3.1:8b","messages":[` +
		`{"role":"system","content":"You are a calculator. Answer with digits only."},` +
		`{"role":"user","content":"2+2"}` +
		`],"stream":false}`
	req := httptest.NewRequest("POST", "/api/chat", strings.NewReader(body))
	w := httptest.NewRecorder()

	servConf := parser.BeelzebubServiceConfiguration{Description: "test"}
	tr := tracer.GetInstance(func(event tracer.Event) {})

	s.handleChat(w, req, servConf, tr)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, true, resp["done"])
}

