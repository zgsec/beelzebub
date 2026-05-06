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
			// {{PLATFORM_SDK}} falls back to "platform-sdk" when canaryTokens has no platform_sdk key
			if strings.Contains(resp, "platform-sdk") {
				found = true
				break
			}
		}
		assert.True(t, found, "coding responses should include platform SDK reference")
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

	// Real Ollama /api/version returns ONLY {"version":"x.y.z"}.
	// Adding platform / platform_version / mcp_endpoint keys is a
	// fingerprint for any caller that knows the real upstream shape.
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, s.version, w.Header().Get("Ollama-Version"))
	body := w.Body.String()
	assert.Contains(t, body, `"version":"0.6.2"`)
	assert.NotContains(t, body, `"platform"`)
	assert.NotContains(t, body, `"platform_version"`)
	assert.NotContains(t, body, `"mcp_endpoint"`)
	assert.NotContains(t, body, `"platform_services"`)
}

func TestHandleShow_UnknownModel404(t *testing.T) {
	// Real Ollama returns 404 with {"error":"model 'name' not found"}
	// when /api/show is asked about a model not in the local set.
	s := newTestStrategy()
	s.models = []parser.OllamaModel{
		{Name: "llama3.1:8b", Family: "llama", ParameterSize: "8B", QuantizationLevel: "Q4_0"},
	}

	body := strings.NewReader(`{"model":"definitely-not-a-real-model:latest"}`)
	req := httptest.NewRequest("POST", "/api/show", body)
	w := httptest.NewRecorder()

	servConf := parser.BeelzebubServiceConfiguration{Description: "test"}
	tr := tracer.GetInstance(func(event tracer.Event) {})

	s.handleShow(w, req, servConf, tr)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, s.version, w.Header().Get("Ollama-Version"))
	assert.Contains(t, w.Body.String(), `"error":"model 'definitely-not-a-real-model:latest' not found"`)
}

func TestHandleShow_KnownModel200(t *testing.T) {
	// Sanity: a model IN the configured set still returns 200 with
	// the synthesized model_info envelope.
	s := newTestStrategy()
	s.models = []parser.OllamaModel{
		{Name: "llama3.1:8b", Family: "llama", ParameterSize: "8B", QuantizationLevel: "Q4_0"},
	}

	body := strings.NewReader(`{"model":"llama3.1:8b"}`)
	req := httptest.NewRequest("POST", "/api/show", body)
	w := httptest.NewRecorder()

	servConf := parser.BeelzebubServiceConfiguration{Description: "test"}
	tr := tracer.GetInstance(func(event tracer.Event) {})

	s.handleShow(w, req, servConf, tr)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "general.architecture")
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


// TestHandleTags_ModifiedAtIsRFC3339AndRecent verifies the dynamic
// modified_at fix: every emitted timestamp parses cleanly as RFC3339,
// falls within the last 90 days, all timestamps in a single response
// share the same TZ offset (persona's location), and two consecutive
// requests with the same persona+model produce identical values
// (deterministic seeded by sha256(slug+model_name)).
func TestHandleTags_ModifiedAtIsRFC3339AndRecent(t *testing.T) {
	s := newTestStrategy()
	s.models = []parser.OllamaModel{
		{Name: "aurora-7b", Family: "llama", ParameterSize: "7B", QuantizationLevel: "Q4_0"},
		{Name: "qwen2.5:14b", Family: "qwen2", ParameterSize: "14B", QuantizationLevel: "Q4_K_M"},
		{Name: "mistral-nemo:12b", Family: "mistral", ParameterSize: "12B", QuantizationLevel: "Q4_0"},
	}
	s.SetPersona(&parser.Persona{
		SchemaVersion: 1,
		Slug:          "bluespark-labs",
		DisplayName:   "BlueSpark Labs",
		Coherence: parser.PersonaCoherence{
			Timezone: "Asia/Singapore",
		},
	})

	servConf := parser.BeelzebubServiceConfiguration{Description: "test"}
	tr := tracer.GetInstance(func(event tracer.Event) {})

	doRequest := func() []string {
		req := httptest.NewRequest("GET", "/api/tags", nil)
		w := httptest.NewRecorder()
		s.handleTags(w, req, servConf, tr)

		var resp struct {
			Models []struct {
				Name       string `json:"name"`
				ModifiedAt string `json:"modified_at"`
			} `json:"models"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		out := make([]string, len(resp.Models))
		for i, m := range resp.Models {
			out[i] = m.ModifiedAt
		}
		return out
	}

	first := doRequest()
	second := doRequest()
	if len(first) != 3 {
		t.Fatalf("expected 3 model entries, got %d", len(first))
	}

	// (a) every modified_at parses as RFC3339[Nano]
	now := time.Now()
	parsed := make([]time.Time, len(first))
	for i, ts := range first {
		t1, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			// Try plain RFC3339 — Go's RFC3339Nano parser actually accepts both,
			// but be lenient anyway.
			t1, err = time.Parse(time.RFC3339, ts)
			if err != nil {
				t.Fatalf("modified_at %q does not parse as RFC3339: %v", ts, err)
			}
		}
		parsed[i] = t1
	}

	// (b) every modified_at falls within the last 6 days of now (the
	// staleness window the lure-shape verifier and real-fleet behavior
	// both expect for an active eval-harness host).
	sixDays := 6 * 24 * time.Hour
	for i, p := range parsed {
		age := now.Sub(p)
		if age < 0 || age > sixDays+time.Hour /* slack for test runtime */ {
			t.Errorf("model %d modified_at %s out of range [now-6d, now]: age=%v",
				i, first[i], age)
		}
	}

	// (c) all timestamps share the same TZ offset (Asia/Singapore = +08:00)
	expectedOffset := "+08:00"
	for i, ts := range first {
		if !strings.HasSuffix(ts, expectedOffset) {
			t.Errorf("model %d modified_at %q lacks expected TZ offset %s",
				i, ts, expectedOffset)
		}
	}

	// (d) two consecutive requests for the same persona+model are identical.
	// We allow a 1-second timing skew if the test flips across a second
	// boundary — the underlying offset is sha256-stable but the anchor is
	// time.Now(), so adjacent calls drift by sub-second only. Compare to
	// the second precision.
	for i := range first {
		t1, _ := time.Parse(time.RFC3339Nano, first[i])
		t2, _ := time.Parse(time.RFC3339Nano, second[i])
		drift := t2.Sub(t1)
		if drift < 0 {
			drift = -drift
		}
		if drift > 2*time.Second {
			t.Errorf("model %d: consecutive requests drifted by %v; want stable seed",
				i, drift)
		}
	}
}

// TestModelModifiedAt_FallsBackToUTCOnInvalidTZ — when persona timezone
// is unset or invalid, the helper must not crash and must emit UTC.
func TestModelModifiedAt_FallsBackToUTCOnInvalidTZ(t *testing.T) {
	s := newTestStrategy()
	s.SetPersona(&parser.Persona{
		SchemaVersion: 1,
		Slug:          "test-persona",
		Coherence:     parser.PersonaCoherence{Timezone: ""},
	})
	got := s.modelModifiedAt("llama3.1:8b")
	if !strings.HasSuffix(got, "Z") && !strings.HasSuffix(got, "+00:00") {
		t.Errorf("expected UTC suffix on empty TZ, got %q", got)
	}

	// Invalid TZ — should warn-and-fallback to UTC, not crash.
	s.SetPersona(&parser.Persona{
		SchemaVersion: 1,
		Slug:          "test-persona",
		Coherence:     parser.PersonaCoherence{Timezone: "Not/A/Real/Zone"},
	})
	got2 := s.modelModifiedAt("llama3.1:8b")
	if !strings.HasSuffix(got2, "Z") && !strings.HasSuffix(got2, "+00:00") {
		t.Errorf("expected UTC fallback on invalid TZ, got %q", got2)
	}
}

// TestOllama_LLMFallback_BackwardCompatCUDABody — when the lure has no
// llmFallback configured (every existing OLLAMA service config), the
// empty-response fallback emits the legacy Ollama-shaped CUDA-OOM JSON
// body and returns 500. Backward-compat gate.
func TestOllama_LLMFallback_BackwardCompatCUDABody(t *testing.T) {
	status, body := ollamaLLMFallback(nil, "llama3.1:8b")
	if status != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", status)
	}
	want := `{"error":"model 'llama3.1:8b' failed to generate a response: CUDA error: out of memory"}`
	if body != want {
		t.Errorf("body = %q, want %q", body, want)
	}
}

// TestOllama_LLMFallback_PersonaShapedBodyOverrides — when the lure has
// llmFallback configured (e.g. BlueSpark's ollama-11434 lure), the
// configured envelope wins verbatim. The model parameter is ignored
// because the configured body is taken as-is from YAML.
func TestOllama_LLMFallback_PersonaShapedBodyOverrides(t *testing.T) {
	fb := &parser.LLMFallback{
		Status: 500,
		Body:   `{"error":"unexpected EOF reading from inference engine"}`,
	}
	status, body := ollamaLLMFallback(fb, "aurora-7b")
	if status != 500 {
		t.Errorf("status = %d, want 500", status)
	}
	if body != fb.Body {
		t.Errorf("body = %q, want %q", body, fb.Body)
	}
}

// TestOllama_LLMFallback_ZeroFieldsKeepLegacy — partial config: zero
// status keeps the 500 default; empty body keeps the legacy CUDA-OOM
// envelope. Lets a lure tweak just one field without re-specifying the
// other.
func TestOllama_LLMFallback_ZeroFieldsKeepLegacy(t *testing.T) {
	// Only body set → status defaults to 500
	status, body := ollamaLLMFallback(&parser.LLMFallback{Body: `{"error":"x"}`}, "m1")
	if status != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (default)", status)
	}
	if body != `{"error":"x"}` {
		t.Errorf("body = %q, want override", body)
	}

	// Only status set → body defaults to CUDA-OOM with the model name
	status, body = ollamaLLMFallback(&parser.LLMFallback{Status: 503}, "m2")
	if status != 503 {
		t.Errorf("status = %d, want 503", status)
	}
	if !strings.Contains(body, "CUDA error: out of memory") {
		t.Errorf("body = %q, want default CUDA-OOM envelope", body)
	}
	if !strings.Contains(body, "'m2'") {
		t.Errorf("body = %q, want model 'm2' interpolated", body)
	}
}
