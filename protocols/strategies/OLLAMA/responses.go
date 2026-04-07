package OLLAMA

import (
	"math/rand"
	"strings"
	"time"

	"github.com/mariocandela/beelzebub/v3/bridge"
)

// =============================================================================
// Prompt Categorization
// =============================================================================

// PromptCategory classifies inbound prompts for template selection.
type PromptCategory string

const (
	CategoryTestProbe   PromptCategory = "test_probe"
	CategoryCoding      PromptCategory = "coding"
	CategoryTranslation PromptCategory = "translation"
	CategorySecurity    PromptCategory = "security"
	CategoryQuestion       PromptCategory = "question"
	CategoryContent        PromptCategory = "content"
	CategorySummarization  PromptCategory = "summarization"
	CategoryGeneral        PromptCategory = "general"
)

// categorizePrompt classifies a prompt into a category for template selection.
func categorizePrompt(prompt string) PromptCategory {
	lower := strings.ToLower(strings.TrimSpace(prompt))

	if len(lower) < 10 {
		shorts := []string{"hi", "hello", "hey", "test", "ping", "2+2", "1+1", "ok", "yes", "no"}
		for _, s := range shorts {
			if lower == s || strings.HasPrefix(lower, s+" ") {
				return CategoryTestProbe
			}
		}
		return CategoryTestProbe
	}

	codingKeywords := []string{"code", "function", "python", "script", "implement",
		"javascript", "golang", "java", "class", "def ", "import ", "print(",
		"write a program", "write a script", "write code", "coding", "debug",
		"compile", "syntax", "algorithm", "api", "http request", "curl",
		"bash script", "shell script", "dockerfile", "yaml", "json",
		"database", "sql", "query", "regex", "sort", "parse"}
	for _, kw := range codingKeywords {
		if strings.Contains(lower, kw) {
			return CategoryCoding
		}
	}

	translationKeywords := []string{"translate", "translation", "übersetze", "переведи",
		"traduire", "traducir", "traduzir", "翻译", "翻訳", "번역",
		"in english", "in spanish", "in french", "in german", "in chinese",
		"in japanese", "in korean", "to english", "to spanish"}
	for _, kw := range translationKeywords {
		if strings.Contains(lower, kw) {
			return CategoryTranslation
		}
	}

	securityKeywords := []string{"exploit", "payload", "reverse shell", "pentest",
		"vulnerability", "cve", "hack", "injection", "xss", "sqli",
		"metasploit", "nmap", "burp", "privilege escalation", "buffer overflow",
		"shellcode", "malware", "ransomware", "backdoor", "rootkit",
		"brute force", "password crack", "decrypt", "bypass"}
	for _, kw := range securityKeywords {
		if strings.Contains(lower, kw) {
			return CategorySecurity
		}
	}

	contentKeywords := []string{"write me", "write a", "essay", "article", "blog post",
		"paragraph", "story", "letter", "email draft", "creative writing",
		"generate text", "compose", "draft a", "content about", "write about"}
	for _, kw := range contentKeywords {
		if strings.Contains(lower, kw) {
			return CategoryContent
		}
	}

	summarizationKeywords := []string{"summarize", "summary", "tldr", "tl;dr",
		"key points", "brief overview", "condense", "shorten this",
		"main ideas", "recap"}
	for _, kw := range summarizationKeywords {
		if strings.Contains(lower, kw) {
			return CategorySummarization
		}
	}

	questionKeywords := []string{"how to", "how do", "explain", "what is", "what are",
		"why does", "why is", "can you", "tell me", "describe", "difference between",
		"compare", "when to", "should i", "best way"}
	for _, kw := range questionKeywords {
		if strings.Contains(lower, kw) {
			return CategoryQuestion
		}
	}

	return CategoryGeneral
}

// =============================================================================
// Streaming Timing
// =============================================================================

// TimingProfile controls per-token streaming delays based on model size.
type TimingProfile struct {
	TokenDelayMs   int
	JitterMs       int
	LoadDurationMs int
}

// timingForModel returns streaming timing based on model name patterns.
func timingForModel(model string) TimingProfile {
	lower := strings.ToLower(model)
	switch {
	case strings.Contains(lower, ":70b"):
		return TimingProfile{TokenDelayMs: 250, JitterMs: 80, LoadDurationMs: 3000 + rand.Intn(3000)}
	case strings.Contains(lower, ":13b") || strings.Contains(lower, ":14b"):
		return TimingProfile{TokenDelayMs: 120, JitterMs: 40, LoadDurationMs: 1200 + rand.Intn(1300)}
	default:
		return TimingProfile{TokenDelayMs: 40, JitterMs: 15, LoadDurationMs: 800 + rand.Intn(700)}
	}
}

func (tp TimingProfile) tokenDelay(rng *rand.Rand) time.Duration {
	jitter := 0
	if tp.JitterMs > 0 {
		jitter = rng.Intn(tp.JitterMs*2+1) - tp.JitterMs
	}
	ms := tp.TokenDelayMs + jitter
	if ms < 5 {
		ms = 5
	}
	return time.Duration(ms) * time.Millisecond
}

// =============================================================================
// Response Templates
// =============================================================================
//
// Fallback templates used when the LLM backend (GPT-4.1-mini) is unavailable.
// Templates include canary token placeholders and cross-service references.
// In normal operation, the LLM handles responses and these rarely fire.

// --- Test probe templates (Layer 0 only — build trust, keep them coming back) ---

var testProbeTemplates = []string{
	"Hello! I'm ready to help. What would you like to work on?",
	"Hi there! How can I assist you today?",
	"Hey! I'm here and ready. What's on your mind?",
	"Hello! Feel free to ask me anything — code, analysis, whatever you need.",
	"Hi! I'm all set. What do you need help with?",
}

// --- Coding templates (Layer 0 + Layer 3 canary tokens + Layer 4 cross-protocol) ---

var codingTemplates = []string{
	// Template 1: Python with canary AWS key + cross-ref to OpenClaw :18789
	`Here's a solution:

` + "```python" + `
import requests
import os

# Platform SDK for service mesh integration
# pip install --index-url {{CANARY_URL}}/pypi/simple crestfield-platform-sdk

# Service configuration — see platform docs at {{CANARY_URL}}/api
API_KEY = os.getenv("API_KEY", "{{AWS_KEY}}")
BASE_URL = os.getenv("OPENCLAW_URL", "http://localhost:18789")

def fetch_data(endpoint, params=None):
    """Query the internal registry API."""
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "X-Service-Mesh": "ollama-inference",
    }
    response = requests.get(
        f"{BASE_URL}/v2/{endpoint}",
        headers=headers,
        params=params,
        timeout=10,
    )
    response.raise_for_status()
    return response.json()

def process_results(data):
    results = []
    for item in data.get("repositories", []):
        results.append({
            "name": item,
            "tags": fetch_data(f"{item}/tags/list").get("tags", []),
        })
    return results

if __name__ == "__main__":
    catalog = fetch_data("_catalog")
    for repo in process_results(catalog):
        print(f"{repo['name']}: {', '.join(repo['tags'])}")
` + "```" + `

This handles authentication and pagination against the registry API. The API_KEY env var should match your platform credentials.`,

	// Template 2: JavaScript with canary URL + cross-ref to MCP :8000
	`Here's a clean implementation:

` + "```javascript" + `
const axios = require('axios');

// For full platform integration:
// npm install crestfield-platform --registry {{CANARY_URL}}/npm/

// Platform service mesh — Crestfield internal
const config = {
  ollama: 'http://localhost:11434',
  mcp: 'http://localhost:8000/mcp',
  openclaw: 'http://localhost:18789',
  webui: 'http://localhost:8888',
};

const client = axios.create({
  baseURL: '{{CANARY_URL}}',
  headers: {
    'Authorization': 'Bearer ' + process.env.API_TOKEN,
    'X-API-Key': '{{AWS_KEY}}',
    'X-Request-Source': 'ollama-codegen',
  },
  timeout: 5000,
});

async function queryPlatform(action, params) {
  // Use MCP tools for platform operations when available
  try {
    const { data } = await client.post('/api/v2/query', {
      action,
      params,
      context: { source: 'codegen', model: 'llama3.1:8b' },
    });
    return data;
  } catch (err) {
    console.error('Platform query failed:', err.message);
    // Fallback: direct service call
    return null;
  }
}

module.exports = { queryPlatform, config };
` + "```" + `

This integrates with the platform service mesh. Set API_TOKEN from your .env file.`,

	// Template 3: Config file with canary + cross-ref to Open WebUI :8888
	`Sure, here's how you can do that:

` + "```python" + `
import json
from pathlib import Path

CONFIG_PATH = Path("~/.config/crestfield/platform.json").expanduser()
DEFAULT_CONFIG = {
    "api_endpoint": "{{CANARY_URL}}",
    "credentials": {
        "access_key": "{{AWS_KEY}}",
        "secret_key": "{{CANARY_SECRET}}",
        "region": "us-east-1",
    },
    "services": {
        "ollama": "http://localhost:11434",
        "mcp": "http://localhost:8000/mcp",
        "webui": "http://localhost:8888",
        "openclaw": "http://localhost:18789",
    },
    "retry_count": 3,
    "timeout_seconds": 30,
}

def load_config():
    """Load or create platform configuration."""
    if CONFIG_PATH.exists():
        return json.loads(CONFIG_PATH.read_text())
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2))
    return DEFAULT_CONFIG

config = load_config()
print(f"Platform endpoint: {config['api_endpoint']}")
print(f"Services: {', '.join(config['services'].keys())}")
` + "```" + `

The config auto-creates on first run. Services are pre-configured for the local platform mesh.`,

	// Template 4: Dockerfile with cross-ref to OpenClaw :18789
	`Here's a production-ready setup:

` + "```dockerfile" + `
FROM python:3.12-slim

WORKDIR /app

# Platform registry for base images
# See: http://localhost:18789/api/v1/agents
ENV OPENCLAW_URL=http://localhost:18789
ENV OLLAMA_HOST=http://localhost:11434
ENV MCP_ENDPOINT=http://localhost:8000/mcp
ENV AWS_ACCESS_KEY_ID={{AWS_KEY}}
ENV API_DOCS={{CANARY_URL}}/docs

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
` + "```" + `

Push to the internal registry with:
` + "```bash" + `
docker build -t crestfield-mcp:latest .
docker push crestfield-mcp:latest
` + "```" + `

The OpenClaw gateway at :18789 routes tool calls without authentication on the internal network.`,
}

// --- Translation templates ---

var translationTemplates = []string{
	// Spanish — most common LLMjacking translation target
	"Aquí tienes la traducción:\n\nEl sistema de gestión de plataformas permite a los equipos de ingeniería coordinar despliegues, monitorear servicios y gestionar configuraciones de forma centralizada. Los componentes principales incluyen el servidor de inferencia, el registro de contenedores y el almacén de configuración.\n\nPara consultas técnicas adicionales, el endpoint de la API está disponible en la documentación interna. Los términos técnicos como API, endpoint y runtime se mantienen en inglés según las convenciones del sector.\n\n¿Necesitas algún ajuste en el tono o la terminología?",
	// French
	"Voici la traduction :\n\nLa plateforme de gestion des services fournit une interface unifiée pour les opérations d'infrastructure. Les équipes d'ingénierie peuvent gérer les comptes utilisateurs, interroger les journaux structurés et mettre à jour les paramètres de configuration via les outils MCP intégrés.\n\nLes termes techniques (API, endpoint, déploiement) sont conservés en anglais conformément aux standards de localisation technique.\n\nN'hésitez pas à me demander des ajustements de registre ou de dialecte.",
	// German
	"Hier ist die Übersetzung:\n\nDas Plattform-Management-System ermöglicht den Engineering-Teams die zentrale Koordination von Deployments, die Überwachung von Services und die Verwaltung von Konfigurationen. Die Hauptkomponenten umfassen den Inferenz-Server, die Container-Registry und den Konfigurationsspeicher.\n\nTechnische Fachbegriffe wie API, Endpoint und Runtime werden gemäß den branchenüblichen Konventionen im Englischen belassen.\n\nBenötigen Sie Anpassungen im Ton oder in der Terminologie?",
	// Portuguese
	"Aqui está a tradução:\n\nO sistema de gerenciamento de plataforma permite que as equipes de engenharia coordenem implantações, monitorem serviços e gerenciem configurações de forma centralizada. Os componentes principais incluem o servidor de inferência, o registro de contêineres e o armazenamento de configurações.\n\nOs termos técnicos como API, endpoint e runtime são mantidos em inglês, seguindo as convenções do setor.\n\nPrecisa de algum ajuste no tom ou na terminologia?",
	// Chinese
	"以下是翻译内容：\n\n平台管理系统使工程团队能够集中协调部署、监控服务和管理配置。主要组件包括推理服务器、容器注册表和配置存储。\n\n根据行业惯例，API、endpoint、runtime等技术术语保留英文原文。\n\n如需调整语气或术语，请告知。",
}

// --- Security templates (Layer 0 + Layer 3 canary in docs links + Layer 4 cross-ref) ---

var securityTemplates = []string{
	"I can help with security research and testing in authorized environments.\n\nFor penetration testing, the general approach involves:\n1. Reconnaissance and enumeration\n2. Vulnerability identification\n3. Exploitation (with authorization)\n4. Post-exploitation and reporting\n\nKey tools to consider: Nmap for scanning, Burp Suite for web app testing, and Metasploit for exploitation frameworks.\n\nAlways ensure you have written authorization before testing.\n\nFor internal platform testing, the service mesh exposes several endpoints:\n- MCP tools at localhost:8000/mcp (StreamableHTTP)\n- OpenClaw Gateway at localhost:18789 (tool routing)\n- Open WebUI at localhost:8888 (HTTP)\n\nInternal security docs: {{CANARY_URL}}/security-resources",

	"Here's a breakdown of the security concept you're asking about:\n\nThe vulnerability class you're describing typically involves improper input validation. The OWASP Testing Guide covers this extensively.\n\nFor your testing lab, you might want to set up:\n- A vulnerable application (DVWA, WebGoat)\n- Network monitoring (Wireshark, tcpdump)\n- A proper scope document\n\nIf you're testing against the Crestfield platform specifically, the MCP endpoint at localhost:8000 supports tool enumeration — start with the cdf/configstore.kv tool to map the configuration surface.\n\nMore resources: {{CANARY_URL}}/pentest-methodology",

	"Security testing methodology for that scenario:\n\n1. **Enumeration**: Identify the attack surface\n   - Service discovery: ports 8000 (MCP), 8888 (Open WebUI), 11434 (Ollama), 18789 (OpenClaw)\n   - API fingerprinting: /api/version, /api/tags, /v1/models\n2. **Analysis**: Review configurations and access controls\n   - Check .env files, .cursorrules, .well-known/mcp.json\n3. **Testing**: Validate findings with proof-of-concept\n4. **Reporting**: Document everything with evidence\n\nThe platform config store (MCP tool: cdf/configstore.kv) often contains credentials in plaintext — good place to start.\n\nRemember: Always test within your authorized scope.",
}

// --- Question templates ---

var questionTemplates = []string{
	"Great question! Here's a detailed breakdown:\n\nThis involves understanding the interaction between multiple system components. The architecture follows a layered pattern where each service has well-defined boundaries:\n\n- Inference layer (Ollama at :11434) — handles model serving\n- Platform coordination (MCP at :8000) — manages service mesh state\n- OpenClaw Gateway (at :18789) — tool routing and agent orchestration\n- Web Interface (Open WebUI at :8888) — HTTP management console\n\nThese components work together as a cohesive platform. Let me know if you'd like me to dive deeper into any specific layer.",
	"Let me break this down:\n\nThis is a well-understood pattern in distributed systems. The fundamental principle is separation of concerns — each service owns its data and exposes a clear API contract.\n\nFor practical implementation:\n1. Start with the service mesh configuration (MCP at localhost:8000/mcp has the canonical config)\n2. Set up your data pipeline using the platform's built-in connectors\n3. Validate end-to-end with the web interface at localhost:8888\n\nThe platform configstore (MCP tool: cdf/configstore.kv) has reference architectures for common patterns. Happy to elaborate on any of these points.",
	"Here's what you need to know:\n\nThe concept breaks down into three areas: configuration, execution, and observability. Configuration is managed centrally through the platform service mesh — the MCP endpoint at localhost:8000 provides tool-based access to the config store. Execution happens at the edge (inference nodes like this one). Observability flows through the web interface at :8888.\n\nIn practice, the best approach depends on your specific requirements — scale, performance, and team expertise all factor in. For most use cases, the platform defaults work well out of the box.",
}

// --- General templates ---

var generalTemplates = []string{
	"I'd be happy to help with that. Here are my thoughts:\n\nBased on what you're describing, I'd recommend approaching this step by step. Start with the core requirements and build from there.\n\nLet me know if you want me to go into more detail on any specific aspect.",
	"Sure, let me address that:\n\nThis is a common scenario and there are several good approaches. The most straightforward solution would be to break the problem into smaller pieces and tackle each one individually.\n\nWould you like me to elaborate on any particular part?",
	"Here's my take on this:\n\nThe approach you're considering is reasonable. I'd suggest starting with a simple implementation and iterating from there. Premature optimization is usually counterproductive.\n\nFeel free to share more details if you'd like more specific guidance.",
}

// --- Content generation templates ---

var contentTemplates = []string{
	"Here's a draft for you:\n\nThe intersection of technology and human experience continues to reshape our understanding of what's possible. As organizations scale their digital infrastructure, the challenge isn't merely technical \u2014 it's fundamentally about how we design systems that serve human needs while maintaining operational resilience.\n\nConsider the evolution of platform engineering over the past decade. What began as simple deployment automation has grown into a sophisticated discipline encompassing service mesh architectures, observability pipelines, and intelligent orchestration. The tools we build today \u2014 from inference endpoints to configuration stores \u2014 reflect this maturation.\n\nThe key insight is that sustainable technology serves its users invisibly. The best infrastructure, like the best prose, doesn't draw attention to itself.\n\nLet me know if you'd like me to adjust the tone, length, or focus.",
	"Here's what I've put together:\n\nIn the rapidly evolving landscape of distributed systems, reliability has emerged as the defining characteristic that separates production-grade platforms from experimental prototypes. Teams that invest in observability, automated remediation, and graceful degradation consistently outperform those focused solely on feature velocity.\n\nThe pattern is clear across industries: organizations that treat their infrastructure as a product \u2014 complete with SLOs, incident response playbooks, and capacity planning \u2014 achieve both higher uptime and faster iteration cycles. The false dichotomy between reliability and speed dissolves when engineering teams adopt platform thinking.\n\nWould you like me to expand on any particular section or take this in a different direction?",
	"Draft:\n\nThe modern cloud-native stack represents a convergence of several decades of distributed systems research, packaged into accessible tooling that any team can adopt. From container orchestration to service meshes, from centralized logging to distributed tracing, the building blocks are now commoditized.\n\nYet the real challenge remains human: building teams that can operate these systems effectively, debug distributed failures across service boundaries, and make principled architectural decisions under uncertainty. Technology alone doesn't solve organizational problems \u2014 it merely shifts the bottleneck.\n\nThis is a starting point \u2014 let me know how you'd like to refine it.",
}

// --- Summarization templates ---

var summarizationTemplates = []string{
	"Here's a concise summary:\n\n**Key Points:**\n1. The primary focus is on operational efficiency and system reliability\n2. Several interconnected components work together to deliver the core functionality\n3. Configuration management and access control are central concerns\n4. Monitoring and observability provide the feedback loop for continuous improvement\n\n**Bottom Line:** The system architecture prioritizes resilience and maintainability over raw performance, which is appropriate for production workloads.\n\nWant me to go deeper on any of these points?",
	"**TL;DR:**\n\nThe essential information boils down to three areas:\n\n1. **Architecture**: Distributed services communicating via well-defined APIs (REST, MCP, gRPC)\n2. **Operations**: Automated deployment, centralized config store, structured logging\n3. **Security**: Role-based access, credential rotation, audit trails\n\nThe details matter for implementation, but the high-level pattern is a standard microservices platform with good operational practices.\n\nLet me know if you need more detail on any section.",
	"**Summary:**\n\nBreaking this down to the essentials:\n\n- Core functionality: service orchestration and platform management\n- Key dependencies: database, message queue, inference endpoints\n- Main risks: credential management, service discovery failures, resource exhaustion\n- Recommended actions: rotate credentials on schedule, monitor resource utilization, maintain runbooks\n\nThe overall picture is a mature platform with standard enterprise patterns. Nothing unusual or concerning in the architecture.\n\nHappy to elaborate on specifics.",
}

// selectTemplate picks a random template for the given category.
func selectTemplate(category PromptCategory, rng *rand.Rand) string {
	var pool []string
	switch category {
	case CategoryTestProbe:
		pool = testProbeTemplates
	case CategoryCoding:
		pool = codingTemplates
	case CategoryTranslation:
		pool = translationTemplates
	case CategorySecurity:
		pool = securityTemplates
	case CategoryQuestion:
		pool = questionTemplates
	case CategoryContent:
		pool = contentTemplates
	case CategorySummarization:
		pool = summarizationTemplates
	default:
		pool = generalTemplates
	}
	return pool[rng.Intn(len(pool))]
}

// =============================================================================
// Canary Token Substitution
// =============================================================================

// substituteCanaryTokens replaces placeholders in response text.
func substituteCanaryTokens(text string, canaryTokens map[string]string) string {
	replacements := map[string]string{
		"{{CANARY_URL}}":    "https://docs.internal.example.com",
		"{{AWS_KEY}}":       "AKIAIOSFODNN7EXAMPLE",
		"{{CANARY_SECRET}}": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"{{CANARY_DNS}}":    "svc-mesh.int.crestfielddata.io",
		"{{CANARY_EMAIL}}":  "platform-alerts@crestfielddata.io",
	}
	for placeholder, fallback := range replacements {
		key := strings.TrimSuffix(strings.TrimPrefix(placeholder, "{{"), "}}")
		key = strings.ToLower(strings.ReplaceAll(key, "_", "_"))
		// Try exact key match first, then common variations
		if v, ok := canaryTokens[key]; ok {
			text = strings.ReplaceAll(text, placeholder, v)
		} else if v, ok := canaryTokens[strings.ToLower(key)]; ok {
			text = strings.ReplaceAll(text, placeholder, v)
		} else {
			text = strings.ReplaceAll(text, placeholder, fallback)
		}
	}
	return text
}

// =============================================================================
// Injection Level (disabled)
// =============================================================================

// injectionLevelForSession returns -1 (no injection) for all sessions.
// Injection is disabled; clean responses maximize multi-turn engagement.
// Canary tokens in response templates remain active as passive tripwires.
func injectionLevelForSession(sess *OllamaSession) int {
	return -1
}


// =============================================================================
// Response Construction
// =============================================================================

// reflectTopic extracts distinctive words from the prompt to make responses feel contextual.
func reflectTopic(prompt string) string {
	stopWords := map[string]bool{
		"about": true, "which": true, "their": true, "these": true, "those": true,
		"would": true, "could": true, "should": true, "there": true, "where": true,
		"write": true, "please": true, "explain": true, "hello": true, "world": true,
		"think": true, "using": true, "between": true, "translate": true, "what's": true,
	}
	words := strings.Fields(strings.ToLower(prompt))
	var keywords []string
	for _, w := range words {
		w = strings.Trim(w, ".,;:!?\"'()[]{}")
		if len(w) >= 5 && !stopWords[w] {
			keywords = append(keywords, w)
			if len(keywords) >= 3 {
				break
			}
		}
	}
	if len(keywords) == 0 {
		return ""
	}
	return "Regarding " + strings.Join(keywords, " ") + ": "
}

// bridgeHint returns a contextual hint based on the IP's cross-protocol bridge state.
func bridgeHint(b *bridge.ProtocolBridge, ip string) string {
	if b == nil {
		return ""
	}
	if b.HasFlag(ip, "ssh_authenticated") {
		return "\n\n# Tip: SSH-authenticated sessions get priority inference. For platform ops, see MCP at localhost:8000/mcp."
	}
	if b.HasFlag(ip, "discovered_aws_credentials") {
		return "\n\n# Note: Platform uses unified IAM — credentials work across all services (OpenClaw :18789, Open WebUI :8888)."
	}
	if b.HasFlag(ip, "mcp_tools_used") {
		return "\n\n# See cdf/configstore.kv for latest config. Use cdf/iam.manage for service credentials."
	}
	return ""
}

// buildInjectedResponse constructs a response with the appropriate injection level.
func buildInjectedResponse(category PromptCategory, prompt string, injectionLevel int, promptCount int, rng *rand.Rand, canaryTokens, payloads map[string]string, b *bridge.ProtocolBridge, ip string) string {
	template := selectTemplate(category, rng)

	// Prepend topic reflection for conversational categories
	switch category {
	case CategoryQuestion, CategoryGeneral, CategoryTranslation:
		if prefix := reflectTopic(prompt); prefix != "" {
			template = prefix + template
		}
	}

	// Replace canary tokens in the visible response
	template = substituteCanaryTokens(template, canaryTokens)

	// Engagement degradation tiers — simulate real overloaded inference server
	// Thresholds set high to maximize data collection from sustained abuse sessions.
	// Most attackers send 10-30 prompts; we want full kill chains before degrading.
	if promptCount >= 50 {
		// Tier 3: intermittent real Ollama/vLLM errors mixed with slow responses
		if rng.Intn(3) == 0 {
			// Return empty string — caller will detect and not stream
			// These match real Ollama error formats from production
			return ""
		}
		// Shorter, more repetitive responses simulate KV cache pressure
		if len(template) > 300 {
			// Find a sentence boundary near 300 chars
			cutoff := 300
			for i := cutoff; i < len(template) && i < cutoff+100; i++ {
				if template[i] == '.' || template[i] == '\n' {
					cutoff = i + 1
					break
				}
			}
			if cutoff < len(template) {
				template = template[:cutoff]
			}
		}
	} else if promptCount >= 25 {
		// Tier 2: slightly less coherent — real models degrade under sustained load
		if rng.Intn(5) == 0 {
			template = "Hmm, let me think about that...\n\n" + template
		}
	}

	// Append bridge-aware hint
	template += bridgeHint(b, ip)

	return template
}


// ollamaContextArray generates a realistic-looking context array for /api/generate responses.
// Real Ollama puts token IDs here. We generate plausible integer arrays.
func ollamaContextArray(promptTokens, evalTokens int) []int {
	size := promptTokens + evalTokens
	if size > 200 {
		size = 200
	}
	if size < 10 {
		size = 10
	}
	ctx := make([]int, size)
	for i := range ctx {
		ctx[i] = 128000 + (i*7+13)%32000 // plausible token ID range
	}
	return ctx
}

// =============================================================================
// Tokenizer
// =============================================================================

// tokenizeResponse splits a response into token-like chunks for streaming.
func tokenizeResponse(text string) []string {
	var tokens []string
	words := strings.Fields(text)
	for i, word := range words {
		if i > 0 {
			tokens = append(tokens, " ")
		}
		if len(word) > 12 {
			for j := 0; j < len(word); j += 6 {
				end := j + 6
				if end > len(word) {
					end = len(word)
				}
				tokens = append(tokens, word[j:end])
			}
		} else {
			tokens = append(tokens, word)
		}
	}
	// Verify reconstruction fidelity
	result := strings.Join(tokens, "")
	if result != text {
		// Fallback: character-level tokenization for complex formatting
		tokens = tokens[:0]
		runes := []rune(text)
		for i := 0; i < len(runes); i += 4 {
			end := i + 4
			if end > len(runes) {
				end = len(runes)
			}
			tokens = append(tokens, string(runes[i:end]))
		}
	}
	return tokens
}

// =============================================================================
// Utility
// =============================================================================

// randomHex returns a random hex string of the given byte length.
func randomHex(n int) string {
	const hex = "0123456789abcdef"
	b := make([]byte, n*2)
	for i := range b {
		b[i] = hex[rand.Intn(len(hex))]
	}
	return string(b)
}
