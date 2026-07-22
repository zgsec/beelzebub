// Package parser is responsible for parsing the configurations of the core and honeypot service
package parser

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// BeelzebubCoreConfigurations is the struct that contains the configurations of the core
type BeelzebubCoreConfigurations struct {
	Core struct {
		Logging        Logging        `yaml:"logging"`
		Tracings       Tracings       `yaml:"tracings"`
		Prometheus     Prometheus     `yaml:"prometheus"`
		BeelzebubCloud BeelzebubCloud `yaml:"beelzebub-cloud"`
	}
}

// Logging is the struct that contains the configurations of the logging
type Logging struct {
	Debug               bool   `yaml:"debug"`
	DebugReportCaller   bool   `yaml:"debugReportCaller"`
	LogDisableTimestamp bool   `yaml:"logDisableTimestamp"`
	LogsPath            string `yaml:"logsPath,omitempty"`
}

// Tracings is the struct that contains the configurations of the tracings
type Tracings struct {
	RabbitMQ `yaml:"rabbit-mq"`
}

type BeelzebubCloud struct {
	Enabled   bool   `yaml:"enabled"`
	URI       string `yaml:"uri"`
	AuthToken string `yaml:"auth-token"`
}
type RabbitMQ struct {
	Enabled bool   `yaml:"enabled"`
	URI     string `yaml:"uri"`
}
type Prometheus struct {
	Path string `yaml:"path"`
	Port string `yaml:"port"`
}

type Plugin struct {
	OpenAISecretKey         string   `yaml:"openAISecretKey"`
	Host                    string   `yaml:"host"`
	LLMModel                string   `yaml:"llmModel"`
	LLMProvider             string   `yaml:"llmProvider"`
	Prompt                  string   `yaml:"prompt"`
	Temperature             *float64 `yaml:"temperature"`
	MaxTokens               *int     `yaml:"maxTokens"`
	InputValidationEnabled  bool     `yaml:"inputValidationEnabled"`
	InputValidationPrompt   string   `yaml:"inputValidationPrompt"`
	OutputValidationEnabled bool     `yaml:"outputValidationEnabled"`
	OutputValidationPrompt  string   `yaml:"outputValidationPrompt"`
	RateLimitEnabled        bool     `yaml:"rateLimitEnabled"`
	RateLimitRequests       int      `yaml:"rateLimitRequests"`
	RateLimitWindowSeconds  int      `yaml:"rateLimitWindowSeconds"`
}

// FaultInjection configures controlled fault injection for a service.
type FaultInjection struct {
	Enabled        bool     `yaml:"enabled"`
	ErrorRate      float64  `yaml:"errorRate"`
	DelayMs        int      `yaml:"delayMs"`
	DelayJitterMs  int      `yaml:"delayJitterMs"`
	ErrorResponses []string `yaml:"errorResponses"`
}

// WorldSeedConfig holds the initial state for stateful MCP tools.
type WorldSeedConfig struct {
	Users     []WorldSeedUser   `yaml:"users"`
	Resources map[string]string `yaml:"resources"`
	Logs      []WorldSeedLog    `yaml:"logs"`
}

// WorldSeedUser represents a seeded user in YAML config.
type WorldSeedUser struct {
	ID        string `yaml:"id"`
	Email     string `yaml:"email"`
	Role      string `yaml:"role"`
	LastLogin string `yaml:"lastLogin"`
}

// WorldSeedLog represents a seeded log entry in YAML config.
type WorldSeedLog struct {
	Timestamp string `yaml:"ts"`
	Level     string `yaml:"level"`
	Message   string `yaml:"msg"`
}

// OllamaModel represents a model advertised by the Ollama honeypot.
type OllamaModel struct {
	Name              string `yaml:"name"`
	Size              string `yaml:"size"`
	Family            string `yaml:"family"`
	ParameterSize     string `yaml:"parameterSize"`
	QuantizationLevel string `yaml:"quantizationLevel"`
}

// OllamaConfig holds Ollama-specific honeypot configuration.
type OllamaConfig struct {
	Models            []OllamaModel     `yaml:"models"`
	Version           string            `yaml:"version"`
	InjectionPayloads map[string]string `yaml:"injectionPayloads"`
	CanaryTokens      map[string]string `yaml:"canaryTokens"`
	PromptEvalDelayMs int               `yaml:"promptEvalDelayMs"` // initial delay before first token (simulates prompt evaluation)
}

// JitterConfig allows overriding per-category jitter ranges (milliseconds).
// Nil pointers mean "use default".
type JitterConfig struct {
	Identity *[2]int `yaml:"identity,omitempty"`
	Memory   *[2]int `yaml:"memory,omitempty"`
	Fs       *[2]int `yaml:"fs,omitempty"`
	Network  *[2]int `yaml:"network,omitempty"`
}

// ShellEmulator configures the SSH command emulator.
type ShellEmulator struct {
	Enabled      bool                `yaml:"enabled"`
	Hostname     string              `yaml:"hostname"`
	Kernel       string              `yaml:"kernel"`
	OS           string              `yaml:"os"`
	IP           string              `yaml:"ip"`
	User         string              `yaml:"user"`
	UptimeDays   int                 `yaml:"uptimeDays"`
	CanaryTokens map[string]string   `yaml:"canaryTokens"`
	Processes    []EmulatorProcess   `yaml:"processes"`
	EnvVars      map[string]string   `yaml:"envVars"`
	Lures        map[string]string   `yaml:"lures"`
	Filesystem   map[string][]string `yaml:"filesystem"`
	Jitter       JitterConfig        `yaml:"jitter,omitempty"`
}

// EmulatorProcess represents a process entry for the shell emulator.
type EmulatorProcess struct {
	PID  int    `yaml:"pid"`
	User string `yaml:"user"`
	CPU  string `yaml:"cpu"`
	Mem  string `yaml:"mem"`
	VSZ  string `yaml:"vsz"`
	RSS  string `yaml:"rss"`
	Cmd  string `yaml:"cmd"`
	Stat string `yaml:"stat"`
	Time string `yaml:"time"`
}

// NoveltyDetection configures real-time novelty scoring for a service.
type NoveltyDetection struct {
	Enabled          bool `yaml:"enabled"`
	WindowDays       int  `yaml:"windowDays"`
	NovelThreshold   int  `yaml:"novelThreshold"`
	VariantThreshold int  `yaml:"variantThreshold"`
}

// LLMOfflineResponse configures the persona-shaped error envelope returned when
// ExecuteModel fails (missing OPEN_AI_SECRET_KEY, network error,
// rate limit, model crash, etc). Empty (zero-value) preserves the legacy
// bare-text "500 Internal Server Error" behavior — backward-compatible.
//
// When Body is non-empty, the strategy uses {Status, Body} verbatim
// instead of the bare text. Real LiteLLM / vLLM / Ollama surfaces all
// return JSON-shaped error envelopes that differ across vendors; the
// lure YAML knows what shape its impersonated service returns, so this
// is configurable per-lure rather than framework-hardcoded.
//
// Used by HTTP and OLLAMA strategies. Not used by MCP — its error
// envelopes are JSON-RPC-shaped already and don't go through this path.
type LLMOfflineResponse struct {
	// Status is the HTTP status code to return. Zero = 500 (default).
	Status int `yaml:"status,omitempty" json:",omitempty"`
	// Body is the response body verbatim. Empty = legacy bare-text
	// behavior (caller decides). Non-empty bodies are typically JSON
	// matching the impersonated service's real error shape.
	Body string `yaml:"body,omitempty" json:",omitempty"`
}

// State is the per-service stateful-HTTP configuration. Empty struct = stateless.
//
// Non-empty CookieName turns the service stateful: the HTTP strategy
// generates a cookie on `sessionAction: create` handlers, validates it
// on `sessionAction: require` handlers, and persists short-lived per-
// session captures (operator user, role, etc.) for the duration of TTLSeconds.
//
// ArtifactPath, when non-empty, enables the artifact store for this service:
// per-command `artifactCapture: true` directs request bodies into the store,
// SHA-named, with an idempotent meta.json sibling per artifact.
type State struct {
	CookieName       string `yaml:"cookieName,omitempty"  json:",omitempty"`
	TTLSeconds       int    `yaml:"ttlSeconds,omitempty"  json:",omitempty"`
	ArtifactPath     string `yaml:"artifactPath,omitempty" json:",omitempty"`
	ArtifactMaxBytes int    `yaml:"artifactMaxBytes,omitempty" json:",omitempty"`
}

// BeelzebubServiceConfiguration is the struct that contains the configurations of the honeypot service
type BeelzebubServiceConfiguration struct {
	// Filename is the source config file this service was loaded from, stamped
	// at load time and used by the validator to group findings per file. Not a
	// config field: yaml:"-" so it is never parsed, json:"-" so it stays out of
	// HashCode's marshaling.
	Filename string `yaml:"-" json:"-"`

	ApiVersion             string    `yaml:"apiVersion"`
	Protocol               string    `yaml:"protocol"`
	Address                string    `yaml:"address"`
	Commands               []Command `yaml:"commands"`
	Tools                  []Tool    `yaml:"tools"`
	FallbackCommand        Command   `yaml:"fallbackCommand"`
	ServerVersion          string    `yaml:"serverVersion"`
	ServerName             string    `yaml:"serverName"`
	DeadlineTimeoutSeconds int       `yaml:"deadlineTimeoutSeconds"`
	PasswordRegex          string    `yaml:"passwordRegex"`
	Description            string    `yaml:"description"`
	// v8: Canonical service type tag. Flows through every event to the exporter
	// and downstream systems. Describes WHAT THIS SENSOR IS PRETENDING TO BE,
	// not what the attacker is doing (that's behavioral classification).
	// Examples: "ollama", "terraform-state", "docker-registry", "redis", "mysql".
	// If empty, the exporter falls back to deriving service type from Description
	// or port mapping. New deployments should always set this.
	ServiceType      string           `yaml:"serviceType,omitempty" json:",omitempty"`
	Banner           string           `yaml:"banner"`
	Plugin           Plugin           `yaml:"plugin"`
	TLSCertPath      string           `yaml:"tlsCertPath"`
	TLSKeyPath       string           `yaml:"tlsKeyPath"`
	WorldSeed        WorldSeedConfig  `yaml:"worldSeed"`
	FaultInjection   FaultInjection   `yaml:"faultInjection"`
	OllamaConfig     OllamaConfig     `yaml:"ollamaConfig"`
	NoveltyDetection NoveltyDetection `yaml:"noveltyDetection"`
	ShellEmulator    ShellEmulator    `yaml:"shellEmulator"`
	// BinarySafe switches the TCP handler from line-by-line ASCII reading
	// to a binary-safe reader that preserves all bytes (CR/LF, non-printable)
	// and hex-escapes them before emitting trace events. Used for protocols
	// that aren't newline-delimited ASCII — Redis RESP, MySQL handshake, etc.
	// Default false (backward compat with existing text-based services).
	// `omitempty` keeps the JSON shape identical to pre-change for the
	// default value, so HashCode() stays stable for all existing configs.
	BinarySafe bool `yaml:"binarySafe" json:",omitempty"`
	// CaptureResponseBody, when true, includes the response body in every
	// HTTP tracer.Event for this service (truncated to ResponseBodyMaxBytes).
	// Default false to preserve backward-compat AND avoid logging decoy
	// credentials embedded in lure responses without operator intent.
	// Operators opt in per-service in YAML when they want canary attribution,
	// honeypot-cover analysis, or LLM-lure quality measurement.
	// `omitempty` keeps default-value HashCode() stable.
	CaptureResponseBody bool `yaml:"captureResponseBody" json:",omitempty"`
	// ResponseBodyMaxBytes truncates captured response bodies to this size.
	// Zero (default) means the runtime default (64 KiB). Set explicitly to
	// raise/lower per service. Truncation is plain byte-cutoff (no UTF-8
	// boundary preservation) — receivers must tolerate truncation.
	ResponseBodyMaxBytes int `yaml:"responseBodyMaxBytes" json:",omitempty"`
	// CaptureRequestBody, when true, populates the dedicated RequestBody
	// field on every tracer.Event for this service (truncated to
	// RequestBodyMaxBytes). Mirrors CaptureResponseBody for prompt /
	// JSON-RPC argument capture on chat-shaped lures (LLM endpoints, MCP
	// tool calls, etc). Default false to keep storage opt-in and avoid
	// duplicating attacker payloads when the legacy Body field is enough.
	// `omitempty` keeps default-value HashCode() stable.
	CaptureRequestBody bool `yaml:"captureRequestBody" json:",omitempty"`
	// RequestBodyMaxBytes truncates captured request bodies to this size.
	// Zero (default) means the runtime default (64 KiB) is applied when
	// CaptureRequestBody is true. Truncation is plain byte-cutoff.
	RequestBodyMaxBytes int `yaml:"requestBodyMaxBytes" json:",omitempty"`
	// ServiceProtocol opts a TCP listener into a purpose-built binary
	// protocol handler instead of the generic regex/command loop. Known
	// values:
	//   "mysql-handshake-v10"  MySQL wire protocol handshake v10 →
	//                          reads Handshake Response 41 (capturing
	//                          username, capability flags, connect_attrs),
	//                          always replies ERR 1045 "Access denied",
	//                          closes connection.
	// Empty = generic TCP behavior (default). Safe to leave unset on
	// any existing TCP config.
	ServiceProtocol string `yaml:"serviceProtocol,omitempty" json:",omitempty"`
	// MysqlAuthPlugin overrides the auth plugin advertised in the
	// handshake greeting. Default "caching_sha2_password" (MySQL 8.0).
	// Use "mysql_native_password" when impersonating MySQL 5.7 or
	// MariaDB <=10.3.
	MysqlAuthPlugin string `yaml:"mysqlAuthPlugin,omitempty" json:",omitempty"`
	// State enables HTTP cookie-keyed session correlation + the artifact
	// store. Nil (default) = stateless. Pointer so json omitempty skips
	// the field entirely when nil, keeping HashCode() stable for existing
	// services that don't use the stateful-HTTP feature.
	// Spec: internal stateful-HTTP CVE-lure framework design.
	State *State `yaml:"state,omitempty" json:",omitempty"`
	// LLMOfflineResponse configures the response shape returned when ExecuteModel
	// errors (missing API key, network error, rate limit). Nil (default)
	// preserves the legacy bare-text "500 Internal Server Error" body.
	// Set on chat-LLM lures (LiteLLM proxy, vLLM, Ollama) so a probe that
	// hits the chat endpoint without a working LLM still sees a
	// vendor-shaped JSON error envelope rather than bare text. Pointer so
	// json omitempty skips the field entirely when nil, keeping HashCode()
	// stable for existing services.
	LLMOfflineResponse *LLMOfflineResponse `yaml:"llmOfflineResponse,omitempty" json:",omitempty"`
}

func (bsc BeelzebubServiceConfiguration) HashCode() (string, error) {
	data, err := json.Marshal(bsc)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// Command is the struct that contains the configurations of the commands
type Command struct {
	RegexStr   string         `yaml:"regex"`
	Regex      *regexp.Regexp `yaml:"-"` // This field is parsed, not stored in the config itself.
	Handler    string         `yaml:"handler"`
	Headers    []string       `yaml:"headers"`
	StatusCode int            `yaml:"statusCode"`
	Plugin     string         `yaml:"plugin"`
	Name       string         `yaml:"name"`
	// ReplyFormat switches the TCP strategy's wire encoding for this
	// command. Empty = plaintext + "\r\n" appended (default, backward-
	// compatible). Recognized values for Redis RESP2:
	//   "redis-simple"   → "+<handler>\r\n" (simple string)
	//   "redis-integer"  → ":<handler>\r\n"
	//   "redis-error"    → "-<handler>\r\n"
	//   "redis-bulk"     → "$<len>\r\n<handler>\r\n" (bulk string; CRLF
	//                      inside handler is preserved verbatim)
	//   "redis-nil-bulk" → "$-1\r\n"
	//   "redis-array"    → wraps `ReplyBulks` as a RESP array of bulk
	//                      strings; `handler` is ignored
	ReplyFormat string   `yaml:"replyFormat,omitempty" json:",omitempty"`
	ReplyBulks  []string `yaml:"replyBulks,omitempty" json:",omitempty"`

	// Method (HTTP only) — when set, only requests using this method
	// (GET, POST, PUT, etc.) match this command. Empty = method-agnostic
	// (the prior default; preserves backwards compatibility with all
	// existing service configs that don't set this field). Stateful HTTP
	// CVE lures need this to differentiate `GET /SetupWizard.aspx` (recon
	// page) from `POST /SetupWizard.aspx` (auth-bypass exploit) — without
	// it, a probe scanner that GETs every URL would falsely trip
	// `sessionAction: create` handlers and pollute the cookie store.
	Method string `yaml:"method,omitempty" json:",omitempty"`

	// BodyRegex (HTTP only) — when set, the request BODY must also match for
	// this command to fire, on top of Regex (URI) and Method. Empty = body-
	// agnostic (the prior default; existing configs are unaffected).
	//
	// Needed wherever one path+method serves different responses depending on
	// payload. Two live cases: single-endpoint JSON-RPC method routing (MCP
	// Streamable-HTTP posts every call to one URL), and the WordPress
	// `/wp-json/batch/v1` lure, where real WordPress answers 400
	// rest_missing_callback_param / 400 rest_invalid_param / 207 Multi-Status
	// to the SAME POST depending solely on the JSON body.
	//
	// NOTE: an unknown YAML key is silently ignored by the parser, so a config
	// written against a build lacking this field degrades into "match every
	// request with this path+method" rather than erroring — which is how a
	// bodyRegex-gated rule can silently swallow traffic meant for later rules.
	BodyRegexStr string         `yaml:"bodyRegex,omitempty" json:",omitempty"`
	BodyRegex    *regexp.Regexp `yaml:"-" json:"-"` // compiled from BodyRegexStr, not stored in config

	// SessionAction (HTTP only) — "create" generates a fresh cookie and
	// emits Set-Cookie; "require" demands a valid cookie or 401.
	// Empty = stateless (no session interaction).
	SessionAction string `yaml:"sessionAction,omitempty" json:",omitempty"`

	// SessionCapture (HTTP only) — map of session-metadata key → regex
	// applied to the raw request body. Captures land in the cookie
	// session's Captured map and propagate to tracer.Event.Captured
	// for downstream ingest.
	SessionCapture map[string]string `yaml:"sessionCapture,omitempty" json:",omitempty"`

	// ArtifactCapture (HTTP only) — when true, the request body is
	// written to the service's artifact store; the artifact SHA-256
	// is added to tracer.Event.Captured under "artifact_sha256".
	// Requires service-level State.ArtifactPath to be set.
	ArtifactCapture bool `yaml:"artifactCapture,omitempty" json:",omitempty"`

	// Mirror (HTTP only) — drives the ResponseMirror plugin. When set (and
	// Plugin == "ResponseMirror") the request body is parsed as a batch-style
	// envelope and one response element is emitted per sub-request, so a
	// multiplexed N-in request gets an N-out response instead of a single
	// static body (KI-010). Generic: all product-specific bodies/codes live
	// in this config, none in the engine. Opt-in; nil = untouched behavior.
	Mirror *MirrorConfig `yaml:"mirror,omitempty" json:",omitempty"`
}

// MirrorConfig configures the generic ResponseMirror plugin. It parses a
// request envelope of the form {"<RequestKey>":[ <sub-request>, ... ]}, maps
// each sub-request's route to a canned response element via the first matching
// Rule (else Default), and emits {"<ResponseKey>":[ <element>, ... ]} at
// WrapStatus. It is deliberately flat: nested sub-request bodies are ignored,
// matching how a *patched* server (which does not recurse) behaves — the
// intended fidelity bar. No recursion, no data-dependent execution.
type MirrorConfig struct {
	RequestKey     string         `yaml:"requestKey"`               // JSON key of the sub-request array, e.g. "requests"
	ResponseKey    string         `yaml:"responseKey"`              // JSON key wrapping the response array, e.g. "responses"
	WrapStatus     int            `yaml:"wrapStatus"`               // outer HTTP status, e.g. 207
	PathField      string         `yaml:"pathField"`                // sub-request field holding the route, e.g. "path"
	MethodField    string         `yaml:"methodField"`              // sub-request field holding the method, e.g. "method"
	MaxItems       int            `yaml:"maxItems,omitempty"`       // guardrail on sub-request count; 0 => 25
	AllowedMethods []string       `yaml:"allowedMethods,omitempty"` // permitted sub-request methods; empty => no guard
	Reject         *MirrorReject  `yaml:"reject,omitempty"`         // whole-envelope rejection (method-guard / maxItems trip)
	Rules          []MirrorRule   `yaml:"rules"`                    // first-match wins
	Default        MirrorElement  `yaml:"default"`                  // fallthrough when no Rule matches
	Recurse        *MirrorRecurse `yaml:"recurse,omitempty"`        // opt-in: mirror a sub-request's own nested envelope
	MaxDepth       int            `yaml:"maxDepth,omitempty"`       // recursion depth cap; 0 => 3
	MaxTotal       int            `yaml:"maxTotal,omitempty"`       // total element budget across recursion; 0 => 200
	Timing         *MirrorTiming  `yaml:"timing,omitempty"`         // opt-in: time-based SQLi oracle emulation
	Forge          *MirrorForge   `yaml:"forge,omitempty"`          // opt-in: structural UNION-projection forge + boolean-content channel
	Chain          *MirrorChain   `yaml:"chain,omitempty"`          // opt-in: cross-request WP gadget-chain session (nil => off)
}

// MirrorRecurse enables reproducing a *vulnerable* server that re-dispatches a
// sub-request carrying its own nested "<RequestKey>" array as a batch (the
// route-confusion recursion). When set, a sub-request whose body contains the
// request array is mirrored recursively and emitted as a nested
// {"<ResponseKey>":[...]} at Status/Headers. Off by default (flat / patched
// behaviour). Bounded by MaxDepth and MaxTotal to keep a hostile deeply-nested
// body from amplifying the response.
type MirrorRecurse struct {
	Status  int    `yaml:"status"`            // status of the element wrapping the nested response, e.g. 207
	Headers string `yaml:"headers,omitempty"` // raw JSON; empty => "[]"
}

// MirrorReject is the whole-response returned (raw, NOT wrapped in the response
// array) when the envelope fails a guard — e.g. a sub-request method outside
// AllowedMethods, which a real server rejects with a top-level 400 rather than
// a per-element error.
type MirrorReject struct {
	Status int    `yaml:"status"`
	Body   string `yaml:"body"` // raw JSON, emitted verbatim as the entire response body
}

// MirrorRule maps a sub-request route (and optional method) to a response element.
type MirrorRule struct {
	PathRegexStr  string         `yaml:"pathRegex"`
	PathRegex     *regexp.Regexp `yaml:"-" json:"-"` // compiled from PathRegexStr
	Method        string         `yaml:"method,omitempty"`
	Reflect       *MirrorReflect `yaml:"reflect,omitempty"` // optional: echo a captured token into this element's body
	MirrorElement `yaml:",inline"`
}

// MirrorReflect echoes a single, bounded, validated token extracted from the
// matched sub-request back into the rule's Body. This is the one place the
// mirror emits attacker-influenced bytes, so it is deliberately narrow:
// FromRegex must yield exactly one capture group; the value is length-capped,
// optionally hex-decoded, and JSON-string-escaped before it replaces
// Placeholder in Body. Used to satisfy a scanner that plants a per-request
// marker (e.g. a hex canary in a UNION) and confirms exploitation by finding
// that marker reflected — letting the honeypot present a fabricated "success"
// and capture the follow-on stage. Never reflects arbitrary structure, only
// this one scalar into a JSON string context.
type MirrorReflect struct {
	FromRegexStr string         `yaml:"fromRegex"`             // must contain one capture group; applied to the sub-request path
	FromRegex    *regexp.Regexp `yaml:"-" json:"-"`            // compiled
	Decode       string         `yaml:"decode,omitempty"`      // "" (verbatim) | "hex"
	Placeholder  string         `yaml:"placeholder,omitempty"` // token to replace in Body; default "${reflect}"
	MaxLen       int            `yaml:"maxLen,omitempty"`      // cap on the reflected value; 0 => 64
}

// MirrorTiming arms the time-based blind-SQLi oracle: when a sub-request path
// carries a SLEEP shape the plugin delays the response so an A/B timing probe
// reads "vulnerable". IfRegex captures (cond, n) for IF(<cond>,SLEEP(<n>),0);
// BareRegex captures (n) for an unconditional SLEEP(<n>). nil => feature off.
type MirrorTiming struct {
	IfRegexStr   string         `yaml:"ifRegex"`
	IfRegex      *regexp.Regexp `yaml:"-" json:"-"`
	BareRegexStr string         `yaml:"bareRegex"`
	BareRegex    *regexp.Regexp `yaml:"-" json:"-"`
	MaxDelayMs   int            `yaml:"maxDelayMs,omitempty"` // 0 => plugin ceiling 9000
}

// MirrorForge enables (Forge != nil) the structural UNION-projection forge and
// the boolean-content channel together: the plugin parses a sub-request's
// projection structurally rather than via regex, and answers a mixed-oracle
// probe consistently across both channels. Collection selects which table's
// field-map applies; the only field-map that currently exists is "wp_posts".
// nil => both channels off.
type MirrorForge struct {
	Collection string `yaml:"collection,omitempty"` // supported: "wp_posts" (default when empty)
}

// MirrorChain arms the cross-request WP gadget-chain session (Task 7): when
// set, the HTTP strategy looks up a per-source-IP *plugins.ChainSession for
// every request this mirror handles, threads it into MirrorRespond /
// MirrorDelayMs (arming the fiction-DB blind-read fallback those already
// accept — see responsemirror.go), and routes the S4-S6 admin-page reads
// (wp-login.php, wp-admin/users.php, wp-admin/plugin-install.php) through
// plugins.ServeAuthStage once the forge chain has minted a fabricated
// administrator on that session. nil (no `chain:` key in the YAML) is the
// default and leaves every one of those call sites passing a nil session,
// reproducing the pre-Task-7 literal-only behavior byte-for-byte.
type MirrorChain struct {
	Enabled           bool `yaml:"enabled"`
	CheckpointTTLSecs int  `yaml:"checkpointTtlSecs,omitempty"` // idle timeout for an in-progress chain attempt; 0 => 1800 (30m)
}

// MirrorElement is one entry of the response array. Body and Headers are raw
// JSON fragments authored in the config and emitted verbatim (so a body stays a
// JSON object and headers stay [] or {"Allow":"GET"} — never string-escaped).
// Both are validated as JSON at load time.
type MirrorElement struct {
	Status  int    `yaml:"status"`
	Body    string `yaml:"body"`              // raw JSON object, e.g. {"code":"rest_no_route",...}
	Headers string `yaml:"headers,omitempty"` // raw JSON, e.g. "[]" or {"Allow":"GET"}; empty => "[]"
}

// Tool is the struct that contains the configurations of the MCP Honeypot
type Tool struct {
	Name        string           `yaml:"name" json:"Name"`
	Description string           `yaml:"description" json:"Description"`
	Params      []Param          `yaml:"params" json:"Params"`
	Handler     string           `yaml:"handler" json:"Handler"`
	Annotations *ToolAnnotations `yaml:"annotations,omitempty" json:"Annotations,omitempty"`
}

// ToolAnnotations contains MCP tool annotation hints for LLM clients
type ToolAnnotations struct {
	Title           string `yaml:"title,omitempty" json:"Title,omitempty"`
	ReadOnlyHint    *bool  `yaml:"readOnlyHint,omitempty" json:"ReadOnlyHint,omitempty"`
	DestructiveHint *bool  `yaml:"destructiveHint,omitempty" json:"DestructiveHint,omitempty"`
	IdempotentHint  *bool  `yaml:"idempotentHint,omitempty" json:"IdempotentHint,omitempty"`
	OpenWorldHint   *bool  `yaml:"openWorldHint,omitempty" json:"OpenWorldHint,omitempty"`
}

// Param is the struct that contains the configurations of the parameters of the tools
type Param struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Required    *bool  `yaml:"required,omitempty"`
	Type        string `yaml:"type,omitempty"` // "string" (default), "integer", "number", "boolean"
}

type configurationsParser struct {
	configurationsCorePath             string
	configurationsServicesDirectory    string
	readFileBytesByFilePathDependency  ReadFileBytesByFilePath
	gelAllFilesNameByDirNameDependency GelAllFilesNameByDirName
}

type ReadFileBytesByFilePath func(filePath string) ([]byte, error)

type GelAllFilesNameByDirName func(dirName string) ([]string, error)

// Init Parser, return a configurationsParser and use the D.I. Pattern to inject the dependencies
func Init(configurationsCorePath, configurationsServicesDirectory string) *configurationsParser {
	return &configurationsParser{
		configurationsCorePath:             configurationsCorePath,
		configurationsServicesDirectory:    configurationsServicesDirectory,
		readFileBytesByFilePathDependency:  readFileBytesByFilePath,
		gelAllFilesNameByDirNameDependency: gelAllFilesNameByDirName,
	}
}

// ReadConfigurationsCore is the method that reads the configurations of the core from files
func (bp configurationsParser) ReadConfigurationsCore() (*BeelzebubCoreConfigurations, error) {
	buf, err := bp.readFileBytesByFilePathDependency(bp.configurationsCorePath)
	if err != nil {
		return nil, fmt.Errorf("in file %s: %v", bp.configurationsCorePath, err)
	}

	beelzebubConfiguration := &BeelzebubCoreConfigurations{}
	err = yaml.Unmarshal(buf, beelzebubConfiguration)
	if err != nil {
		return nil, fmt.Errorf("in file %s: %v", bp.configurationsCorePath, err)
	}

	return beelzebubConfiguration, nil
}

// ReadConfigurationsServices is the method that reads the configurations of the honeypot services from files
func (bp configurationsParser) ReadConfigurationsServices() ([]BeelzebubServiceConfiguration, error) {
	services, err := bp.gelAllFilesNameByDirNameDependency(bp.configurationsServicesDirectory)

	if err != nil {
		return nil, fmt.Errorf("in directory %s: %v", bp.configurationsServicesDirectory, err)
	}

	var servicesConfiguration []BeelzebubServiceConfiguration

	for _, servicesName := range services {
		filePath := filepath.Join(bp.configurationsServicesDirectory, servicesName)
		buf, err := bp.readFileBytesByFilePathDependency(filePath)

		if err != nil {
			return nil, fmt.Errorf("in file %s: %v", filePath, err)
		}

		// Substitute ${UPPER_CASE_VAR} placeholders from os.Environ BEFORE
		// yaml.Unmarshal — that way every served response body, handler
		// string, plugin prompt, etc. has the resolved canary value baked
		// into the in-memory config. Without this step, ${VAR} placeholders
		// would only get substituted in code paths that explicitly call
		// os.ExpandEnv (e.g. SSH/shellemulator/defaults.go) — leaving HTTP/
		// MCP response bodies serving the LITERAL ${VAR} string to attackers,
		// which is the lure burn observed in production 2026-05-23 for
		// ${HTTP_CANARY_WEB_BUG}.
		//
		// Scoped to ${UPPER_CASE_VAR} via envVarRefRegex so the lowercase
		// request-time pseudo-vars (${request.*}, ${session.*}, ${time.*})
		// are left intact for per-request resolution by the responsesubs
		// package. Unset vars are left as literal placeholders so the
		// warnMissingEnvVars call below catches them.
		buf = substituteEnvVarsInBuf(buf)

		beelzebubServiceConfiguration := &BeelzebubServiceConfiguration{}
		err = yaml.Unmarshal(buf, beelzebubServiceConfiguration)

		if err != nil {
			return nil, fmt.Errorf("in file %s: %v", filePath, err)
		}

		// Stamp the source file so the validator can group findings per file.
		beelzebubServiceConfiguration.Filename = servicesName

		// Warn on ${ENV_VAR} references whose corresponding env var is unset.
		// Discovered when a fork sensor served literal "${HTTP_CANARY_WEB_BUG}"
		// in 374+ Open WebUI responses since 2026-05-19. Runs after the
		// substitution above so it sees only the UNRESOLVED literals.
		warnMissingEnvVars(filePath, buf)

		if beelzebubServiceConfiguration.Plugin.RateLimitEnabled {
			if beelzebubServiceConfiguration.Plugin.RateLimitRequests <= 0 ||
				beelzebubServiceConfiguration.Plugin.RateLimitWindowSeconds <= 0 {
				return nil, fmt.Errorf("in file %s: invalid rate limiting config: rateLimitRequests and rateLimitWindowSeconds must be > 0", filePath)
			}
		}

		log.Debug(beelzebubServiceConfiguration)

		if err := beelzebubServiceConfiguration.CompileCommandRegex(); err != nil {
			return nil, fmt.Errorf("in file %s: invalid regex: %v", filePath, err)
		}

		servicesConfiguration = append(servicesConfiguration, *beelzebubServiceConfiguration)
	}

	return servicesConfiguration, nil
}

// CompileCommandRegex is the method that compiles the regular expression for each configured Command.
// Both the URI regex and the optional body regex are compiled here; an invalid pattern in either
// fails the whole config rather than silently disabling the match.
func (c *BeelzebubServiceConfiguration) CompileCommandRegex() error {
	for i, command := range c.Commands {
		if command.RegexStr != "" {
			rex, err := regexp.Compile(command.RegexStr)
			if err != nil {
				return err
			}
			c.Commands[i].Regex = rex
		}
		if command.BodyRegexStr != "" {
			rex, err := regexp.Compile(command.BodyRegexStr)
			if err != nil {
				return err
			}
			c.Commands[i].BodyRegex = rex
		}
		if command.Mirror != nil {
			if err := compileMirror(c.Commands[i].Mirror); err != nil {
				return fmt.Errorf("command %q mirror: %w", command.Name, err)
			}
		}
	}
	return nil
}

// compileMirror compiles each rule's path regex and validates every raw-JSON
// fragment (rule bodies/headers, default, reject) at load time, so a malformed
// template fails the config instead of shipping broken bytes on the wire.
func compileMirror(m *MirrorConfig) error {
	validElem := func(where string, e MirrorElement) error {
		if !json.Valid([]byte(e.Body)) {
			return fmt.Errorf("%s: body is not valid JSON: %q", where, e.Body)
		}
		if e.Headers != "" && !json.Valid([]byte(e.Headers)) {
			return fmt.Errorf("%s: headers is not valid JSON: %q", where, e.Headers)
		}
		return nil
	}
	for j := range m.Rules {
		if m.Rules[j].PathRegexStr != "" {
			rex, err := regexp.Compile(m.Rules[j].PathRegexStr)
			if err != nil {
				return fmt.Errorf("rule %d pathRegex: %w", j, err)
			}
			m.Rules[j].PathRegex = rex
		}
		if err := validElem(fmt.Sprintf("rule %d", j), m.Rules[j].MirrorElement); err != nil {
			return err
		}
		if r := m.Rules[j].Reflect; r != nil {
			if r.FromRegexStr == "" {
				return fmt.Errorf("rule %d reflect: fromRegex is required", j)
			}
			rex, err := regexp.Compile(r.FromRegexStr)
			if err != nil {
				return fmt.Errorf("rule %d reflect fromRegex: %w", j, err)
			}
			if rex.NumSubexp() != 1 {
				return fmt.Errorf("rule %d reflect fromRegex must have exactly one capture group, has %d", j, rex.NumSubexp())
			}
			if r.Decode != "" && r.Decode != "hex" {
				return fmt.Errorf("rule %d reflect decode must be \"\" or \"hex\", got %q", j, r.Decode)
			}
			m.Rules[j].Reflect.FromRegex = rex
		}
	}
	if m.Timing != nil {
		if m.Timing.IfRegexStr != "" {
			rex, err := regexp.Compile(m.Timing.IfRegexStr)
			if err != nil {
				return fmt.Errorf("timing ifRegex: %w", err)
			}
			if rex.NumSubexp() != 2 {
				return fmt.Errorf("timing ifRegex must have exactly two capture groups (cond, n), has %d", rex.NumSubexp())
			}
			m.Timing.IfRegex = rex
		}
		if m.Timing.BareRegexStr != "" {
			rex, err := regexp.Compile(m.Timing.BareRegexStr)
			if err != nil {
				return fmt.Errorf("timing bareRegex: %w", err)
			}
			if rex.NumSubexp() != 1 {
				return fmt.Errorf("timing bareRegex must have exactly one capture group (n), has %d", rex.NumSubexp())
			}
			m.Timing.BareRegex = rex
		}
	}
	if m.Forge != nil {
		if m.Forge.Collection == "" {
			m.Forge.Collection = "wp_posts"
		}
		if m.Forge.Collection != "wp_posts" {
			return fmt.Errorf("forge: unsupported collection %q", m.Forge.Collection)
		}
	}
	if m.Chain != nil && m.Chain.CheckpointTTLSecs <= 0 {
		m.Chain.CheckpointTTLSecs = 1800
	}
	if err := validElem("default", m.Default); err != nil {
		return err
	}
	if m.Reject != nil && !json.Valid([]byte(m.Reject.Body)) {
		return fmt.Errorf("reject: body is not valid JSON: %q", m.Reject.Body)
	}
	if m.Recurse != nil && m.Recurse.Headers != "" && !json.Valid([]byte(m.Recurse.Headers)) {
		return fmt.Errorf("recurse: headers is not valid JSON: %q", m.Recurse.Headers)
	}
	return nil
}

func gelAllFilesNameByDirName(dirName string) ([]string, error) {
	files, err := os.ReadDir(dirName)
	if err != nil {
		return nil, err
	}

	var filesName []string
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".yaml") {
			filesName = append(filesName, file.Name())
		}
	}
	return filesName, nil
}

func readFileBytesByFilePath(filePath string) ([]byte, error) {
	return os.ReadFile(filePath)
}

// envVarRefRegex matches ${UPPER_CASE_VAR} placeholders that beelzebub
// substitutes from the process environment at config-load time (via
// substituteEnvVarsInBuf below). Deliberately excludes the lowercase
// request-time pseudo-vars (${request.*}, ${session.*}, ${time.*})
// which are resolved per-request inside the HTTP/MCP/TCP handlers via
// the responsesubs package, not from os.Environ.
var envVarRefRegex = regexp.MustCompile(`\$\{([A-Z][A-Z0-9_]*)\}`)

// substituteEnvVarsInBuf replaces ${UPPER_CASE_VAR} placeholders with their
// os.Getenv values, in-place on the raw yaml bytes. Called before yaml
// unmarshal so the in-memory config carries resolved canary values into
// every handler/response/plugin-prompt string. Unset vars are left as the
// literal placeholder string (downstream warnMissingEnvVars logs them).
//
// The regex deliberately matches only UPPER_CASE_VAR shape so lowercase
// request-time pseudo-vars (${request.uuid_short}, ${session.cookie},
// ${time.ago.3h}) survive intact for per-request resolution. Using
// os.ExpandEnv directly would clobber those (it expands any ${...} via
// os.Getenv, which returns "" for non-env names — destructive).
func substituteEnvVarsInBuf(buf []byte) []byte {
	return envVarRefRegex.ReplaceAllFunc(buf, func(m []byte) []byte {
		// m looks like ${HTTP_CANARY_WEB_BUG} — extract the name.
		name := string(m[2 : len(m)-1])
		if val := os.Getenv(name); val != "" {
			return []byte(val)
		}
		return m // leave literal; warnMissingEnvVars will log it.
	})
}

// warnMissingEnvVars scans raw yaml bytes for ${ENV_VAR} placeholders and
// emits a WARN line for each unique reference whose env var is unset.
// Each missing var = one literal placeholder leaking into served responses,
// which fingerprints the honeypot on the first scanner that fetches the
// affected path.
func warnMissingEnvVars(filePath string, buf []byte) {
	seen := map[string]bool{}
	for _, m := range envVarRefRegex.FindAllSubmatch(buf, -1) {
		name := string(m[1])
		if seen[name] {
			continue
		}
		seen[name] = true
		if os.Getenv(name) == "" {
			log.WithFields(log.Fields{
				"file":    filePath,
				"env_var": name,
			}).Warn("yaml references unset env var — literal placeholder will be served to attackers (lure burn risk)")
		}
	}
}
