// Package tracer is responsible for tracing the events that occur in the honeypots
package tracer

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
)

const Workers = 5

type Event struct {
	DateTime   string
	RemoteAddr string
	Protocol   string
	Command    string
	// CommandRaw is a hex-escaped representation of the raw bytes the
	// attacker sent for binary protocols (Redis RESP, MySQL handshake, etc).
	// Only populated when the service config sets `binarySafe: true`.
	// Empty for ASCII protocols. Stored alongside Command (which holds the
	// protocol-decoded form) so downstream classifiers can reason about the
	// wire-level protocol class without re-parsing.
	CommandRaw      string `json:"CommandRaw,omitempty"`
	CommandOutput   string
	Status          string
	Msg             string
	ID              string
	Environ         string
	User            string
	Password        string
	Client          string
	Headers         string
	HeadersMap      map[string][]string
	Cookies         string
	UserAgent       string
	HostHTTPRequest string
	Body            string
	HTTPMethod      string
	RequestURI      string
	Description     string
	SourceIp        string
	SourcePort      string
	TLSServerName   string
	Handler         string

	// Session correlation
	SessionKey string `json:"SessionKey,omitempty"`
	Sequence   int    `json:"Sequence,omitempty"`
	// CorrelationID is a deterministic IP hash. DEPRECATED for cross-protocol
	// actor linking — it cannot distinguish actors behind one IP (NAT) or
	// separate campaigns from the same IP over time. Use ActorID instead; this
	// field is retained only for back-compat with pre-cutover consumers.
	CorrelationID string `json:"CorrelationID,omitempty"`
	// ActorID is the bridge-minted cross-protocol actor-episode key: stable for
	// one actor across protocols within an activity window, and rolled to a new
	// value after an idle gap (campaign separation). Populated by the registered
	// actor resolver in TraceEvent. Empty on stock (non-fork) sensors.
	ActorID string `json:"ActorID,omitempty"`

	// MCP-specific
	ToolName      string `json:"ToolName,omitempty"`
	ToolArguments string `json:"ToolArguments,omitempty"`
	// MCP initialize handshake (emitted by the AfterInitialize hook, not tool calls).
	// clientInfo is attacker-controlled; capabilities is the more structural fingerprint.
	MCPClientName      string `json:"MCPClientName,omitempty"`
	MCPClientVersion   string `json:"MCPClientVersion,omitempty"`
	MCPProtocolVersion string `json:"MCPProtocolVersion,omitempty"`
	MCPCapabilities    string `json:"MCPCapabilities,omitempty"` // JSON-encoded client capabilities
	// Records the honeypot's own tarpit delay for this event, so net attacker
	// think-time = delta_ms - injected_delay_ms is recoverable.
	InjectedDelayMs int64 `json:"InjectedDelayMs,omitempty"`

	// Timing
	InterEventMs int64 `json:"InterEventMs,omitempty"`

	// Retry detection
	IsRetry bool   `json:"IsRetry,omitempty"`
	RetryOf string `json:"RetryOf,omitempty"`

	// Cross-protocol
	CrossProtocolRef string `json:"CrossProtocolRef,omitempty"`

	// Fault injection
	FaultInjected string `json:"FaultInjected,omitempty"`

	// Tool chain analysis
	ToolChainDepth int    `json:"ToolChainDepth,omitempty"`
	ToolDependency string `json:"ToolDependency,omitempty"`

	// Agent classification (on End events)
	AgentScore    int    `json:"AgentScore,omitempty"`
	AgentCategory string `json:"AgentCategory,omitempty"`
	AgentSignals  string `json:"AgentSignals,omitempty"`

	// Novelty detection
	NoveltyScore    int    `json:"NoveltyScore,omitempty"`
	NoveltyCategory string `json:"NoveltyCategory,omitempty"`
	NoveltySignals  string `json:"NoveltySignals,omitempty"`

	// Response metrics
	ResponseBytes int64 `json:"ResponseBytes,omitempty"` // actual HTTP response body size (bytes)

	// Network fingerprints
	JA4H        string `json:"JA4H,omitempty"`
	HeaderOrder string `json:"HeaderOrder,omitempty"` // wire-order header names, comma-separated
	// JA4HSorted is true when JA4H was computed from sorted header names
	// (raw wire order unavailable, e.g. capture truncated). Such a hash is
	// NOT comparable to spec wire-order JA4H — downstream pivots must exclude
	// sorted hashes rather than silently mixing the two families.
	JA4HSorted bool   `json:"JA4HSorted,omitempty"`
	HASSH      string `json:"HASSH,omitempty"`

	// v8: Service port extracted from listener address.
	ServicePort string `json:"ServicePort,omitempty"`

	// v8: Canonical service type from sensor config. Describes what the sensor
	// is pretending to be (e.g., "ollama", "terraform-state", "redis").
	// Provides context for downstream classification without biasing toward
	// specific path patterns. Scales to any service type without code changes.
	ServiceType string `json:"ServiceType,omitempty"`

	// v8: Raw SSH KEX algorithm lists (preserved alongside the HASSH MD5 hash).
	HASSHAlgorithms string `json:"HASSHAlgorithms,omitempty"`

	// v8: HTTP response status code for lure effectiveness research.
	ResponseStatusCode int `json:"ResponseStatusCode,omitempty"`

	// v8: SSH terminal metadata from PTY request.
	PTYTerm   string `json:"PTYTerm,omitempty"`
	PTYWidth  int    `json:"PTYWidth,omitempty"`
	PTYHeight int    `json:"PTYHeight,omitempty"`

	// v8: JA4 TLS ClientHello fingerprint.
	JA4 string `json:"JA4,omitempty"`
	// JA3 TLS ClientHello fingerprint (classic Salesforce). Emitted alongside
	// JA4 for cross-corpus lookup (Shodan/GreyNoise/VT index JA3 heavily).
	JA3 string `json:"JA3,omitempty"`
	// HTTP2 is the Akamai HTTP/2 fingerprint (SETTINGS|WINDOW_UPDATE|PRIORITY|
	// pseudo-header-order), parsed from the decrypted opening frames. Empty for
	// HTTP/1.1 connections.
	HTTP2 string `json:"HTTP2,omitempty"`

	// v8: Telnet subnegotiation data from IAC SB...SE blocks.
	// NAWS = terminal dimensions, TTYPE = terminal software, TSPEED = connection speed.
	// Strong client fingerprint: real terminals vary, bots use 80x24 or 0x0.
	TelnetTermType string `json:"TelnetTermType,omitempty"`
	TelnetWidth    int    `json:"TelnetWidth,omitempty"`
	TelnetHeight   int    `json:"TelnetHeight,omitempty"`
	TelnetSpeed    string `json:"TelnetSpeed,omitempty"`

	// v8: SSH public key metadata (structured, not crammed into Command field).
	// key.Type() + fingerprint was previously stored as Command on Stateless events.
	// These structured fields enable: key type distribution analysis, RSA exponent
	// detection (e=37 PuTTYgen vs e=65537 OpenSSH), cross-session key matching.
	SSHKeyType        string `json:"SSHKeyType,omitempty"`
	SSHKeyFingerprint string `json:"SSHKeyFingerprint,omitempty"`

	// v8: Per-request response timing — how long the honeypot took to respond.
	// Critical for: lure effectiveness research, agent timing decontamination,
	// detecting when our LLM responses are suspiciously slow vs real services.
	ResponseTimeMs int64 `json:"ResponseTimeMs,omitempty"`

	// v8: HTTP response body bytes served to the attacker. Opt-in per service
	// via parser.BeelzebubServiceConfiguration.CaptureResponseBody. Truncated
	// to ResponseBodyMaxBytes (default 64 KiB) to bound storage. Empty when
	// flag is off; ResponseBytes (count) is still populated regardless.
	// Required for: AKIA canary attribution (token embedded in response, not
	// request), honeypot-detection probe verification, lure quality A/B,
	// LLM-side prompt-injection detection.
	ResponseBody string `json:"ResponseBody,omitempty"`

	// v8: HTTP request body bytes from the attacker, dedicated capture (mirrors
	// ResponseBody). Opt-in per service via parser.BeelzebubServiceConfiguration.
	// CaptureRequestBody, truncated to RequestBodyMaxBytes (default 64 KiB).
	// Required for: prompt capture on LLM-shaped lures (LiteLLM, vLLM,
	// Ollama, Open WebUI), MCP tool argument retention, prompt-injection
	// research. Distinct from the legacy Body field (which is always set,
	// not truncated, and used by HTTP/MCP for backwards-compat); RequestBody
	// is the bounded, opt-in equivalent that downstream pipelines should
	// prefer when the operator has explicitly opted in.
	RequestBody string `json:"RequestBody,omitempty"`

	// v8: HTTP response headers served, comma-separated "Name: value" pairs.
	// Captured alongside ResponseBody under the same opt-in flag. Detects
	// honeypot fingerprinting via static header sets.
	ResponseHeaders string `json:"ResponseHeaders,omitempty"`

	// Captured carries lure-namespaced session metadata extracted by
	// HTTP strategy's stateful handlers (sessionCapture) plus the
	// artifact_sha256 when an artifact was written. Keys MUST be
	// dot-namespaced by service to avoid collision: "screenconnect.operator_user".
	// Propagates through to the aggregator's deception_metadata JSONB column.
	Captured map[string]string `json:"Captured,omitempty"`

	// WS-4 Slice B (2026-05-12): body-capture integrity fields. Hashes are
	// computed over the FULL raw body bytes BEFORE any truncation, so the
	// hash is forensic identity even when RequestBody / ResponseBody are
	// truncated for storage. Empty when the body was empty (per Slice B Q1
	// — see docs/strategy/2026-05-12-ws4-slice-b-body-capture-design.md in
	// the honeypot-research repo). Hashing runs unconditionally on every
	// body the wire carried — independent of CaptureRequestBody — so the
	// hash field always reflects "what was on the wire" (Slice B Q5).
	RequestBodySha256  string `json:"RequestBodySha256,omitempty"`
	ResponseBodySha256 string `json:"ResponseBodySha256,omitempty"`

	// RequestBodyParts is populated by the HTTP strategy when a request
	// arrives with a multipart/* Content-Type. JSON / opaque to all
	// downstream consumers — see MultipartPart struct in tracer/multipart.go.
	// Nil for non-multipart traffic and for protocols other than HTTP
	// (Slice B Q2: MCP/OLLAMA/openai never carry multipart in practice).
	RequestBodyParts []MultipartPart `json:"RequestBodyParts,omitempty"`

	// Stimulus battery (active-instrument): which stimulus was presented on
	// this event and which cohort the source IP fell in. Empty for untagged
	// events. Flow through to the collector + ingest via generic JSON marshal.
	StimulusID      string `json:"StimulusID,omitempty"`
	StimulusVariant string `json:"StimulusVariant,omitempty"`
}

type (
	Protocol int
	Status   int
)

const (
	HTTP Protocol = iota
	SSH
	TCP
	MCP
	TELNET
)

func (protocol Protocol) String() string {
	return [...]string{"HTTP", "SSH", "TCP", "MCP", "TELNET"}[protocol]
}

const (
	Start Status = iota
	End
	Stateless
	Interaction
)

func (status Status) String() string {
	return [...]string{"Start", "End", "Stateless", "Interaction"}[status]
}

type Strategy func(event Event)

type Tracer interface {
	TraceEvent(event Event)
}

type tracer struct {
	strategy          Strategy
	eventsChan        chan Event
	eventsTotal       prometheus.Counter
	eventsSSHTotal    prometheus.Counter
	eventsTCPTotal    prometheus.Counter
	eventsHTTPTotal   prometheus.Counter
	eventsMCPTotal    prometheus.Counter
	eventsTelnetTotal prometheus.Counter

	strategyMutex sync.RWMutex
	timingCache   *TimingCache
}

var lock = &sync.Mutex{}
var singleton *tracer

func GetInstance(defaultStrategy Strategy) *tracer {
	if singleton == nil {
		lock.Lock()
		defer lock.Unlock()
		// This is to prevent expensive lock operations every time the GetInstance method is called
		if singleton == nil {
			singleton = &tracer{
				strategy:    defaultStrategy,
				eventsChan:  make(chan Event, Workers),
				timingCache: NewTimingCache(),
				eventsTotal: promauto.NewCounter(prometheus.CounterOpts{
					Namespace: "beelzebub",
					Name:      "events_total",
					Help:      "The total number of events",
				}),
				eventsSSHTotal: promauto.NewCounter(prometheus.CounterOpts{
					Namespace: "beelzebub",
					Name:      "ssh_events_total",
					Help:      "The total number of SSH events",
				}),
				eventsTCPTotal: promauto.NewCounter(prometheus.CounterOpts{
					Namespace: "beelzebub",
					Name:      "tcp_events_total",
					Help:      "The total number of TCP events",
				}),
				eventsHTTPTotal: promauto.NewCounter(prometheus.CounterOpts{
					Namespace: "beelzebub",
					Name:      "http_events_total",
					Help:      "The total number of HTTP events",
				}),
				eventsMCPTotal: promauto.NewCounter(prometheus.CounterOpts{
					Namespace: "beelzebub",
					Name:      "mcp_events_total",
					Help:      "The total number of MCP events",
				}),
				eventsTelnetTotal: promauto.NewCounter(prometheus.CounterOpts{
					Namespace: "beelzebub",
					Name:      "telnet_events_total",
					Help:      "The total number of TELNET events",
				}),
			}

			for i := 0; i < Workers; i++ {
				go func(i int) {
					log.Debug("Trace worker: ", i)
					for event := range singleton.eventsChan {
						// Read the strategy under its mutex; SetStrategy may
						// swap it concurrently (data race on the raw field).
						singleton.GetStrategy()(event)
					}
				}(i)
			}
		}
	}

	return singleton
}

func (tracer *tracer) SetStrategy(strategy Strategy) {
	tracer.strategyMutex.Lock()
	defer tracer.strategyMutex.Unlock()
	tracer.strategy = strategy
}

func (tracer *tracer) GetStrategy() Strategy {
	tracer.strategyMutex.RLock()
	defer tracer.strategyMutex.RUnlock()
	return tracer.strategy
}

// CorrelationIDFromIP returns a deterministic short hash of an IP.
//
// DEPRECATED for actor correlation: it is a pure function of the IP, so it
// cannot separate distinct actors behind one IP (NAT) or distinct campaigns
// from the same IP over time. Use the bridge-minted ActorID (see ActorResolver)
// for genuine cross-protocol linkage. Retained only to keep the legacy
// CorrelationID field populated for pre-cutover consumers.
func CorrelationIDFromIP(ip string) string {
	h := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(h[:8])
}

// ActorResolver maps a source IP (at a given event time) to a cross-protocol
// actor-episode id. The bridge implements this; the tracer stays decoupled from
// the bridge package via this function type.
type ActorResolver func(ip string, t time.Time) string

var (
	actorResolverMu sync.RWMutex
	actorResolver   ActorResolver
)

// SetActorResolver registers (or clears, with nil) the resolver TraceEvent uses
// to populate Event.ActorID. Wired by builder to the shared ProtocolBridge.
func SetActorResolver(r ActorResolver) {
	actorResolverMu.Lock()
	defer actorResolverMu.Unlock()
	actorResolver = r
}

// CleanTimingCache evicts inter-event-timing entries idle longer than maxAge
// from the singleton's cache. Without periodic cleaning the per-session-key map
// grows unboundedly AND a returning IP's InterEventMs is computed against a
// weeks-old "last event," yielding garbage deltas that pollute timing-based
// agent scoring. Wired to a lifecycle cleaner in builder. No-op before the
// singleton exists.
func CleanTimingCache(maxAge time.Duration) {
	if singleton != nil && singleton.timingCache != nil {
		singleton.timingCache.Clean(maxAge)
	}
}

// ExtractPort returns the port portion of a listen address.
// Handles ":22", "0.0.0.0:22", "[::]:3306", and bare ":8000".
func ExtractPort(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return strings.TrimPrefix(addr, ":")
	}
	return port
}

func (tracer *tracer) TraceEvent(event Event) {
	now := time.Now().UTC()
	event.DateTime = now.Format(time.RFC3339Nano)

	// Auto-populate CorrelationID from SourceIp if not already set (legacy).
	if event.CorrelationID == "" && event.SourceIp != "" {
		event.CorrelationID = CorrelationIDFromIP(event.SourceIp)
	}

	// Auto-populate the cross-protocol ActorID from the registered resolver
	// (the shared bridge) if not already set. Mirrors CorrelationID; no-op when
	// no resolver is wired (e.g. stock sensors, unit tests).
	if event.ActorID == "" && event.SourceIp != "" {
		actorResolverMu.RLock()
		r := actorResolver
		actorResolverMu.RUnlock()
		if r != nil {
			event.ActorID = r(event.SourceIp, now)
		}
	}

	// Compute inter-event timing if session key is set
	if event.SessionKey != "" && tracer.timingCache != nil {
		event.InterEventMs = tracer.timingCache.RecordAndDelta(event.SessionKey)
	}

	tracer.eventsChan <- event

	tracer.updatePrometheusCounters(event.Protocol)
}

func (tracer *tracer) updatePrometheusCounters(protocol string) {
	switch protocol {
	case HTTP.String():
		tracer.eventsHTTPTotal.Inc()
	case SSH.String():
		tracer.eventsSSHTotal.Inc()
	case TCP.String():
		tracer.eventsTCPTotal.Inc()
	case MCP.String():
		tracer.eventsMCPTotal.Inc()
	case TELNET.String():
		tracer.eventsTelnetTotal.Inc()
	}
	tracer.eventsTotal.Inc()
}
