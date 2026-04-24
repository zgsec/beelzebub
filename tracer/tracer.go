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
	DateTime      string
	RemoteAddr    string
	Protocol      string
	Command       string
	// CommandRaw is a hex-escaped representation of the raw bytes the
	// attacker sent for binary protocols (Redis RESP, MySQL handshake, etc).
	// Only populated when the service config sets `binarySafe: true`.
	// Empty for ASCII protocols. Stored alongside Command (which holds the
	// protocol-decoded form) so downstream classifiers can reason about the
	// wire-level protocol class without re-parsing.
	CommandRaw    string `json:"CommandRaw,omitempty"`
	CommandOutput string
	Status        string
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
	SessionKey    string `json:"SessionKey,omitempty"`
	Sequence      int    `json:"Sequence,omitempty"`
	CorrelationID string `json:"CorrelationID,omitempty"`

	// MCP-specific
	ToolName      string `json:"ToolName,omitempty"`
	ToolArguments string `json:"ToolArguments,omitempty"`

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
	HASSH       string `json:"HASSH,omitempty"`

	// v8: Service port extracted from listener address. Replaces the exporter's
	// DescriptionToPort string-matching which breaks on novel sensor configs.
	ServicePort string `json:"ServicePort,omitempty"`

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
						singleton.strategy(event)
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

// CorrelationIDFromIP returns a deterministic short hash of an IP for cross-protocol linking.
func CorrelationIDFromIP(ip string) string {
	h := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(h[:8])
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
	event.DateTime = time.Now().UTC().Format(time.RFC3339Nano)

	// Auto-populate CorrelationID from SourceIp if not already set
	if event.CorrelationID == "" && event.SourceIp != "" {
		event.CorrelationID = CorrelationIDFromIP(event.SourceIp)
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
