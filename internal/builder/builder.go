package builder

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/bridge"
	"github.com/beelzebub-labs/beelzebub/v3/internal/faults"
	"github.com/beelzebub-labs/beelzebub/v3/internal/lifecycle"
	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/MCP"
	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/OLLAMA"
	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/TELNET"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/plugins"
	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols"
	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/HTTP"
	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/SSH"
	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/TCP"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	amqp "github.com/rabbitmq/amqp091-go"
	log "github.com/sirupsen/logrus"
)

const RabbitmqQueueName = "event"

type Builder struct {
	beelzebubServicesConfiguration []parser.BeelzebubServiceConfiguration
	beelzebubCoreConfigurations    *parser.BeelzebubCoreConfigurations
	traceStrategy                  tracer.Strategy
	rabbitMQChannel                *amqp.Channel
	rabbitMQConnection             *amqp.Connection
	logsFile                       *os.File

	// persona holds deception content loaded from /configurations/persona.yaml
	// at startup. Nil means no persona file was found (backward-compat mode).
	persona *parser.Persona
}

// SetPersona stores the loaded persona for use by protocol strategies.
func (b *Builder) SetPersona(p *parser.Persona) *Builder {
	b.persona = p
	return b
}

// Persona returns the loaded persona, or nil if none was loaded.
func (b *Builder) Persona() *parser.Persona {
	return b.persona
}

func (b *Builder) setTraceStrategy(traceStrategy tracer.Strategy) {
	b.traceStrategy = traceStrategy
}

func (b *Builder) buildLogger(configurations parser.Logging) error {
	// No logsPath: log to stdout only. A missing path must not abort boot —
	// fresh sensor stand-ups often ship a minimal core config without one.
	output := io.Writer(os.Stdout)
	if configurations.LogsPath != "" {
		logsFile, err := os.OpenFile(configurations.LogsPath, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
		if err != nil {
			return err
		}
		output = io.MultiWriter(os.Stdout, logsFile)
		b.logsFile = logsFile
	}

	log.SetOutput(output)

	log.SetFormatter(&log.JSONFormatter{
		DisableTimestamp: configurations.LogDisableTimestamp,
	})
	log.SetReportCaller(configurations.DebugReportCaller)
	if configurations.Debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	return nil
}

func (b *Builder) buildRabbitMQ(rabbitMQURI string) error {
	rabbitMQConnection, err := amqp.Dial(rabbitMQURI)
	if err != nil {
		return err
	}

	b.rabbitMQChannel, err = rabbitMQConnection.Channel()
	if err != nil {
		return err
	}

	//creates a queue if it doesn't already exist, or ensures that an existing queue matches the same parameters.
	if _, err = b.rabbitMQChannel.QueueDeclare(RabbitmqQueueName, false, false, false, false, nil); err != nil {
		return err
	}

	b.rabbitMQConnection = rabbitMQConnection
	return nil
}

func (b *Builder) Close() error {
	// Close log file if it was opened
	if b.logsFile != nil {
		if err := b.logsFile.Close(); err != nil {
			return err
		}
	}

	// Close RabbitMQ connections. Channel may be nil if buildRabbitMQ failed
	// after dialing but before opening the channel.
	if b.rabbitMQChannel != nil {
		if err := b.rabbitMQChannel.Close(); err != nil {
			return err
		}
	}
	if b.rabbitMQConnection != nil {
		if err := b.rabbitMQConnection.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (b *Builder) Run() error {
	fmt.Println(
		`
██████  ███████ ███████ ██      ███████ ███████ ██████  ██    ██ ██████  
██   ██ ██      ██      ██         ███  ██      ██   ██ ██    ██ ██   ██ 
██████  █████   █████   ██        ███   █████   ██████  ██    ██ ██████  
██   ██ ██      ██      ██       ███    ██      ██   ██ ██    ██ ██   ██ 
██████  ███████ ███████ ███████ ███████ ███████ ██████   ██████  ██████  
Honeypot Framework, happy hacking!`)
	// Init Prometheus openmetrics
	go func() {
		if (b.beelzebubCoreConfigurations.Core.Prometheus != parser.Prometheus{}) {
			http.Handle(b.beelzebubCoreConfigurations.Core.Prometheus.Path, promhttp.Handler())

			if err := http.ListenAndServe(b.beelzebubCoreConfigurations.Core.Prometheus.Port, nil); err != nil {
				log.Fatalf("Error init Prometheus: %s", err.Error())
			}
		}
	}()

	// Init shared cross-protocol bridge
	protocolBridge := bridge.NewBridge()

	// Periodically prune stale bridge state. Without this, discoveredCreds and
	// sessionFlags grow unboundedly — the bug Track 5 surfaced. 5-minute tick
	// + 60-minute TTL matches the cleanup cadence used by HTTP / TCP / TELNET
	// session stores. context.Background() preserves the previous
	// no-shutdown behavior; when builder gains a real lifecycle context, this
	// is the seam to thread it through.
	go lifecycle.Cleaner(context.Background(), 5*time.Minute, "bridge.clean", func() {
		protocolBridge.Clean(60 * time.Minute)
	})

	// Init Protocol strategies
	secureShellStrategy := &SSH.SSHStrategy{Bridge: protocolBridge}
	hypertextTransferProtocolStrategy := &HTTP.HTTPStrategy{Bridge: protocolBridge}
	transmissionControlProtocolStrategy := &TCP.TCPStrategy{Bridge: protocolBridge}
	modelContextProtocolStrategy := &MCP.MCPStrategy{Bridge: protocolBridge}
	telnetStrategy := &TELNET.TelnetStrategy{Bridge: protocolBridge}
	ollamaStrategy := &OLLAMA.OllamaStrategy{Bridge: protocolBridge}

	// Propagate persona to strategies that use deception content
	modelContextProtocolStrategy.SetPersona(b.persona)
	ollamaStrategy.SetPersona(b.persona)

	// Init Tracer strategies, and set the trace strategy default HTTP
	protocolManager := protocols.InitProtocolManager(b.traceStrategy, hypertextTransferProtocolStrategy)

	if b.beelzebubCoreConfigurations.Core.BeelzebubCloud.Enabled {
		conf := b.beelzebubCoreConfigurations.Core.BeelzebubCloud

		beelzebubCloud := plugins.InitBeelzebubCloud(conf.URI, conf.AuthToken, true)

		if honeypotsConfiguration, _, err := beelzebubCloud.GetHoneypotsConfigurations(); err != nil {
			return err
		} else {
			if len(honeypotsConfiguration) == 0 {
				return errors.New("no honeypots configuration found")
			}
			b.beelzebubServicesConfiguration = honeypotsConfiguration
		}
	}

	for _, beelzebubServiceConfiguration := range b.beelzebubServicesConfiguration {
		// Create per-service fault injector if configured
		var faultInjector *faults.Injector
		if beelzebubServiceConfiguration.FaultInjection.Enabled {
			faultInjector = faults.NewInjector(faults.Config{
				Enabled:        beelzebubServiceConfiguration.FaultInjection.Enabled,
				ErrorRate:      beelzebubServiceConfiguration.FaultInjection.ErrorRate,
				DelayMs:        beelzebubServiceConfiguration.FaultInjection.DelayMs,
				DelayJitterMs:  beelzebubServiceConfiguration.FaultInjection.DelayJitterMs,
				ErrorResponses: beelzebubServiceConfiguration.FaultInjection.ErrorResponses,
			})
		}

		switch beelzebubServiceConfiguration.Protocol {
		case "http":
			hypertextTransferProtocolStrategy.Fault = faultInjector
			protocolManager.SetProtocolStrategy(hypertextTransferProtocolStrategy)
		case "ssh":
			secureShellStrategy.Fault = faultInjector
			protocolManager.SetProtocolStrategy(secureShellStrategy)
		case "tcp":
			protocolManager.SetProtocolStrategy(transmissionControlProtocolStrategy)
		case "mcp":
			modelContextProtocolStrategy.Fault = faultInjector
			protocolManager.SetProtocolStrategy(modelContextProtocolStrategy)
		case "telnet":
			telnetStrategy.Fault = faultInjector
			protocolManager.SetProtocolStrategy(telnetStrategy)
		case "ollama":
			ollamaStrategy.Fault = faultInjector
			protocolManager.SetProtocolStrategy(ollamaStrategy)
		default:
			log.Fatalf("protocol %s not managed", beelzebubServiceConfiguration.Protocol)
		}

		if err := protocolManager.InitService(beelzebubServiceConfiguration); err != nil {
			return fmt.Errorf("error during init protocol: %s, %s", beelzebubServiceConfiguration.Protocol, err.Error())
		}
	}

	return nil
}

func (b *Builder) build() *Builder {
	return &Builder{
		beelzebubServicesConfiguration: b.beelzebubServicesConfiguration,
		traceStrategy:                  b.traceStrategy,
		beelzebubCoreConfigurations:    b.beelzebubCoreConfigurations,
		persona:                        b.persona,
	}
}

func NewBuilder() *Builder {
	return &Builder{}
}
