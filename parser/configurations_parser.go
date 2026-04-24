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
	InjectionPayloads map[string]string  `yaml:"injectionPayloads"`
	CanaryTokens      map[string]string  `yaml:"canaryTokens"`
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

// BeelzebubServiceConfiguration is the struct that contains the configurations of the honeypot service
type BeelzebubServiceConfiguration struct {
	ApiVersion             string          `yaml:"apiVersion"`
	Protocol               string          `yaml:"protocol"`
	Address                string          `yaml:"address"`
	Commands               []Command       `yaml:"commands"`
	Tools                  []Tool          `yaml:"tools"`
	FallbackCommand        Command         `yaml:"fallbackCommand"`
	ServerVersion          string          `yaml:"serverVersion"`
	ServerName             string          `yaml:"serverName"`
	DeadlineTimeoutSeconds int             `yaml:"deadlineTimeoutSeconds"`
	PasswordRegex          string          `yaml:"passwordRegex"`
	Description            string          `yaml:"description"`
	// v8: Canonical service type tag. Flows through every event to the exporter
	// and downstream systems. Describes WHAT THIS SENSOR IS PRETENDING TO BE,
	// not what the attacker is doing (that's behavioral classification).
	// Examples: "ollama", "terraform-state", "docker-registry", "redis", "mysql".
	// If empty, the exporter falls back to deriving service type from Description
	// or port mapping. New deployments should always set this.
	ServiceType            string          `yaml:"serviceType,omitempty" json:",omitempty"`
	Banner                 string          `yaml:"banner"`
	Plugin                 Plugin          `yaml:"plugin"`
	TLSCertPath            string          `yaml:"tlsCertPath"`
	TLSKeyPath             string          `yaml:"tlsKeyPath"`
	WorldSeed              WorldSeedConfig `yaml:"worldSeed"`
	FaultInjection         FaultInjection  `yaml:"faultInjection"`
	OllamaConfig           OllamaConfig    `yaml:"ollamaConfig"`
	NoveltyDetection       NoveltyDetection `yaml:"noveltyDetection"`
	ShellEmulator          ShellEmulator    `yaml:"shellEmulator"`
	// BinarySafe switches the TCP handler from line-by-line ASCII reading
	// to a binary-safe reader that preserves all bytes (CR/LF, non-printable)
	// and hex-escapes them before emitting trace events. Used for protocols
	// that aren't newline-delimited ASCII — Redis RESP, MySQL handshake, etc.
	// Default false (backward compat with existing text-based services).
	// `omitempty` keeps the JSON shape identical to pre-change for the
	// default value, so HashCode() stays stable for all existing configs.
	BinarySafe bool `yaml:"binarySafe" json:",omitempty"`
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
}

// Tool is the struct that contains the configurations of the MCP Honeypot
type Tool struct {
	Name            string           `yaml:"name" json:"Name"`
	Description     string           `yaml:"description" json:"Description"`
	Params          []Param          `yaml:"params" json:"Params"`
	Handler         string           `yaml:"handler" json:"Handler"`
	Annotations     *ToolAnnotations `yaml:"annotations,omitempty" json:"Annotations,omitempty"`
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

		beelzebubServiceConfiguration := &BeelzebubServiceConfiguration{}
		err = yaml.Unmarshal(buf, beelzebubServiceConfiguration)

		if err != nil {
			return nil, fmt.Errorf("in file %s: %v", filePath, err)
		}

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
func (c *BeelzebubServiceConfiguration) CompileCommandRegex() error {
	for i, command := range c.Commands {
		if command.RegexStr != "" {
			rex, err := regexp.Compile(command.RegexStr)
			if err != nil {
				return err
			}
			c.Commands[i].Regex = rex
		}
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
