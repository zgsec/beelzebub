package shellemulator

import (
	"os"
	"strings"
	"time"

	"github.com/mariocandela/beelzebub/v3/parser"
)

// Process holds a rendered process table entry.
type Process struct {
	PID  int
	User string
	CPU  string
	Mem  string
	VSZ  string
	RSS  string
	Cmd  string
	Stat string
	Time string
}

// Listener represents a listening port for netstat/ss output.
type Listener struct {
	Proto   string
	Local   string
	PID     int
	Program string
}

// NetworkConfig holds interface and routing info.
type NetworkConfig struct {
	Interface string
	MAC       string
	IP        string
	Netmask   string
	Broadcast string
	Gateway   string
}

// Persona is the complete world state the emulator renders from.
type Persona struct {
	Hostname   string
	Kernel     string
	OS         string
	IP         string
	User       string
	BootTime   time.Time
	Processes  []Process
	EnvVars    map[string]string
	Lures      map[string]string
	Filesystem map[string][]string
	Network    NetworkConfig
	Listeners  []Listener
}

// DefaultCanaryTokens provides example fallback values when no real tokens are configured.
// In production, these are overridden by env-var-backed YAML values.
var DefaultCanaryTokens = map[string]string{
	"aws_key":     "AKIAIOSFODNN7EXAMPLE",
	"aws_secret":  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	"api_key":     "sk-live-7f8g9h0j1k2l3m4n5o6p",
	"db_password": "s3cur3-pr0d-pw-2024",
	"canary_dns":  "svc-mesh.int.crestfielddata.io",
	"docker_auth": "ZGVwbG95OnN1cDNyLXMzY3IzdC1wQHNz",
}

// resolveTokens expands ${ENV_VAR} references in token values via os.ExpandEnv,
// then merges with DefaultCanaryTokens (config values take precedence).
func resolveTokens(configTokens map[string]string) map[string]string {
	merged := make(map[string]string, len(DefaultCanaryTokens))
	for k, v := range DefaultCanaryTokens {
		merged[k] = v
	}
	for k, v := range configTokens {
		resolved := os.ExpandEnv(v)
		if resolved != "" {
			merged[k] = resolved
		}
	}
	return merged
}

// substituteTokens replaces {{KEY}} placeholders in content with resolved token values.
func substituteTokens(content string, tokens map[string]string) string {
	for key, val := range tokens {
		placeholder := "{{" + strings.ToUpper(key) + "}}"
		content = strings.ReplaceAll(content, placeholder, val)
	}
	return content
}

// DefaultPersona returns the default Ubuntu 22.04 server persona.
// All credential values use {{PLACEHOLDER}} format for canary token substitution.
func DefaultPersona() *Persona {
	return &Persona{
		Hostname: "prod-web-01",
		Kernel:   "5.15.0-91-generic",
		OS:       "Ubuntu 22.04.4 LTS",
		IP:       "10.0.1.100",
		User:     "root",
		Processes: []Process{
			{PID: 1, User: "root", CPU: "0.0", Mem: "0.1", VSZ: "168K", RSS: "11M", Cmd: "/sbin/init", Stat: "Ss", Time: "0:03"},
			{PID: 412, User: "root", CPU: "0.0", Mem: "0.2", VSZ: "92M", RSS: "18M", Cmd: "/lib/systemd/systemd-journald", Stat: "Ss", Time: "0:08"},
			{PID: 587, User: "root", CPU: "0.0", Mem: "0.1", VSZ: "15M", RSS: "6M", Cmd: "/usr/sbin/sshd -D", Stat: "Ss", Time: "0:00"},
			{PID: 602, User: "root", CPU: "0.0", Mem: "0.1", VSZ: "24M", RSS: "8M", Cmd: "/usr/sbin/cron -f", Stat: "Ss", Time: "0:01"},
			{PID: 842, User: "root", CPU: "0.2", Mem: "1.8", VSZ: "1.2G", RSS: "72M", Cmd: "/usr/bin/dockerd -H fd://", Stat: "Ssl", Time: "0:12"},
			{PID: 903, User: "root", CPU: "0.1", Mem: "0.8", VSZ: "712M", RSS: "32M", Cmd: "containerd", Stat: "Ssl", Time: "0:05"},
			{PID: 1105, User: "root", CPU: "0.3", Mem: "0.5", VSZ: "141M", RSS: "21M", Cmd: "nginx: master process /usr/sbin/nginx", Stat: "Ss", Time: "0:02"},
			{PID: 1106, User: "www-data", CPU: "0.0", Mem: "0.3", VSZ: "142M", RSS: "14M", Cmd: "nginx: worker process", Stat: "S", Time: "0:01"},
			{PID: 1247, User: "root", CPU: "0.5", Mem: "1.2", VSZ: "620M", RSS: "48M", Cmd: "node /opt/app/server.js", Stat: "Ssl", Time: "0:18"},
			{PID: 1389, User: "postgres", CPU: "0.1", Mem: "1.5", VSZ: "217M", RSS: "62M", Cmd: "/usr/lib/postgresql/15/bin/postgres -D /var/lib/postgresql/15/main", Stat: "Ss", Time: "0:04"},
			{PID: 1390, User: "postgres", CPU: "0.0", Mem: "0.3", VSZ: "217M", RSS: "12M", Cmd: "postgres: checkpointer", Stat: "Ss", Time: "0:01"},
			{PID: 1391, User: "postgres", CPU: "0.0", Mem: "0.3", VSZ: "217M", RSS: "12M", Cmd: "postgres: background writer", Stat: "Ss", Time: "0:00"},
			{PID: 1502, User: "root", CPU: "1.8", Mem: "4.2", VSZ: "2.1G", RSS: "168M", Cmd: "/usr/local/bin/ollama serve", Stat: "Ssl", Time: "2:47"},
			{PID: 2891, User: "root", CPU: "0.0", Mem: "0.1", VSZ: "15M", RSS: "6M", Cmd: "sshd: root@pts/0", Stat: "Ss", Time: "0:00"},
			{PID: 2893, User: "root", CPU: "0.0", Mem: "0.1", VSZ: "8M", RSS: "5M", Cmd: "-bash", Stat: "Ss", Time: "0:00"},
		},
		EnvVars: map[string]string{
			"SHELL":              "/bin/bash",
			"PATH":               "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"HOME":               "/root",
			"LOGNAME":            "root",
			"USER":               "root",
			"LANG":               "en_US.UTF-8",
			"TERM":               "xterm-256color",
			"OLLAMA_HOST":        "http://localhost:11434",
			"DOCKER_HOST":        "unix:///var/run/docker.sock",
			"AWS_DEFAULT_REGION": "us-east-1",
			"KUBECONFIG":         "/root/.kube/config",
		},
		Lures: map[string]string{
			"/root/.aws/credentials": "[default]\naws_access_key_id = {{AWS_KEY}}\naws_secret_access_key = {{AWS_SECRET}}\nregion = us-east-1",
			"/opt/app/.env": "NODE_ENV=production\nPORT=3000\nDB_HOST=10.0.1.50\nDB_USER=app_prod\nDB_PASSWORD={{DB_PASSWORD}}\nDB_NAME=app_production\nAPI_KEY={{API_KEY}}\nJWT_SECRET=a1b2c3d4e5f6a7b8c9d0e1f2\nREDIS_URL=redis://10.0.1.51:6379\nOLLAMA_HOST=http://localhost:11434\nMCP_ENDPOINT=http://localhost:8000/mcp",
			"/root/.bash_history": "ssh ubuntu@10.0.1.50\ndocker ps\ncat /opt/app/.env\nsystemctl restart nginx\nkubectl get pods -n production\npsql -U app_prod -h 10.0.1.50 app_production\ncurl -s http://localhost:11434/api/tags\ncat /root/.aws/credentials\ndocker logs app-node --tail 50\nnetstat -tulpn\nvim /etc/nginx/sites-enabled/default\ncertbot renew --dry-run\napt update && apt upgrade -y\ntail -f /var/log/nginx/access.log\ngit -C /opt/app pull origin main\ncurl -X POST http://localhost:8000/mcp -d '{\"method\":\"tools/list\"}'",
			"/root/.ssh/authorized_keys": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7fake...truncated... deploy@ci-server\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake...truncated... admin@workstation",
			"/root/.ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACBfakekey1234567890abcdefghijklmnopqrstuvwxyzAAAA\n-----END OPENSSH PRIVATE KEY-----",
			"/root/.docker/config.json": "{\n\t\"auths\": {\n\t\t\"https://index.docker.io/v1/\": {\n\t\t\t\"auth\": \"{{DOCKER_AUTH}}\"\n\t\t},\n\t\t\"registry.internal:5000\": {\n\t\t\t\"auth\": \"YWRtaW46cjNnMXN0cnktcEBzcw==\"\n\t\t}\n\t}\n}",
			"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\nsystemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\nsshd:x:110:65534::/run/sshd:/usr/sbin/nologin\npostgres:x:113:120:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash",
			"/etc/hosts": "127.0.0.1\tlocalhost\n10.0.1.100\tprod-web-01\n10.0.1.50\tdb-primary\n10.0.1.51\tredis-01\n10.0.1.52\tdb-replica-01\n\n# The following lines are desirable for IPv6 capable hosts\n::1     ip6-localhost ip6-loopback\nfe00::0 ip6-localnet",
		},
		Filesystem: map[string][]string{
			"/":                 {"bin", "boot", "dev", "etc", "home", "lib", "lib64", "media", "mnt", "opt", "proc", "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var"},
			"/root":            {".aws", ".bash_history", ".bashrc", ".cache", ".docker", ".kube", ".local", ".profile", ".ssh", "snap"},
			"/root/.aws":       {"credentials", "config"},
			"/root/.ssh":       {"authorized_keys", "id_rsa", "id_rsa.pub", "known_hosts"},
			"/root/.docker":    {"config.json"},
			"/root/.kube":      {"config"},
			"/home":            {"ubuntu"},
			"/home/ubuntu":     {".bashrc", ".profile", ".ssh"},
			"/opt":             {"app", "containerd"},
			"/opt/app":         {".env", "server.js", "package.json", "node_modules", ".git"},
			"/tmp":             {"systemd-private-abc123", "npm-12345"},
			"/var":             {"backups", "cache", "lib", "log", "mail", "opt", "run", "spool", "tmp", "www"},
			"/var/log":         {"auth.log", "syslog", "nginx", "postgresql", "docker.log", "kern.log", "dpkg.log"},
			"/var/log/nginx":   {"access.log", "error.log"},
			"/etc":             {"apt", "cron.d", "default", "hostname", "hosts", "init.d", "nginx", "os-release", "passwd", "resolv.conf", "shadow", "ssh", "ssl", "sudoers", "systemd"},
			"/etc/nginx":       {"nginx.conf", "sites-available", "sites-enabled", "conf.d"},
			"/proc":            {"cpuinfo", "meminfo", "version", "uptime", "loadavg", "stat", "net"},
			"/usr":             {"bin", "include", "lib", "local", "sbin", "share"},
			"/usr/local":       {"bin", "lib", "share"},
			"/usr/local/bin":   {"ollama", "docker-compose"},
		},
		Network: NetworkConfig{
			Interface: "eth0",
			MAC:       "02:42:ac:11:00:02",
			IP:        "10.0.1.100",
			Netmask:   "255.255.255.0",
			Broadcast: "10.0.1.255",
			Gateway:   "10.0.1.1",
		},
		Listeners: []Listener{
			{Proto: "tcp", Local: "0.0.0.0:22", PID: 587, Program: "sshd"},
			{Proto: "tcp", Local: "0.0.0.0:80", PID: 1105, Program: "nginx"},
			{Proto: "tcp", Local: "0.0.0.0:443", PID: 1105, Program: "nginx"},
			{Proto: "tcp", Local: "127.0.0.1:3000", PID: 1247, Program: "node"},
			{Proto: "tcp", Local: "127.0.0.1:5432", PID: 1389, Program: "postgres"},
			{Proto: "tcp", Local: "0.0.0.0:11434", PID: 1502, Program: "ollama"},
			{Proto: "tcp6", Local: ":::2222", PID: 587, Program: "sshd"},
		},
	}
}

// MergeConfig merges YAML overrides into the default persona.
// Maps are merged (YAML values override defaults). Slices replace if non-empty.
// Strings override if non-empty.
func MergeConfig(defaults *Persona, cfg parser.ShellEmulator) *Persona {
	p := *defaults

	if cfg.Hostname != "" {
		p.Hostname = cfg.Hostname
	}
	if cfg.Kernel != "" {
		p.Kernel = cfg.Kernel
	}
	if cfg.OS != "" {
		p.OS = cfg.OS
	}
	if cfg.IP != "" {
		p.IP = cfg.IP
		p.Network.IP = cfg.IP
	}
	if cfg.User != "" {
		p.User = cfg.User
	}

	// Processes: replace entirely if provided
	if len(cfg.Processes) > 0 {
		p.Processes = make([]Process, len(cfg.Processes))
		for i, cp := range cfg.Processes {
			p.Processes[i] = Process{
				PID:  cp.PID,
				User: cp.User,
				CPU:  cp.CPU,
				Mem:  cp.Mem,
				VSZ:  cp.VSZ,
				RSS:  cp.RSS,
				Cmd:  cp.Cmd,
				Stat: cp.Stat,
				Time: cp.Time,
			}
		}
	}

	// EnvVars: merge (YAML overrides defaults)
	if len(cfg.EnvVars) > 0 {
		merged := make(map[string]string, len(p.EnvVars)+len(cfg.EnvVars))
		for k, v := range p.EnvVars {
			merged[k] = v
		}
		for k, v := range cfg.EnvVars {
			merged[k] = v
		}
		p.EnvVars = merged
	}

	// Lures: merge (YAML overrides defaults)
	if len(cfg.Lures) > 0 {
		merged := make(map[string]string, len(p.Lures)+len(cfg.Lures))
		for k, v := range p.Lures {
			merged[k] = v
		}
		for k, v := range cfg.Lures {
			merged[k] = v
		}
		p.Lures = merged
	}

	// Filesystem: merge (YAML overrides defaults)
	if len(cfg.Filesystem) > 0 {
		merged := make(map[string][]string, len(p.Filesystem)+len(cfg.Filesystem))
		for k, v := range p.Filesystem {
			merged[k] = v
		}
		for k, v := range cfg.Filesystem {
			merged[k] = v
		}
		p.Filesystem = merged
	}

	return &p
}
