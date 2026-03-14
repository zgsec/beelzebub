package shellemulator

import (
	"fmt"
	"hash/fnv"
	"math/rand"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mariocandela/beelzebub/v3/parser"
)

// Session tracks per-connection state.
type Session struct {
	User        string
	CWD         string
	CmdCount    int
	PIDOffset   int                // random 0-200, shifts non-system PIDs per session
	ShellPID    int                // unique shell PID per session
	LoginTime   time.Time          // when session started
	FileOverlay map[string]string  // path → content (written files)
	DirOverlay  map[string][]string // dir → additional entries
	Deleted     map[string]bool    // path → true (rm'd files)
}

// initOverlays ensures overlay maps are allocated.
func (s *Session) initOverlays() {
	if s.FileOverlay == nil {
		s.FileOverlay = make(map[string]string)
	}
	if s.DirOverlay == nil {
		s.DirOverlay = make(map[string][]string)
	}
	if s.Deleted == nil {
		s.Deleted = make(map[string]bool)
	}
}

// Emulator dispatches shell commands against a persona.
type Emulator struct {
	persona  *Persona
	handlers map[string]handlerFunc
	jitter   map[string]string // command → jitter category
}

type handlerFunc func(args []string, sess *Session) string

// jitter categories with min/max milliseconds
var jitterRanges = map[string][2]int{
	"identity": {1, 5},
	"memory":   {2, 10},
	"fs":       {3, 25},
	"network":  {5, 30},
}

// Compiled regexes for redirect parsing.
var (
	redirectAppendRe    = regexp.MustCompile(`^(.+?)\s*>>\s*(.+)$`)
	redirectOverwriteRe = regexp.MustCompile(`^(.+?)\s*>\s*(.+)$`)
)

// cmdNoop is a named no-op handler for commands that need no output.
func (*Emulator) cmdNoop(args []string, sess *Session) string { return "" }

// cmdDef associates a handler method with a jitter category.
type cmdDef struct {
	handler  func(*Emulator, []string, *Session) string
	category string
}

// commandTable declares all supported commands declaratively.
var commandTable = map[string]cmdDef{
	// Identity/system
	"whoami":   {(*Emulator).cmdWhoami, "identity"},
	"id":       {(*Emulator).cmdID, "identity"},
	"hostname": {(*Emulator).cmdHostname, "identity"},
	"uname":    {(*Emulator).cmdUname, "identity"},
	"uptime":   {(*Emulator).cmdUptime, "identity"},
	"w":        {(*Emulator).cmdW, "identity"},
	"who":      {(*Emulator).cmdWho, "identity"},
	"last":     {(*Emulator).cmdLast, "identity"},
	"date":     {(*Emulator).cmdDate, "identity"},

	// Filesystem
	"pwd":  {(*Emulator).cmdPwd, "fs"},
	"cd":   {(*Emulator).cmdCd, "fs"},
	"ls":   {(*Emulator).cmdLs, "fs"},
	"cat":  {(*Emulator).cmdCat, "fs"},
	"find": {(*Emulator).cmdFind, "fs"},
	"file": {(*Emulator).cmdFile, "fs"},
	"df":   {(*Emulator).cmdDf, "fs"},
	"mount": {(*Emulator).cmdMount, "fs"},
	"du":   {(*Emulator).cmdDu, "fs"},
	"stat": {(*Emulator).cmdStat, "fs"},
	"wc":   {(*Emulator).cmdWc, "fs"},
	"head": {(*Emulator).cmdHead, "fs"},
	"tail": {(*Emulator).cmdTail, "fs"},

	// Network
	"ifconfig": {(*Emulator).cmdIfconfig, "network"},
	"ip":       {(*Emulator).cmdIP, "network"},
	"netstat":  {(*Emulator).cmdNetstat, "network"},
	"ss":       {(*Emulator).cmdSS, "network"},
	"ping":     {(*Emulator).cmdPing, "network"},
	"dig":      {(*Emulator).cmdDig, "network"},
	"nslookup": {(*Emulator).cmdNslookup, "network"},

	// Process/resource
	"ps":        {(*Emulator).cmdPs, "memory"},
	"free":      {(*Emulator).cmdFree, "memory"},
	"top":       {(*Emulator).cmdTop, "memory"},
	"docker":    {(*Emulator).cmdDocker, "memory"},
	"systemctl": {(*Emulator).cmdSystemctl, "memory"},
	"service":   {(*Emulator).cmdService, "memory"},
	"lsof":      {(*Emulator).cmdLsof, "memory"},
	"kill":      {(*Emulator).cmdKill, "memory"},

	// Credential lures
	"env":      {(*Emulator).cmdEnv, "memory"},
	"printenv": {(*Emulator).cmdEnv, "memory"},
	"history":  {(*Emulator).cmdHistory, "memory"},
	"set":      {(*Emulator).cmdEnv, "memory"},

	// Utility
	"echo":    {(*Emulator).cmdEcho, "identity"},
	"which":   {(*Emulator).cmdWhich, "identity"},
	"type":    {(*Emulator).cmdType, "identity"},
	"command": {(*Emulator).cmdCommand, "identity"},
	"grep":    {(*Emulator).cmdGrep, "identity"},
	"export":  {(*Emulator).cmdExport, "identity"},
	"alias":   {(*Emulator).cmdAlias, "identity"},
	"unset":   {(*Emulator).cmdUnset, "identity"},

	// No-ops
	"true":   {(*Emulator).cmdNoop, "identity"},
	"false":  {(*Emulator).cmdNoop, "identity"},
	"clear":  {(*Emulator).cmdNoop, "identity"},
	"reset":  {(*Emulator).cmdNoop, "identity"},
	"logout": {(*Emulator).cmdNoop, "identity"},
	"exit":   {(*Emulator).cmdNoop, "identity"},

	// Destructive (with session overlay support)
	"rm":    {(*Emulator).cmdRm, "fs"},
	"mkdir": {(*Emulator).cmdMkdir, "fs"},
	"touch": {(*Emulator).cmdTouch, "fs"},
	"cp":    {(*Emulator).cmdCp, "fs"},
	"mv":    {(*Emulator).cmdNoop, "fs"},
	"chmod": {(*Emulator).cmdNoop, "fs"},
	"chown": {(*Emulator).cmdNoop, "fs"},
}

// NewEmulator creates an emulator from config, merging with defaults.
func NewEmulator(cfg parser.ShellEmulator) *Emulator {
	p := MergeConfig(DefaultPersona(), cfg)

	// Resolve canary tokens and substitute into persona
	tokens := resolveTokens(cfg.CanaryTokens)
	for path, content := range p.Lures {
		p.Lures[path] = substituteTokens(content, tokens)
	}
	for key, val := range p.EnvVars {
		p.EnvVars[key] = substituteTokens(val, tokens)
	}

	// Set BootTime from config UptimeDays (default 23)
	uptimeDays := cfg.UptimeDays
	if uptimeDays <= 0 {
		uptimeDays = 23
	}
	p.BootTime = time.Now().Add(-time.Duration(uptimeDays) * 24 * time.Hour)

	// Add /proc/<pid>/ entries for each process
	var procPIDs []string
	for _, proc := range p.Processes {
		pidStr := strconv.Itoa(proc.PID)
		procPIDs = append(procPIDs, pidStr)
		p.Filesystem["/proc/"+pidStr] = []string{"cmdline", "cwd", "environ", "exe", "fd", "maps", "root", "stat", "status"}
	}
	// Add PID dirs to /proc listing
	if existing, ok := p.Filesystem["/proc"]; ok {
		p.Filesystem["/proc"] = append(existing, procPIDs...)
	}

	// Update /etc/hosts to include actual hostname
	if hosts, ok := p.Lures["/etc/hosts"]; ok {
		p.Lures["/etc/hosts"] = strings.ReplaceAll(hosts, "prod-web-01", p.Hostname)
	}

	e := &Emulator{persona: p}

	e.handlers = make(map[string]handlerFunc, len(commandTable))
	e.jitter = make(map[string]string, len(commandTable))
	for name, def := range commandTable {
		method := def.handler
		e.handlers[name] = func(args []string, sess *Session) string {
			return method(e, args, sess)
		}
		e.jitter[name] = def.category
	}

	return e
}

// Execute tries to handle the command. Returns (output, true) if handled,
// or ("", false) to fall through to LLM.
func (e *Emulator) Execute(cmd string, sess *Session) (string, bool) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "", true
	}

	sess.CmdCount++
	sess.initOverlays()

	// Handle output redirects: echo "x" > file / echo "x" >> file
	if output, redirected := e.handleRedirect(cmd, sess); redirected {
		return output, true
	}

	// Handle pipes: execute only the first command, apply simple pipe filters
	if strings.Contains(cmd, "|") {
		return e.executePipedWithJitter(cmd, sess)
	}

	base, args := parseCommand(cmd)
	handler, ok := e.handlers[base]
	if !ok {
		return "", false
	}

	output := handler(args, sess)
	e.applyJitter(base)
	return output, true
}

// handleRedirect parses "cmd > file" and "cmd >> file" patterns.
func (e *Emulator) handleRedirect(cmd string, sess *Session) (string, bool) {
	// Match >> (append) first, then > (overwrite)
	var cmdPart, filePart string
	var appendMode bool

	if m := redirectAppendRe.FindStringSubmatch(cmd); m != nil {
		cmdPart = strings.TrimSpace(m[1])
		filePart = strings.TrimSpace(m[2])
		appendMode = true
	} else if m := redirectOverwriteRe.FindStringSubmatch(cmd); m != nil {
		cmdPart = strings.TrimSpace(m[1])
		filePart = strings.TrimSpace(m[2])
		appendMode = false
	} else {
		return "", false
	}

	filePath := resolvePath(filePart, sess.CWD)

	// Execute the command part to get output
	base, args := parseCommand(cmdPart)
	handler, ok := e.handlers[base]
	var output string
	if ok {
		output = handler(args, sess)
	} else {
		// For things like echo "test" > file, produce inline
		output = cmdPart
	}

	// Write to overlay
	if appendMode {
		if existing, ok := sess.FileOverlay[filePath]; ok {
			sess.FileOverlay[filePath] = existing + "\n" + output
		} else {
			sess.FileOverlay[filePath] = output
		}
	} else {
		sess.FileOverlay[filePath] = output
	}

	// Add to parent dir overlay
	dir := path.Dir(filePath)
	base2 := path.Base(filePath)
	sess.DirOverlay[dir] = appendUnique(sess.DirOverlay[dir], base2)
	delete(sess.Deleted, filePath)

	e.applyJitter("echo")
	return "", true
}

// executePipedWithJitter handles pipe chains and applies jitter.
func (e *Emulator) executePipedWithJitter(cmd string, sess *Session) (string, bool) {
	output, handled := e.executePiped(cmd, sess)
	if handled {
		// Use jitter category of the first command
		base, _ := parseCommand(strings.TrimSpace(strings.Split(cmd, "|")[0]))
		e.applyJitter(base)
	}
	return output, handled
}

// applyJitter sleeps a small random duration to simulate real I/O latency.
func (e *Emulator) applyJitter(cmd string) {
	cat, ok := e.jitter[cmd]
	if !ok {
		cat = "identity"
	}
	bounds, ok := jitterRanges[cat]
	if !ok {
		return
	}
	ms := bounds[0] + rand.Intn(bounds[1]-bounds[0]+1)
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

// executePiped handles simple pipe chains.
func (e *Emulator) executePiped(cmd string, sess *Session) (string, bool) {
	parts := strings.Split(cmd, "|")
	if len(parts) < 2 {
		return "", false
	}

	// Execute first command
	firstCmd := strings.TrimSpace(parts[0])
	base, args := parseCommand(firstCmd)
	handler, ok := e.handlers[base]
	if !ok {
		return "", false
	}
	output := handler(args, sess)

	// Apply pipe filters
	for _, pipePart := range parts[1:] {
		pipePart = strings.TrimSpace(pipePart)
		pipeBase, pipeArgs := parseCommand(pipePart)
		switch pipeBase {
		case "head":
			n := 10
			if len(pipeArgs) > 0 && strings.HasPrefix(pipeArgs[0], "-") {
				fmt.Sscanf(pipeArgs[0], "-%d", &n)
			}
			lines := strings.Split(output, "\n")
			if n < len(lines) {
				lines = lines[:n]
			}
			output = strings.Join(lines, "\n")
		case "tail":
			n := 10
			if len(pipeArgs) > 0 && strings.HasPrefix(pipeArgs[0], "-") {
				fmt.Sscanf(pipeArgs[0], "-%d", &n)
			}
			lines := strings.Split(output, "\n")
			if n < len(lines) {
				lines = lines[len(lines)-n:]
			}
			output = strings.Join(lines, "\n")
		case "grep":
			if len(pipeArgs) == 0 {
				continue
			}
			pattern := pipeArgs[0]
			invert := false
			if pattern == "-v" && len(pipeArgs) > 1 {
				invert = true
				pattern = pipeArgs[1]
			}
			lines := strings.Split(output, "\n")
			var filtered []string
			for _, line := range lines {
				match := strings.Contains(line, pattern)
				if invert {
					match = !match
				}
				if match {
					filtered = append(filtered, line)
				}
			}
			output = strings.Join(filtered, "\n")
		case "wc":
			if len(pipeArgs) > 0 && pipeArgs[0] == "-l" {
				count := len(strings.Split(output, "\n"))
				if output == "" {
					count = 0
				}
				output = fmt.Sprintf("%d", count)
			}
		case "sort":
			lines := strings.Split(output, "\n")
			sort.Strings(lines)
			output = strings.Join(lines, "\n")
		default:
			// Unknown pipe filter — fall through to LLM for the whole command
			return "", false
		}
	}

	return output, true
}

// BuildPromptContext serializes the world state for injection into LLM system prompt.
func (e *Emulator) BuildPromptContext() string {
	p := e.persona
	var b strings.Builder

	b.WriteString(fmt.Sprintf("SYSTEM: %s | %s | %s x86_64 | %s/24\n", p.Hostname, p.OS, p.Kernel, p.IP))

	// Processes summary
	var procs []string
	for _, proc := range p.Processes {
		// Extract base name
		name := proc.Cmd
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
		if idx := strings.Index(name, " "); idx >= 0 {
			name = name[:idx]
		}
		procs = append(procs, name)
	}
	b.WriteString(fmt.Sprintf("PROCESSES: %s\n", strings.Join(procs, " ")))

	// Listeners
	var listeners []string
	for _, l := range p.Listeners {
		listeners = append(listeners, fmt.Sprintf("%s(%s)", l.Program, l.Local))
	}
	b.WriteString(fmt.Sprintf("LISTENERS: %s\n", strings.Join(listeners, " ")))

	// Env vars (selected)
	var envParts []string
	for k, v := range p.EnvVars {
		if k == "PATH" || k == "HOME" || k == "SHELL" || k == "LANG" || k == "TERM" || k == "LOGNAME" || k == "USER" {
			continue
		}
		envParts = append(envParts, fmt.Sprintf("%s=%s", k, v))
	}
	sort.Strings(envParts)
	b.WriteString(fmt.Sprintf("ENV: %s\n", strings.Join(envParts, " ")))

	// Lure files
	var lureFiles []string
	for path := range p.Lures {
		lureFiles = append(lureFiles, path)
	}
	sort.Strings(lureFiles)
	b.WriteString(fmt.Sprintf("FILES: %s\n", strings.Join(lureFiles, " ")))

	// Users from /etc/passwd
	b.WriteString(fmt.Sprintf("USERS: %s(uid=0) ubuntu(uid=1000) www-data(uid=33) postgres(uid=113) sshd(uid=110)\n", p.User))

	return b.String()
}

// parseCommand splits a command string into base command and arguments.
func parseCommand(cmd string) (string, []string) {
	// Handle semicolons — only process first command
	if idx := strings.Index(cmd, ";"); idx >= 0 {
		cmd = cmd[:idx]
	}

	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return "", nil
	}
	return fields[0], fields[1:]
}

// resolvePath resolves a relative path against the session CWD.
func resolvePath(p string, cwd string) string {
	if p == "" {
		return cwd
	}
	if strings.HasPrefix(p, "/") {
		return path.Clean(p)
	}
	if p == "~" || strings.HasPrefix(p, "~/") {
		return path.Clean("/root" + p[1:])
	}
	return path.Clean(cwd + "/" + p)
}

// appendUnique adds an entry to a slice if not already present.
func appendUnique(slice []string, entry string) []string {
	for _, s := range slice {
		if s == entry {
			return slice
		}
	}
	return append(slice, entry)
}

// --- Temporal helpers ---

// formatUptime formats a duration as Linux uptime output.
func formatUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%d days, %2d:%02d", days, hours, mins)
	}
	return fmt.Sprintf("%2d:%02d", hours, mins)
}

// randomTimeBetween returns a deterministic-looking random time between start and end,
// seeded by the entry name for per-entry consistency within a session.
func randomTimeBetween(start, end time.Time, seed string) time.Time {
	if end.Before(start) {
		return start
	}
	h := fnv.New64a()
	h.Write([]byte(seed))
	delta := end.Sub(start)
	offset := time.Duration(h.Sum64() % uint64(delta))
	return start.Add(offset)
}

// formatLsTimestamp formats a time like ls -la does: "Jan 10 12:00" or "Jan 10  2023" for old files.
func formatLsTimestamp(t time.Time) string {
	now := time.Now()
	sixMonthsAgo := now.AddDate(0, -6, 0)
	if t.Before(sixMonthsAgo) {
		return t.Format("Jan _2  2006")
	}
	return t.Format("Jan _2 15:04")
}

// formatPsStart formats a time like ps START column: "Jan10" or "14:22".
func formatPsStart(t time.Time, boot time.Time) string {
	now := time.Now()
	if now.Sub(t) > 24*time.Hour {
		return t.Format("Jan02")
	}
	return t.Format("15:04")
}

// sessionPID applies the per-session PID offset to non-system PIDs.
func sessionPID(pid int, sess *Session) int {
	if pid <= 100 {
		return pid // system PIDs stay fixed
	}
	return pid + sess.PIDOffset
}

// --- Identity/system commands ---

func (e *Emulator) cmdWhoami(args []string, sess *Session) string {
	return e.persona.User
}

func (e *Emulator) cmdID(args []string, sess *Session) string {
	if e.persona.User == "root" {
		return "uid=0(root) gid=0(root) groups=0(root)"
	}
	return fmt.Sprintf("uid=1000(%s) gid=1000(%s) groups=1000(%s)", e.persona.User, e.persona.User, e.persona.User)
}

func (e *Emulator) cmdHostname(args []string, sess *Session) string {
	return e.persona.Hostname
}

func (e *Emulator) cmdUname(args []string, sess *Session) string {
	if len(args) == 0 {
		return "Linux"
	}
	flag := strings.Join(args, " ")
	switch flag {
	case "-a":
		buildDate := e.persona.BootTime.Add(-30 * 24 * time.Hour).Format("Mon Jan _2 15:04:05 UTC 2006")
		return fmt.Sprintf("Linux %s %s #101-Ubuntu SMP %s x86_64 x86_64 x86_64 GNU/Linux", e.persona.Hostname, e.persona.Kernel, buildDate)
	case "-r":
		return e.persona.Kernel
	case "-m":
		return "x86_64"
	case "-n":
		return e.persona.Hostname
	case "-s":
		return "Linux"
	case "-v":
		buildDate := e.persona.BootTime.Add(-30 * 24 * time.Hour).Format("Mon Jan _2 15:04:05 UTC 2006")
		return fmt.Sprintf("#101-Ubuntu SMP %s", buildDate)
	default:
		return "Linux"
	}
}

func (e *Emulator) cmdUptime(args []string, sess *Session) string {
	now := time.Now()
	up := now.Sub(e.persona.BootTime)
	uptimeStr := formatUptime(up)
	nowStr := now.Format("15:04:05")

	if len(args) > 0 && args[0] == "-p" {
		days := int(up.Hours()) / 24
		hours := int(up.Hours()) % 24
		mins := int(up.Minutes()) % 60
		return fmt.Sprintf("up %d days, %d hours, %d minutes", days, hours, mins)
	}
	// Vary load average slightly based on time
	load1 := 0.30 + float64(now.Second()%20)/100.0
	load5 := 0.35 + float64(now.Minute()%15)/100.0
	load15 := 0.28 + float64(now.Hour()%10)/100.0
	return fmt.Sprintf(" %s up %s,  1 user,  load average: %.2f, %.2f, %.2f",
		nowStr, uptimeStr, load1, load5, load15)
}

func (e *Emulator) cmdW(args []string, sess *Session) string {
	now := time.Now()
	up := now.Sub(e.persona.BootTime)
	uptimeStr := formatUptime(up)
	nowStr := now.Format("15:04:05")
	load1 := 0.30 + float64(now.Second()%20)/100.0
	load5 := 0.35 + float64(now.Minute()%15)/100.0
	load15 := 0.28 + float64(now.Hour()%10)/100.0

	loginTime := sess.LoginTime
	if loginTime.IsZero() {
		loginTime = now.Add(-5 * time.Minute)
	}

	return fmt.Sprintf(" %s up %s,  1 user,  load average: %.2f, %.2f, %.2f\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n%s     pts/0    10.0.1.1         %s    0.00s  0.01s  0.00s w",
		nowStr, uptimeStr, load1, load5, load15, e.persona.User, loginTime.Format("15:04"))
}

func (e *Emulator) cmdWho(args []string, sess *Session) string {
	loginTime := sess.LoginTime
	if loginTime.IsZero() {
		loginTime = time.Now().Add(-5 * time.Minute)
	}
	return fmt.Sprintf("%s     pts/0        %s (10.0.1.1)", e.persona.User, loginTime.Format("2006-01-02 15:04"))
}

func (e *Emulator) cmdLast(args []string, sess *Session) string {
	now := time.Now()
	boot := e.persona.BootTime
	user := e.persona.User

	// Generate realistic login history spread backwards from now
	login1 := sess.LoginTime
	if login1.IsZero() {
		login1 = now.Add(-5 * time.Minute)
	}
	login2Start := boot.Add(time.Duration(rand.Intn(int(now.Sub(boot).Hours())+1)) * time.Hour)
	login2End := login2Start.Add(3*time.Hour + 22*time.Minute)
	login3Start := boot.Add(time.Duration(rand.Intn(int(now.Sub(boot).Hours())+1)) * time.Hour)
	login3End := login3Start.Add(1*time.Hour + 44*time.Minute)

	lines := []string{
		fmt.Sprintf("%s     pts/0        10.0.1.1         %s   still logged in", user, login1.Format("Mon Jan _2 15:04")),
		fmt.Sprintf("%s     pts/0        10.0.1.1         %s - %s  (03:22)", user, login2Start.Format("Mon Jan _2 15:04"), login2End.Format("15:04")),
		fmt.Sprintf("%s     pts/1        10.0.1.5         %s - %s  (01:44)", user, login3Start.Format("Mon Jan _2 15:04"), login3End.Format("15:04")),
		fmt.Sprintf("reboot   system boot  %s %s   still running", e.persona.Kernel, boot.Format("Mon Jan _2 15:04")),
		"",
		fmt.Sprintf("wtmp begins %s", boot.Format("Mon Jan _2 15:04:05 2006")),
	}
	return strings.Join(lines, "\n")
}

func (e *Emulator) cmdDate(args []string, sess *Session) string {
	return time.Now().UTC().Format("Mon Jan  2 15:04:05 UTC 2006")
}

// --- Filesystem commands ---

func (e *Emulator) cmdPwd(args []string, sess *Session) string {
	return sess.CWD
}

func (e *Emulator) cmdCd(args []string, sess *Session) string {
	if len(args) == 0 || args[0] == "~" {
		sess.CWD = "/root"
		return ""
	}
	target := resolvePath(args[0], sess.CWD)

	// Check real filesystem
	if _, ok := e.persona.Filesystem[target]; ok {
		sess.CWD = target
		return ""
	}
	// Check overlay dirs
	if _, ok := sess.DirOverlay[target]; ok {
		sess.CWD = target
		return ""
	}
	if target == "/" {
		sess.CWD = "/"
		return ""
	}
	return fmt.Sprintf("bash: cd: %s: No such file or directory", args[0])
}

func (e *Emulator) cmdLs(args []string, sess *Session) string {
	long := false
	all := false
	human := false
	var targetPath string

	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			if strings.Contains(arg, "l") {
				long = true
			}
			if strings.Contains(arg, "a") {
				all = true
			}
			if strings.Contains(arg, "h") {
				human = true
			}
		} else {
			targetPath = arg
		}
	}

	dir := sess.CWD
	if targetPath != "" {
		dir = resolvePath(targetPath, sess.CWD)
	}

	// Handle /proc/<pid>/ paths
	if strings.HasPrefix(dir, "/proc/") {
		parts := strings.SplitN(strings.TrimPrefix(dir, "/proc/"), "/", 2)
		if pid, err := strconv.Atoi(parts[0]); err == nil && len(parts) == 1 {
			// Find the process (accounting for PID offset)
			for _, proc := range e.persona.Processes {
				if sessionPID(proc.PID, sess) == pid || proc.PID == pid {
					entries := []string{"cmdline", "cwd", "environ", "exe", "fd", "maps", "root", "stat", "status"}
					if long {
						var lines []string
						lines = append(lines, fmt.Sprintf("total %d", len(entries)*4))
						for _, entry := range entries {
							lines = append(lines, fmt.Sprintf("-r--r--r--  1 %s %s    0 %s %s", proc.User, proc.User, formatLsTimestamp(time.Now()), entry))
						}
						return strings.Join(lines, "\n")
					}
					return strings.Join(entries, "  ")
				}
			}
		}
	}

	entries, ok := e.persona.Filesystem[dir]
	if !ok {
		// Check overlay dirs
		if overlayEntries, ok := sess.DirOverlay[dir]; ok {
			entries = overlayEntries
		} else if _, isLure := e.persona.Lures[dir]; isLure {
			if long {
				ts := randomTimeBetween(e.persona.BootTime, time.Now(), path.Base(dir))
				return fmt.Sprintf("-rw-r--r-- 1 %s %s  %d %s %s", e.persona.User, e.persona.User, len(e.persona.Lures[dir]), formatLsTimestamp(ts), path.Base(dir))
			}
			return path.Base(dir)
		} else {
			return fmt.Sprintf("ls: cannot access '%s': No such file or directory", targetPath)
		}
	}

	// Merge overlay entries, exclude deleted
	if overlayEntries, ok := sess.DirOverlay[dir]; ok {
		for _, oe := range overlayEntries {
			entries = appendUnique(entries, oe)
		}
	}
	var filteredEntries []string
	for _, entry := range entries {
		entryPath := path.Join(dir, entry)
		if sess.Deleted[entryPath] {
			continue
		}
		filteredEntries = append(filteredEntries, entry)
	}
	entries = filteredEntries

	if !long {
		if all {
			entries = append([]string{".", ".."}, entries...)
		}
		return strings.Join(entries, "  ")
	}

	// Long format
	_ = human
	var lines []string
	lines = append(lines, fmt.Sprintf("total %d", len(entries)*4))
	if all {
		dirTs := randomTimeBetween(e.persona.BootTime, time.Now(), dir)
		lines = append(lines, fmt.Sprintf("drwxr-xr-x %2d %s %s 4096 %s .", len(entries)+2, e.persona.User, e.persona.User, formatLsTimestamp(dirTs)))
		lines = append(lines, fmt.Sprintf("drwxr-xr-x %2d %s %s 4096 %s ..", 4, e.persona.User, e.persona.User, formatLsTimestamp(dirTs)))
	}
	for _, entry := range entries {
		entryPath := path.Join(dir, entry)
		ts := randomTimeBetween(e.persona.BootTime, time.Now(), entryPath)
		tsStr := formatLsTimestamp(ts)

		if _, isDir := e.persona.Filesystem[entryPath]; isDir {
			lines = append(lines, fmt.Sprintf("drwxr-xr-x  2 %s %s 4096 %s %s", e.persona.User, e.persona.User, tsStr, entry))
		} else if content, isLure := e.persona.Lures[entryPath]; isLure {
			lines = append(lines, fmt.Sprintf("-rw-r--r--  1 %s %s %4d %s %s", e.persona.User, e.persona.User, len(content), tsStr, entry))
		} else if content, isOverlay := sess.FileOverlay[entryPath]; isOverlay {
			lines = append(lines, fmt.Sprintf("-rw-r--r--  1 %s %s %4d %s %s", e.persona.User, e.persona.User, len(content), formatLsTimestamp(time.Now()), entry))
		} else if strings.HasPrefix(entry, ".") {
			lines = append(lines, fmt.Sprintf("-rw-------  1 %s %s  256 %s %s", e.persona.User, e.persona.User, tsStr, entry))
		} else {
			lines = append(lines, fmt.Sprintf("-rw-r--r--  1 %s %s  512 %s %s", e.persona.User, e.persona.User, tsStr, entry))
		}
	}
	return strings.Join(lines, "\n")
}

func (e *Emulator) cmdCat(args []string, sess *Session) string {
	if len(args) == 0 {
		return ""
	}

	var outputs []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		filePath := resolvePath(arg, sess.CWD)

		// Check session overlay first (mutable FS)
		if content, ok := sess.FileOverlay[filePath]; ok {
			outputs = append(outputs, content)
			continue
		}

		// Check if deleted
		if sess.Deleted[filePath] {
			outputs = append(outputs, fmt.Sprintf("cat: %s: No such file or directory", filePath))
			continue
		}

		// Check lures
		if content, ok := e.persona.Lures[filePath]; ok {
			outputs = append(outputs, content)
			continue
		}

		// /proc/<pid>/cmdline and /proc/<pid>/status
		if strings.HasPrefix(filePath, "/proc/") {
			if out, ok := e.handleProcCat(filePath, sess); ok {
				outputs = append(outputs, out)
				continue
			}
		}

		// Generated files
		switch filePath {
		case "/etc/os-release":
			outputs = append(outputs, e.genOSRelease())
		case "/etc/hostname":
			outputs = append(outputs, e.persona.Hostname)
		case "/etc/resolv.conf":
			outputs = append(outputs, fmt.Sprintf("nameserver 10.0.1.1\nnameserver 8.8.8.8\nsearch %s.internal", e.persona.Hostname))
		case "/proc/cpuinfo":
			outputs = append(outputs, e.genCPUInfo())
		case "/proc/meminfo":
			outputs = append(outputs, e.genMemInfo())
		case "/proc/version":
			outputs = append(outputs, fmt.Sprintf("Linux version %s (buildd@lcy02-amd64-037) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023", e.persona.Kernel))
		case "/etc/shadow", "/etc/sudoers":
			outputs = append(outputs, fmt.Sprintf("cat: %s: Permission denied", filePath))
		default:
			outputs = append(outputs, fmt.Sprintf("cat: %s: No such file or directory", filePath))
		}
	}
	return strings.Join(outputs, "\n")
}

// handleProcCat handles cat /proc/<pid>/cmdline and /proc/<pid>/status.
func (e *Emulator) handleProcCat(filePath string, sess *Session) (string, bool) {
	// Parse /proc/<pid>/<entry>
	parts := strings.SplitN(strings.TrimPrefix(filePath, "/proc/"), "/", 2)
	if len(parts) != 2 {
		return "", false
	}
	pid, err := strconv.Atoi(parts[0])
	if err != nil {
		return "", false
	}
	entry := parts[1]

	// Find process matching this PID (check with offset or raw)
	for _, proc := range e.persona.Processes {
		if sessionPID(proc.PID, sess) == pid || proc.PID == pid {
			switch entry {
			case "cmdline":
				// Real Linux uses null bytes; cat shows them concatenated
				return strings.ReplaceAll(proc.Cmd, " ", "\x00"), true
			case "status":
				baseName := proc.Cmd
				if idx := strings.LastIndex(baseName, "/"); idx >= 0 {
					baseName = baseName[idx+1:]
				}
				if idx := strings.Index(baseName, " "); idx >= 0 {
					baseName = baseName[:idx]
				}
				uid := "0"
				if proc.User != "root" {
					uid = "1000"
				}
				return fmt.Sprintf("Name:\t%s\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t%d\nPid:\t%d\nPPid:\t1\nUid:\t%s\t%s\t%s\t%s\nGid:\t%s\t%s\t%s\t%s\nThreads:\t1\nVmPeak:\t%s\nVmSize:\t%s\nVmRSS:\t%s",
					baseName, pid, pid, uid, uid, uid, uid, uid, uid, uid, uid, proc.VSZ, proc.VSZ, proc.RSS), true
			case "environ":
				return fmt.Sprintf("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\x00HOME=/root\x00LANG=en_US.UTF-8"), true
			default:
				return "", false
			}
		}
	}
	return "", false
}

func (e *Emulator) cmdFind(args []string, sess *Session) string {
	searchDir := "."
	var namePattern string
	onlyType := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-name":
			if i+1 < len(args) {
				namePattern = args[i+1]
				i++
			}
		case "-type":
			if i+1 < len(args) {
				onlyType = args[i+1]
				i++
			}
		default:
			if !strings.HasPrefix(args[i], "-") {
				searchDir = args[i]
			}
		}
	}

	rootDir := resolvePath(searchDir, sess.CWD)
	var results []string

	for dir, entries := range e.persona.Filesystem {
		if !strings.HasPrefix(dir, rootDir) && dir != rootDir {
			continue
		}
		if onlyType != "f" {
			// Include the directory itself
			if dir != rootDir {
				results = append(results, dir)
			}
		}
		if onlyType != "d" {
			for _, entry := range entries {
				entryPath := path.Join(dir, entry)
				if namePattern != "" {
					// Simple glob: only support *pattern* style
					pattern := strings.ReplaceAll(namePattern, "*", "")
					if !strings.Contains(entry, pattern) {
						continue
					}
				}
				// Skip if it's a known directory
				if _, isDir := e.persona.Filesystem[entryPath]; isDir && onlyType == "f" {
					continue
				}
				results = append(results, entryPath)
			}
		}
	}

	// Include overlay entries
	for dir, entries := range sess.DirOverlay {
		if !strings.HasPrefix(dir, rootDir) && dir != rootDir {
			continue
		}
		for _, entry := range entries {
			entryPath := path.Join(dir, entry)
			if !sess.Deleted[entryPath] {
				results = appendUnique(results, entryPath)
			}
		}
	}

	sort.Strings(results)
	if len(results) == 0 {
		return ""
	}
	return strings.Join(results, "\n")
}

func (e *Emulator) cmdFile(args []string, sess *Session) string {
	if len(args) == 0 {
		return "Usage: file [-bchiklLNnprsvzZ0] [--apple] [--extension] [--mime-encoding] [--mime-type] [-e testname] [-F separator] [-f namefile] [-m magicfiles] [-P name=value] file ..."
	}
	filePath := resolvePath(args[0], sess.CWD)
	if _, ok := sess.FileOverlay[filePath]; ok {
		return fmt.Sprintf("%s: ASCII text", args[0])
	}
	if _, ok := e.persona.Lures[filePath]; ok {
		return fmt.Sprintf("%s: ASCII text", args[0])
	}
	if _, ok := e.persona.Filesystem[filePath]; ok {
		return fmt.Sprintf("%s: directory", args[0])
	}
	return fmt.Sprintf("%s: cannot open `%s' (No such file or directory)", args[0], args[0])
}

func (e *Emulator) cmdDf(args []string, sess *Session) string {
	human := false
	for _, a := range args {
		if strings.Contains(a, "h") {
			human = true
		}
	}
	if human {
		return `Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        50G   18G   30G  38% /
tmpfs           2.0G     0  2.0G   0% /dev/shm
/dev/sda15      105M  6.1M   99M   6% /boot/efi
overlay          50G   18G   30G  38% /var/lib/docker/overlay2`
	}
	return `Filesystem     1K-blocks    Used Available Use% Mounted on
/dev/sda1       51474044 18247832  30587548  38% /
tmpfs            2014208        0   2014208   0% /dev/shm
/dev/sda15        106858     6186    100672   6% /boot/efi`
}

func (e *Emulator) cmdMount(args []string, sess *Session) string {
	return `/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)
/dev/sda15 on /boot/efi type vfat (rw,relatime,fmask=0077,dmask=0077)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)
overlay on /var/lib/docker/overlay2 type overlay (rw,relatime)`
}

func (e *Emulator) cmdDu(args []string, sess *Session) string {
	if len(args) > 0 {
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				return fmt.Sprintf("4.2G\t%s", a)
			}
		}
	}
	return "4.2G\t."
}

func (e *Emulator) cmdStat(args []string, sess *Session) string {
	if len(args) == 0 {
		return "stat: missing operand"
	}
	target := args[len(args)-1]
	filePath := resolvePath(target, sess.CWD)
	boot := e.persona.BootTime
	ts := randomTimeBetween(boot, time.Now(), filePath)
	if _, ok := e.persona.Filesystem[filePath]; ok {
		return fmt.Sprintf("  File: %s\n  Size: 4096      \tBlocks: 8          IO Block: 4096   directory\nDevice: 801h/2049d\tInode: 262145      Links: 4\nAccess: (0755/drwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)\nAccess: %s\nModify: %s\nChange: %s\n Birth: %s",
			target, ts.Format("2006-01-02 15:04:05.000000000 -0700"), ts.Add(-48*time.Hour).Format("2006-01-02 15:04:05.000000000 -0700"),
			ts.Add(-48*time.Hour).Format("2006-01-02 15:04:05.000000000 -0700"), boot.Format("2006-01-02 15:04:05.000000000 -0700"))
	}
	if _, ok := e.persona.Lures[filePath]; ok {
		return fmt.Sprintf("  File: %s\n  Size: 512       \tBlocks: 8          IO Block: 4096   regular file\nDevice: 801h/2049d\tInode: 524289      Links: 1\nAccess: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)\nAccess: %s\nModify: %s\nChange: %s\n Birth: %s",
			target, ts.Format("2006-01-02 15:04:05.000000000 -0700"), ts.Add(-48*time.Hour).Format("2006-01-02 15:04:05.000000000 -0700"),
			ts.Add(-48*time.Hour).Format("2006-01-02 15:04:05.000000000 -0700"), boot.Format("2006-01-02 15:04:05.000000000 -0700"))
	}
	return fmt.Sprintf("stat: cannot statx '%s': No such file or directory", target)
}

func (e *Emulator) cmdWc(args []string, sess *Session) string {
	if len(args) == 0 {
		return ""
	}
	lineFlag := false
	var filePath string
	for _, a := range args {
		if a == "-l" {
			lineFlag = true
		} else if !strings.HasPrefix(a, "-") {
			filePath = a
		}
	}
	if filePath == "" {
		return ""
	}
	resolved := resolvePath(filePath, sess.CWD)
	// Check overlay first
	if content, ok := sess.FileOverlay[resolved]; ok {
		lines := strings.Count(content, "\n") + 1
		if lineFlag {
			return fmt.Sprintf("%d %s", lines, filePath)
		}
		words := len(strings.Fields(content))
		return fmt.Sprintf("  %d  %d %d %s", lines, words, len(content), filePath)
	}
	if content, ok := e.persona.Lures[resolved]; ok {
		lines := strings.Count(content, "\n") + 1
		if lineFlag {
			return fmt.Sprintf("%d %s", lines, filePath)
		}
		words := len(strings.Fields(content))
		return fmt.Sprintf("  %d  %d %d %s", lines, words, len(content), filePath)
	}
	return fmt.Sprintf("wc: %s: No such file or directory", filePath)
}

func (e *Emulator) cmdHead(args []string, sess *Session) string {
	n := 10
	var filePath string
	for i, a := range args {
		if strings.HasPrefix(a, "-n") {
			if a == "-n" && i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &n)
			} else {
				fmt.Sscanf(a, "-n%d", &n)
			}
		} else if strings.HasPrefix(a, "-") && a != "-n" {
			fmt.Sscanf(a, "-%d", &n)
		} else if !strings.HasPrefix(a, "-") {
			filePath = a
		}
	}
	if filePath == "" {
		return ""
	}
	resolved := resolvePath(filePath, sess.CWD)
	// Check overlay first
	content, ok := sess.FileOverlay[resolved]
	if !ok {
		content, ok = e.persona.Lures[resolved]
	}
	if ok {
		lines := strings.Split(content, "\n")
		if n < len(lines) {
			lines = lines[:n]
		}
		return strings.Join(lines, "\n")
	}
	return fmt.Sprintf("head: cannot open '%s' for reading: No such file or directory", filePath)
}

func (e *Emulator) cmdTail(args []string, sess *Session) string {
	n := 10
	var filePath string
	for i, a := range args {
		if strings.HasPrefix(a, "-n") {
			if a == "-n" && i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &n)
			} else {
				fmt.Sscanf(a, "-n%d", &n)
			}
		} else if strings.HasPrefix(a, "-") && a != "-f" && a != "-n" {
			fmt.Sscanf(a, "-%d", &n)
		} else if !strings.HasPrefix(a, "-") {
			filePath = a
		}
	}
	if filePath == "" {
		return ""
	}
	resolved := resolvePath(filePath, sess.CWD)
	content, ok := sess.FileOverlay[resolved]
	if !ok {
		content, ok = e.persona.Lures[resolved]
	}
	if ok {
		lines := strings.Split(content, "\n")
		if n < len(lines) {
			lines = lines[len(lines)-n:]
		}
		return strings.Join(lines, "\n")
	}
	return fmt.Sprintf("tail: cannot open '%s' for reading: No such file or directory", filePath)
}

// --- Network commands ---

func (e *Emulator) cmdIfconfig(args []string, sess *Session) string {
	n := e.persona.Network
	return fmt.Sprintf(`eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet %s  netmask %s  broadcast %s
        ether %s  txqueuelen 0  (Ethernet)
        RX packets 8421937  bytes 12847293847 (12.8 GB)
        TX packets 5928471  bytes 894728194 (894.7 MB)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 2847291  bytes 384729184 (384.7 MB)
        TX packets 2847291  bytes 384729184 (384.7 MB)`, n.IP, n.Netmask, n.Broadcast, n.MAC)
}

func (e *Emulator) cmdIP(args []string, sess *Session) string {
	n := e.persona.Network
	if len(args) == 0 {
		return "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n       ip addr | ip route | ip link"
	}
	switch args[0] {
	case "addr", "a", "address":
		return fmt.Sprintf(`1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether %s brd ff:ff:ff:ff:ff:ff
    inet %s/24 brd %s scope global eth0
       valid_lft forever preferred_lft forever`, n.MAC, n.IP, n.Broadcast)
	case "route", "r":
		return fmt.Sprintf("default via %s dev eth0 proto dhcp src %s metric 100\n%s/24 dev eth0 proto kernel scope link src %s", n.Gateway, n.IP, n.IP[:strings.LastIndex(n.IP, ".")+1]+"0", n.IP)
	case "link", "l":
		return fmt.Sprintf(`1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether %s brd ff:ff:ff:ff:ff:ff`, n.MAC)
	default:
		return "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }"
	}
}

func (e *Emulator) cmdNetstat(args []string, sess *Session) string {
	flagStr := strings.Join(args, " ")
	if strings.Contains(flagStr, "tulpn") || strings.Contains(flagStr, "tlnp") || strings.Contains(flagStr, "an") {
		var lines []string
		lines = append(lines, "Active Internet connections (only servers)")
		lines = append(lines, "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name")
		for _, l := range e.persona.Listeners {
			lines = append(lines, fmt.Sprintf("%-5s 0      0      %-23s 0.0.0.0:*               LISTEN      %d/%s", l.Proto, l.Local, sessionPID(l.PID, sess), l.Program))
		}
		return strings.Join(lines, "\n")
	}
	return "Active Internet connections (w/o servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State"
}

func (e *Emulator) cmdSS(args []string, sess *Session) string {
	flagStr := strings.Join(args, " ")
	if strings.Contains(flagStr, "tulpn") || strings.Contains(flagStr, "tlnp") {
		var lines []string
		lines = append(lines, "Netid  State   Recv-Q  Send-Q    Local Address:Port     Peer Address:Port  Process")
		for _, l := range e.persona.Listeners {
			parts := strings.SplitN(l.Local, ":", 2)
			addr, port := parts[0], parts[1]
			lines = append(lines, fmt.Sprintf("%-6s LISTEN  0       128       %15s:%-5s   0.0.0.0:*      users:((\"%s\",pid=%d,fd=3))", l.Proto[:3], addr, port, l.Program, sessionPID(l.PID, sess)))
		}
		return strings.Join(lines, "\n")
	}
	return "Netid  State   Recv-Q  Send-Q    Local Address:Port     Peer Address:Port  Process"
}

func (e *Emulator) cmdPing(args []string, sess *Session) string {
	host := "localhost"
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			host = a
			break
		}
	}
	return fmt.Sprintf(`PING %s (%s) 56(84) bytes of data.
64 bytes from %s: icmp_seq=1 ttl=64 time=0.023 ms
64 bytes from %s: icmp_seq=2 ttl=64 time=0.031 ms
64 bytes from %s: icmp_seq=3 ttl=64 time=0.028 ms

--- %s ping statistics ---
3 packets transmitted, 3 received, 0%% packet loss, time 2048ms
rtt min/avg/max/mdev = 0.023/0.027/0.031/0.003 ms`, host, host, host, host, host, host)
}

func (e *Emulator) cmdDig(args []string, sess *Session) string {
	host := "localhost"
	for _, a := range args {
		if !strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "@") {
			host = a
			break
		}
	}
	now := time.Now()
	return fmt.Sprintf(`;; ANSWER SECTION:
%s.		300	IN	A	93.184.216.34

;; Query time: 12 msec
;; SERVER: 10.0.1.1#53(10.0.1.1)
;; WHEN: %s
;; MSG SIZE  rcvd: 56`, host, now.UTC().Format("Mon Jan 02 15:04:05 UTC 2006"))
}

func (e *Emulator) cmdNslookup(args []string, sess *Session) string {
	host := "localhost"
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			host = a
			break
		}
	}
	return fmt.Sprintf("Server:\t\t10.0.1.1\nAddress:\t10.0.1.1#53\n\nNon-authoritative answer:\nName:\t%s\nAddress: 93.184.216.34", host)
}

// --- Process/resource commands ---

func (e *Emulator) cmdPs(args []string, sess *Session) string {
	flagStr := strings.Join(args, " ")
	if strings.Contains(flagStr, "aux") || strings.Contains(flagStr, "-ef") {
		var lines []string
		boot := e.persona.BootTime
		if strings.Contains(flagStr, "aux") {
			lines = append(lines, "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND")
			for _, p := range e.persona.Processes {
				pid := sessionPID(p.PID, sess)
				// Spread process start times from boot to boot+1h
				procStart := boot.Add(time.Duration(p.PID%3600) * time.Second)
				startStr := formatPsStart(procStart, boot)
				lines = append(lines, fmt.Sprintf("%-8s %5d  %s  %s %6s %5s ?        %s  %s   %s %s",
					p.User, pid, p.CPU, p.Mem, p.VSZ, p.RSS, p.Stat, startStr, p.Time, p.Cmd))
			}
			// Add current shell process
			lines = append(lines, fmt.Sprintf("%-8s %5d  0.0  0.1     8M    5M pts/0    Ss   %s   0:00 -bash",
				e.persona.User, sess.ShellPID, formatPsStart(sess.LoginTime, boot)))
		} else {
			lines = append(lines, "UID          PID    PPID  C STIME TTY          TIME CMD")
			for _, p := range e.persona.Processes {
				pid := sessionPID(p.PID, sess)
				ppid := 1
				if p.PID == 1 {
					ppid = 0
				}
				procStart := boot.Add(time.Duration(p.PID%3600) * time.Second)
				startStr := formatPsStart(procStart, boot)
				lines = append(lines, fmt.Sprintf("%-8s %5d %7d  0 %s ?        %s %s",
					p.User, pid, ppid, startStr, p.Time, p.Cmd))
			}
		}
		return strings.Join(lines, "\n")
	}
	return fmt.Sprintf("  PID TTY          TIME CMD\n %d pts/0    00:00:00 bash", sess.ShellPID)
}

func (e *Emulator) cmdFree(args []string, sess *Session) string {
	human := false
	for _, a := range args {
		if strings.Contains(a, "h") {
			human = true
		}
	}
	if human {
		return `               total        used        free      shared  buff/cache   available
Mem:           3.8Gi       1.8Gi       271Mi        12Mi       1.8Gi       1.8Gi
Swap:          2.0Gi       512Mi       1.5Gi`
	}
	return `               total        used        free      shared  buff/cache   available
Mem:         4028416     1847392      284736       12480     1896288     1923648
Swap:        2097148      524288     1572860`
}

func (e *Emulator) cmdTop(args []string, sess *Session) string {
	now := time.Now()
	up := now.Sub(e.persona.BootTime)
	uptimeStr := formatUptime(up)
	nowStr := now.Format("15:04:05")
	load1 := 0.30 + float64(now.Second()%20)/100.0
	load5 := 0.35 + float64(now.Minute()%15)/100.0
	load15 := 0.28 + float64(now.Hour()%10)/100.0

	var lines []string
	lines = append(lines, fmt.Sprintf("top - %s up %s,  1 user,  load average: %.2f, %.2f, %.2f", nowStr, uptimeStr, load1, load5, load15))
	lines = append(lines, "Tasks: 127 total,   1 running, 126 sleeping,   0 stopped,   0 zombie")
	lines = append(lines, "%Cpu(s):  3.2 us,  1.1 sy,  0.0 ni, 95.2 id,  0.3 wa,  0.0 hi,  0.2 si,  0.0 st")
	lines = append(lines, "MiB Mem :   3934.0 total,    278.1 free,   1804.1 used,   1851.8 buff/cache")
	lines = append(lines, "MiB Swap:   2048.0 total,   1536.0 free,    512.0 used.   1878.6 avail Mem")
	lines = append(lines, "")
	lines = append(lines, "    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND")
	for _, p := range e.persona.Processes {
		if len(lines) > 20 {
			break
		}
		cmd := p.Cmd
		if idx := strings.LastIndex(cmd, "/"); idx >= 0 {
			cmd = cmd[idx+1:]
		}
		if idx := strings.Index(cmd, " "); idx >= 0 {
			cmd = cmd[:idx]
		}
		pid := sessionPID(p.PID, sess)
		lines = append(lines, fmt.Sprintf(" %5d %-8s  20   0 %7s %5s %5s S  %5s %5s   %s %s",
			pid, p.User, p.VSZ, p.RSS, "4M", p.CPU, p.Mem, p.Time, cmd))
	}
	return strings.Join(lines, "\n")
}

func (e *Emulator) cmdDocker(args []string, sess *Session) string {
	if len(args) == 0 {
		return "Usage:  docker [OPTIONS] COMMAND\n\nA self-sufficient runtime for containers"
	}
	switch args[0] {
	case "ps":
		showAll := false
		for _, a := range args[1:] {
			if a == "-a" || a == "--all" {
				showAll = true
			}
		}
		up := formatUptime(time.Now().Sub(e.persona.BootTime))
		lines := []string{"CONTAINER ID   IMAGE                    COMMAND                  CREATED      STATUS       PORTS                    NAMES"}
		lines = append(lines, fmt.Sprintf("a1b2c3d4e5f6   nginx:1.24-alpine        \"/docker-entrypoint.…\"   %s ago  Up %s   0.0.0.0:80->80/tcp       nginx-proxy", up, up))
		lines = append(lines, fmt.Sprintf("b2c3d4e5f6a1   node:18-slim             \"node /opt/app/serve…\"   %s ago  Up %s   127.0.0.1:3000->3000/tcp app-node", up, up))
		lines = append(lines, fmt.Sprintf("c3d4e5f6a1b2   postgres:15              \"docker-entrypoint.s…\"   %s ago  Up %s   127.0.0.1:5432->5432/tcp app-db", up, up))
		if showAll {
			lines = append(lines, fmt.Sprintf("d4e5f6a1b2c3   redis:7-alpine           \"docker-entrypoint.s…\"   %s ago  Exited (0)                                redis-cache", up))
		}
		return strings.Join(lines, "\n")
	case "images":
		return `REPOSITORY         TAG             IMAGE ID       CREATED        SIZE
nginx              1.24-alpine     a1b2c3d4e5f6   4 weeks ago    42.6MB
node               18-slim         b2c3d4e5f6a1   4 weeks ago    238MB
postgres           15              c3d4e5f6a1b2   4 weeks ago    412MB
redis              7-alpine        d4e5f6a1b2c3   4 weeks ago    28.5MB`
	case "logs":
		now := time.Now()
		return fmt.Sprintf("[%s] Server started on port 3000\n[%s] Connected to database\n[%s] GET /api/health 200 2ms\n[%s] GET /api/users 200 15ms\n[%s] POST /api/data 201 42ms",
			now.Add(-3*time.Minute).Format("2006-01-02 15:04:05"),
			now.Add(-3*time.Minute+time.Second).Format("2006-01-02 15:04:05"),
			now.Add(-2*time.Minute).Format("2006-01-02 15:04:05"),
			now.Add(-1*time.Minute).Format("2006-01-02 15:04:05"),
			now.Add(-30*time.Second).Format("2006-01-02 15:04:05"))
	case "info":
		return fmt.Sprintf("Server:\n Containers: 4\n  Running: 3\n  Paused: 0\n  Stopped: 1\n Storage Driver: overlay2\n Docker Root Dir: /var/lib/docker\n Server Version: 24.0.7\n Operating System: %s\n Kernel Version: %s", e.persona.OS, e.persona.Kernel)
	default:
		return fmt.Sprintf("docker: '%s' is not a docker command.", args[0])
	}
}

func (e *Emulator) cmdSystemctl(args []string, sess *Session) string {
	if len(args) == 0 {
		return "systemctl [OPTIONS...] COMMAND ..."
	}
	switch args[0] {
	case "status":
		if len(args) > 1 {
			svc := args[1]
			boot := e.persona.BootTime
			up := formatUptime(time.Now().Sub(boot))
			return fmt.Sprintf("● %s.service - %s Service\n     Loaded: loaded (/lib/systemd/system/%s.service; enabled; vendor preset: enabled)\n     Active: active (running) since %s; %s ago\n   Main PID: 1105\n      Tasks: 5 (limit: 4553)\n     Memory: 28.4M\n        CPU: 2.147s\n     CGroup: /system.slice/%s.service",
				svc, strings.Title(svc), svc, boot.Format("Mon 2006-01-02 15:04:05 UTC"), up, svc)
		}
		return "systemctl status: requires a service name"
	case "list-units", "list-unit-files":
		return `  UNIT                        LOAD   ACTIVE SUB     DESCRIPTION
  docker.service              loaded active running Docker Application Container Engine
  nginx.service               loaded active running A high performance web server
  postgresql.service          loaded active running PostgreSQL RDBMS
  ssh.service                 loaded active running OpenBSD Secure Shell server
  cron.service                loaded active running Regular background program processing
  systemd-journald.service    loaded active running Journal Service`
	default:
		return ""
	}
}

func (e *Emulator) cmdService(args []string, sess *Session) string {
	return ` [ + ]  cron
 [ + ]  docker
 [ + ]  nginx
 [ + ]  postgresql
 [ + ]  ssh
 [ - ]  rsync
 [ - ]  ufw`
}

func (e *Emulator) cmdLsof(args []string, sess *Session) string {
	flagStr := strings.Join(args, " ")
	if strings.Contains(flagStr, "-i") {
		var lines []string
		lines = append(lines, "COMMAND     PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME")
		for _, l := range e.persona.Listeners {
			pid := sessionPID(l.PID, sess)
			lines = append(lines, fmt.Sprintf("%-9s %5d %8s    3u  IPv4 %6d      0t0  TCP %s (LISTEN)",
				l.Program, pid, "root", pid*100, l.Local))
		}
		return strings.Join(lines, "\n")
	}
	return "COMMAND     PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME"
}

func (e *Emulator) cmdKill(args []string, sess *Session) string {
	return ""
}

// --- Credential lure commands ---

func (e *Emulator) cmdEnv(args []string, sess *Session) string {
	var lines []string
	// Sort for deterministic output
	keys := make([]string, 0, len(e.persona.EnvVars))
	for k := range e.persona.EnvVars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		lines = append(lines, fmt.Sprintf("%s=%s", k, e.persona.EnvVars[k]))
	}
	return strings.Join(lines, "\n")
}

func (e *Emulator) cmdHistory(args []string, sess *Session) string {
	if content, ok := e.persona.Lures["/root/.bash_history"]; ok {
		lines := strings.Split(content, "\n")
		var numbered []string
		for i, line := range lines {
			numbered = append(numbered, fmt.Sprintf("  %3d  %s", i+1, line))
		}
		return strings.Join(numbered, "\n")
	}
	return ""
}

// --- Utility commands ---

func (e *Emulator) cmdEcho(args []string, sess *Session) string {
	if len(args) == 0 {
		return ""
	}
	// Handle $VAR expansion
	var parts []string
	for _, a := range args {
		if strings.HasPrefix(a, "$") {
			varName := strings.TrimPrefix(a, "$")
			varName = strings.Trim(varName, "{}")
			if val, ok := e.persona.EnvVars[varName]; ok {
				parts = append(parts, val)
				continue
			}
		}
		// Strip surrounding quotes
		a = strings.Trim(a, "\"'")
		parts = append(parts, a)
	}
	return strings.Join(parts, " ")
}

func (e *Emulator) cmdWhich(args []string, sess *Session) string {
	if len(args) == 0 {
		return ""
	}
	knownBins := map[string]string{
		"bash": "/usr/bin/bash", "sh": "/usr/bin/sh", "ls": "/usr/bin/ls",
		"cat": "/usr/bin/cat", "grep": "/usr/bin/grep", "find": "/usr/bin/find",
		"ps": "/usr/bin/ps", "top": "/usr/bin/top", "docker": "/usr/bin/docker",
		"nginx": "/usr/sbin/nginx", "node": "/usr/bin/node", "python3": "/usr/bin/python3",
		"curl": "/usr/bin/curl", "wget": "/usr/bin/wget", "ssh": "/usr/bin/ssh",
		"git": "/usr/bin/git", "vim": "/usr/bin/vim", "nano": "/usr/bin/nano",
		"systemctl": "/usr/bin/systemctl", "journalctl": "/usr/bin/journalctl",
		"ollama": "/usr/local/bin/ollama", "kubectl": "/usr/local/bin/kubectl",
		"psql": "/usr/bin/psql", "pg_dump": "/usr/bin/pg_dump",
	}
	cmd := args[0]
	if p, ok := knownBins[cmd]; ok {
		return p
	}
	return fmt.Sprintf("%s not found", cmd)
}

func (e *Emulator) cmdType(args []string, sess *Session) string {
	if len(args) == 0 {
		return ""
	}
	builtins := map[string]bool{"cd": true, "echo": true, "export": true, "alias": true, "unset": true, "exit": true}
	cmd := args[0]
	if builtins[cmd] {
		return fmt.Sprintf("%s is a shell builtin", cmd)
	}
	result := e.cmdWhich(args, sess)
	if strings.Contains(result, "not found") {
		return fmt.Sprintf("bash: type: %s: not found", cmd)
	}
	return fmt.Sprintf("%s is %s", cmd, result)
}

func (e *Emulator) cmdCommand(args []string, sess *Session) string {
	if len(args) > 0 && args[0] == "-v" {
		return e.cmdWhich(args[1:], sess)
	}
	return ""
}

func (e *Emulator) cmdGrep(args []string, sess *Session) string {
	if len(args) < 2 {
		return ""
	}
	pattern := args[0]
	invert := false
	var filePaths []string

	i := 0
	for i < len(args) {
		if args[i] == "-v" {
			invert = true
		} else if args[i] == "-i" || args[i] == "-r" || args[i] == "-n" || args[i] == "-l" {
			// skip flag
		} else if !strings.HasPrefix(args[i], "-") {
			if pattern == args[0] && i == 0 {
				// first non-flag is pattern, already captured
			} else {
				filePaths = append(filePaths, args[i])
			}
		}
		i++
	}

	// Separate pattern from files for simpler logic
	if len(filePaths) == 0 {
		// No file specified — need piped input (handled in executePiped)
		return ""
	}

	var results []string
	for _, fp := range filePaths {
		resolved := resolvePath(fp, sess.CWD)
		// Check overlay first
		content, ok := sess.FileOverlay[resolved]
		if !ok {
			content, ok = e.persona.Lures[resolved]
		}
		if !ok {
			// Check generated files
			switch resolved {
			case "/etc/passwd":
				content = e.persona.Lures["/etc/passwd"]
			default:
				continue
			}
		}
		for _, line := range strings.Split(content, "\n") {
			match := strings.Contains(line, pattern)
			if invert {
				match = !match
			}
			if match {
				if len(filePaths) > 1 {
					results = append(results, fmt.Sprintf("%s:%s", fp, line))
				} else {
					results = append(results, line)
				}
			}
		}
	}
	return strings.Join(results, "\n")
}

func (e *Emulator) cmdExport(args []string, sess *Session) string {
	return ""
}

func (e *Emulator) cmdAlias(args []string, sess *Session) string {
	if len(args) == 0 {
		return "alias ll='ls -la'\nalias la='ls -A'\nalias l='ls -CF'"
	}
	return ""
}

func (e *Emulator) cmdUnset(args []string, sess *Session) string {
	return ""
}

// --- Destructive commands (with session overlay) ---

func (e *Emulator) cmdRm(args []string, sess *Session) string {
	sess.initOverlays()
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		filePath := resolvePath(arg, sess.CWD)
		sess.Deleted[filePath] = true
		delete(sess.FileOverlay, filePath)
	}
	return ""
}

func (e *Emulator) cmdMkdir(args []string, sess *Session) string {
	sess.initOverlays()
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		dirPath := resolvePath(arg, sess.CWD)
		if sess.DirOverlay[dirPath] == nil {
			sess.DirOverlay[dirPath] = []string{}
		}
		// Add to parent
		parent := path.Dir(dirPath)
		sess.DirOverlay[parent] = appendUnique(sess.DirOverlay[parent], path.Base(dirPath))
	}
	return ""
}

func (e *Emulator) cmdTouch(args []string, sess *Session) string {
	sess.initOverlays()
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		filePath := resolvePath(arg, sess.CWD)
		if _, exists := sess.FileOverlay[filePath]; !exists {
			sess.FileOverlay[filePath] = ""
		}
		parent := path.Dir(filePath)
		sess.DirOverlay[parent] = appendUnique(sess.DirOverlay[parent], path.Base(filePath))
		delete(sess.Deleted, filePath)
	}
	return ""
}

func (e *Emulator) cmdCp(args []string, sess *Session) string {
	sess.initOverlays()
	// Simple cp src dst
	var nonFlags []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			nonFlags = append(nonFlags, a)
		}
	}
	if len(nonFlags) == 2 {
		src := resolvePath(nonFlags[0], sess.CWD)
		dst := resolvePath(nonFlags[1], sess.CWD)
		// Try overlay, then lures
		if content, ok := sess.FileOverlay[src]; ok {
			sess.FileOverlay[dst] = content
		} else if content, ok := e.persona.Lures[src]; ok {
			sess.FileOverlay[dst] = content
		}
		parent := path.Dir(dst)
		sess.DirOverlay[parent] = appendUnique(sess.DirOverlay[parent], path.Base(dst))
	}
	return ""
}

// --- Generated file content ---

func (e *Emulator) genOSRelease() string {
	name := "Ubuntu"
	versionID := "22.04"
	version := "22.04.4 LTS (Jammy Jellyfish)"
	codename := "jammy"

	return fmt.Sprintf(`PRETTY_NAME="%s"
NAME="%s"
VERSION_ID="%s"
VERSION="%s"
VERSION_CODENAME=%s
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"`, e.persona.OS, name, versionID, version, codename)
}

func (e *Emulator) genCPUInfo() string {
	return `processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 85
model name	: Intel(R) Xeon(R) Platinum 8275CL CPU @ 3.00GHz
stepping	: 7
cpu MHz		: 2999.998
cache size	: 36608 KB
physical id	: 0
siblings	: 2
core id		: 0
cpu cores	: 2
bogomips	: 5999.99
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmon rep_good nopl xtopology tsc_reliable nonstop_tsc cpuid pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single ssbd ibrs ibpb stibp fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid mpx avx512f avx512dq rdseed adx smap clflushopt clwb avx512cd avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves ida arat pku ospke

processor	: 1
vendor_id	: GenuineIntel
cpu family	: 6
model		: 85
model name	: Intel(R) Xeon(R) Platinum 8275CL CPU @ 3.00GHz
stepping	: 7
cpu MHz		: 2999.998
cache size	: 36608 KB
physical id	: 0
siblings	: 2
core id		: 1
cpu cores	: 2
bogomips	: 5999.99`
}

func (e *Emulator) genMemInfo() string {
	return `MemTotal:        4028416 kB
MemFree:          284736 kB
MemAvailable:    1923648 kB
Buffers:          142592 kB
Cached:          1753696 kB
SwapCached:        12480 kB
Active:          1847392 kB
Inactive:        1524480 kB
SwapTotal:       2097148 kB
SwapFree:        1572860 kB
Dirty:               128 kB
Writeback:             0 kB
AnonPages:       1436672 kB
Mapped:           384512 kB
Shmem:             12480 kB`
}
