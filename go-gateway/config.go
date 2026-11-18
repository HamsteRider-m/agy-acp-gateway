package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	McpBridgeName       = "ws-bridge"
	LegacyMcpBridgeName = "dsh-bridge"
	AwaitToolName       = "ws_await_result"
	LegacyAwaitToolName = "dsh_await_result"
	CallToolName        = "ws_call_tool"
	LegacyCallToolName  = "dsh_call_tool"
	UtilWorkerTtl       = 20 * time.Second
	MaxTranscriptChar   = 1800000
)

// ProjectHome: project root (<root>/bin/agy-acp-gateway -> <root>); override with AGY_GW_HOME
var ProjectHome = resolveProjectHome()

func resolveProjectHome() string {
	if v := strings.TrimSpace(os.Getenv("AGY_GW_HOME")); v != "" {
		return v
	}
	if exe, err := os.Executable(); err == nil {
		if real, err2 := filepath.EvalSymlinks(exe); err2 == nil {
			exe = real
		}
		dir := filepath.Dir(exe)
		if filepath.Base(dir) == "bin" {
			return filepath.Dir(dir)
		}
		return dir
	}
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

var (
	PatchedAgyBin                  = envStr("AGY_ACP_BIN", filepath.Join(ProjectHome, "bin", "agy-acp-900k"))
	PureApiHome                    = envStr("AGY_PURE_API_HOME", filepath.Join(ProjectHome, "runtime", "pure-api-home"))
	DefaultCwd                     = envStr("AGY_DEFAULT_CWD", os.TempDir())
	MaxLiveWorkers                 = envInt("AGY_MAX_LIVE_WORKERS", 8)
	MaxConcurrentPrompts           = envInt("AGY_MAX_CONCURRENT_PROMPTS", 6)
	IdleWorkerTtl                  = time.Duration(envInt("AGY_IDLE_WORKER_TTL_SEC", 1200)) * time.Second
	ParkedTtl                      = time.Duration(envInt("AGY_PARKED_TTL_SEC", 300)) * time.Second
	MaxToolRelays                  = envIntAllowSigned("AGY_MAX_TOOL_RELAYS", 4)
	MaxBodyBytes                   = int64(envInt("AGY_MAX_BODY_MB", 64)) * 1024 * 1024
	AllowedCorsOrigins             = parseCorsOrigins(os.Getenv("AGY_CORS_ORIGINS"))
	promptSem                      = make(chan struct{}, MaxConcurrentPrompts)
	ListenHost                     = envStr("AGY_LISTEN_HOST", "127.0.0.1")
	GatewayPort                    = envInt("AGY_GW_PORT", 18890)
	DashboardPort                  = envInt("AGY_DASH_PORT", 18891)
	GatewayLogFile                 = envStr("AGY_GW_LOG", filepath.Join(ProjectHome, "logs", "gateway.log"))
	GatewayStateDB                 = envStr("AGY_STATE_DB", filepath.Join(ProjectHome, "runtime", "gateway.db"))
	WafRewriteRulesFile            = envStr("AGY_WAF_RULES_FILE", "")
	WafAutoBisectEnabled           = envBool("AGY_WAF_AUTOBISECT", true)
	TmpLogFile                     = envStr("AGY_GW_TMPLOG", "")
	McpTrace                       = os.Getenv("AGY_MCP_TRACE") == "1"
	LogHeaders                     = os.Getenv("AGY_LOG_HEADERS") == "1"
	UseG1Credits                   = os.Getenv("AGY_USE_G1_CREDITS") == "1"
	CacheWarnMinTokens             = envInt("AGY_CACHE_WARN_MIN_TOKENS", 80000)
	CacheWarnStreak                = envInt("AGY_CACHE_WARN_STREAK", 3)
	PrefillCancelMinElapsed        = time.Duration(envInt("AGY_PREFILL_CANCEL_MIN_ELAPSED_SEC", 30)) * time.Second
	PrefillCancelGrace             = time.Duration(envInt("AGY_PREFILL_CANCEL_GRACE_SEC", 45)) * time.Second
	prefillMinElapsedEnvSet        = strings.TrimSpace(os.Getenv("AGY_PREFILL_CANCEL_MIN_ELAPSED_SEC")) != ""
	prefillGraceEnvSet             = strings.TrimSpace(os.Getenv("AGY_PREFILL_CANCEL_GRACE_SEC")) != ""
	MaxImagesGemini                = envInt("AGY_MAX_IMAGES_GEMINI", 200)
	MaxImagesClaude                = envInt("AGY_MAX_IMAGES_CLAUDE", 100)
	MaxImageBytes                  = envInt("AGY_MAX_IMAGE_BYTES", 10*1024*1024)
	MaxPromptImageBytes            = envInt("AGY_MAX_PROMPT_IMAGE_BYTES", 32*1024*1024)
	MaxTextFileBytes               = envInt("AGY_MAX_TEXT_FILE_BYTES", 2*1024*1024)
	FetchRemoteImages              = envBool("AGY_FETCH_IMAGES", true)
	ConvKeepDays                   = envIntAllowSigned("AGY_CONV_KEEP_DAYS", 0)
	AcpRecordDir                   = strings.TrimSpace(os.Getenv("AGY_ACP_RECORD"))
	mcpToolNameRe                  = regexp.MustCompile(`[^a-zA-Z0-9_-]`)
	acpRecordMu                    sync.Mutex
	argonDegradationDetectedTotal  atomic.Int64
	argonDegradationRecoveredTotal atomic.Int64
	cacheBurnWarningsTotal         atomic.Int64
	orphanRelayCapsTotal           atomic.Int64
	engineExitsTotal               atomic.Int64
	workerCapRejectionsTotal       atomic.Int64
	softDetachJoinedTotal          atomic.Int64
	softDetachExpiredTotal         atomic.Int64
	softDetachSupersededTotal      atomic.Int64
)

func parseCorsOrigins(raw string) map[string]bool {
	out := make(map[string]bool)
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out[item] = true
		}
	}
	return out
}

func initConfig() {
	ProjectHome = resolveProjectHome()
	PatchedAgyBin = envStr("AGY_ACP_BIN", filepath.Join(ProjectHome, "bin", "agy-acp-900k"))
	PureApiHome = envStr("AGY_PURE_API_HOME", filepath.Join(ProjectHome, "runtime", "pure-api-home"))
	DefaultCwd = envStr("AGY_DEFAULT_CWD", os.TempDir())
	MaxLiveWorkers = envInt("AGY_MAX_LIVE_WORKERS", 8)
	MaxConcurrentPrompts = envInt("AGY_MAX_CONCURRENT_PROMPTS", 6)
	IdleWorkerTtl = time.Duration(envInt("AGY_IDLE_WORKER_TTL_SEC", 1200)) * time.Second
	ParkedTtl = time.Duration(envInt("AGY_PARKED_TTL_SEC", 300)) * time.Second
	MaxToolRelays = envIntAllowSigned("AGY_MAX_TOOL_RELAYS", 4)
	MaxBodyBytes = int64(envInt("AGY_MAX_BODY_MB", 64)) * 1024 * 1024
	AllowedCorsOrigins = parseCorsOrigins(os.Getenv("AGY_CORS_ORIGINS"))
	promptSem = make(chan struct{}, MaxConcurrentPrompts)
	ListenHost = envStr("AGY_LISTEN_HOST", "127.0.0.1")
	GatewayPort = envInt("AGY_GW_PORT", 18890)
	DashboardPort = envInt("AGY_DASH_PORT", 18891)
	GatewayLogFile = envStr("AGY_GW_LOG", filepath.Join(ProjectHome, "logs", "gateway.log"))
	GatewayStateDB = envStr("AGY_STATE_DB", filepath.Join(ProjectHome, "runtime", "gateway.db"))
	WafRewriteRulesFile = envStr("AGY_WAF_RULES_FILE", "")
	WafAutoBisectEnabled = envBool("AGY_WAF_AUTOBISECT", true)
	TosTrippedFile = envStr("AGY_TOS_TRIPPED_FILE", filepath.Join(ProjectHome, "runtime", "tos-tripped"))
	TmpLogFile = strings.TrimSpace(os.Getenv("AGY_GW_TMPLOG"))
	McpTrace = os.Getenv("AGY_MCP_TRACE") == "1"
	LogHeaders = os.Getenv("AGY_LOG_HEADERS") == "1"
	UseG1Credits = os.Getenv("AGY_USE_G1_CREDITS") == "1"
	CacheWarnMinTokens = envInt("AGY_CACHE_WARN_MIN_TOKENS", 80000)
	CacheWarnStreak = envInt("AGY_CACHE_WARN_STREAK", 3)
	PrefillCancelMinElapsed = time.Duration(envInt("AGY_PREFILL_CANCEL_MIN_ELAPSED_SEC", 30)) * time.Second
	PrefillCancelGrace = time.Duration(envInt("AGY_PREFILL_CANCEL_GRACE_SEC", 45)) * time.Second
	prefillMinElapsedEnvSet = strings.TrimSpace(os.Getenv("AGY_PREFILL_CANCEL_MIN_ELAPSED_SEC")) != ""
	prefillGraceEnvSet = strings.TrimSpace(os.Getenv("AGY_PREFILL_CANCEL_GRACE_SEC")) != ""
	MaxImagesGemini = envInt("AGY_MAX_IMAGES_GEMINI", 200)
	MaxImagesClaude = envInt("AGY_MAX_IMAGES_CLAUDE", 100)
	MaxImageBytes = envInt("AGY_MAX_IMAGE_BYTES", 10*1024*1024)
	MaxPromptImageBytes = envInt("AGY_MAX_PROMPT_IMAGE_BYTES", 32*1024*1024)
	MaxTextFileBytes = envInt("AGY_MAX_TEXT_FILE_BYTES", 2*1024*1024)
	FetchRemoteImages = envBool("AGY_FETCH_IMAGES", true)
	ConvKeepDays = envIntAllowSigned("AGY_CONV_KEEP_DAYS", 0)
	AcpRecordDir = strings.TrimSpace(os.Getenv("AGY_ACP_RECORD"))
	apiKeys = loadAPIKeys()
	GlobalStore.Init(GatewayStateDB)
}

func truncateRunes(s string, maxRunes int) string {
	if maxRunes <= 0 || len(s) <= maxRunes {
		return s
	}
	r := []rune(s)
	if len(r) <= maxRunes {
		return s
	}
	return string(r[:maxRunes])
}

func recordAcpLine(direction string, raw []byte) {
	if AcpRecordDir == "" {
		return
	}
	_ = os.MkdirAll(AcpRecordDir, 0700)
	var parsed map[string]any
	lineStr := string(bytes.TrimSpace(raw))
	if json.Unmarshal(raw, &parsed) == nil {
		if params, ok := parsed["params"].(map[string]any); ok {
			if blocks, okB := params["prompt"].([]any); okB {
				for _, b := range blocks {
					if bm, okM := b.(map[string]any); okM {
						if t, okT := bm["text"].(string); okT && len(t) > 200 {
							bm["text"] = truncateRunes(t, 200) + "...[truncated]"
						}
					}
				}
			}
		}
		if b2, err := redactLogJSON(parsed); err == nil {
			lineStr = string(b2)
		}
	}
	rec, _ := json.Marshal(map[string]any{
		"ts":   time.Now().UTC().Format(time.RFC3339Nano),
		"dir":  direction,
		"line": redactSecretsInString(lineStr),
	})
	acpRecordMu.Lock()
	if f, err := openPrivateLog(filepath.Join(AcpRecordDir, "acp-traffic.ndjson")); err == nil {
		_, _ = f.Write(append(rec, '\n'))
		_ = f.Close()
	}
	acpRecordMu.Unlock()
}

func envStr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func envIntAllowSigned(k string, def int) int {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envBool(k string, def bool) bool {
	if v := strings.ToLower(strings.TrimSpace(os.Getenv(k))); v != "" {
		switch v {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
	}
	return def
}

func effectiveWafRulesFile() string {
	if p := strings.TrimSpace(WafRewriteRulesFile); p != "" {
		return p
	}
	if p := strings.TrimSpace(os.Getenv("AGY_WAF_RULES_FILE")); p != "" {
		return p
	}
	if db := strings.TrimSpace(GatewayStateDB); db != "" {
		return filepath.Join(filepath.Dir(db), "waf_rewrite_rules.json")
	}
	return filepath.Join(ProjectHome, "runtime", "waf_rewrite_rules.json")
}

func effectiveMaxToolRelays() int {
	return envIntAllowSigned("AGY_MAX_TOOL_RELAYS", MaxToolRelays)
}

func effectiveParkedTtl() time.Duration {
	if sec := envInt("AGY_PARKED_TTL_SEC", 0); sec > 0 {
		return time.Duration(sec) * time.Second
	}
	return ParkedTtl
}

var (
	logMu         sync.Mutex
	logFileHandle *os.File
	logFilePath   string
	logFileSize   int64
	LogMaxBytes   = int64(envInt("AGY_LOG_MAX_MB", 20)) * 1024 * 1024
)

func rotateLogFileLocked(path string) {
	if logFileHandle != nil {
		_ = logFileHandle.Close()
		logFileHandle = nil
	}
	for i := 4; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", path, i)
		dst := fmt.Sprintf("%s.%d", path, i+1)
		if _, err := os.Stat(src); err == nil {
			_ = os.Rename(src, dst)
		}
	}
	_ = os.Rename(path, path+".1")
	logFileSize = 0
}

func writeGatewayLogLocked(line string) {
	if GatewayLogFile == "" {
		return
	}
	if logFileHandle != nil && logFilePath != GatewayLogFile {
		_ = logFileHandle.Close()
		logFileHandle = nil
	}
	if logFileHandle != nil && LogMaxBytes > 0 && logFileSize+int64(len(line)) > LogMaxBytes {
		rotateLogFileLocked(GatewayLogFile)
	}
	if logFileHandle == nil {
		_ = os.MkdirAll(filepath.Dir(GatewayLogFile), 0700)
		if f, err := openPrivateLog(GatewayLogFile); err == nil {
			logFileHandle = f
			logFilePath = GatewayLogFile
			if st, errS := f.Stat(); errS == nil {
				logFileSize = st.Size()
			} else {
				logFileSize = 0
			}
		}
	}
	if logFileHandle != nil {
		if n, err := logFileHandle.WriteString(line); err == nil {
			logFileSize += int64(n)
		}
	}
}

func LogEvent(category, message string, meta map[string]any) {
	ts := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	metaStr := ""
	if len(meta) > 0 {
		if b, err := redactLogJSON(meta); err == nil {
			metaStr = " " + string(b)
		}
	}
	line := redactSecretsInString(fmt.Sprintf("[%s] [%s] %s%s\n", ts, category, message, metaStr))
	os.Stdout.WriteString(line)
	logMu.Lock()
	writeGatewayLogLocked(line)
	if TmpLogFile != "" {
		if f, err := openPrivateLog(TmpLogFile); err == nil {
			_, _ = f.WriteString(line)
			_ = f.Close()
		}
	}
	logMu.Unlock()
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func shortSha256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:16]
}

func mcpToolName(hostName string) string {
	neutral := NeutralizeToolIdentifier(hostName)
	clean := mcpToolNameRe.ReplaceAllString(neutral, "_")
	if len(clean) > 40 {
		clean = clean[:40]
	}
	return fmt.Sprintf("ws_%s_%s", clean, shortSha256(hostName)[:12])
}

func writeFileIfChanged(path string, content []byte, perm os.FileMode) {
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, content) {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	_ = os.WriteFile(path, content, perm)
}

func isLiteralCDrivePath(clean string) bool {
	if clean == "/mnt/c" || strings.HasPrefix(clean, "/mnt/c/") {
		return true
	}
	if len(clean) >= 2 && (clean[0] == 'C' || clean[0] == 'c') && clean[1] == ':' {
		return true
	}
	return false
}

func isWindowsCDrivePath(p string) bool {
	if strings.TrimSpace(p) == "" {
		return false
	}
	clean := filepath.Clean(p)
	if isLiteralCDrivePath(clean) {
		return true
	}
	cur := clean
	for {
		if _, err := os.Lstat(cur); err == nil {
			if resolved, rErr := filepath.EvalSymlinks(cur); rErr == nil {
				resolvedClean := filepath.Clean(resolved)
				if isLiteralCDrivePath(resolvedClean) {
					return true
				}
				if rel, relErr := filepath.Rel(cur, clean); relErr == nil && rel != "." {
					if isLiteralCDrivePath(filepath.Clean(filepath.Join(resolvedClean, rel))) {
						return true
					}
				}
			}
			break
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	return false
}

func seedDefaultCliProject(projectPath string) {
	if isWindowsCDrivePath(projectPath) {
		return
	}
	if raw, err := os.ReadFile(projectPath); err == nil {
		var existing map[string]any
		if json.Unmarshal(raw, &existing) == nil && existing["id"] == "default-cli-project" {
			return
		}
	}
	b, _ := json.MarshalIndent(map[string]any{
		"id":               "default-cli-project",
		"name":             "CLI Project",
		"projectResources": map[string]any{},
	}, "", "  ")
	writeFileIfChanged(projectPath, append(b, '\n'), 0644)
}

func seedOnboardingFile(onboardingPath string) {
	if isWindowsCDrivePath(onboardingPath) {
		return
	}
	existing := map[string]any{}
	if raw, err := os.ReadFile(onboardingPath); err == nil {
		_ = json.Unmarshal(raw, &existing)
		if existing == nil {
			existing = map[string]any{}
		}
	}
	cDone, _ := existing["consumerOnboardingComplete"].(bool)
	oDone, _ := existing["onboardingComplete"].(bool)
	if cDone && oDone {
		return
	}
	existing["consumerOnboardingComplete"] = true
	if _, hasEnt := existing["enterpriseOnboardingComplete"].(bool); !hasEnt {
		existing["enterpriseOnboardingComplete"] = false
	}
	existing["onboardingComplete"] = true
	b, err := json.Marshal(existing)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(onboardingPath), 0700)
	_ = os.WriteFile(onboardingPath, append(b, '\n'), 0600)
}

func writeBridgeAgentPlugin(bridgeName string) {
	agentDir := filepath.Join(PureApiHome, "config", "plugins", bridgeName, "agents")
	_ = os.MkdirAll(agentDir, 0755)
	pluginJson := filepath.Join(PureApiHome, "config", "plugins", bridgeName, "plugin.json")
	writeFileIfChanged(pluginJson, []byte(fmt.Sprintf("{\"name\":%q}\n", bridgeName)), 0644)
	agentMd := filepath.Join(agentDir, bridgeName+".md")
	// Keep <identity> byte-identical to bin/agy-acp-900k's LINT.IfChange(antigravity_identity) block
	// so upstream abuse.pi sees native Antigravity identity without CLI-tool boilerplate mismatches.
	mdContent := strings.Join([]string{
		"---",
		"name: " + bridgeName,
		`description: "Primary-model workspace bridge"`,
		"excludeDefaultComponents: true",
		"mainAgent: true",
		"tools:",
		"  - search_web",
		"  - read_url_content",
		"---",
		"<identity>",
		"You are Antigravity, a powerful agentic AI coding assistant designed by the Google Deepmind team working on Advanced Agentic Coding.",
		"You are pair programming with a USER to solve their coding task. The task may require creating a new codebase, modifying or debugging an existing codebase, or simply answering a question.",
		"The USER will send you requests, which you must always prioritize addressing. User requests are enclosed within <USER_REQUEST> tags.",
		"</identity>",
		"SPECIAL INSTRUCTION: think silently if needed. EFFORT LEVEL: 1.00.",
		fmt.Sprintf("Follow the appended system instructions. Use the %s MCP tools for all workspace file and command operations, and use built-in search_web / read_url_content when web search or URL reading is needed.", bridgeName),
		"",
	}, "\n")
	writeFileIfChanged(agentMd, []byte(mdContent), 0644)
}

func EnsurePureApiHome() {
	if isWindowsCDrivePath(PureApiHome) {
		return
	}
	writeBridgeAgentPlugin(McpBridgeName)
	writeBridgeAgentPlugin(LegacyMcpBridgeName)
	seedDefaultCliProject(filepath.Join(PureApiHome, "config", "projects", "default-cli-project.json"))

	// App data (oauth token, conversations, logs). Locally it may be a symlink to ~/.gemini/antigravity-cli
	// (AGY_APPDATA_LINK); in the container it is a plain directory on the data volume.
	appDataLink := filepath.Join(PureApiHome, "antigravity-cli")
	if _, err := os.Lstat(appDataLink); os.IsNotExist(err) {
		if target := strings.TrimSpace(os.Getenv("AGY_APPDATA_LINK")); target != "" && !isWindowsCDrivePath(target) {
			_ = os.Symlink(target, appDataLink)
		} else {
			_ = os.MkdirAll(appDataLink, 0700)
		}
	}
	seedOnboardingFile(filepath.Join(appDataLink, "cache", "onboarding.json"))
}

func ConversationsDir() string {
	return envStr("AGY_CONV_DIR", filepath.Join(PureApiHome, "antigravity-cli", "conversations"))
}

func sameDirOrPath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	ca := filepath.Clean(a)
	cb := filepath.Clean(b)
	if ca == cb {
		return true
	}
	ia, errA := os.Stat(ca)
	ib, errB := os.Stat(cb)
	return errA == nil && errB == nil && os.SameFile(ia, ib)
}

func isAppConvExplicitlyDisabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("AGY_APP_CONV_DIR"))) {
	case "off", "none", "0", "false", "no":
		return true
	default:
		return false
	}
}

// AppConversationsDir returns the strictly READ-ONLY Antigravity Desktop App conversations
// directory (e.g. ~/.gemini/antigravity/conversations).
//   - Controlled by AGY_APP_CONV_DIR: "off"/"none"/"0"/"false"/"no" disables it; any other
//     non-empty path (unless Windows C: drive or identical to ConversationsDir()) is used.
//   - When AGY_APP_CONV_DIR is unset: auto-discovers sibling <parent(AGY_APPDATA_LINK)>/antigravity/conversations
//     ONLY when AGY_CONV_DIR is unset and AGY_APPDATA_LINK is non-empty, keeping isolated test
//     instances (go test, fake_instance.py, non-18890 gw.sh) 100% hermetic.
func AppConversationsDir() string {
	if isAppConvExplicitlyDisabled() {
		return ""
	}
	if raw := strings.TrimSpace(os.Getenv("AGY_APP_CONV_DIR")); raw != "" {
		clean := filepath.Clean(raw)
		if isWindowsCDrivePath(clean) || sameDirOrPath(clean, ConversationsDir()) {
			return ""
		}
		return clean
	}
	if strings.TrimSpace(os.Getenv("AGY_CONV_DIR")) != "" {
		return ""
	}
	appdataLink := strings.TrimSpace(os.Getenv("AGY_APPDATA_LINK"))
	if appdataLink == "" || isWindowsCDrivePath(appdataLink) {
		return ""
	}
	candidate := filepath.Join(filepath.Dir(filepath.Clean(appdataLink)), "antigravity", "conversations")
	if isWindowsCDrivePath(candidate) || sameDirOrPath(candidate, ConversationsDir()) {
		return ""
	}
	if info, err := os.Stat(candidate); err == nil && info.IsDir() {
		return candidate
	}
	return ""
}
