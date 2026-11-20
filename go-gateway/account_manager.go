package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	gwcfg "agy-acp-gateway-go/internal/config"
)

// ProxyPresetOption describes a zero-secret selectable proxy egress option in the web UI.
type ProxyPresetOption struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Region      string `json:"region"`
	Description string `json:"description"`
}

// BuiltinProxyPresets contains only generic egress options safe for open-source distribution.
// Operators can provide additional named proxy presets via AGY_PROXY_PRESETS_FILE (JSON array).
var BuiltinProxyPresets = []ProxyPresetOption{
	{ID: "direct", Label: "宿主机直连 (Direct)", Region: "DIRECT", Description: "不走代理，使用宿主机原生出口 IP"},
	{ID: "custom", Label: "自定义 HTTP/SOCKS5 代理", Region: "CUSTOM", Description: "手动指定代理地址 (支持 http://, https://, socks5://)"},
}

var (
	validAccountIDRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	validProxyPresetRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	oauthURLRe         = regexp.MustCompile(`https://accounts\.google\.com/o/oauth2/[^\s"']+`)
)

type preReadBodyCtxKeyType struct{}

var preReadBodyCtxKey = preReadBodyCtxKeyType{}

func withPreReadBody(r *http.Request, raw []byte) *http.Request {
	if r == nil {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), preReadBodyCtxKey, raw))
}

func preReadBodyFromContext(r *http.Request) ([]byte, bool) {
	if r == nil {
		return nil, false
	}
	b, ok := r.Context().Value(preReadBodyCtxKey).([]byte)
	return b, ok
}

// LoadProxyPresets returns generic presets merged with optional external presets from AGY_PROXY_PRESETS_FILE.
func LoadProxyPresets() []ProxyPresetOption {
	direct := BuiltinProxyPresets[0]
	custom := BuiltinProxyPresets[1]
	out := []ProxyPresetOption{direct}
	seen := map[string]bool{"direct": true, "custom": true}

	if path := gwcfg.Current().ProxyPresetsFile; path != "" {
		if b, err := os.ReadFile(path); err == nil {
			var extra []ProxyPresetOption
			if json.Unmarshal(b, &extra) == nil {
				for _, p := range extra {
					p.ID = strings.ToLower(strings.TrimSpace(p.ID))
					if p.ID == "" || seen[p.ID] || !validProxyPresetRe.MatchString(p.ID) {
						continue
					}
					seen[p.ID] = true
					if strings.TrimSpace(p.Label) == "" {
						p.Label = p.ID
					}
					out = append(out, p)
				}
			}
		}
	}
	out = append(out, custom)
	return out
}

func validateProxyPreset(preset string) error {
	p := strings.ToLower(strings.TrimSpace(preset))
	if p == "" || p == "direct" || p == "custom" {
		return nil
	}
	if !validProxyPresetRe.MatchString(p) {
		return errors.New("代理预设 ID 仅允许小写字母、数字、连字符或下划线 (1-64 位)")
	}
	return nil
}

func validateCustomProxyURL(raw string) error {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	if strings.ContainsAny(s, "\r\n\t ") {
		return errors.New("自定义代理 URL 不可包含空白或换行符")
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return errors.New("自定义代理 URL 格式无效")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks5", "socks5h":
		return nil
	default:
		return errors.New("自定义代理协议仅支持 http / https / socks5 / socks5h")
	}
}

func maskProxyURL(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil {
		return "***"
	}
	if u.User != nil {
		if _, hasPw := u.User.Password(); hasPw {
			u.User = url.UserPassword(u.User.Username(), "***")
		}
	}
	return u.String()
}

// AccountProfile persists configuration for one isolated account environment.
type AccountProfile struct {
	ID             string   `json:"id"`
	Label          string   `json:"label"`
	Primary        bool     `json:"primary"`
	Enabled        bool     `json:"enabled"`
	ProxyPreset    string   `json:"proxyPreset"`
	CustomProxy    string   `json:"customProxy,omitempty"`
	MaxLiveWorkers int      `json:"maxLiveWorkers"`
	BoundKeys      []string `json:"boundKeys"`
	AllowedModels  []string `json:"allowedModels"`
	DefaultModels  []string `json:"defaultModels,omitempty"`
}

func (a AccountProfile) AllowsModel(canonicalModelID string) bool {
	if canonicalModelID == "" {
		return true
	}
	for _, m := range a.AllowedModels {
		if m == "*" || strings.EqualFold(strings.TrimSpace(m), canonicalModelID) {
			return true
		}
	}
	return false
}

func (a AccountProfile) AllowsAllCanonicalModels() bool {
	for _, m := range a.AllowedModels {
		if m == "*" {
			return true
		}
	}
	for _, m := range AgyModels {
		if !a.AllowsModel(m.ID) {
			return false
		}
	}
	return len(AgyModels) > 0
}

func normalizeCanonicalModelList(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if raw == "*" {
			for _, m := range AgyModels {
				if !seen[m.ID] {
					seen[m.ID] = true
					out = append(out, m.ID)
				}
			}
			continue
		}
		sel := ResolveRequestedModel(raw, nil)
		if !sel.Explicit || sel.Model == nil || sel.Model.ID == "" {
			continue
		}
		cid := sel.Model.ID
		if !seen[cid] {
			seen[cid] = true
			out = append(out, cid)
		}
	}
	return out
}

type accountsFileSchema struct {
	Version  int              `json:"version"`
	Accounts []AccountProfile `json:"accounts"`
}

type accountWorkerProc struct {
	id       string
	gwPort   int
	dashPort int
	cmd      *exec.Cmd
	proxy    *httputil.ReverseProxy
	done     chan struct{}
	readyCh  chan struct{}
	readyErr error
	stopped  bool
}

type pendingOAuthSession struct {
	accountID string
	authURL   string
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	output    *bytes.Buffer
	outMu     sync.Mutex
	tokenPath string
	bakPath   string
	startedAt time.Time
	done      chan struct{}
	doneCh    chan error
}

type stickyAccountEntry struct {
	accountID string
	modelID   string
	lastSeen  time.Time
}

type tokenCacheEntry struct {
	exists    bool
	checkedAt time.Time
}

// AccountManager supervises isolated per-account directories, OAuth handshakes, child worker
// processes, strict per-account model allowlists, and session-sticky pool round-robin routing.
type AccountManager struct {
	mu              sync.RWMutex
	filePath        string
	baseDataDir     string
	accounts        []AccountProfile
	workers         map[string]*accountWorkerProc
	oauthMu         sync.Mutex
	oauthActive     map[string]*pendingOAuthSession
	stickyMu        sync.Mutex
	stickySessions  map[string]stickyAccountEntry
	stickyLastPrune time.Time
	rrCounters      map[string]uint64
	tokCacheMu      sync.RWMutex
	tokCache        map[string]tokenCacheEntry
}

var GlobalAccountManager = NewAccountManager()

func isChildAccountWorker() bool {
	return gwcfg.Current().ChildAccountWorker
}

func NewAccountManager() *AccountManager {
	return &AccountManager{
		workers:        make(map[string]*accountWorkerProc),
		oauthActive:    make(map[string]*pendingOAuthSession),
		stickySessions: make(map[string]stickyAccountEntry),
		rrCounters:     make(map[string]uint64),
		tokCache:       make(map[string]tokenCacheEntry),
	}
}

func resolveAccountsFilePath() (filePath, baseDataDir string) {
	if v := gwcfg.Current().AccountsFile; v != "" {
		return v, filepath.Dir(v)
	}
	dbPath := strings.TrimSpace(GatewayStateDB)
	if dbPath == "" {
		dbPath = gwcfg.Current().GatewayStateDB
	}
	baseDir := filepath.Dir(dbPath)
	if baseDir == "" || baseDir == "." {
		baseDir = "."
	}
	return filepath.Join(baseDir, "accounts.json"), baseDir
}

func defaultSeededAccounts() []AccountProfile {
	snap := gwcfg.Current()
	primID := strings.ToLower(strings.TrimSpace(snap.InstanceID))
	if !validAccountIDRe.MatchString(primID) {
		primID = "primary"
	}
	primLabel := strings.TrimSpace(snap.InstanceLabel)
	if primLabel == "" {
		primLabel = "主实例"
	}
	maxW := snap.MaxLiveWorkers
	if maxW <= 0 {
		maxW = 8
	}
	allModels := make([]string, 0, len(AgyModels))
	for _, m := range AgyModels {
		allModels = append(allModels, m.ID)
	}
	return []AccountProfile{
		{
			ID:             primID,
			Label:          primLabel,
			Primary:        true,
			Enabled:        true,
			ProxyPreset:    "direct",
			MaxLiveWorkers: maxW,
			BoundKeys:      []string{},
			AllowedModels:  allModels,
			DefaultModels:  allModels,
		},
	}
}

// Init loads or seeds accounts.json and starts workers for any authenticated non-primary accounts.
func (am *AccountManager) Init() {
	if isChildAccountWorker() {
		return
	}
	am.mu.Lock()
	am.filePath, am.baseDataDir = resolveAccountsFilePath()
	loaded := am.loadFromDiskLocked()
	if !loaded || len(am.accounts) == 0 {
		if !testing.Testing() || gwcfg.Current().AccountsFile != "" {
			am.accounts = defaultSeededAccounts()
			_ = am.saveToDiskLocked()
		} else {
			am.accounts = nil
		}
	}
	accountsCopy := make([]AccountProfile, len(am.accounts))
	copy(accountsCopy, am.accounts)
	am.mu.Unlock()

	for _, acc := range accountsCopy {
		if !acc.Primary && acc.Enabled && am.HasOAuthToken(acc.ID) {
			_ = am.EnsureAccountWorkerRunning(acc.ID)
		}
	}
}

func (am *AccountManager) ensureInitialized() {
	am.mu.RLock()
	fp := am.filePath
	ready := len(am.accounts) > 0
	am.mu.RUnlock()
	if !ready && (!testing.Testing() || gwcfg.Current().AccountsFile != "" || (fp != "" && fileExists(fp))) {
		am.Init()
	}
}

func (am *AccountManager) loadFromDiskLocked() bool {
	if am.filePath == "" || !fileExists(am.filePath) {
		return false
	}
	b, err := os.ReadFile(am.filePath)
	if err != nil {
		return false
	}
	var f accountsFileSchema
	if err := json.Unmarshal(b, &f); err != nil || len(f.Accounts) == 0 {
		return false
	}
	am.accounts = normalizeAccountsList(f.Accounts, f.Version)
	return true
}

func normalizeAccountsList(in []AccountProfile, schemaVer int) []AccountProfile {
	out := make([]AccountProfile, 0, len(in))
	seen := make(map[string]bool)
	hasPrimary := false
	for _, a := range in {
		a.ID = strings.ToLower(strings.TrimSpace(a.ID))
		if !validAccountIDRe.MatchString(a.ID) || seen[a.ID] {
			continue
		}
		seen[a.ID] = true
		a.Label = strings.TrimSpace(a.Label)
		if a.Label == "" {
			a.Label = a.ID
		}
		if a.Primary {
			if hasPrimary {
				a.Primary = false
			} else {
				hasPrimary = true
			}
		}
		if a.MaxLiveWorkers <= 0 {
			if a.Primary {
				a.MaxLiveWorkers = 8
			} else {
				a.MaxLiveWorkers = 3
			}
		}
		if a.ProxyPreset == "" {
			a.ProxyPreset = "direct"
		}
		if a.BoundKeys == nil {
			a.BoundKeys = []string{}
		}
		out = append(out, a)
	}
	if len(out) > 0 && !hasPrimary {
		out[0].Primary = true
	}

	// For v1 -> v2 migration, collect models claimed by non-primary accounts so primary retains all other models cleanly.
	nonPrimClaimed := make(map[string]bool)
	if schemaVer < 2 {
		for _, a := range out {
			if !a.Primary {
				src := a.AllowedModels
				if src == nil {
					src = a.DefaultModels
				}
				for _, cid := range normalizeCanonicalModelList(src) {
					nonPrimClaimed[cid] = true
				}
			}
		}
	}
	for i := range out {
		a := &out[i]
		if a.AllowedModels == nil {
			if schemaVer < 2 && a.Primary {
				primSet := make([]string, 0, len(AgyModels))
				for _, m := range AgyModels {
					if !nonPrimClaimed[m.ID] {
						primSet = append(primSet, m.ID)
					}
				}
				if len(primSet) == 0 {
					for _, m := range AgyModels {
						primSet = append(primSet, m.ID)
					}
				}
				a.AllowedModels = primSet
			} else if len(a.DefaultModels) > 0 {
				a.AllowedModels = normalizeCanonicalModelList(a.DefaultModels)
			} else {
				a.AllowedModels = []string{}
			}
		} else {
			a.AllowedModels = normalizeCanonicalModelList(a.AllowedModels)
		}
		a.DefaultModels = append([]string{}, a.AllowedModels...)
	}
	return out
}

func (am *AccountManager) saveToDiskLocked() error {
	if am.filePath == "" {
		am.filePath, am.baseDataDir = resolveAccountsFilePath()
	}
	if err := os.MkdirAll(filepath.Dir(am.filePath), 0o700); err != nil {
		return err
	}
	payload := accountsFileSchema{
		Version:  2,
		Accounts: am.accounts,
	}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	tmp := am.filePath + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, am.filePath)
}

func (am *AccountManager) AccountHomeDir(accountID string) string {
	am.ensureInitialized()
	am.mu.RLock()
	base := am.baseDataDir
	var isPrim bool
	for _, a := range am.accounts {
		if a.ID == accountID && a.Primary {
			isPrim = true
			break
		}
	}
	am.mu.RUnlock()
	if isPrim {
		return filepath.Dir(PureApiHome)
	}
	return filepath.Join(base, "accounts", accountID)
}

func (am *AccountManager) AccountTokenPath(accountID string) string {
	am.ensureInitialized()
	am.mu.RLock()
	var isPrim bool
	for _, a := range am.accounts {
		if a.ID == accountID && a.Primary {
			isPrim = true
			break
		}
	}
	am.mu.RUnlock()
	if isPrim {
		return filepath.Join(PureApiHome, "antigravity-cli", "antigravity-oauth-token")
	}
	return filepath.Join(am.AccountHomeDir(accountID), ".gemini", "antigravity-cli", "antigravity-oauth-token")
}

func (am *AccountManager) InvalidateTokenCache(accountID string) {
	am.tokCacheMu.Lock()
	if accountID == "" {
		am.tokCache = make(map[string]tokenCacheEntry)
	} else {
		delete(am.tokCache, accountID)
	}
	am.tokCacheMu.Unlock()
}

func (am *AccountManager) HasOAuthToken(accountID string) bool {
	if !testing.Testing() {
		am.tokCacheMu.RLock()
		if ce, ok := am.tokCache[accountID]; ok && time.Since(ce.checkedAt) < 2*time.Second {
			am.tokCacheMu.RUnlock()
			return ce.exists
		}
		am.tokCacheMu.RUnlock()
	}
	p := am.AccountTokenPath(accountID)
	info, err := os.Stat(p)
	exists := err == nil && !info.IsDir() && info.Size() > 16
	if !testing.Testing() {
		am.tokCacheMu.Lock()
		am.tokCache[accountID] = tokenCacheEntry{exists: exists, checkedAt: time.Now()}
		am.tokCacheMu.Unlock()
	}
	return exists
}

// ResolveAccountProxy turns an AccountProfile's proxyPreset / customProxy into an upstream HTTP/SOCKS5
// proxy URL at runtime without persisting or exposing proxy tokens in accounts.json.
func (am *AccountManager) ResolveAccountProxy(acc AccountProfile) string {
	preset := strings.ToLower(strings.TrimSpace(acc.ProxyPreset))
	snap := gwcfg.Current()
	switch preset {
	case "", "direct":
		if acc.Primary {
			return snap.UpstreamProxy
		}
		return ""
	case "custom":
		if err := validateCustomProxyURL(acc.CustomProxy); err != nil {
			return ""
		}
		return strings.TrimSpace(acc.CustomProxy)
	default:
		if !validProxyPresetRe.MatchString(preset) {
			return ""
		}
		resinTok := snap.ResinProxyToken
		resinHost := snap.ResinHost
		if resinHost == "" {
			resinHost = "resin:2260"
		}
		if resinTok == "" {
			// Fallback: extract password from AGY_UPSTREAM_PROXY if formatted as http://user:pass@host:port
			if raw := snap.UpstreamProxy; raw != "" {
				if u, err := url.Parse(raw); err == nil && u.User != nil {
					if pw, ok := u.User.Password(); ok && pw != "" {
						resinTok = pw
						if u.Host != "" {
							resinHost = u.Host
						}
					}
				}
			}
		}
		if resinTok == "" {
			if err := validateCustomProxyURL(acc.CustomProxy); err == nil {
				return strings.TrimSpace(acc.CustomProxy)
			}
			return ""
		}
		u := &url.URL{
			Scheme: "http",
			User:   url.UserPassword(preset+"."+acc.ID, resinTok),
			Host:   resinHost,
		}
		return u.String()
	}
}

func (am *AccountManager) ListAccounts() []AccountProfile {
	am.ensureInitialized()
	am.mu.RLock()
	defer am.mu.RUnlock()
	out := make([]AccountProfile, len(am.accounts))
	copy(out, am.accounts)
	return out
}

func (am *AccountManager) GetPrimaryAccount() (AccountProfile, bool) {
	am.ensureInitialized()
	am.mu.RLock()
	defer am.mu.RUnlock()
	for _, a := range am.accounts {
		if a.Primary {
			return a, true
		}
	}
	return AccountProfile{}, false
}

func (am *AccountManager) GetAccount(id string) (AccountProfile, bool) {
	am.ensureInitialized()
	am.mu.RLock()
	defer am.mu.RUnlock()
	for _, a := range am.accounts {
		if a.ID == id {
			return a, true
		}
	}
	return AccountProfile{}, false
}

func (am *AccountManager) allocatePortsLocked(accountID string) (gwPort, dashPort int) {
	if w, ok := am.workers[accountID]; ok && w.gwPort > 0 {
		return w.gwPort, w.dashPort
	}
	idx := 1
	for i, a := range am.accounts {
		if a.ID == accountID {
			idx = i + 1
			break
		}
	}
	used := make(map[int]bool)
	for _, w := range am.workers {
		used[w.gwPort] = true
		used[w.dashPort] = true
	}
	base := 28900 + idx*2
	for used[base] || used[base+1] {
		base += 2
	}
	return base, base + 1
}

// EnsureAccountWorkerRunning spawns or verifies the isolated child gateway process for a non-primary account.
func (am *AccountManager) EnsureAccountWorkerRunning(accountID string) error {
	if isChildAccountWorker() || testing.Testing() {
		return nil
	}
	am.ensureInitialized()
	am.mu.Lock()
	var acc AccountProfile
	found := false
	for _, a := range am.accounts {
		if a.ID == accountID {
			acc = a
			found = true
			break
		}
	}
	if !found {
		am.mu.Unlock()
		return fmt.Errorf("unknown account %q", accountID)
	}
	if acc.Primary {
		am.mu.Unlock()
		return nil
	}
	if w, ok := am.workers[accountID]; ok && w.cmd != nil && w.cmd.Process != nil && !w.stopped {
		readyCh := w.readyCh
		am.mu.Unlock()
		if readyCh != nil {
			<-readyCh
			return w.readyErr
		}
		return nil
	}

	homeDir := filepath.Join(am.baseDataDir, "accounts", acc.ID)
	for _, sub := range []string{"", ".gemini/antigravity-cli", "logs", "workspace"} {
		p := filepath.Join(homeDir, sub)
		if err := os.MkdirAll(p, 0o700); err != nil {
			am.mu.Unlock()
			return err
		}
	}

	gwPort, dashPort := am.allocatePortsLocked(acc.ID)
	exePath, err := os.Executable()
	if err != nil {
		am.mu.Unlock()
		return err
	}
	resolvedProxy := am.ResolveAccountProxy(acc)

	cmd := exec.Command(exePath)
	cmd.Dir = filepath.Join(homeDir, "workspace")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	env := make([]string, 0, len(os.Environ())+16)
	for _, kv := range os.Environ() {
		switch {
		case strings.HasPrefix(kv, "HOME="),
			strings.HasPrefix(kv, "AGY_CHILD_ACCOUNT_WORKER="),
			strings.HasPrefix(kv, "AGY_PURE_API_HOME="),
			strings.HasPrefix(kv, "AGY_DEFAULT_CWD="),
			strings.HasPrefix(kv, "AGY_STATE_DB="),
			strings.HasPrefix(kv, "AGY_TOS_TRIPPED_FILE="),
			strings.HasPrefix(kv, "AGY_GW_LOG="),
			strings.HasPrefix(kv, "AGY_LISTEN_HOST="),
			strings.HasPrefix(kv, "AGY_GW_PORT="),
			strings.HasPrefix(kv, "AGY_DASH_PORT="),
			strings.HasPrefix(kv, "AGY_INSTANCE_ID="),
			strings.HasPrefix(kv, "AGY_INSTANCE_LABEL="),
			strings.HasPrefix(kv, "AGY_MAX_LIVE_WORKERS="),
			strings.HasPrefix(kv, "AGY_UPSTREAM_PROXY="),
			strings.HasPrefix(kv, "AGY_DASHBOARD_PEERS="),
			strings.HasPrefix(kv, "AGY_ACCOUNTS_FILE="),
			strings.HasPrefix(kv, "AGY_PROXY_PRESETS_FILE="),
			strings.HasPrefix(kv, "AGY_RESIN_PROXY_TOKEN="),
			strings.HasPrefix(kv, "AGY_RESIN_HOST="):
			continue
		}
		env = append(env, kv)
	}
	env = append(env,
		"AGY_CHILD_ACCOUNT_WORKER=1",
		"HOME="+homeDir,
		"AGY_PURE_API_HOME="+filepath.Join(homeDir, ".gemini"),
		"AGY_DEFAULT_CWD="+filepath.Join(homeDir, "workspace"),
		"AGY_STATE_DB="+filepath.Join(homeDir, "gateway.db"),
		"AGY_TOS_TRIPPED_FILE="+filepath.Join(homeDir, "tos-tripped"),
		"AGY_GW_LOG="+filepath.Join(homeDir, "logs", "gateway.log"),
		"AGY_LISTEN_HOST=127.0.0.1",
		fmt.Sprintf("AGY_GW_PORT=%d", gwPort),
		fmt.Sprintf("AGY_DASH_PORT=%d", dashPort),
		"AGY_INSTANCE_ID="+acc.ID,
		"AGY_INSTANCE_LABEL="+acc.Label,
		fmt.Sprintf("AGY_MAX_LIVE_WORKERS=%d", acc.MaxLiveWorkers),
		"AGY_UPSTREAM_PROXY="+resolvedProxy,
		"AGY_DASHBOARD_PEERS=",
	)
	cmd.Env = env

	if err := cmd.Start(); err != nil {
		am.mu.Unlock()
		return err
	}

	targetURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", gwPort))
	rp := httputil.NewSingleHostReverseProxy(targetURL)
	rp.FlushInterval = -1
	rp.Transport = &http.Transport{
		Proxy:               nil,
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     60 * time.Second,
	}
	accIDCopy := acc.ID
	rp.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, proxyErr error) {
		writeAccountRouteError(rw, req.URL.Path, http.StatusBadGateway, "account_worker_error", "account_worker_unreachable",
			fmt.Sprintf("Account %q worker proxy error: %s", accIDCopy, gwcfg.RedactSecretsInString(proxyErr.Error())))
	}

	proc := &accountWorkerProc{
		id:       acc.ID,
		gwPort:   gwPort,
		dashPort: dashPort,
		cmd:      cmd,
		proxy:    rp,
		done:     make(chan struct{}),
		readyCh:  make(chan struct{}),
	}
	am.workers[acc.ID] = proc
	am.mu.Unlock()

	go func(p *accountWorkerProc) {
		_ = p.cmd.Wait()
		am.mu.Lock()
		p.stopped = true
		am.mu.Unlock()
		close(p.done)
	}(proc)

	// Wait briefly for child /healthz on loopback, aborting immediately if child exits early
	deadline := time.Now().Add(4 * time.Second)
	healthURL := fmt.Sprintf("http://127.0.0.1:%d/healthz", gwPort)
	healthy := false
	for time.Now().Before(deadline) {
		select {
		case <-proc.done:
			proc.readyErr = fmt.Errorf("worker for account %q exited before becoming healthy", acc.ID)
			close(proc.readyCh)
			return proc.readyErr
		default:
		}
		resp, err := peerHTTPClient.Get(healthURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				healthy = true
				break
			}
		}
		time.Sleep(40 * time.Millisecond)
	}
	if !healthy {
		proc.readyErr = fmt.Errorf("worker for account %q healthz timeout", acc.ID)
	}
	close(proc.readyCh)
	return proc.readyErr
}

func (am *AccountManager) StopAccountWorker(accountID string) {
	am.mu.Lock()
	w, ok := am.workers[accountID]
	if ok {
		delete(am.workers, accountID)
	}
	am.mu.Unlock()
	if ok && w != nil && w.cmd != nil && w.cmd.Process != nil {
		_ = syscall.Kill(-w.cmd.Process.Pid, syscall.SIGTERM)
		if w.done != nil {
			select {
			case <-w.done:
			case <-time.After(7 * time.Second):
				_ = syscall.Kill(-w.cmd.Process.Pid, syscall.SIGKILL)
				<-w.done
			}
		}
	}
}

func (am *AccountManager) StopAll() {
	am.oauthMu.Lock()
	for _, s := range am.oauthActive {
		am.cancelOAuthSessionLocked(s, true)
	}
	am.oauthMu.Unlock()

	am.mu.RLock()
	ids := make([]string, 0, len(am.workers))
	for id := range am.workers {
		ids = append(ids, id)
	}
	am.mu.RUnlock()

	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(accID string) {
			defer wg.Done()
			am.StopAccountWorker(accID)
		}(id)
	}
	wg.Wait()
}

func (am *AccountManager) IsWorkerRunning(accountID string) (running bool, gwPort, dashPort int) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	if w, ok := am.workers[accountID]; ok && w != nil && !w.stopped {
		return true, w.gwPort, w.dashPort
	}
	return false, 0, 0
}

// splitKeyAccountSuffix splits "<master_key>@<account_id>" or "<master_key>#<account_id>".
func splitKeyAccountSuffix(candidate string) (baseKey, accountID string, ok bool) {
	for _, sep := range []string{"@", "#"} {
		if idx := strings.LastIndex(candidate, sep); idx > 0 && idx < len(candidate)-1 {
			base := candidate[:idx]
			acc := strings.ToLower(strings.TrimSpace(candidate[idx+1:]))
			if validAccountIDRe.MatchString(acc) {
				return base, acc, true
			}
		}
	}
	return "", "", false
}

// MatchesAccountKey reports whether candidate matches any account's boundKeys or "<master_key>@<account_id>".
func (am *AccountManager) MatchesAccountKey(candidate string) (accountID string, matched bool) {
	if candidate == "" {
		return "", false
	}
	am.ensureInitialized()
	if base, accID, ok := splitKeyAccountSuffix(candidate); ok {
		if rawMasterKeyMatches(base) {
			if _, exists := am.GetAccount(accID); exists {
				return accID, true
			}
		}
	}
	cBytes := []byte(candidate)
	am.mu.RLock()
	defer am.mu.RUnlock()
	for _, acc := range am.accounts {
		if !acc.Enabled {
			continue
		}
		for _, bk := range acc.BoundKeys {
			bk = strings.TrimSpace(bk)
			if bk != "" && subtle.ConstantTimeCompare(cBytes, []byte(bk)) == 1 {
				return acc.ID, true
			}
		}
	}
	return "", false
}

func quotaBucketStillExhausted(b QuotaBucket, now time.Time) bool {
	if b.RemainingFraction > 0.0005 {
		return false
	}
	if b.ResetTime != "" {
		if rt, err := time.Parse(time.RFC3339, b.ResetTime); err == nil && !now.Before(rt) {
			return false
		}
	}
	return true
}

func extraPoolStillExhausted(ep *ExtraPoolQuota, now time.Time) bool {
	if ep == nil || ep.RemainingFraction == nil || *ep.RemainingFraction > 0.0005 {
		return false
	}
	if ep.ResetTime != "" {
		if rt, err := time.Parse(time.RFC3339, ep.ResetTime); err == nil && !now.Before(rt) {
			return false
		}
	}
	return true
}

func quotaGroupsModel5hExhausted(groups []QuotaGroup, argonPool *ExtraPoolQuota, canonicalModelID string, now time.Time) bool {
	lowModel := strings.ToLower(strings.TrimSpace(canonicalModelID))
	isClaude := strings.HasPrefix(lowModel, "claude-")
	isArgon := lowModel == "gemini-4-argon"
	if isArgon && extraPoolStillExhausted(argonPool, now) {
		return true
	}
	for _, g := range groups {
		if isClaude {
			lowName := strings.ToLower(g.Name)
			if strings.Contains(lowName, "claude") || strings.Contains(lowName, "gpt") {
				for _, b := range g.Buckets {
					if b.Window == "5h" && quotaBucketStillExhausted(b, now) {
						return true
					}
				}
			}
		} else if strings.EqualFold(g.Name, "Gemini Models") {
			for _, b := range g.Buckets {
				if b.Window == "5h" && quotaBucketStillExhausted(b, now) {
					return true
				}
			}
		}
	}
	return false
}

func isPrimaryModel5hExhausted(canonicalModelID string) bool {
	quotaMu.Lock()
	snap := cachedQuota
	snapAt := cachedQuotaAt
	quotaMu.Unlock()
	if snap == nil || time.Since(snapAt) > 20*time.Minute {
		return false
	}
	return quotaGroupsModel5hExhausted(snap.Groups, snap.ArgonPool, canonicalModelID, time.Now())
}

func isAccountModel5hExhausted(accountID string, dashPort int, canonicalModelID string) bool {
	if dashPort <= 0 {
		return false
	}
	cacheKey := fmt.Sprintf("%s|http://127.0.0.1:%d", accountID, dashPort)
	peerDashCacheMu.Lock()
	cached, ok := peerDashCache[cacheKey]
	peerDashCacheMu.Unlock()
	now := time.Now()
	// Trigger non-blocking background refresh if peer quota cache is missing or older than 60s
	if !testing.Testing() && (!ok || cached.decoded == nil || now.Sub(cached.fetchedAt) > 60*time.Second) {
		peer := gwcfg.DashboardPeerConfig{
			ID:      accountID,
			Label:   accountID,
			BaseURL: fmt.Sprintf("http://127.0.0.1:%d", dashPort),
		}
		fallbackKey := defaultPeerAPIKey(gwcfg.Current())
		go func(p gwcfg.DashboardPeerConfig, k string) {
			_, _, _, _, _ = fetchPeerDashboard(p, false, k)
		}(peer, fallbackKey)
	}
	if !ok || cached.decoded == nil || now.Sub(cached.fetchedAt) > 20*time.Minute {
		return false
	}
	return quotaGroupsModel5hExhausted(cached.decoded.Quota.Groups, cached.decoded.Quota.ArgonPool, canonicalModelID, now)
}

func (am *AccountManager) stickyTTL() time.Duration {
	ttl := gwcfg.Current().IdleWorkerTtl
	if ttl < 15*time.Minute {
		ttl = 15 * time.Minute
	}
	return ttl
}

// ClearStickyForAccount drops all sticky session bindings pointing to accountID (e.g., on edit/delete).
func (am *AccountManager) ClearStickyForAccount(accountID string) {
	am.stickyMu.Lock()
	defer am.stickyMu.Unlock()
	for k, v := range am.stickySessions {
		if v.accountID == accountID {
			delete(am.stickySessions, k)
		}
	}
}

// ResolveExplicitAccount resolves an explicit target account from bound API key (highest priority)
// or X-Agy-Account header (only permitted for master keys / auth-disabled, never to override a bound key).
func (am *AccountManager) ResolveExplicitAccount(r *http.Request) (acc AccountProfile, routeMode string, explicit bool, invalidErr error) {
	am.ensureInitialized()
	hdr := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Agy-Account")))
	if reqK := requestKey(r); reqK != "" {
		if accID, ok := am.MatchesAccountKey(reqK); ok {
			if hdr != "" && hdr != accID {
				return AccountProfile{}, "key-bound", true, fmt.Errorf("X-Agy-Account %q cannot override API key bound to account %q", hdr, accID)
			}
			if a, exists := am.GetAccount(accID); exists && a.Enabled {
				return a, "key-bound", true, nil
			}
			return AccountProfile{}, "key-bound", true, fmt.Errorf("account %q bound to this API key is disabled", accID)
		}
	}
	if hdr != "" {
		if a, ok := am.GetAccount(hdr); ok && a.Enabled {
			return a, "header-bound", true, nil
		}
		return AccountProfile{}, "header-bound", true, fmt.Errorf("account %q is not found or disabled", hdr)
	}
	return AccountProfile{}, "", false, nil
}

// ResolveTargetAccount determines which account should serve an incoming API request, enforcing
// strict per-account model allowlists and performing session-sticky round-robin across accounts
// that share the same model when called with a pool/master key.
func (am *AccountManager) ResolveTargetAccount(r *http.Request, canonicalModelID string) (AccountProfile, bool) {
	acc, _, _, status := am.ResolveTargetAccountDetailed(r, canonicalModelID, extractSessionKeyFromHeaders(r))
	return acc, status == 0 && acc.ID != ""
}

// ResolveTargetAccountDetailed returns the chosen account, routeMode, or an HTTP denial error (403/503).
func (am *AccountManager) ResolveTargetAccountDetailed(r *http.Request, canonicalModelID, sessionKey string) (acc AccountProfile, routeMode string, denyErr error, statusCode int) {
	am.ensureInitialized()
	// 1. Explicit header or bound key -> strict single-account routing + strict allowlist
	if expAcc, mode, isExplicit, invErr := am.ResolveExplicitAccount(r); isExplicit {
		if invErr != nil {
			return AccountProfile{}, mode, invErr, http.StatusForbidden
		}
		if canonicalModelID != "" && !expAcc.AllowsModel(canonicalModelID) {
			allowedDesc := "无"
			if len(expAcc.AllowedModels) > 0 {
				allowedDesc = strings.Join(expAcc.AllowedModels, ", ")
			}
			return expAcc, mode, fmt.Errorf("Account %q (%s) does not bind model %q (allowed: %s)", expAcc.ID, expAcc.Label, canonicalModelID, allowedDesc), http.StatusForbidden
		}
		return expAcc, mode, nil, 0
	}

	// 2. Pool / Master key -> select strictly from enabled accounts that bind canonicalModelID
	if canonicalModelID == "" {
		return AccountProfile{}, "", nil, 0
	}

	am.mu.RLock()
	boundEnabled := make([]AccountProfile, 0, len(am.accounts))
	for _, a := range am.accounts {
		if a.Enabled && a.AllowsModel(canonicalModelID) {
			boundEnabled = append(boundEnabled, a)
		}
	}
	am.mu.RUnlock()

	if len(boundEnabled) == 0 {
		return AccountProfile{}, "pool-deny", fmt.Errorf("Model %q is not bound to any enabled account; bind it in /acp/ dashboard first", canonicalModelID), http.StatusForbidden
	}

	authed := make([]AccountProfile, 0, len(boundEnabled))
	for _, a := range boundEnabled {
		if a.Primary || am.HasOAuthToken(a.ID) {
			authed = append(authed, a)
		}
	}
	if len(authed) == 0 {
		return boundEnabled[0], "pool-unauth", fmt.Errorf("No authenticated account available for model %q; authorize one in /acp/ dashboard first", canonicalModelID), http.StatusServiceUnavailable
	}

	// Partition into 5h-healthy vs exhausted (checking BOTH primary and child accounts)
	healthy := make([]AccountProfile, 0, len(authed))
	healthyByID := make(map[string]AccountProfile, len(authed))
	authedByID := make(map[string]AccountProfile, len(authed))
	for _, a := range authed {
		authedByID[a.ID] = a
		exhausted := false
		if a.Primary {
			exhausted = isPrimaryModel5hExhausted(canonicalModelID)
		} else {
			_, _, dashPort := am.IsWorkerRunning(a.ID)
			exhausted = isAccountModel5hExhausted(a.ID, dashPort, canonicalModelID)
		}
		if !exhausted {
			healthy = append(healthy, a)
			healthyByID[a.ID] = a
		}
	}
	pool := healthy
	if len(pool) == 0 {
		pool = authed
	}

	now := time.Now()
	ttl := am.stickyTTL()
	compositeKey := ""
	if sessionKey != "" {
		compositeKey = sessionKey + "|" + canonicalModelID
	}

	am.stickyMu.Lock()
	defer am.stickyMu.Unlock()

	// Throttled TTL prune + hard cap (2048 entries) to bound memory & lock time
	if len(am.stickySessions) > 512 && now.Sub(am.stickyLastPrune) >= time.Minute {
		am.stickyLastPrune = now
		for k, v := range am.stickySessions {
			if now.Sub(v.lastSeen) > ttl {
				delete(am.stickySessions, k)
			}
		}
	}
	const maxStickyEntries = 2048
	if len(am.stickySessions) >= maxStickyEntries {
		// Evict expired first; if still at cap, evict oldest entries until under cap.
		for k, v := range am.stickySessions {
			if now.Sub(v.lastSeen) > ttl {
				delete(am.stickySessions, k)
			}
		}
		for len(am.stickySessions) >= maxStickyEntries {
			var oldestKey string
			var oldestTime time.Time
			for k, v := range am.stickySessions {
				if oldestKey == "" || v.lastSeen.Before(oldestTime) {
					oldestKey = k
					oldestTime = v.lastSeen
				}
			}
			if oldestKey == "" {
				break
			}
			delete(am.stickySessions, oldestKey)
		}
	}

	// 2a. Check sticky hit for (sessionKey, canonicalModelID)
	if compositeKey != "" {
		if entry, ok := am.stickySessions[compositeKey]; ok && now.Sub(entry.lastSeen) <= ttl {
			if len(healthy) > 0 {
				if stickyAcc, okH := healthyByID[entry.accountID]; okH {
					entry.lastSeen = now
					am.stickySessions[compositeKey] = entry
					return stickyAcc, "pool-sticky", nil, 0
				}
			} else if stickyAcc, okA := authedByID[entry.accountID]; okA {
				entry.lastSeen = now
				am.stickySessions[compositeKey] = entry
				return stickyAcc, "pool-sticky", nil, 0
			}
		}
	}

	// 2b. New session (or previous sticky account disabled/5h-exhausted) -> per-model Round-Robin
	rr := am.rrCounters[canonicalModelID]
	chosen := pool[rr%uint64(len(pool))]
	am.rrCounters[canonicalModelID] = rr + 1
	if compositeKey != "" {
		am.stickySessions[compositeKey] = stickyAccountEntry{
			accountID: chosen.ID,
			modelID:   canonicalModelID,
			lastSeen:  now,
		}
	}
	return chosen, "pool-rr", nil, 0
}

// FilterModelsForRequest filters /v1/models output strictly by the caller's bound account or pool allowlists.
func (am *AccountManager) FilterModelsForRequest(r *http.Request, all []map[string]any) (filtered []map[string]any, accountID string) {
	if isChildAccountWorker() || !am.HasConfiguredAccounts() {
		return all, ""
	}
	return am.filterModelItems(r, all, "id")
}

// FilterGeminiModelsForRequest filters /v1beta/models output strictly by the caller's bound account or pool allowlists.
func (am *AccountManager) FilterGeminiModelsForRequest(r *http.Request, all []map[string]any) (filtered []map[string]any, accountID string) {
	if isChildAccountWorker() || !am.HasConfiguredAccounts() {
		return all, ""
	}
	return am.filterModelItems(r, all, "name")
}

func (am *AccountManager) filterModelItems(r *http.Request, all []map[string]any, idField string) (filtered []map[string]any, accountID string) {
	am.ensureInitialized()
	extractCID := func(item map[string]any) string {
		idStr, _ := item[idField].(string)
		idStr = strings.TrimPrefix(idStr, "models/")
		return ResolveRequestedModel(idStr, nil).Model.ID
	}
	if expAcc, _, isExplicit, invErr := am.ResolveExplicitAccount(r); isExplicit {
		if invErr != nil {
			return []map[string]any{}, ""
		}
		out := make([]map[string]any, 0, len(all))
		for _, item := range all {
			if expAcc.AllowsModel(extractCID(item)) {
				out = append(out, item)
			}
		}
		return out, expAcc.ID
	}

	am.mu.RLock()
	enabled := make([]AccountProfile, 0, len(am.accounts))
	for _, a := range am.accounts {
		if a.Enabled {
			enabled = append(enabled, a)
		}
	}
	am.mu.RUnlock()

	out := make([]map[string]any, 0, len(all))
	for _, item := range all {
		cid := extractCID(item)
		for _, a := range enabled {
			if a.AllowsModel(cid) {
				out = append(out, item)
				break
			}
		}
	}
	return out, ""
}

func (am *AccountManager) HasConfiguredAccounts() bool {
	am.ensureInitialized()
	am.mu.RLock()
	defer am.mu.RUnlock()
	return len(am.accounts) > 0
}

func (am *AccountManager) HasNonPrimaryAccounts() bool {
	am.ensureInitialized()
	am.mu.RLock()
	defer am.mu.RUnlock()
	for _, a := range am.accounts {
		if !a.Primary && a.Enabled {
			return true
		}
	}
	return false
}

func extractSessionKeyFromHeaders(r *http.Request) string {
	if r == nil {
		return ""
	}
	for _, hdr := range []string{
		"X-Session-Id",
		"X-Claude-Code-Session-Id",
		"X-Claude-Session-Id",
		"X-Conversation-Id",
		"X-Thread-Id",
		"Session-Id",
		"Conversation-Id",
		"Anthropic-Session-Id",
	} {
		if v := strings.TrimSpace(r.Header.Get(hdr)); v != "" {
			return "hdr:" + v
		}
	}
	return ""
}

type routingModelOnly struct {
	Model string `json:"model"`
}

type routingBodyHints struct {
	PromptCacheKey json.RawMessage   `json:"prompt_cache_key"`
	User           json.RawMessage   `json:"user"`
	Metadata       json.RawMessage   `json:"metadata"`
	System         json.RawMessage   `json:"system"`
	Instructions   json.RawMessage   `json:"instructions"`
	Messages       []json.RawMessage `json:"messages"`
	Input          json.RawMessage   `json:"input"`
	Contents       []json.RawMessage `json:"contents"`
}

func rawJSONString(raw json.RawMessage) string {
	var s string
	if len(raw) > 0 && json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	return ""
}

func clipBytes(b []byte, maxLen int) []byte {
	b = bytes.TrimSpace(b)
	if len(b) > maxLen {
		return b[:maxLen]
	}
	return b
}

func cleanGeminiV1BetaPath(rawPath string) string {
	clean, _ := extractGeminiPathKey(rawPath)
	if clean != "" {
		return clean
	}
	return rawPath
}

func (am *AccountManager) isSimpleSinglePrimary(r *http.Request) (string, bool) {
	if r != nil {
		if strings.TrimSpace(r.Header.Get("X-Agy-Account")) != "" {
			return "", false
		}
		if rawKey := requestKey(r); strings.Contains(rawKey, "@") {
			return "", false
		}
	}
	am.mu.RLock()
	defer am.mu.RUnlock()
	if len(am.accounts) != 1 {
		return "", false
	}
	a := am.accounts[0]
	if !a.Primary || !a.Enabled || len(a.BoundKeys) > 0 {
		return "", false
	}
	for _, m := range AgyModels {
		if !a.AllowsModel(m.ID) {
			return "", false
		}
	}
	return a.ID, true
}

func extractRequestRoutingHints(r *http.Request) (canonicalModel, sessionKey string, rawBody []byte, malformedJSON, tooLarge bool, readErr error) {
	if r == nil || r.URL == nil {
		return "", "", nil, false, false, nil
	}
	sessionKey = extractSessionKeyFromHeaders(r)
	p := cleanGeminiV1BetaPath(r.URL.Path)
	if strings.HasPrefix(p, "/v1beta/models/") {
		rest := strings.TrimPrefix(p, "/v1beta/models/")
		for strings.HasPrefix(rest, "models/") {
			rest = strings.TrimPrefix(rest, "models/")
		}
		if idx := strings.IndexAny(rest, ":/"); idx > 0 {
			rest = rest[:idx]
		}
		if strings.TrimSpace(rest) != "" {
			canonicalModel = ResolveRequestedModel(rest, nil).Model.ID
		}
	}
	if r.Body == nil || r.Method != http.MethodPost {
		return canonicalModel, sessionKey, nil, false, false, nil
	}
	if r.ContentLength > MaxBodyBytes {
		return canonicalModel, sessionKey, nil, false, true, nil
	}
	origBody := r.Body
	raw, err := io.ReadAll(io.LimitReader(origBody, MaxBodyBytes+1))
	_ = origBody.Close()
	if err != nil {
		return canonicalModel, sessionKey, nil, false, false, err
	}
	if int64(len(raw)) > MaxBodyBytes {
		return canonicalModel, sessionKey, nil, false, true, nil
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	r.ContentLength = int64(len(raw))
	r.TransferEncoding = nil

	trimmedRaw := bytes.TrimSpace(raw)
	if len(trimmedRaw) == 0 || trimmedRaw[0] != '{' {
		return canonicalModel, sessionKey, raw, true, false, nil
	}

	// Extract "model" independently so non-string optional hint fields can never break model extraction.
	var mo routingModelOnly
	if err := json.Unmarshal(raw, &mo); err != nil {
		return canonicalModel, sessionKey, raw, true, false, nil
	}
	if canonicalModel == "" && strings.TrimSpace(mo.Model) != "" {
		canonicalModel = ResolveRequestedModel(mo.Model, nil).Model.ID
	}

	var hints routingBodyHints
	if sessionKey == "" && json.Unmarshal(raw, &hints) == nil {
		if k := rawJSONString(hints.PromptCacheKey); k != "" {
			sessionKey = "pck:" + k
		} else {
			var metaObj struct {
				UserID string `json:"user_id"`
			}
			metaUID := ""
			if len(hints.Metadata) > 0 && json.Unmarshal(hints.Metadata, &metaObj) == nil {
				metaUID = strings.TrimSpace(metaObj.UserID)
			}
			// Claude Code embeds per-session UUID in metadata.user_id (e.g. user_..._session_<uuid>).
			// For generic user IDs without a session marker, prefer conversation fingerprint so parallel threads split cleanly.
			if metaUID != "" && strings.Contains(strings.ToLower(metaUID), "session") {
				sessionKey = "meta:" + metaUID
			} else {
				var firstMsg []byte
				if len(hints.Messages) > 0 {
					firstMsg = clipBytes(hints.Messages[0], 1024)
				} else if len(hints.Contents) > 0 {
					firstMsg = clipBytes(hints.Contents[0], 1024)
				} else if len(hints.Input) > 0 {
					trimmed := bytes.TrimSpace(hints.Input)
					if len(trimmed) > 0 && trimmed[0] == '[' {
						var arr []json.RawMessage
						if json.Unmarshal(trimmed, &arr) == nil && len(arr) > 0 {
							firstMsg = clipBytes(arr[0], 1024)
						}
					} else {
						firstMsg = clipBytes(trimmed, 1024)
					}
				}
				sysPart := clipBytes(hints.System, 512)
				if len(sysPart) == 0 {
					sysPart = clipBytes(hints.Instructions, 512)
				}
				if len(firstMsg) > 0 || len(sysPart) > 0 {
					h := sha256.New()
					h.Write(sysPart)
					h.Write([]byte{'|'})
					h.Write(firstMsg)
					sessionKey = "fp:" + hex.EncodeToString(h.Sum(nil))[:16]
				} else if metaUID != "" {
					sessionKey = "meta:" + metaUID
				} else if k := rawJSONString(hints.User); k != "" {
					sessionKey = "usr:" + k
				}
			}
		}
	}
	return canonicalModel, sessionKey, raw, false, false, nil
}

func writeAccountRouteError(w http.ResponseWriter, path string, statusCode int, errType, errCode, msg string) {
	if strings.HasPrefix(path, "/v1beta/") {
		writeGeminiError(w, statusCode, msg)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type": "error",
		"error": map[string]any{
			"type":    errType,
			"code":    errCode,
			"message": msg,
		},
	})
}

// TryRouteAPIRequest routes /v1/* and /v1beta/* requests with strict per-account model allowlists
// and session-sticky round-robin across accounts sharing a model. Returns the (possibly context-enriched)
// request and true if handled/proxied.
func (am *AccountManager) TryRouteAPIRequest(w http.ResponseWriter, r *http.Request) (*http.Request, bool) {
	if isChildAccountWorker() || !am.HasConfiguredAccounts() {
		return r, false
	}
	p := cleanGeminiV1BetaPath(r.URL.Path)
	isModelList := r.Method == http.MethodGet && (p == "/v1/models" || p == "/v1beta/models" || p == "/v1beta/models/")
	if isModelList {
		if expAcc, mode, isExplicit, invErr := am.ResolveExplicitAccount(r); isExplicit {
			if invErr != nil {
				writeAccountRouteError(w, p, http.StatusForbidden, "permission_error", "account_not_available", invErr.Error())
				return r, true
			}
			w.Header().Set("X-Agy-Account", expAcc.ID)
			w.Header().Set("X-Agy-Route-Mode", mode)
		}
		return r, false
	}
	isPostGen := r.Method == http.MethodPost && (p == "/v1/messages" || p == "/v1/chat/completions" || p == "/v1/responses" || p == "/v1/messages/count_tokens")
	isV1BetaModelOp := strings.HasPrefix(p, "/v1beta/models/") && strings.Trim(strings.TrimPrefix(p, "/v1beta/models/"), "/") != ""
	if !isPostGen && !isV1BetaModelOp {
		return r, false
	}

	// Single-account fast path: skip pre-reading request body when only the unrestricted primary exists.
	if primaryID, fast := am.isSimpleSinglePrimary(r); fast {
		w.Header().Set("X-Agy-Account", primaryID)
		w.Header().Set("X-Agy-Route-Mode", "primary-fast")
		return r, false
	}

	modelID, sessionKey, rawBody, malformedJSON, tooLarge, readErr := extractRequestRoutingHints(r)
	if tooLarge {
		writeAccountRouteError(w, p, http.StatusRequestEntityTooLarge, "invalid_request_error", "request_too_large", "Request body exceeds maximum size")
		return r, true
	}
	if readErr != nil {
		writeAccountRouteError(w, p, http.StatusBadRequest, "invalid_request_error", "body_read_error", "Failed to read request body")
		return r, true
	}
	if rawBody != nil {
		r = withPreReadBody(r, rawBody)
	}
	// Let invalid explicit account targeting fail fast even on malformed bodies;
	// otherwise let malformed POST bodies fall through to the native protocol 400 Bad Request handler.
	if r.Method == http.MethodPost && malformedJSON {
		if _, _, isExplicit, invErr := am.ResolveExplicitAccount(r); isExplicit && invErr != nil {
			writeAccountRouteError(w, p, http.StatusForbidden, "permission_error", "account_not_available", invErr.Error())
			return r, true
		}
		return r, false
	}

	// Resolve missing/empty "model" on generation/count_tokens POST to DefaultModelID so allowlists can never be bypassed.
	if modelID == "" && isPostGen {
		modelID = ResolveRequestedModel("", nil).Model.ID
	}

	acc, routeMode, denyErr, statusCode := am.ResolveTargetAccountDetailed(r, modelID, sessionKey)
	if denyErr != nil {
		if acc.ID != "" {
			w.Header().Set("X-Agy-Account", acc.ID)
		}
		if routeMode != "" {
			w.Header().Set("X-Agy-Route-Mode", routeMode)
		}
		errType := "permission_error"
		errCode := "model_not_allowed"
		if statusCode == http.StatusServiceUnavailable {
			errType = "account_not_authenticated"
			errCode = "account_not_authenticated"
		}
		writeAccountRouteError(w, p, statusCode, errType, errCode, denyErr.Error())
		return r, true
	}

	if acc.ID == "" || acc.Primary {
		if acc.ID != "" {
			w.Header().Set("X-Agy-Account", acc.ID)
		}
		if routeMode != "" {
			w.Header().Set("X-Agy-Route-Mode", routeMode)
		}
		return r, false
	}
	if !am.HasOAuthToken(acc.ID) {
		w.Header().Set("X-Agy-Account", acc.ID)
		w.Header().Set("X-Agy-Route-Mode", routeMode)
		writeAccountRouteError(w, p, http.StatusServiceUnavailable, "account_not_authenticated", "account_not_authenticated",
			fmt.Sprintf("Account %q (%s) has no OAuth credentials yet; authorize it in the /acp/ dashboard first.", acc.ID, acc.Label))
		return r, true
	}
	if err := am.EnsureAccountWorkerRunning(acc.ID); err != nil {
		writeAccountRouteError(w, p, http.StatusBadGateway, "account_worker_error", "account_worker_error",
			fmt.Sprintf("Failed to start worker for account %q: %v", acc.ID, err))
		return r, true
	}

	am.mu.RLock()
	proc := am.workers[acc.ID]
	proxy := (*httputil.ReverseProxy)(nil)
	if proc != nil && !proc.stopped {
		proxy = proc.proxy
	}
	am.mu.RUnlock()
	if proxy == nil {
		writeAccountRouteError(w, p, http.StatusServiceUnavailable, "account_worker_error", "account_worker_unavailable",
			fmt.Sprintf("Worker for account %q is temporarily unavailable; retry shortly.", acc.ID))
		return r, true
	}

	// Rewrite outbound auth header to primary master key so child worker accepts it regardless of boundKey/@suffix
	if masterKey := defaultPeerAPIKey(gwcfg.Current()); masterKey != "" {
		r.Header.Set("x-api-key", masterKey)
		r.Header.Del("Authorization")
		r.Header.Del("x-goog-api-key")
	}
	w.Header().Set("X-Agy-Account", acc.ID)
	if routeMode != "" {
		w.Header().Set("X-Agy-Route-Mode", routeMode)
	}
	proxy.ServeHTTP(w, r)
	return r, true
}

// Keep unused error import lint-clean if needed.
var _ = errors.New
