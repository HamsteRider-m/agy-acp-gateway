package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	reversibleSegPrefix = "wsseg_"
	reversibleTagPrefix = "wstag_"
	reversibleTokenLen  = 14 // 6-byte prefix + 8 lowercase hex chars
	reversibleMaxHold   = reversibleTokenLen - 1
)

var (
	// Vendor-prefixed host XML wrapper tags (never matches standard HTML/JSX tags like <div>, <span>, <Button>).
	vendorWrapperTagRe = regexp.MustCompile(
		`<(/?)\s*((?i:` +
			`claude_[a-zA-Z0-9_-]*` +
			`|dsh_[a-zA-Z0-9_-]*` +
			`|deepseek_[a-zA-Z0-9_-]*` +
			`|codex_[a-zA-Z0-9_-]*` +
			`|cursor_[a-zA-Z0-9_-]*` +
			`|windsurf_[a-zA-Z0-9_-]*` +
			`|cline_[a-zA-Z0-9_-]*` +
			`|roo_[a-zA-Z0-9_-]*` +
			`|kilo_[a-zA-Z0-9_-]*` +
			`|opencode_[a-zA-Z0-9_-]*` +
			`|openclaw_[a-zA-Z0-9_-]*` +
			`|clawdbot_[a-zA-Z0-9_-]*` +
			`|augment_[a-zA-Z0-9_-]*` +
			`|anthropic_[a-zA-Z0-9_-]*` +
			`|environment_details` +
			`))\b([^>]*)>`,
	)

	// High-risk vendor/harness phrases that may appear inside masked file paths or quoted checkout paths
	// (e.g. "/Applications/DeepSeek Harness.app/..." or "C:\Program Files\Claude Code\...").
	sensitivePathPhraseRe = regexp.MustCompile(
		`(?i)DeepSeek[\s_-]+Harness` +
			`|Claude[\s_-]+Code` +
			`|Claude[\s_-]+Agent[\s_-]+SDK` +
			`|OpenAI[\s_-]+Codex` +
			`|Codex[\s_-]+CLI` +
			`|Anthropic` +
			`|OpenClaw` +
			`|ClawdBot` +
			`|Roo[\s_-]+Code` +
			`|Kilo[\s_-]+Code` +
			`|Augment[\s_-]+Code` +
			`|PI-Desktop`,
	)

	toolVendorTokenReplacements = []textReplacement{
		{regexp.MustCompile(`(?i)deepseek[_-]+harness`), "ws_harness"},
		{regexp.MustCompile(`(?i)DeepSeekHarness`), "WsHarness"},
		{regexp.MustCompile(`(?i)claude[_-]+code`), "ws_agent"},
		{regexp.MustCompile(`(?i)ClaudeCode`), "WsAgent"},
		{regexp.MustCompile(`(?i)codex[_-]+cli`), "ws_cli"},
		{regexp.MustCompile(`(?i)open[_-]?claw`), "ws_claw"},
		{regexp.MustCompile(`(?i)clawd[_-]?bot`), "ws_bot"},
		{regexp.MustCompile(`(?i)roo[_-]+code`), "ws_roo"},
		{regexp.MustCompile(`(?i)kilo[_-]+code`), "ws_kilo"},
		{regexp.MustCompile(`(?i)augment[_-]+code`), "ws_augment"},
		{regexp.MustCompile(`(?i)^dsh([_-])`), "ws${1}"},
		{regexp.MustCompile(`(?i)([_-])dsh([_-])`), "${1}ws${2}"},
		{regexp.MustCompile(`(?i)([_-])dsh$`), "${1}ws"},
		{regexp.MustCompile(`(?i)^claude([_-])`), "ws${1}"},
		{regexp.MustCompile(`(?i)([_-])claude([_-])`), "${1}ws${2}"},
		{regexp.MustCompile(`(?i)^anthropic([_-])`), "provider${1}"},
		{regexp.MustCompile(`(?i)([_-])anthropic([_-])`), "${1}provider${2}"},
		{regexp.MustCompile(`(?i)^codex([_-])`), "ws${1}"},
		{regexp.MustCompile(`(?i)([_-])codex([_-])`), "${1}ws${2}"},
	}
)

// NeutralizeToolIdentifier rewrites third-party agent/vendor tokens inside client tool identifiers
// (such as "dsh_present" -> "ws_present" or "mcp__claude_code__open" -> "mcp__ws_agent__open")
// while keeping standard tool names ("Bash", "Read", "Edit", "Write", "Grep", "Glob", etc.) unchanged.
func NeutralizeToolIdentifier(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || isInternalBridgeTool(trimmed) {
		return trimmed
	}
	out := trimmed
	for _, item := range toolVendorTokenReplacements {
		out = item.re.ReplaceAllString(out, item.repl)
	}
	return out
}

// ReversibleSessionCodec maintains a deterministic per-session bidirectional mapping between
// sensitive client path segments / vendor XML wrapper tags and fixed 14-byte neutral tokens
// (wsseg_<8hex>, wstag_<8hex>), inspired by gpt-load's deterministic redaction token design
// while preserving natural-language readability and upstream TPU prefix cache stability.
type ReversibleSessionCodec struct {
	mu            sync.RWMutex
	key           []byte
	origToAlias   map[string]string
	aliasToOrig   map[string]string
	empty         atomic.Bool
	historySeeded atomic.Bool
}

func NewReversibleSessionCodec(tenantKey string) *ReversibleSessionCodec {
	if tenantKey == "" {
		tenantKey = "default-session"
	}
	c := &ReversibleSessionCodec{
		key:         []byte("agy-reversible-v1:" + tenantKey),
		origToAlias: make(map[string]string),
		aliasToOrig: make(map[string]string),
	}
	c.empty.Store(true)
	return c
}

func (c *ReversibleSessionCodec) SetTenantKey(tenantKey string) {
	if c == nil || tenantKey == "" {
		return
	}
	c.mu.Lock()
	c.key = []byte("agy-reversible-v1:" + tenantKey)
	c.mu.Unlock()
}

func (c *ReversibleSessionCodec) IsEmpty() bool {
	if c == nil {
		return true
	}
	return c.empty.Load()
}

func (c *ReversibleSessionCodec) Count() int {
	if c == nil || c.empty.Load() {
		return 0
	}
	c.mu.RLock()
	n := len(c.aliasToOrig)
	c.mu.RUnlock()
	return n
}

func (c *ReversibleSessionCodec) getOrCreateAlias(prefix, orig string) string {
	if orig == "" {
		return ""
	}
	scopedKey := prefix + orig
	c.mu.RLock()
	if existing, ok := c.origToAlias[scopedKey]; ok {
		c.mu.RUnlock()
		return existing
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.origToAlias[scopedKey]; ok {
		return existing
	}
	for attempt := 0; ; attempt++ {
		mac := hmac.New(sha256.New, c.key)
		mac.Write([]byte(scopedKey))
		if attempt > 0 {
			mac.Write([]byte{0})
			mac.Write([]byte{byte(attempt)})
		}
		sum := mac.Sum(nil)
		cand := prefix + hex.EncodeToString(sum[:4]) // 6 + 8 = 14 ASCII bytes
		if prevOrig, taken := c.aliasToOrig[cand]; !taken || prevOrig == orig {
			c.origToAlias[scopedKey] = cand
			c.aliasToOrig[cand] = orig
			c.empty.Store(false)
			return cand
		}
	}
}

func (c *ReversibleSessionCodec) Lookup(alias string) (string, bool) {
	if c == nil || len(alias) != reversibleTokenLen || c.empty.Load() {
		return "", false
	}
	c.mu.RLock()
	orig, ok := c.aliasToOrig[alias]
	c.mu.RUnlock()
	return orig, ok
}

// EncodeOutboundText replaces vendor XML wrapper tags with wstag_<8hex> and sensitive vendor phrases
// inside path/identifier spans with wsseg_<8hex>, registering reversible entries in the session table.
func (c *ReversibleSessionCodec) EncodeOutboundText(s string) string {
	if c == nil || s == "" {
		return s
	}

	// 1. Alias vendor-prefixed XML wrapper tags: <dsh_artifact id="1"> -> <wstag_xxxxxxxx id="1">
	if strings.IndexByte(s, '<') >= 0 && vendorWrapperTagRe.MatchString(s) {
		s = vendorWrapperTagRe.ReplaceAllStringFunc(s, func(full string) string {
			sub := vendorWrapperTagRe.FindStringSubmatch(full)
			if len(sub) != 4 {
				return full
			}
			alias := c.getOrCreateAlias(reversibleTagPrefix, sub[2])
			return "<" + sub[1] + alias + sub[3] + ">"
		})
	}

	// 2. Alias sensitive vendor phrases remaining inside file paths, Windows paths, and quoted paths
	// (including unquoted spaced paths like /Applications/DeepSeek Harness.app/...) after Layer A
	// SanitizeOutboundText has already rewritten ordinary prose mentions.
	if sensitivePathPhraseRe.MatchString(s) {
		s = sensitivePathPhraseRe.ReplaceAllStringFunc(s, func(phrase string) string {
			return c.getOrCreateAlias(reversibleSegPrefix, phrase)
		})
	}
	return s
}

func (c *ReversibleSessionCodec) EncodePromptBlocks(blocks []map[string]any) []map[string]any {
	if c == nil || len(blocks) == 0 {
		return blocks
	}
	out := make([]map[string]any, len(blocks))
	for i, blk := range blocks {
		cp := make(map[string]any, len(blk))
		for k, v := range blk {
			cp[k] = v
		}
		if txt, ok := cp["text"].(string); ok && txt != "" {
			cp["text"] = c.EncodeOutboundText(txt)
		}
		if res, ok := cp["resource"].(map[string]any); ok && res != nil {
			resCp := make(map[string]any, len(res))
			for rk, rv := range res {
				resCp[rk] = rv
			}
			if rt, okT := resCp["text"].(string); okT && rt != "" {
				resCp["text"] = c.EncodeOutboundText(rt)
			}
			cp["resource"] = resCp
		}
		out[i] = cp
	}
	return out
}

func (c *ReversibleSessionCodec) EncodeValue(v any) any {
	if c == nil || v == nil {
		return v
	}
	switch x := v.(type) {
	case string:
		return c.EncodeOutboundText(x)
	case []string:
		out := make([]string, len(x))
		for i, elem := range x {
			out[i] = c.EncodeOutboundText(elem)
		}
		return out
	case map[string]any:
		return c.EncodeMap(x)
	case []any:
		out := make([]any, len(x))
		for i, elem := range x {
			out[i] = c.EncodeValue(elem)
		}
		return out
	default:
		return v
	}
}

func (c *ReversibleSessionCodec) EncodeMap(m map[string]any) map[string]any {
	if c == nil || m == nil {
		return m
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[c.EncodeOutboundText(k)] = c.EncodeValue(v)
	}
	return out
}

func (c *ReversibleSessionCodec) SeedFromToolsCatalog(cat []ToolDef) {
	if c == nil || len(cat) == 0 {
		return
	}
	for _, t := range cat {
		if t.Description != "" {
			_ = c.EncodeOutboundText(t.Description)
		}
		if t.Parameters != nil {
			_ = c.EncodeMap(t.Parameters)
		}
	}
}

// SeedFromConversation deterministically repopulates alias mappings after a gateway process restart
// so resumed ACP sessions still restore wsseg_*/wstag_* tokens generated on earlier turns.
func (c *ReversibleSessionCodec) SeedFromConversation(sysText string, messages []map[string]any) {
	if c == nil {
		return
	}
	c.historySeeded.Store(true)
	if sysText != "" {
		_ = c.EncodeOutboundText(sysText)
	}
	for _, m := range messages {
		if txt := formatSingleMessageText(m); txt != "" {
			_ = c.EncodeOutboundText(txt)
		}
	}
}

func (c *ReversibleSessionCodec) SeedFromConversationOnce(sysText string, messages []map[string]any) {
	if c == nil || c.historySeeded.Swap(true) {
		return
	}
	if sysText != "" {
		_ = c.EncodeOutboundText(sysText)
	}
	for _, m := range messages {
		if txt := formatSingleMessageText(m); txt != "" {
			_ = c.EncodeOutboundText(txt)
		}
	}
}

func (c *ReversibleSessionCodec) MarkHistorySeeded() {
	if c != nil {
		c.historySeeded.Store(true)
	}
}

func isLowerHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')
}

func hasReversiblePrefixAt(s string, pos int) bool {
	if pos+6 > len(s) {
		return false
	}
	p := s[pos : pos+6]
	return p == reversibleSegPrefix || p == reversibleTagPrefix
}

func isCompleteReversibleTokenAt(s string, pos int) bool {
	if pos+reversibleTokenLen > len(s) || !hasReversiblePrefixAt(s, pos) {
		return false
	}
	for i := pos + 6; i < pos+reversibleTokenLen; i++ {
		if !isLowerHexByte(s[i]) {
			return false
		}
	}
	return true
}

func isPartialReversiblePrefix(tail string) bool {
	n := len(tail)
	if n == 0 || n >= reversibleTokenLen {
		return false
	}
	if n <= 6 {
		return strings.HasPrefix(reversibleSegPrefix, tail) || strings.HasPrefix(reversibleTagPrefix, tail)
	}
	p := tail[:6]
	if p != reversibleSegPrefix && p != reversibleTagPrefix {
		return false
	}
	for i := 6; i < n; i++ {
		if !isLowerHexByte(tail[i]) {
			return false
		}
	}
	return true
}

// RestoreText replaces any registered wsseg_<8hex> / wstag_<8hex> tokens in s with their exact originals.
func (c *ReversibleSessionCodec) RestoreText(s string) string {
	if c == nil || c.empty.Load() || len(s) < reversibleTokenLen {
		return s
	}
	if !strings.Contains(s, "ws") {
		return s
	}
	var b strings.Builder
	changed := false
	last := 0
	for i := 0; i <= len(s)-reversibleTokenLen; {
		if s[i] == 'w' && isCompleteReversibleTokenAt(s, i) {
			tok := s[i : i+reversibleTokenLen]
			if orig, ok := c.Lookup(tok); ok {
				if !changed {
					b.Grow(len(s) + 32)
					changed = true
				}
				b.WriteString(s[last:i])
				b.WriteString(orig)
				i += reversibleTokenLen
				last = i
				continue
			}
		}
		i++
	}
	if !changed {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// RestoreValue recursively restores reversible tokens inside decoded tool call JSON structures.
func (c *ReversibleSessionCodec) RestoreValue(v any) any {
	if c == nil || c.empty.Load() || v == nil {
		return v
	}
	switch x := v.(type) {
	case string:
		return c.RestoreText(x)
	case []string:
		out := make([]string, len(x))
		for i, elem := range x {
			out[i] = c.RestoreText(elem)
		}
		return out
	case map[string]any:
		return c.RestoreMap(x)
	case []any:
		out := make([]any, len(x))
		for i, elem := range x {
			out[i] = c.RestoreValue(elem)
		}
		return out
	default:
		return v
	}
}

func (c *ReversibleSessionCodec) RestoreMap(m map[string]any) map[string]any {
	if c == nil || c.empty.Load() || m == nil {
		return m
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[c.RestoreText(k)] = c.RestoreValue(v)
	}
	return out
}

// StreamRestorer restores wsseg_<8hex> / wstag_<8hex> tokens across arbitrary streaming chunk boundaries,
// holding at most 13 trailing bytes when a partial token prefix appears at the end of a chunk and
// holding 0 bytes when the session codec has no registered entries.
type StreamRestorer struct {
	codec   *ReversibleSessionCodec
	pending string
}

func (c *ReversibleSessionCodec) NewStreamRestorer() *StreamRestorer {
	return &StreamRestorer{codec: c}
}

func (r *StreamRestorer) Push(chunk string) string {
	if r == nil || chunk == "" {
		return chunk
	}
	if r.codec == nil || r.codec.IsEmpty() {
		if r.pending != "" {
			out := r.pending + chunk
			r.pending = ""
			return out
		}
		return chunk
	}
	buf := r.pending + chunk
	r.pending = ""

	maxHold := reversibleMaxHold
	if len(buf) < maxHold {
		maxHold = len(buf)
	}
	holdLen := 0
	for k := maxHold; k >= 1; k-- {
		if isPartialReversiblePrefix(buf[len(buf)-k:]) {
			holdLen = k
			break
		}
	}
	safe := buf[:len(buf)-holdLen]
	r.pending = buf[len(buf)-holdLen:]
	if safe == "" {
		return ""
	}
	return r.codec.RestoreText(safe)
}

func (r *StreamRestorer) Flush() string {
	if r == nil || r.pending == "" {
		return ""
	}
	tail := r.pending
	r.pending = ""
	if r.codec != nil && !r.codec.IsEmpty() {
		return r.codec.RestoreText(tail)
	}
	return tail
}
