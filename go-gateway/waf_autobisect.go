package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type wafRewriteRule struct {
	ID          string `json:"id"`
	Literal     string `json:"literal"`
	Replacement string `json:"replacement"`
	Source      string `json:"source"`
	CreatedAt   string `json:"createdAt"`
}

type wafRuleFilePayload struct {
	Version int              `json:"version"`
	Rules   []wafRewriteRule `json:"rules"`
}

type wafRuleCache struct {
	mu      sync.RWMutex
	path    string
	mtimeNs int64
	size    int64
	rules   []wafRewriteRule
}

var (
	globalWafRules         wafRuleCache
	wafBisectMu            sync.Mutex
	wafCooldownMu          sync.Mutex
	wafCooldownUntil       time.Time
	WafBisectCooldownDur   = 30 * time.Second
	WafBisectMaxProbes     = 14
	WafBisectHealedTotal   atomic.Int64
	workspaceContextSpanRe = regexp.MustCompile(`(?s)<workspace-context>.*?</workspace-context>`)
)

type wafFastCancelledError struct {
	Detail string
}

func (e *wafFastCancelledError) Error() string {
	det := strings.TrimSpace(e.Detail)
	if det == "" {
		det = "RESOURCE_EXHAUSTED (code 429): Resource has been exhausted (e.g. check quota)."
	}
	return "Antigravity upstream rate limit or transient failure: ⚠ Agent execution terminated due to error: " + det
}

func (e *wafFastCancelledError) toSoftError() *SoftError {
	return &SoftError{
		StatusCode: 429,
		ErrorType:  "rate_limit_error",
		Message:    e.Error(),
	}
}

func resetWafRuleCacheForTest() {
	globalWafRules.mu.Lock()
	globalWafRules.path = ""
	globalWafRules.mtimeNs = 0
	globalWafRules.size = 0
	globalWafRules.rules = nil
	globalWafRules.mu.Unlock()

	wafCooldownMu.Lock()
	wafCooldownUntil = time.Time{}
	wafCooldownMu.Unlock()
}

func loadDynamicWafRules() []wafRewriteRule {
	target := effectiveWafRulesFile()
	if target == "" {
		return nil
	}
	st, err := os.Stat(target)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			globalWafRules.mu.Lock()
			if globalWafRules.path == target && len(globalWafRules.rules) > 0 {
				globalWafRules.rules = nil
				globalWafRules.mtimeNs = 0
				globalWafRules.size = 0
			}
			globalWafRules.mu.Unlock()
		}
		return nil
	}
	mtimeNs := st.ModTime().UnixNano()
	sz := st.Size()

	globalWafRules.mu.RLock()
	if globalWafRules.path == target && globalWafRules.mtimeNs == mtimeNs && globalWafRules.size == sz {
		cp := append([]wafRewriteRule(nil), globalWafRules.rules...)
		globalWafRules.mu.RUnlock()
		return cp
	}
	globalWafRules.mu.RUnlock()

	raw, err := os.ReadFile(target)
	if err != nil {
		return nil
	}
	var parsed wafRuleFilePayload
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil
	}
	var valid []wafRewriteRule
	for _, r := range parsed.Rules {
		lit := strings.TrimSpace(r.Literal)
		if len(lit) >= 12 {
			r.Literal = lit
			valid = append(valid, r)
		}
	}
	globalWafRules.mu.Lock()
	globalWafRules.path = target
	globalWafRules.mtimeNs = mtimeNs
	globalWafRules.size = sz
	globalWafRules.rules = valid
	cp := append([]wafRewriteRule(nil), valid...)
	globalWafRules.mu.Unlock()
	return cp
}

func stripOrphanBulletLines(s string) string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		if trimmed == "-" || trimmed == "*" {
			continue
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

func ApplyDynamicWafRules(s string) string {
	if s == "" {
		return ""
	}
	rules := loadDynamicWafRules()
	if len(rules) == 0 {
		return s
	}
	out := s
	changed := false
	for _, r := range rules {
		if r.Literal != "" && strings.Contains(out, r.Literal) {
			out = strings.ReplaceAll(out, r.Literal, r.Replacement)
			changed = true
		}
	}
	if !changed {
		return s
	}
	out = stripOrphanBulletLines(out)
	out = multiBlankLinesRe.ReplaceAllString(strings.TrimSpace(out), "\n\n")
	return out
}

func ApplyDynamicWafRulesInWorkspaceContext(s string) string {
	if s == "" || !strings.Contains(s, "<workspace-context>") {
		return s
	}
	rules := loadDynamicWafRules()
	if len(rules) == 0 {
		return s
	}
	return workspaceContextSpanRe.ReplaceAllStringFunc(s, func(span string) string {
		inner := strings.TrimPrefix(span, "<workspace-context>")
		inner = strings.TrimSuffix(inner, "</workspace-context>")
		changed := false
		for _, r := range rules {
			if r.Literal != "" && strings.Contains(inner, r.Literal) {
				inner = strings.ReplaceAll(inner, r.Literal, r.Replacement)
				changed = true
			}
		}
		if !changed {
			return span
		}
		inner = stripOrphanBulletLines(inner)
		trimmed := strings.TrimSpace(multiBlankLinesRe.ReplaceAllString(inner, "\n\n"))
		if trimmed == "" {
			return ""
		}
		return "<workspace-context>\n" + trimmed + "\n</workspace-context>"
	})
}

func persistDynamicWafRule(literal, source string) error {
	lit := strings.TrimSpace(redactSecretsInString(literal))
	if len(lit) < 12 {
		return errors.New("waf rule literal too short")
	}
	target := effectiveWafRulesFile()
	if target == "" || isWindowsCDrivePath(target) {
		return errors.New("waf rules target path unavailable or forbidden")
	}
	existing := loadDynamicWafRules()
	for _, r := range existing {
		if r.Literal == lit {
			return nil
		}
	}
	newRule := wafRewriteRule{
		ID:          "waf_" + shortSha256(lit)[:12],
		Literal:     lit,
		Replacement: "",
		Source:      source,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	existing = append(existing, newRule)
	if len(existing) > 256 {
		existing = existing[len(existing)-256:]
	}
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		return err
	}
	payloadBytes, err := json.MarshalIndent(wafRuleFilePayload{
		Version: 1,
		Rules:   existing,
	}, "", "  ")
	if err != nil {
		return err
	}
	payloadBytes = append(payloadBytes, '\n')
	f, err := os.CreateTemp(filepath.Dir(target), ".waf-rules-*")
	if err != nil {
		return err
	}
	tmpName := f.Name()
	_, wErr := f.Write(payloadBytes)
	if wErr == nil {
		wErr = f.Chmod(0600)
	}
	if wErr == nil {
		wErr = f.Sync()
	}
	cErr := f.Close()
	if wErr == nil {
		wErr = cErr
	}
	if wErr != nil {
		_ = os.Remove(tmpName)
		return wErr
	}
	if err := os.Rename(tmpName, target); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	_ = loadDynamicWafRules()
	return nil
}

func isBisectableInstant429Detail(detail string) bool {
	low := strings.ToLower(strings.TrimSpace(detail))
	if low == "" {
		return false
	}
	if isAccountQuotaOrBillingExhausted(low) {
		return false
	}
	return strings.Contains(low, "429") || strings.Contains(low, "resource_exhausted")
}

func isBisectableSoftError(se *SoftError) bool {
	if se == nil || se.StatusCode != 429 {
		return false
	}
	return isBisectableInstant429Detail(se.Message)
}

func isWafBisectInCooldown() bool {
	wafCooldownMu.Lock()
	until := wafCooldownUntil
	wafCooldownMu.Unlock()
	return !until.IsZero() && time.Now().Before(until)
}

func markWafBisectCooldown() {
	wafCooldownMu.Lock()
	wafCooldownUntil = time.Now().Add(WafBisectCooldownDur)
	wafCooldownMu.Unlock()
}

type bisectCandidate struct {
	Text     string
	InPrompt bool
}

func splitCandidateSentences(text string) []string {
	var out []string
	seen := make(map[string]bool)
	for _, rawLine := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if bm := leadingMarkdownBulletRe.FindStringSubmatch(line); len(bm) == 3 {
			line = strings.TrimSpace(bm[2])
		}
		start := 0
		for _, loc := range sentenceBoundaryRe.FindAllStringIndex(line, -1) {
			part := strings.TrimSpace(line[start:loc[1]])
			if len(part) >= 12 && !seen[part] {
				seen[part] = true
				out = append(out, part)
			}
			start = loc[1]
		}
		tail := strings.TrimSpace(line[start:])
		if len(tail) >= 12 && !seen[tail] {
			seen[tail] = true
			out = append(out, tail)
		}
	}
	return out
}

// extractBisectCandidates extracts candidate sentences ONLY from client harness system instructions
// and <workspace-context> blocks (converted from <system-reminder>). Ordinary user message prose
// is NEVER inspected, bisected, or persisted.
func extractBisectCandidates(prunedSys string, promptBlocks []map[string]any) []bisectCandidate {
	const maxBisectCandidates = 256
	var sysCands, ctxCands []bisectCandidate
	seen := make(map[string]bool)
	for _, s := range splitCandidateSentences(prunedSys) {
		key := "sys:" + s
		if !seen[key] {
			seen[key] = true
			sysCands = append(sysCands, bisectCandidate{Text: s, InPrompt: false})
		}
	}
	for _, blk := range promptBlocks {
		txt, _ := blk["text"].(string)
		if txt == "" || !strings.Contains(txt, "<workspace-context>") {
			continue
		}
		for _, span := range workspaceContextSpanRe.FindAllString(txt, -1) {
			inner := strings.TrimSuffix(strings.TrimPrefix(span, "<workspace-context>"), "</workspace-context>")
			for _, s := range splitCandidateSentences(inner) {
				key := "ctx:" + s
				if !seen[key] {
					seen[key] = true
					ctxCands = append(ctxCands, bisectCandidate{Text: s, InPrompt: true})
				}
			}
		}
	}
	if len(sysCands)+len(ctxCands) > maxBisectCandidates {
		// Reserve up to 64 slots for <workspace-context> sentences so large CLAUDE.md / AGENTS.md
		// system prompts never starve injected <system-reminder> boilerplate triggers.
		ctxCap := len(ctxCands)
		if ctxCap > 64 {
			ctxCap = 64
		}
		sysCap := maxBisectCandidates - ctxCap
		if sysCap < len(sysCands) {
			sysCands = sysCands[:sysCap]
		}
		if len(sysCands)+len(ctxCands) > maxBisectCandidates {
			ctxCands = ctxCands[:maxBisectCandidates-len(sysCands)]
		}
	}
	cands := make([]bisectCandidate, 0, len(sysCands)+len(ctxCands))
	cands = append(cands, sysCands...)
	cands = append(cands, ctxCands...)
	return cands
}

func buildBisectProbeInputs(sub []bisectCandidate) (sysText, userText string) {
	var sysParts, ctxParts []string
	for _, c := range sub {
		if c.InPrompt {
			ctxParts = append(ctxParts, c.Text)
		} else {
			sysParts = append(sysParts, c.Text)
		}
	}
	sysText = strings.Join(sysParts, "\n")
	if len(ctxParts) > 0 {
		userText = "<workspace-context>\n" + strings.Join(ctxParts, "\n") + "\n</workspace-context>\nReply with OK."
	} else {
		userText = "Reply with OK."
	}
	return sysText, userText
}

func runWafAutoBisectProbe(parentCtx context.Context, sysText, userText string) (ok200 bool, hit429 bool, err error) {
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	if parentCtx.Err() != nil {
		return false, false, parentCtx.Err()
	}
	probeCtx, cancel := context.WithTimeout(parentCtx, 15*time.Second)
	defer cancel()

	probeSess := NewAcpProjectSession("util:waf-bisect-"+randomHex(6), DefaultCwd, sysText)
	probeSess.isWafBisectProbe = true
	probeSess.skipSystemReprune = true
	probeSess.setDesiredSelection(ModelSelection{
		Model:        ModelOrDefault("gemini-3.8-flash"),
		Tier:         "low",
		ExplicitTier: true,
	})
	var releaseProbeSlot func()
	probeSess.onBeforeSpawn = func(ps *AcpProjectSession) error {
		rel, rErr := reserveGlobalProbeWorkerSlot(ps)
		if rErr != nil {
			return rErr
		}
		releaseProbeSlot = rel
		return nil
	}
	defer func() {
		probeSess.HibernateWorker("waf_bisect_probe_done", true)
		if releaseProbeSlot != nil {
			releaseProbeSlot()
		}
	}()

	if err := probeSess.openFreshSession(nil, "low"); err != nil {
		if isBisectableInstant429Detail(err.Error()) {
			return false, true, nil
		}
		return false, false, err
	}
	probeBlocks := []map[string]any{
		{"type": "text", "text": userText},
	}
	if probeSess.Codec != nil {
		probeBlocks = probeSess.Codec.EncodePromptBlocks(probeBlocks)
	}
	res, pErr := probeSess.executePromptOrPark(probeCtx, probeBlocks, nil, 0)
	if pErr != nil {
		var fc *wafFastCancelledError
		if errors.As(pErr, &fc) || isBisectableInstant429Detail(pErr.Error()) {
			return false, true, nil
		}
		return false, false, pErr
	}
	if se := DetectAntigravitySoftError(res.Text); se != nil {
		if isBisectableSoftError(se) {
			return false, true, nil
		}
		return false, false, se
	}
	if res.FailedNotice != "" {
		if isBisectableInstant429Detail(res.FailedNotice) {
			return false, true, nil
		}
		return false, false, errors.New(res.FailedNotice)
	}
	return true, false, nil
}

// runWafAutoBisectAndPersist runs a bounded flash-low binary search over client harness system /
// <workspace-context> sentences when a cold-start request hits instant abuse.pi 429.
// If a single offending boilerplate sentence is isolated and verified, it is persisted atomically
// to waf_rewrite_rules.json so the immediate replay and all future sessions succeed cleanly.
func runWafAutoBisectAndPersist(ctx context.Context, convKey, prunedSys string, rawPromptBlocks []map[string]any) (healed bool, learned string) {
	if !WafAutoBisectEnabled || isWafBisectInCooldown() {
		return false, ""
	}
	cands := extractBisectCandidates(prunedSys, rawPromptBlocks)
	if len(cands) < 2 {
		return false, ""
	}
	if !wafBisectMu.TryLock() {
		return false, ""
	}
	defer wafBisectMu.Unlock()

	if isWafBisectInCooldown() {
		return false, ""
	}

	probesUsed := 0
	maxProbes := WafBisectMaxProbes
	if maxProbes < 6 {
		maxProbes = 6
	}
	probe := func(sub []bisectCandidate) (ok200, hit429, hardErr bool) {
		if probesUsed >= maxProbes || (ctx != nil && ctx.Err() != nil) {
			return false, false, true
		}
		probesUsed++
		sTxt, uTxt := buildBisectProbeInputs(sub)
		ok, h429, pErr := runWafAutoBisectProbe(ctx, sTxt, uTxt)
		return ok, h429, (!ok && !h429 && pErr != nil)
	}

	// Probe 1: Cleanroom baseline ("" system, "Reply with OK.").
	// If baseline also fails or 429s, upstream is genuinely throttled -> record cooldown and exit immediately.
	baseOK, _, _ := probe(nil)
	if !baseOK {
		markWafBisectCooldown()
		LogEvent("WAF_AUTOBISECT_SKIP", "Cleanroom baseline probe did not succeed; treating 429 as genuine upstream throttle", map[string]any{
			"convKey":    convKey,
			"probesUsed": probesUsed,
		})
		return false, ""
	}

	// Probe 2: Full candidate set. Must reproduce 429 to confirm trigger is in harness boilerplate.
	_, fullHit429, fullErr := probe(cands)
	if fullErr || !fullHit429 {
		return false, ""
	}

	// Binary search O(log N) to isolate offending sentence.
	cur := cands
	for len(cur) > 1 && probesUsed < maxProbes {
		mid := len(cur) / 2
		left := cur[:mid]
		right := cur[mid:]
		leftOK, leftHit, leftErr := probe(left)
		if leftErr || (!leftOK && !leftHit) {
			// Transport/engine/slot failure: abort immediately rather than misattributing to right half.
			return false, ""
		}
		if leftHit {
			cur = left
			continue
		}
		cur = right
	}
	if len(cur) != 1 {
		return false, ""
	}
	offender := cur[0]

	// Dual confirmation:
	//   1) offender alone -> 429
	//   2) all candidates minus offender -> 200 OK
	if len(cands) > 1 {
		_, aloneHit, aloneErr := probe([]bisectCandidate{offender})
		if aloneErr || !aloneHit {
			return false, ""
		}
	}
	without := make([]bisectCandidate, 0, len(cands)-1)
	for _, c := range cands {
		if c.Text != offender.Text || c.InPrompt != offender.InPrompt {
			without = append(without, c)
		}
	}
	cleanOK, _, cleanErr := probe(without)
	if cleanErr || !cleanOK {
		return false, ""
	}

	src := "system"
	if offender.InPrompt {
		src = "workspace-context"
	}
	if err := persistDynamicWafRule(offender.Text, src); err != nil {
		LogEvent("WAF_AUTOBISECT_ERR", "Failed to persist learned WAF rule", map[string]any{
			"convKey": convKey,
			"error":   err.Error(),
		})
		return false, ""
	}
	WafBisectHealedTotal.Add(1)
	LogEvent("WAF_AUTOBISECT_HEALED", "Isolated & persisted unknown client harness WAF trigger sentence via flash-low auto-bisect", map[string]any{
		"convKey":    convKey,
		"source":     src,
		"probesUsed": probesUsed,
		"ruleId":     "waf_" + shortSha256(strings.TrimSpace(redactSecretsInString(offender.Text)))[:12],
		"preview":    truncateRunes(redactSecretsInString(offender.Text), 120),
	})
	return true, offender.Text
}
