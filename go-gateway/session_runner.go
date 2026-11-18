package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

func (s *AcpProjectSession) alignTpuTailUsage(inTok, cachedTok, outTok, steps int, source string) *TurnUsage {
	// Report agy's raw split. Quota measurements on 2026-11-11 matched the raw uncached/cached
	// token counts; the former fixed 2054-token "TPU tail" shift under-stated billable input.
	alignedIn := inTok
	alignedCr := cachedTok
	if alignedIn+alignedCr > 0 {
		s.mu.Lock()
		s.LastCachedReadTokens = alignedIn + alignedCr
		s.mu.Unlock()
	}
	if outTok <= 0 {
		outTok = 16
	}
	return &TurnUsage{
		InputTokens:            alignedIn,
		CachedReadTokens:       alignedCr,
		OutputTokens:           outTok,
		RawUncachedInputTokens: inTok,
		RawTpuCachedTokens:     cachedTok,
		ContextInputTokens:     alignedIn,
		ContextCachedTokens:    alignedCr,
		StepsInPrompt:          steps,
		UsageSource:            source,
	}
}

// normalizeTurnUsage is the per-session usage ledger. gen_metadata rows are the primary key:
// every row after the cursor is summed (several generations per prompt happen on retries and
// multi-step turns) and the cursor moves past all of them, so each generation is reported
// exactly once. Steps are only a fallback for databases that never had gen_metadata rows; when
// gen_metadata exists but has nothing new (a tool batch split from an already-billed generation),
// the turn reports zero usage instead of re-reading an old row.
func (s *AcpProjectSession) normalizeTurnUsage(rawUsage map[string]any, isToolUseStep bool, promptChars, outChars int) *TurnUsage {
	s.mu.Lock()
	steps := s.PromptStepCount
	if steps < 1 {
		steps = 1
	}
	sid := s.SessionID
	lastIdx := s.LastSeenDbStepIdx
	lastGenIdx := s.LastSeenGenMetaIdx
	lastCached := s.LastCachedReadTokens
	modelID := s.ModelID
	s.mu.Unlock()

	gens, maxGen, genOK := s.readSessionGenMetadataAfter(sid, lastGenIdx)
	if len(gens) > 0 {
		var sumIn, sumCr, sumOut, sumTh int
		var sumStreamMs, sumDecOut, sumDecStreamMs, firstGenTtftMs int
		var report *ArgonDegradationReport
		for i, gm := range gens {
			sumIn += gm.InputTokens
			sumCr += gm.CachedReadTokens
			sumOut += gm.OutputTokens
			sumTh += gm.ThoughtTokens
			rawTtft := int(math.Round(gm.TtftSeconds * 1000))
			rawStream := int(math.Round(gm.StreamSeconds * 1000))
			gTtft, gStream, _, _, gDec := computeStepTiming(rawTtft, rawStream, rawTtft+rawStream, gm.OutputTokens)
			if i == 0 && gTtft > 0 {
				firstGenTtftMs = gTtft
			}
			if gStream > 0 {
				sumStreamMs += gStream
			}
			if gDec > 0 && gStream > 0 {
				sumDecOut += gm.OutputTokens
				sumDecStreamMs += gStream
			}
			deg := EvaluateArgonDegradation(gm, modelID)
			if report == nil || (deg != nil && deg.Degraded && !report.Degraded) {
				report = deg
			}
		}
		last := gens[len(gens)-1]
		maxStep := s.readMaxSessionStepIdx(sid)
		s.mu.Lock()
		if maxGen > s.LastSeenGenMetaIdx {
			s.LastSeenGenMetaIdx = maxGen
		}
		if maxStep > s.LastSeenDbStepIdx {
			s.LastSeenDbStepIdx = maxStep
		}
		s.mu.Unlock()
		u := s.alignTpuTailUsage(sumIn, sumCr, sumOut, len(gens), "db")
		u.ContextInputTokens = last.InputTokens
		u.ContextCachedTokens = last.CachedReadTokens
		s.mu.Lock()
		s.LastCachedReadTokens = last.InputTokens + last.CachedReadTokens
		s.mu.Unlock()
		u.ThinkingTokens = sumTh
		u.Degradation = report
		u.Generations = len(gens)
		u.ServedModel = last.ServedModel
		u.GenTtftMs = firstGenTtftMs
		if sumStreamMs > 0 {
			u.StreamMs = sumStreamMs
		}
		if sumDecStreamMs > 0 && sumDecOut > 0 {
			u.DecodeTps = math.Round((float64(sumDecOut)/(float64(sumDecStreamMs)/1000.0))*10) / 10
		}
		return u
	}
	hasGenRows := genOK && (lastGenIdx >= 0 || maxGen >= 0)
	if genOK && maxGen > lastGenIdx {
		s.mu.Lock()
		if maxGen > s.LastSeenGenMetaIdx {
			s.LastSeenGenMetaIdx = maxGen
		}
		s.mu.Unlock()
	}
	if hasGenRows {
		return &TurnUsage{StepsInPrompt: 0, UsageSource: "none"}
	}

	stepRows, maxStep, stepOK := s.readSessionStepsAfter(sid, lastIdx)
	if len(stepRows) > 0 {
		var sumIn, sumCr, sumOut, sumTh int
		var sumStreamMs, sumDecOut, sumDecStreamMs, firstStepTtftMs int
		for i, st := range stepRows {
			sumIn += st.RawIn
			sumCr += st.RawCr
			sumOut += st.OutTok
			sumTh += st.ThTok
			if i == 0 && st.TtftMs > 0 {
				firstStepTtftMs = st.TtftMs
			}
			if st.StreamMs > 0 {
				sumStreamMs += st.StreamMs
			}
			if st.DecodeTps > 0 && st.StreamMs > 0 {
				sumDecOut += st.OutTok
				sumDecStreamMs += st.StreamMs
			}
		}
		last := stepRows[len(stepRows)-1]
		s.mu.Lock()
		if maxStep > s.LastSeenDbStepIdx {
			s.LastSeenDbStepIdx = maxStep
		}
		s.mu.Unlock()
		u := s.alignTpuTailUsage(sumIn, sumCr, sumOut, len(stepRows), "db")
		u.ContextInputTokens = last.RawIn
		u.ContextCachedTokens = last.RawCr
		s.mu.Lock()
		s.LastCachedReadTokens = last.RawIn + last.RawCr
		s.mu.Unlock()
		u.ThinkingTokens = sumTh
		u.Generations = len(stepRows)
		u.ServedModel = last.ServedModel
		u.GenTtftMs = firstStepTtftMs
		if sumStreamMs > 0 {
			u.StreamMs = sumStreamMs
		}
		if sumDecStreamMs > 0 && sumDecOut > 0 {
			u.DecodeTps = math.Round((float64(sumDecOut)/(float64(sumDecStreamMs)/1000.0))*10) / 10
		}
		return u
	}
	if stepOK && (lastIdx >= 0 || genOK) {
		// Readable session database without any new generation: nothing new to bill.
		return &TurnUsage{StepsInPrompt: 0, UsageSource: "none"}
	}

	estIn := promptChars / 4
	if estIn < 16 {
		estIn = 120
	}
	estOut := outChars / 4
	if estOut < 16 {
		estOut = 32
	}

	if isToolUseStep || rawUsage == nil {
		return &TurnUsage{
			InputTokens:      estIn,
			CachedReadTokens: lastCached,
			OutputTokens:     estOut,
			StepsInPrompt:    1,
			UsageSource:      "estimate",
		}
	}
	cumIn, _ := toInt(rawUsage["inputTokens"])
	cumCr, _ := toInt(rawUsage["cachedReadTokens"])
	outTok, _ := toInt(rawUsage["outputTokens"])
	thTok, _ := toInt(rawUsage["thoughtTokens"])
	u := s.alignTpuTailUsage(cumIn/steps, cumCr/steps, outTok, steps, "acp")
	if thTok > 0 {
		u.ThinkingTokens = thTok
	}
	return u
}

// normalizeTurnUsageAsync gives agy a short adaptive window to land the generation row of a turn/tool batch.
func (s *AcpProjectSession) normalizeTurnUsageAsync(rawUsage map[string]any, isToolUseStep bool, promptChars, outChars int) *TurnUsage {
	s.mu.Lock()
	sid := s.SessionID
	lastGenIdx := s.LastSeenGenMetaIdx
	s.mu.Unlock()

	backoffs := [...]time.Duration{
		5 * time.Millisecond,
		10 * time.Millisecond,
		20 * time.Millisecond,
		40 * time.Millisecond,
		60 * time.Millisecond,
		60 * time.Millisecond,
		60 * time.Millisecond,
	}
	for attempt := 0; attempt <= len(backoffs); attempt++ {
		if gens, _, ok := s.readSessionGenMetadataAfter(sid, lastGenIdx); len(gens) > 0 || !ok {
			break
		}
		if attempt < len(backoffs) {
			time.Sleep(backoffs[attempt])
		}
	}
	return s.normalizeTurnUsage(rawUsage, isToolUseStep, promptChars, outChars)
}

func (s *AcpProjectSession) logTurnStats(mode string, elapsedMs int, res TurnResult) {
	s.logTurnStatsWithReason(mode, "", elapsedMs, res)
}

func (s *AcpProjectSession) logTurnStatsWithReason(mode, rolloverReason string, elapsedMs int, res TurnResult) {
	inTok := 0
	crTok := 0
	outTok := 0
	stepsInPrompt := 1
	rawIn := 0
	rawCr := 0
	usageSource := "unknown"
	if res.Usage != nil {
		inTok = res.Usage.InputTokens
		crTok = res.Usage.CachedReadTokens
		outTok = res.Usage.OutputTokens
		stepsInPrompt = res.Usage.StepsInPrompt
		rawIn = res.Usage.RawUncachedInputTokens
		rawCr = res.Usage.RawTpuCachedTokens
		usageSource = res.Usage.UsageSource
	}
	measured := usageSource == "db" || usageSource == "acp"
	hitRate := "N/A"
	if measured && inTok+crTok > 0 {
		hitRate = formatPercent(float64(crTok) / float64(inTok+crTok) * 100)
	}
	ttft := res.TtftMs
	if ttft <= 0 {
		ttft = elapsedMs
	}
	if elapsedMs > 0 && ttft > elapsedMs {
		ttft = elapsedMs
	}
	tps := 0.0
	streamMs := 0
	decodeTps := 0.0
	upstreamTtftMs := 0
	if res.Usage != nil && res.Usage.GenTtftMs > 0 {
		upstreamTtftMs = res.Usage.GenTtftMs
	}
	if measured && elapsedMs > 0 && outTok > 0 {
		tps = math.Round((float64(outTok)/(float64(elapsedMs)/1000.0))*10) / 10
		if res.Usage != nil && res.Usage.StreamMs > 0 {
			if res.Usage.StreamMs <= elapsedMs {
				streamMs = res.Usage.StreamMs
				decodeTps = res.Usage.DecodeTps
			} else if elapsedMs > ttft && ttft > 0 {
				_, streamMs, _, _, decodeTps = computeStepTiming(ttft, 0, elapsedMs, outTok)
			} else {
				_, streamMs, _, _, decodeTps = computeStepTiming(0, elapsedMs, elapsedMs, outTok)
			}
		} else if elapsedMs > ttft && ttft > 0 {
			_, streamMs, _, _, decodeTps = computeStepTiming(ttft, 0, elapsedMs, outTok)
		}
	}
	thinkLen := len(res.Thinking)
	thinkTok := 0
	if res.Usage != nil && res.Usage.ThinkingTokens > 0 {
		thinkTok = res.Usage.ThinkingTokens
	} else if thinkLen > 0 {
		thinkTok = int(math.Round(float64(thinkLen) / 3.2))
		if thinkTok < 1 {
			thinkTok = 1
		}
		if thinkTok > outTok {
			thinkTok = outTok
		}
	}
	thinkingMs := res.ThinkingMs
	if streamMs > 0 && thinkingMs > streamMs {
		thinkingMs = streamMs
	}
	if thinkingMs == 0 && thinkTok > 0 && outTok >= thinkTok && streamMs > 0 {
		thinkingMs = int(math.Round(float64(streamMs) * float64(thinkTok) / float64(outTok)))
	}

	now := time.Now().UTC()
	servedModel := ""
	if res.Usage != nil {
		servedModel = res.Usage.ServedModel
	}
	s.mu.Lock()
	var prev *TurnHistoryEntry
	afterColdStart := false
	for i := len(s.TurnHistory) - 1; i >= 0 && i >= len(s.TurnHistory)-16; i-- {
		h := &s.TurnHistory[i]
		if h.SessionID != s.SessionID {
			break
		}
		if h.Mode == "cold_start" || h.Mode == "compaction_rollover" || h.Mode == "argon_degraded_recovery" || h.Mode == "high_capacity_fallback" || h.Mode == "waf_autobisect_recovery" {
			afterColdStart = true
		}
		if h.Usage != nil && (h.Usage.UsageSource == "db" || h.Usage.UsageSource == "acp") {
			prev = h
			break
		}
	}
	turnStartAt := now
	if elapsedMs > 0 {
		turnStartAt = now.Add(-time.Duration(elapsedMs) * time.Millisecond)
	}
	cacheMiss := classifyCacheMissWithReason(mode, rolloverReason, res.Usage, prev, s.ModelID, turnStartAt)
	var emitBurnWarn string
	var burnStreak int
	var burnUncached int64
	var burnCtx int
	emitHighTierCacheFallback := false
	if measured && res.Usage != nil {
		ctxTok := res.Usage.ContextTotal()
		uncachedIn := inTok
		if res.Usage.ContextInputTokens > 0 {
			uncachedIn = res.Usage.ContextInputTokens
		} else if rawIn > 0 {
			uncachedIn = rawIn
		}
		if ctxTok > 0 {
			switch {
			case cacheMiss == "" || ctxTok < CacheWarnMinTokens || cacheMiss == "cold_start" || cacheMiss == "model_switch" || strings.HasPrefix(cacheMiss, "rollover"):
				s.resetCacheBurnLocked()
			case cacheMiss == "zero" || cacheMiss == "prefix_only":
				s.ZeroCacheStreak++
				s.ZeroCacheUncachedTokens += int64(uncachedIn)
				if s.ZeroCacheStreak >= CacheWarnStreak {
					s.LastCacheWarning = fmt.Sprintf(
						"consecutive-zero-cache; streak=%d; context_tokens=%d; uncached_tokens=%d; model=%s",
						s.ZeroCacheStreak, ctxTok, s.ZeroCacheUncachedTokens, s.ModelID,
					)
					emitBurnWarn = s.LastCacheWarning
					burnStreak = s.ZeroCacheStreak
					burnUncached = s.ZeroCacheUncachedTokens
					burnCtx = ctxTok
				}
			}
			if s.ModelID == "gemini-4-carbon" && s.ThoughtLevel == "high" {
				if cacheMiss == "zero" && ctxTok >= 48000 && (ttft >= 10000 || elapsedMs >= 15000) {
					s.highTierZeroCacheStreak++
					if s.highTierZeroCacheStreak >= 2 && s.SessionID != "" && s.capacityFallbackSid != s.SessionID {
						s.capacityFallbackSid = s.SessionID
						s.highTierZeroCacheStreak = 0
						emitHighTierCacheFallback = true
						burnCtx = ctxTok
					}
				} else if cacheMiss == "" || cacheMiss == "cold_start" || cacheMiss == "model_switch" || strings.HasPrefix(cacheMiss, "rollover") {
					s.highTierZeroCacheStreak = 0
				}
			} else {
				s.highTierZeroCacheStreak = 0
			}
		}
	}
	if res.Usage != nil && s.LastCacheWarning != "" {
		res.Usage.CacheWarning = s.LastCacheWarning
	}
	relays := s.relaysThisTurn
	s.relaysThisTurn = 0
	s.TotalTurns++
	if n := len(s.TurnHistory); n > 0 && s.TurnHistory[n-1].TurnIndex >= s.TotalTurns {
		s.TotalTurns = s.TurnHistory[n-1].TurnIndex + 1
	}
	idx := s.TotalTurns
	entry := TurnHistoryEntry{
		TurnIndex:      idx,
		CompletedAtMs:  now.UnixMilli(),
		Ts:             now.Format(time.RFC3339),
		SessionID:      s.SessionID,
		Mode:           mode,
		ElapsedMs:      elapsedMs,
		TtftMs:         ttft,
		UpstreamTtftMs: upstreamTtftMs,
		StreamMs:       streamMs,
		Tps:            tps,
		DecodeTps:      decodeTps,
		HasThinking:    thinkTok > 0,
		ThinkingTokens: thinkTok,
		ThinkingMs:     thinkingMs,
		RetryCount:     res.RetryCount,
		Usage:          res.Usage,
		CacheHitRate:   hitRate,
		StopReason:     res.StopReason,
		Model:          s.ModelID,
		ThoughtLevel:   s.ThoughtLevel,
		ServedModel:    servedModel,
		CacheMiss:      cacheMiss,
		ClientID:       s.ClientID,
		ClientLabel:    s.ClientLabel,
		Protocol:       s.Protocol,
	}
	s.TurnHistory = append(s.TurnHistory, entry)
	// Bounded ring buffer (max 150 entries) to prevent unbounded memory growth
	if len(s.TurnHistory) > 150 {
		s.TurnHistory = s.TurnHistory[len(s.TurnHistory)-150:]
	}
	sid := s.SessionID
	turnModel, turnTier := s.ModelID, s.ThoughtLevel
	turnClient, turnProto := s.ClientLabel, s.Protocol
	s.mu.Unlock()
	if emitHighTierCacheFallback {
		LogEvent("HIGH_TIER_CACHE_DEGRADE_FALLBACK", "Armed in-place medium-tier fallback after consecutive carbon-high zero-cache misses", map[string]any{
			"convKey":       s.ConvKey,
			"sessionId":     sid,
			"model":         turnModel,
			"fromTier":      turnTier,
			"toTier":        "medium",
			"contextTokens": burnCtx,
		})
	}
	if emitBurnWarn != "" {
		cacheBurnWarningsTotal.Add(1)
		LogEvent("CACHE_BURN_WARNING", fmt.Sprintf("Long-context session missed cache %d consecutive turns (%s)", burnStreak, turnModel), map[string]any{
			"convKey":        s.ConvKey,
			"sessionId":      sid,
			"model":          turnModel,
			"thoughtLevel":   turnTier,
			"servedModel":    servedModel,
			"streak":         burnStreak,
			"contextTokens":  burnCtx,
			"uncachedTokens": burnUncached,
			"cacheMiss":      cacheMiss,
		})
	}
	GlobalStore.InsertTurn(s.ConvKey, entry)
	GlobalStore.UpsertSession(s)

	preview := res.Text
	if len(preview) > 120 {
		preview = preview[:120]
	}
	NotifyGatewayTurnCompleted()
	LogEvent("TURN_DONE", fmt.Sprintf("Completed turn (%s) in %dms", res.StopReason, elapsedMs), map[string]any{
		"convKey":                s.ConvKey,
		"sessionId":              sid,
		"client":                 turnClient,
		"protocol":               turnProto,
		"model":                  turnModel,
		"thoughtLevel":           turnTier,
		"mode":                   mode,
		"ttftMs":                 ttft,
		"upstreamTtftMs":         upstreamTtftMs,
		"streamMs":               streamMs,
		"tps":                    tps,
		"decodeTps":              decodeTps,
		"hasThinking":            thinkTok > 0,
		"thinkingTokens":         thinkTok,
		"thinkingMs":             thinkingMs,
		"retryCount":             res.RetryCount,
		"inputTokens":            inTok,
		"cachedReadTokens":       crTok,
		"rawUncachedInputTokens": rawIn,
		"rawTpuCachedTokens":     rawCr,
		"usageSource":            usageSource,
		"stepsInPrompt":          stepsInPrompt,
		"cacheHitRate":           hitRate,
		"outputTokens":           outTok,
		"toolCallsCount":         len(res.ToolCalls),
		"textPreview":            preview,
		"servedModel":            servedModel,
		"cacheMiss":              cacheMiss,
		"afterColdStart":         afterColdStart,
		"toolRelays":             relays,
		"generations":            generationsOf(res.Usage),
	})
}

func generationsOf(u *TurnUsage) int {
	if u == nil {
		return 0
	}
	return u.Generations
}

type softDetachError struct {
	cause error
}

func (e *softDetachError) Error() string {
	if e == nil || e.cause == nil {
		return "turn soft-detached during prefill"
	}
	return e.cause.Error()
}

func (e *softDetachError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func isSoftDetachedErr(err error) bool {
	var se *softDetachError
	return errors.As(err, &se)
}

type turnDetachMeta struct {
	sid             string
	mode            string
	rolloverReason  string
	turnStart       time.Time
	msgCount        int
	firstUserFp     string
	cancelledHistFp string
	isCompactionReq bool
}

type turnDetachMetaKey struct{}

func withTurnDetachMeta(ctx context.Context, meta *turnDetachMeta) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if meta == nil {
		return ctx
	}
	return context.WithValue(ctx, turnDetachMetaKey{}, meta)
}

func turnDetachMetaFromContext(ctx context.Context) *turnDetachMeta {
	if ctx == nil {
		return nil
	}
	meta, _ := ctx.Value(turnDetachMetaKey{}).(*turnDetachMeta)
	return meta
}

type detachedTurnState struct {
	reqFp           string
	turn            *activeTurnState
	sid             string
	mode            string
	rolloverReason  string
	turnStart       time.Time
	msgCount        int
	promptChars     int
	firstUserFp     string
	cancelledHistFp string
	isCompactionReq bool
	settledResult   *TurnResult
	passiveExtended bool
	graceTimer      *time.Timer
}

func valueHasCacheControl(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		if x["cache_control"] != nil {
			return true
		}
		if bc, ok := x["content"]; ok && bc != nil {
			return valueHasCacheControl(bc)
		}
	case []any:
		for _, it := range x {
			if valueHasCacheControl(it) {
				return true
			}
		}
	case []map[string]any:
		for _, it := range x {
			if valueHasCacheControl(it) {
				return true
			}
		}
	}
	return false
}

func stripCacheControlValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		if !valueHasCacheControl(x) {
			return x
		}
		cp := make(map[string]any, len(x))
		for k, val := range x {
			if k == "cache_control" {
				continue
			}
			if k == "content" && val != nil {
				cp[k] = stripCacheControlValue(val)
			} else {
				cp[k] = val
			}
		}
		return cp
	case []any:
		if !valueHasCacheControl(x) {
			return x
		}
		out := make([]any, len(x))
		for i, it := range x {
			out[i] = stripCacheControlValue(it)
		}
		return out
	case []map[string]any:
		if !valueHasCacheControl(x) {
			return x
		}
		out := make([]map[string]any, len(x))
		for i, it := range x {
			if m, ok := stripCacheControlValue(it).(map[string]any); ok {
				out[i] = m
			} else {
				out[i] = it
			}
		}
		return out
	default:
		return v
	}
}

func stripCacheControlFromMessages(messages []map[string]any) []map[string]any {
	if len(messages) == 0 || !valueHasCacheControl(messages) {
		return messages
	}
	if cleaned, ok := stripCacheControlValue(messages).([]map[string]any); ok {
		return cleaned
	}
	return messages
}

func computeTurnRequestFingerprint(modelID, tier, sysText string, tools []ToolDef, messages []map[string]any) string {
	return computeTurnRequestFingerprintWithDirective(modelID, tier, sysText, tools, messages, "")
}

func computeTurnRequestFingerprintWithDirective(modelID, tier, sysText string, tools []ToolDef, messages []map[string]any, directiveToken string) string {
	type fpPayload struct {
		Model       string           `json:"m"`
		Tier        string           `json:"t"`
		Cwd         string           `json:"c,omitempty"`
		Directive   string           `json:"d,omitempty"`
		ToolDigests []string         `json:"td,omitempty"`
		Messages    []map[string]any `json:"ms"`
	}
	var toolDigests []string
	if len(tools) > 0 {
		toolDigests = make([]string, 0, len(tools))
		for _, t := range tools {
			toolDigests = append(toolDigests, toolDefDigest(t))
		}
		sort.Strings(toolDigests)
	}
	cleanMsgs := stripCacheControlFromMessages(messages)
	cwd := extractCwdFromSystem(sysText, cleanMsgs)
	h := sha256.New()
	enc := json.NewEncoder(h)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(fpPayload{
		Model:       modelID,
		Tier:        tier,
		Cwd:         cwd,
		Directive:   directiveToken,
		ToolDigests: toolDigests,
		Messages:    cleanMsgs,
	}); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func canonicalizeHistoryFpValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		cp := make(map[string]any, len(x))
		for k, val := range x {
			if k == "cache_control" {
				continue
			}
			if (k == "text" || k == "content") && val != nil {
				if s, okS := val.(string); okS {
					if core := strings.TrimSpace(volatileFirstTurnTagRe.ReplaceAllString(s, "")); core != "" {
						cp[k] = core
						continue
					}
				}
				cp[k] = canonicalizeHistoryFpValue(val)
			} else {
				cp[k] = val
			}
		}
		return cp
	case []any:
		out := make([]any, len(x))
		for i, it := range x {
			out[i] = canonicalizeHistoryFpValue(it)
		}
		return out
	case []map[string]any:
		out := make([]map[string]any, len(x))
		for i, it := range x {
			if m, ok := canonicalizeHistoryFpValue(it).(map[string]any); ok {
				out[i] = m
			} else {
				out[i] = it
			}
		}
		return out
	default:
		return v
	}
}

func computeMessagesSliceFingerprint(messages []map[string]any) string {
	if len(messages) == 0 {
		return ""
	}
	normMsgs := canonicalizeHistoryFpValue(messages)
	h := sha256.New()
	enc := json.NewEncoder(h)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(normMsgs); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func cancelledHistoryDiverged(messages []map[string]any, msgCnt int, lastTurnAsst bool, cancelledFp string) bool {
	if msgCnt <= 0 || lastTurnAsst {
		return false
	}
	if len(messages) < msgCnt || cancelledFp == "" {
		return true
	}
	return computeMessagesSliceFingerprint(messages[:msgCnt]) != cancelledFp
}

func (s *AcpProjectSession) HasDetachedTurn() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	has := s.detachedTurn != nil
	s.mu.Unlock()
	return has
}

func (s *AcpProjectSession) effectiveSoftDetachPolicy(promptChars int) (minElapsed, grace time.Duration, maxDetaches int) {
	minElapsed = PrefillCancelMinElapsed
	grace = PrefillCancelGrace
	maxDetaches = 3
	if s == nil {
		return minElapsed, grace, maxDetaches
	}
	s.mu.Lock()
	estTokens := s.LastCachedReadTokens
	if s.LastReportedContextUsed > estTokens {
		estTokens = s.LastReportedContextUsed
	}
	sysLen := len(s.SystemText)
	s.mu.Unlock()
	if charEst := (promptChars + sysLen) / 4; charEst > estTokens {
		estTokens = charEst
	}
	canScaleMin := !prefillMinElapsedEnvSet && PrefillCancelMinElapsed == 30*time.Second
	canScaleGrace := !prefillGraceEnvSet && PrefillCancelGrace == 45*time.Second
	switch {
	case estTokens >= 120000:
		if canScaleMin {
			minElapsed = 5 * time.Second
		}
		if canScaleGrace {
			grace = 120 * time.Second
		}
		maxDetaches = 6
	case estTokens >= 48000:
		if canScaleMin {
			minElapsed = 8 * time.Second
		}
		if canScaleGrace {
			grace = 90 * time.Second
		}
		maxDetaches = 5
	}
	return minElapsed, grace, maxDetaches
}

func (s *AcpProjectSession) tryStartSoftDetach(turn *activeTurnState, reqFp, sid, mode, rolloverReason string, turnStart, waitStart time.Time, msgCount int, firstUserFp, cancelledHistFp string, isCompactionReq bool) bool {
	return s.tryStartSoftDetachWithChars(turn, reqFp, sid, mode, rolloverReason, turnStart, waitStart, msgCount, firstUserFp, cancelledHistFp, isCompactionReq, 0)
}

func (s *AcpProjectSession) tryStartSoftDetachWithChars(turn *activeTurnState, reqFp, sid, mode, rolloverReason string, turnStart, waitStart time.Time, msgCount int, firstUserFp, cancelledHistFp string, isCompactionReq bool, promptChars int) bool {
	if s == nil || turn == nil || reqFp == "" || PrefillCancelGrace <= 0 {
		return false
	}
	minElapsed, graceDur, maxDetaches := s.effectiveSoftDetachPolicy(promptChars)
	s.mu.Lock()
	coalesced := s.coalesceHandoff
	if coalesced {
		s.coalesceHandoff = false
	}
	s.mu.Unlock()

	elapsedStart := waitStart
	if !turnStart.IsZero() && (elapsedStart.IsZero() || turnStart.Before(elapsedStart)) {
		elapsedStart = turnStart
	}
	if elapsedStart.IsZero() {
		elapsedStart = turn.createdAt
	}
	if !coalesced && time.Since(elapsedStart) < minElapsed {
		return false
	}
	prevDetaches := turn.SoftDetachCount()
	if (!coalesced && prevDetaches >= maxDetaches) || !turn.CanSoftDetach() {
		return false
	}
	s.mu.Lock()
	if s.closing || !turn.CanSoftDetach() || (prevDetaches == 0 && s.activeTurn != turn) {
		s.mu.Unlock()
		return false
	}
	if sid == "" {
		sid = s.SessionID
	}
	det := &detachedTurnState{
		reqFp:           reqFp,
		turn:            turn,
		sid:             sid,
		mode:            mode,
		rolloverReason:  rolloverReason,
		turnStart:       turnStart,
		msgCount:        msgCount,
		promptChars:     promptChars,
		firstUserFp:     firstUserFp,
		cancelledHistFp: cancelledHistFp,
		isCompactionReq: isCompactionReq,
	}
	s.detachedTurn = det
	det.graceTimer = time.AfterFunc(graceDur, func() {
		s.expireDetachedTurn(det)
	})
	s.mu.Unlock()
	turn.DetachSubscriber()
	LogEvent("PREFILL_SOFT_DETACH", "Client disconnected after prefill threshold; holding upstream turn in grace window", map[string]any{
		"convKey":        s.ConvKey,
		"sessionId":      sid,
		"mode":           mode,
		"waitMs":         time.Since(elapsedStart).Milliseconds(),
		"graceSec":       int(graceDur.Seconds()),
		"detachCount":    turn.SoftDetachCount(),
		"reqFingerprint": reqFp[:12],
	})
	return true
}

func (s *AcpProjectSession) settleDetachedTurn(det *detachedTurnState, reason, eventName string) {
	if s == nil || det == nil || det.turn == nil {
		return
	}
	settled := det.settledResult
	if settled == nil {
		select {
		case res := <-det.turn.resolveChan:
			det.turn.MarkResultConsumed()
			settled = &res
		default:
		}
	}
	det.turn.mu.Lock()
	alreadyUpstreamDone := det.turn.upstreamDone && !det.turn.failed
	det.turn.mu.Unlock()

	if settled != nil || alreadyUpstreamDone {
		s.mu.Lock()
		s.ForceRolloverNext = true
		s.ForceRolloverReason = "rollover_unclaimed_detached"
		if s.activeTurn == det.turn {
			s.activeTurn = nil
		}
		s.mu.Unlock()
		det.turn.CleanupSubscriber()
		if det.turn.releaseSem != nil {
			det.turn.releaseOnce.Do(det.turn.releaseSem)
		}
		det.turn.CancelContext()
		det.turn.closeDelta()
		// Close and reset session state (including any unclaimed tool_use ParkedCalls and gateway.db
		// msg_count) so both in-process next turns and restarts roll over cleanly with full history.
		s.HibernateWorker("unclaimed_detached_rollover", true)
		s.mu.Lock()
		s.ForceRolloverNext = true
		s.ForceRolloverReason = "rollover_unclaimed_detached"
		s.mu.Unlock()
		LogEvent(eventName, "Detached turn finished unclaimed before cleanup; rolling over on next turn", map[string]any{
			"convKey":   s.ConvKey,
			"sessionId": det.sid,
			"reason":    reason,
		})
		return
	}

	s.CancelActiveTurn(reason)
	if reason == "superseded_by_new_request" && det.msgCount <= 2 {
		s.HibernateWorker("superseded_turn1", true)
	} else {
		s.mu.Lock()
		s.MessageCount = det.msgCount
		s.lastTurnAssistant = false
		s.cancelledHistoryFp = det.cancelledHistFp
		if det.firstUserFp != "" {
			s.HistoryFingerprint = det.firstUserFp
		}
		s.mu.Unlock()
	}
	LogEvent(eventName, "Cancelled detached upstream turn", map[string]any{
		"convKey":   s.ConvKey,
		"sessionId": det.sid,
		"reason":    reason,
	})
}

func (s *AcpProjectSession) expireDetachedTurn(det *detachedTurnState) {
	if s == nil || det == nil {
		return
	}
	s.mu.Lock()
	if s.detachedTurn != det {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	ch := s.ensureQueueSem()
	ch <- struct{}{}
	defer s.releaseTurnQueue()

	s.mu.Lock()
	if s.detachedTurn != det {
		s.mu.Unlock()
		return
	}
	s.detachedTurn = nil
	s.IsBusy = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.IsBusy = false
		s.mu.Unlock()
	}()

	// If a non-trivial (>=16K-token) upstream turn already finished cleanly as a pure end_turn
	// (0 tool calls, no errors), release promptSem immediately and hold the completed TurnResult
	// passively so a late retry claims the warm result in 0ms instead of rollover_unclaimed_detached.
	if det.settledResult == nil && !det.passiveExtended && det.turn != nil {
		select {
		case res := <-det.turn.resolveChan:
			det.turn.MarkResultConsumed()
			s.mu.Lock()
			estCtx := s.LastCachedReadTokens
			if s.LastReportedContextUsed > estCtx {
				estCtx = s.LastReportedContextUsed
			}
			s.mu.Unlock()
			if uTot := res.Usage.ContextTotal(); uTot > estCtx {
				estCtx = uTot
			}
			if cEst := det.promptChars / 4; cEst > estCtx {
				estCtx = cEst
			}
			if estCtx >= 16000 && len(res.ToolCalls) == 0 && res.StopReason != "tool_use" &&
				res.FailedNotice == "" && DetectAntigravitySoftError(res.Text) == nil {
				det.turn.CleanupSubscriber()
				if det.turn.releaseSem != nil {
					det.turn.releaseOnce.Do(det.turn.releaseSem)
				}
				det.turn.CancelContext()
				det.turn.closeDelta()
				passiveHold := PrefillCancelGrace
				if !prefillGraceEnvSet && PrefillCancelGrace == 45*time.Second {
					passiveHold = 120 * time.Second
				}
				s.mu.Lock()
				if s.activeTurn == det.turn {
					s.activeTurn = nil
				}
				det.settledResult = &res
				det.passiveExtended = true
				s.detachedTurn = det
				det.graceTimer = time.AfterFunc(passiveHold, func() {
					s.expireDetachedTurn(det)
				})
				s.mu.Unlock()
				LogEvent("PREFILL_SOFT_DETACH_HOLD", "Holding completed detached end_turn result in passive claim buffer", map[string]any{
					"convKey":   s.ConvKey,
					"sessionId": det.sid,
					"holdSec":   int(passiveHold.Seconds()),
				})
				return
			}
			det.settledResult = &res
		default:
		}
	}

	softDetachExpiredTotal.Add(1)
	s.settleDetachedTurn(det, "prefill_grace_expired", "PREFILL_SOFT_DETACH_EXPIRED")
}

func (s *AcpProjectSession) AbortDetachedTurn(reason string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	det := s.detachedTurn
	if det == nil {
		s.mu.Unlock()
		return
	}
	s.detachedTurn = nil
	wasBusy := s.IsBusy
	s.IsBusy = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.IsBusy = wasBusy
		s.mu.Unlock()
	}()
	if det.graceTimer != nil {
		det.graceTimer.Stop()
	}
	if reason == "superseded_by_new_request" {
		softDetachSupersededTotal.Add(1)
	}
	s.settleDetachedTurn(det, reason, "PREFILL_SOFT_DETACH_SUPERSEDED")
}

func (s *AcpProjectSession) recordRecentCompletedTurn(reqFp string, res TurnResult) {
	if s == nil || reqFp == "" || len(res.ToolCalls) > 0 || res.FailedNotice != "" || DetectAntigravitySoftError(res.Text) != nil {
		return
	}
	s.mu.Lock()
	if s.coalesceHandoff {
		s.lastCompletedReqFp = reqFp
		s.lastCompletedResult = res
		s.lastCompletedAt = time.Now()
		s.coalesceHandoff = false
	}
	s.mu.Unlock()
}

func (s *AcpProjectSession) tryReplayRecentCompletedTurn(reqFp string, onDelta func(DeltaChunk)) (TurnResult, bool) {
	if s == nil || reqFp == "" {
		return TurnResult{}, false
	}
	s.mu.Lock()
	matched := s.lastCompletedReqFp == reqFp && !s.lastCompletedAt.IsZero() && time.Since(s.lastCompletedAt) < 15*time.Second
	var res TurnResult
	if matched {
		res = s.lastCompletedResult
		s.lastCompletedReqFp = ""
	}
	s.mu.Unlock()
	if !matched {
		return TurnResult{}, false
	}
	if onDelta != nil {
		if res.Thinking != "" {
			onDelta(DeltaChunk{Type: "thinking", Thinking: res.Thinking})
		}
		if res.Text != "" {
			onDelta(DeltaChunk{Type: "text", Text: res.Text})
		}
	}
	return res, true
}

func (s *AcpProjectSession) finalizeCompletedTurn(ctx context.Context, res TurnResult, turnStart time.Time, firstDeltaNs int64, messages []map[string]any, currentFirstFp string, isCompactionReq bool, sid, mode, rolloverReason string) (TurnResult, error) {
	elapsed := int(time.Since(turnStart).Milliseconds())
	res.TtftMs = resolveTurnTtftMs(turnStart, elapsed, firstDeltaNs, res)

	if se := DetectAntigravitySoftError(res.Text); se != nil {
		isTransientWarm := mode != "parked_mcp_resume" &&
			(se.StatusCode == http.StatusTooManyRequests || se.StatusCode == http.StatusServiceUnavailable || se.StatusCode == 529) &&
			se.ErrorType != "tos_circuit_breaker"
		s.mu.Lock()
		warmMsgCnt := s.MessageCount
		s.mu.Unlock()
		if !isTransientWarm || warmMsgCnt == 0 {
			s.HibernateWorker("soft_error_reset", true)
		}
	} else if res.FailedNotice != "" {
		if mode == "parked_mcp_resume" {
			s.HibernateWorker("soft_error_reset", true)
		}
		// Keep MessageCount on non-parked failed notice so client can retry onto the live session.
	} else {
		s.mu.Lock()
		s.MessageCount = len(messages) + 1
		s.lastTurnAssistant = true
		s.cancelledHistoryFp = ""
		if currentFirstFp != "" {
			s.HistoryFingerprint = currentFirstFp
		}
		if isCompactionReq {
			s.ForceRolloverNext = true
			s.ForceRolloverReason = "rollover_compaction"
		}
		if ctxTot := res.Usage.ContextTotal(); ctxTot > 0 {
			s.LastCachedReadTokens = ctxTot
		}
		s.mu.Unlock()
	}

	res.SessionID = sid
	res.ConvKey = s.ConvKey
	res.ElapsedMs = elapsed
	res.Mode = mode
	s.logTurnStatsWithReason(mode, rolloverReason, elapsed, res)
	if err := failedNoticeError(res); err != nil {
		return TurnResult{}, err
	}
	s.recordRecentCompletedTurn(requestFingerprintFromContext(ctx), res)
	return res, nil
}

func (s *AcpProjectSession) JoinDetachedTurn(ctx context.Context, reqFp string, messages []map[string]any, onDelta func(DeltaChunk)) (TurnResult, bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = withRequestFingerprint(ctx, reqFp)
	var finishDeltaGuard func()
	ctx, onDelta, finishDeltaGuard = guardDeltaCallback(ctx, onDelta)
	defer finishDeltaGuard()
	s.mu.Lock()
	det := s.detachedTurn
	if det == nil || det.reqFp != reqFp {
		s.mu.Unlock()
		return TurnResult{}, false, nil
	}
	s.detachedTurn = nil
	if det.graceTimer != nil {
		det.graceTimer.Stop()
	}
	s.IsBusy = true
	s.LastUsedAt = time.Now()
	s.mu.Unlock()
	softDetachJoinedTotal.Add(1)

	defer func() {
		s.mu.Lock()
		s.IsBusy = false
		s.LastUsedAt = time.Now()
		s.mu.Unlock()
	}()

	notifySessionWarn(ctx, s)
	var firstDeltaNs atomic.Int64
	wrappedDelta := wrapDeltaFirstTimer(onDelta, &firstDeltaNs)
	LogEvent("PREFILL_SOFT_DETACH_JOIN", "Singleflight joined retry onto live detached turn", map[string]any{
		"convKey":        s.ConvKey,
		"sessionId":      det.sid,
		"mode":           det.mode,
		"reqFingerprint": reqFp[:12],
	})

	if det.settledResult != nil {
		res := *det.settledResult
		if wrappedDelta != nil {
			if res.Thinking != "" {
				wrappedDelta(DeltaChunk{Type: "thinking", Thinking: res.Thinking})
			}
			if res.Text != "" {
				wrappedDelta(DeltaChunk{Type: "text", Text: res.Text})
			}
		}
		if res.Usage != nil && res.Usage.Degradation != nil && res.Usage.Degradation.Degraded {
			s.recordArgonDegradation(det.sid, res.Usage.Degradation, res.EmittedDeltas)
			s.mu.Lock()
			s.ForceRolloverNext = true
			s.ForceRolloverReason = "rollover_degraded"
			s.mu.Unlock()
		}
		finalRes, err := s.finalizeCompletedTurn(ctx, res, det.turnStart, firstDeltaNs.Load(), messages, det.firstUserFp, det.isCompactionReq, det.sid, det.mode, det.rolloverReason)
		return finalRes, true, err
	}

	if det.turn.HasDeltaChannel() {
		det.turn.AttachSubscriber(wrappedDelta)
	}

	select {
	case res := <-det.turn.resolveChan:
		det.turn.MarkResultConsumed()
		if !det.turn.HasDeltaChannel() && wrappedDelta != nil {
			if res.Thinking != "" {
				wrappedDelta(DeltaChunk{Type: "thinking", Thinking: res.Thinking})
			}
			if res.Text != "" {
				wrappedDelta(DeltaChunk{Type: "text", Text: res.Text})
			}
		}
		if len(res.ToolCalls) == 0 && det.turn.deltaDone != nil {
			<-det.turn.deltaDone
		}
		det.turn.DrainAndDetachSubscriber(ctx)
		if det.turn.releaseSem != nil {
			det.turn.releaseOnce.Do(det.turn.releaseSem)
		}
		if res.Usage != nil && res.Usage.Degradation != nil && res.Usage.Degradation.Degraded {
			s.recordArgonDegradation(det.sid, res.Usage.Degradation, res.EmittedDeltas)
			s.mu.Lock()
			s.ForceRolloverNext = true
			s.ForceRolloverReason = "rollover_degraded"
			s.mu.Unlock()
		}
		finalRes, err := s.finalizeCompletedTurn(ctx, res, det.turnStart, firstDeltaNs.Load(), messages, det.firstUserFp, det.isCompactionReq, det.sid, det.mode, det.rolloverReason)
		return finalRes, true, err
	case err := <-det.turn.errChan:
		det.turn.MarkResultConsumed()
		det.turn.CleanupSubscriber()
		if det.turn.releaseSem != nil {
			det.turn.releaseOnce.Do(det.turn.releaseSem)
		}
		s.HibernateWorker("prompt_rpc_error", true)
		return TurnResult{}, true, err
	case <-ctx.Done():
		cancFp := det.cancelledHistFp
		if cancFp == "" {
			cancFp = computeMessagesSliceFingerprint(messages)
		}
		if s.tryStartSoftDetachWithChars(det.turn, det.reqFp, det.sid, det.mode, det.rolloverReason, det.turnStart, det.turnStart, det.msgCount, det.firstUserFp, cancFp, det.isCompactionReq, det.promptChars) {
			return TurnResult{}, true, &softDetachError{cause: ctx.Err()}
		}
		var settled *TurnResult
		select {
		case res := <-det.turn.resolveChan:
			det.turn.MarkResultConsumed()
			settled = &res
		default:
		}
		det.turn.mu.Lock()
		alreadyUpstreamDone := det.turn.upstreamDone && !det.turn.failed
		det.turn.mu.Unlock()
		det.turn.CleanupSubscriber()
		if det.turn.releaseSem != nil {
			det.turn.releaseOnce.Do(det.turn.releaseSem)
		}
		det.turn.CancelContext()
		det.turn.closeDelta()
		if settled != nil || alreadyUpstreamDone {
			s.HibernateWorker("unclaimed_detached_rollover", true)
			s.mu.Lock()
			s.ForceRolloverNext = true
			s.ForceRolloverReason = "rollover_unclaimed_detached"
			s.mu.Unlock()
			return TurnResult{}, true, ctx.Err()
		}
		s.CancelActiveTurn("client_disconnect")
		if det.sid != "" {
			GlobalEngine.CancelSession(det.sid)
		}
		s.mu.Lock()
		s.MessageCount = len(messages)
		s.lastTurnAssistant = false
		s.cancelledHistoryFp = cancFp
		s.mu.Unlock()
		return TurnResult{}, true, ctx.Err()
	}
}

// cacheHitSlackTokens: a turn counts as a cache hit when the uncached part of its prompt is at
// most max(8K, 10%) tokens, i.e. only the new user/tool delta was uncached.
const cacheHitSlackTokens = 8192

// classifyCacheMiss labels why a measured turn missed the upstream implicit cache:
// rollover/cold_start (gateway started a fresh session), model_switch, shrink (agy shortened the
// prompt), gap_ttl (idle >= 5 min, beyond the observed cache lifetime), zero (nothing cached) and
// prefix_only (only the system prefix was cached). Hits and estimated rows return "".
func classifyCacheMiss(mode string, u *TurnUsage, prev *TurnHistoryEntry, curModel string, now time.Time) string {
	return classifyCacheMissWithReason(mode, "", u, prev, curModel, now)
}

func classifyCacheMissWithReason(mode, rolloverReason string, u *TurnUsage, prev *TurnHistoryEntry, curModel string, now time.Time) string {
	if u == nil || (u.UsageSource != "db" && u.UsageSource != "acp") {
		return ""
	}
	in, cr := u.ContextInputTokens, u.ContextCachedTokens
	if in == 0 && cr == 0 {
		in, cr = u.RawUncachedInputTokens, u.RawTpuCachedTokens
	}
	if in == 0 && cr == 0 {
		in, cr = u.InputTokens, u.CachedReadTokens
	}
	total := in + cr
	if total == 0 {
		return ""
	}
	slack := total / 10
	if slack < cacheHitSlackTokens {
		slack = cacheHitSlackTokens
	}
	if in <= slack {
		return ""
	}
	switch mode {
	case "cold_start":
		return "cold_start"
	case "argon_degraded_recovery", "high_capacity_fallback", "waf_autobisect_recovery":
		if rolloverReason != "" {
			return rolloverReason
		}
		return "rollover"
	case "compaction_rollover":
		if rolloverReason != "" {
			return rolloverReason
		}
		return "rollover"
	}
	if prev != nil {
		if prev.Model != "" && curModel != "" && prev.Model != curModel {
			return "model_switch"
		}
		if prev.Usage != nil {
			prevTotal := prev.Usage.ContextTotal()
			if prevTotal == 0 {
				prevTotal = prev.Usage.RawUncachedInputTokens + prev.Usage.RawTpuCachedTokens
			}
			if prevTotal > 0 && total+2048 < prevTotal {
				return "shrink"
			}
		}
		if prev.CompletedAtMs > 0 && now.UnixMilli()-prev.CompletedAtMs >= 300000 {
			return "gap_ttl"
		}
	}
	if cr == 0 {
		return "zero"
	}
	return "prefix_only"
}

func promptBlocksCharLen(blocks []map[string]any) int {
	total := 0
	for _, b := range blocks {
		if t, ok := b["text"].(string); ok {
			total += len(t)
		} else if res, ok := b["resource"].(map[string]any); ok {
			if rt, okT := res["text"].(string); okT {
				total += len(rt)
			}
		}
	}
	return total
}

func (s *AcpProjectSession) executePromptOrPark(ctx context.Context, promptBlocks []map[string]any, onDelta func(DeltaChunk), contDepth int) (TurnResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	sem := promptSem
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return TurnResult{}, ctx.Err()
	}

	if err := circuitError(); err != nil {
		<-sem
		return TurnResult{}, err
	}
	s.mu.Lock()
	s.PromptStepCount = 1
	s.orphanRelayHops = 0
	s.lastOrphanRelayAt = time.Time{}
	s.orphanCapLogged = false
	s.RecentToolSigs = nil
	s.PendingSiblingCalls = nil
	s.RelayedCalls = nil
	s.reportedToolCalls = make(map[string]reportedToolIdentity)
	if s.LastSeenDbStepIdx > s.LastPlannerBatchIdx {
		s.LastPlannerBatchIdx = s.LastSeenDbStepIdx
	}
	s.PromptInFlight = true
	sid := s.SessionID
	clearCancelledWatermark := s.wasCancelledTurn && contDepth == 0
	if clearCancelledWatermark {
		s.wasCancelledTurn = false
	}
	isProbe := s.isWafBisectProbe
	allowFast := s.allowWafFastCancel && contDepth == 0 && s.MessageCount == 0
	codec := s.Codec
	turn := newActiveTurnStateWithCodec(onDelta, func() { <-sem }, codec)
	if isProbe || allowFast {
		turn.onRetryNotice = func(attempt int, detail string) {
			if !isBisectableInstant429Detail(detail) {
				return
			}
			turn.mu.Lock()
			elapsed := time.Since(turn.createdAt)
			minAtt := 2
			if isProbe {
				minAtt = 1
			}
			shouldCancel := !turn.fastCancelledForBisect && !turn.resolved && !turn.emittedText &&
				len(turn.thoughtChks) == 0 && len(turn.toolCalls) == 0 &&
				attempt >= minAtt && elapsed < 8*time.Second
			if shouldCancel {
				turn.fastCancelledForBisect = true
				turn.fastCancelDetail = detail
			}
			turn.mu.Unlock()
			if shouldCancel {
				if !isProbe {
					LogEvent("WAF_FAST_CANCEL", "Aborted first-turn instant 429 retry loop to run WAF auto-bisect", map[string]any{
						"convKey":   s.ConvKey,
						"sessionId": sid,
						"attempt":   attempt,
						"elapsedMs": elapsed.Milliseconds(),
						"detail":    detail,
					})
				}
				go GlobalEngine.CancelSession(sid)
			}
		}
	}
	s.activeTurn = turn
	s.mu.Unlock()
	if clearCancelledWatermark {
		s.advanceUsageWatermarks(sid)
	}

	promptChars := promptBlocksCharLen(promptBlocks)

	origTurn := turn
	go func() {
		defer close(origTurn.bgDone)
		defer origTurn.releaseOnce.Do(origTurn.releaseSem)
		rawRes, err := GlobalEngine.RPC("session/prompt", map[string]any{
			"sessionId": sid,
			"prompt":    promptBlocks,
		}, 3600*time.Second)

		s.mu.Lock()
		s.PromptInFlight = false
		s.PendingSiblingCalls = nil
		s.RelayedCalls = nil
		s.reportedToolCalls = nil
		cur := s.activeTurn
		// After a parked tool resumes, resumeParkedTurn installs a NEW activeTurn on the same in-flight
		// prompt; the original turn was already resolved (tool_use). Resolve whichever turn is current.
		target := turn
		turn.mu.Lock()
		origResolved := turn.resolved
		turn.mu.Unlock()
		if origResolved && cur != nil && cur != turn {
			target = cur
		}
		if cur == target || cur == turn {
			s.activeTurn = nil
		}
		s.mu.Unlock()
		turn := target // shadow: do not mutate the outer variable from this goroutine
		defer func() {
			if turn.releaseSem != nil {
				turn.releaseOnce.Do(turn.releaseSem)
			}
		}()

		turn.mu.Lock()
		if turn.batchTimer != nil {
			turn.batchTimer.Stop()
		}
		alreadyResolved := turn.resolved
		turn.mu.Unlock()

		if alreadyResolved {
			s.mu.Lock()
			wasCanc := s.wasCancelledTurn
			s.mu.Unlock()
			if wasCanc {
				s.advanceUsageWatermarks(sid)
			}
			return
		}

		if err != nil {
			s.advanceUsageWatermarks(sid)
			turn.mu.Lock()
			turn.resolved = true
			turn.failed = true
			turn.upstreamDone = true
			turn.mu.Unlock()
			turn.CancelContext()
			turn.closeDelta()
			if turn.releaseSem != nil {
				turn.releaseOnce.Do(turn.releaseSem)
			}
			select {
			case turn.errChan <- err:
			default:
			}
			return
		}

		var parsed struct {
			StopReason string         `json:"stopReason"`
			Usage      map[string]any `json:"usage"`
		}
		_ = json.Unmarshal(rawRes, &parsed)

		turn.mu.Lock()
		prevFinishInfo := turn.noticeInfo
		held := turn.finishNoticeLocked()
		finishDroppedInfo := turn.noticeInfo > prevFinishInfo
		finishRetryAttempt := turn.lastRetryAttempt
		finishRetryDetail := turn.lastRetryDetail
		if held != "" {
			turn.textChunks = append(turn.textChunks, held)
		}
		turn.mu.Unlock()
		if finishDroppedInfo {
			meta := map[string]any{"convKey": s.ConvKey}
			if finishRetryAttempt > 0 {
				meta["attempt"] = finishRetryAttempt
			}
			if finishRetryDetail != "" {
				meta["detail"] = finishRetryDetail
			}
			LogEvent("RETRY_NOTICE_FILTERED", "Dropped internal agy retry/limit/cancel notice", meta)
		}
		if held != "" {
			turn.pushDelta(DeltaChunk{Type: "text", Text: held})
		}

		turn.mu.Lock()
		txt := strings.Join(turn.textChunks, "")
		thk := strings.Join(turn.thoughtChks, "")
		tcalls := turn.toolCalls
		effectiveNotice := formatTerminalNoticeWithDetail(turn.noticeText, turn.lastRetryDetail)
		if effectiveNotice != "" {
			LogEvent("AGY_NOTICE_FILTERED", "Withheld agy terminal notice from client stream", map[string]any{
				"convKey": s.ConvKey, "notice": effectiveNotice, "replyChars": len(txt),
			})
		}
		failedNotice := ""
		if turn.noticeFailed && len(tcalls) == 0 && strings.TrimSpace(txt) != "" {
			// agy failed after part of the reply was already produced (R5): report a failure
			failedNotice = effectiveNotice
		}
		txt = noticeOnlyText(txt, effectiveNotice, len(tcalls))
		if s.Codec != nil {
			if DetectAntigravitySoftError(txt) == nil {
				txt = s.Codec.RestoreText(txt)
			}
			thk = s.Codec.RestoreText(thk)
		}
		fastCancelled := turn.fastCancelledForBisect
		fastDetail := turn.fastCancelDetail
		firstAt := turn.firstChunk
		if firstAt.IsZero() {
			firstAt = time.Now()
		}
		ttft := int(firstAt.Sub(turn.createdAt).Milliseconds())
		if ttft < 10 {
			ttft = 10
		}
		thinkingMs := turn.computeThinkingMsLocked()
		retryCnt := turn.retryCountLocked()
		turn.resolved = true
		turn.upstreamDone = true
		turn.mu.Unlock()

		if parsed.StopReason == "max_tokens" && contDepth < 3 && len(tcalls) == 0 && failedNotice == "" {
			turn.closeDelta()
			emittedSoFar := int(turn.emittedDeltas.Load())
			if turn.releaseSem != nil {
				turn.releaseOnce.Do(turn.releaseSem)
			}
			LogEvent("AUTO_CONTINUE", fmt.Sprintf("Auto-continuing truncated response (depth=%d)", contDepth+1), map[string]any{
				"convKey":   s.ConvKey,
				"sessionId": sid,
			})
			var contDelta func(DeltaChunk)
			if turn.HasDeltaChannel() {
				contDelta = func(c DeltaChunk) { turn.emitSubscriberDelta(c) }
			}
			contCtx := turn.turnCtx
			if contCtx == nil {
				contCtx = context.Background()
			}
			nextRes, contErr := s.executePromptOrPark(contCtx, []map[string]any{
				{"type": "text", "text": "Continue exactly where you stopped. Do not repeat anything already written."},
			}, contDelta, contDepth+1)
			if contErr != nil {
				turn.mu.Lock()
				turn.failed = true
				turn.mu.Unlock()
				turn.CancelContext()
				turn.closeDelta()
				select {
				case turn.errChan <- contErr:
				default:
				}
				return
			}
			if strings.TrimSpace(txt) != "" && nextRes.FailedNotice == "" && len(nextRes.ToolCalls) == 0 && DetectAntigravitySoftError(nextRes.Text) != nil {
				nextRes.FailedNotice = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(nextRes.Text), "⚠"))
				nextRes.Text = txt
			} else {
				nextRes.Text = txt + nextRes.Text
			}
			nextRes.Thinking = thk + nextRes.Thinking
			nextRes.EmittedDeltas += emittedSoFar
			if nextRes.Usage != nil && nextRes.Usage.UsageSource == "acp" && parsed.Usage != nil {
				if hopOut, ok := toInt(parsed.Usage["outputTokens"]); ok && hopOut > 0 {
					nextRes.Usage.OutputTokens += hopOut
				}
				if hopTh, ok := toInt(parsed.Usage["thoughtTokens"]); ok && hopTh > 0 {
					nextRes.Usage.ThinkingTokens += hopTh
				}
			}
			nextRes.FirstChunkAt = firstAt
			nextRes.TtftMs = ttft
			nextRes.ThinkingMs += thinkingMs
			nextRes.RetryCount += retryCnt
			turn.CancelContext()
			turn.closeDelta()
			select {
			case turn.resolveChan <- nextRes:
			default:
			}
			return
		}

		if parsed.StopReason == "cancelled" {
			// The prompt was cancelled upstream (session closed, cancel, engine restart). Never
			// report it as a successful (possibly empty) end_turn, and advance generation cursors
			// so aborted rows in <sid>.db are never summed into a subsequent turn.
			turn.mu.Lock()
			turn.failed = true
			turn.mu.Unlock()
			s.advanceUsageWatermarks(sid)
			turn.CancelContext()
			turn.closeDelta()
			if turn.releaseSem != nil {
				turn.releaseOnce.Do(turn.releaseSem)
			}
			if fastCancelled {
				select {
				case turn.errChan <- &wafFastCancelledError{Detail: fastDetail}:
				default:
				}
				return
			}
			LogEvent("TURN_CANCELLED", "Upstream prompt ended with stopReason=cancelled", map[string]any{
				"convKey": s.ConvKey, "sessionId": sid, "replyChars": len(txt),
			})
			select {
			case turn.errChan <- &SoftError{StatusCode: http.StatusServiceUnavailable, ErrorType: "api_error", Message: "Antigravity upstream cancelled the turn before it completed"}:
			default:
			}
			return
		}

		turn.CancelContext()
		turn.closeDelta()
		emitted := int(turn.emittedDeltas.Load())
		usage := s.normalizeTurnUsageAsync(parsed.Usage, false, promptChars, len(txt)+len(thk))
		if turn.releaseSem != nil {
			turn.releaseOnce.Do(turn.releaseSem)
		}
		finalStop := "end_turn"
		if parsed.StopReason == "max_tokens" {
			finalStop = "max_tokens"
		}
		select {
		case turn.resolveChan <- TurnResult{
			StopReason:    finalStop,
			Text:          txt,
			Thinking:      thk,
			ToolCalls:     nil,
			Usage:         usage,
			TtftMs:        ttft,
			ThinkingMs:    thinkingMs,
			RetryCount:    retryCnt,
			EmittedDeltas: emitted,
			FirstChunkAt:  firstAt,
			FailedNotice:  failedNotice,
		}:
		default:
		}
	}()

	waitStart := time.Now()
	select {
	case res := <-turn.resolveChan:
		turn.MarkResultConsumed()
		turn.DrainAndDetachSubscriber(ctx)
		return res, nil
	case err := <-turn.errChan:
		turn.MarkResultConsumed()
		turn.CleanupSubscriber()
		return TurnResult{}, err
	case <-ctx.Done():
		if contDepth == 0 {
			reqFp := requestFingerprintFromContext(ctx)
			meta := turnDetachMetaFromContext(ctx)
			sidDet := sid
			modeDet := "cold_start"
			rollDet := ""
			turnStartDet := waitStart
			msgCountDet := 0
			firstUserDet := ""
			cancFpDet := ""
			isCompDet := false
			if meta != nil {
				if meta.sid != "" {
					sidDet = meta.sid
				}
				if meta.mode != "" {
					modeDet = meta.mode
				}
				rollDet = meta.rolloverReason
				if !meta.turnStart.IsZero() {
					turnStartDet = meta.turnStart
				}
				msgCountDet = meta.msgCount
				firstUserDet = meta.firstUserFp
				cancFpDet = meta.cancelledHistFp
				isCompDet = meta.isCompactionReq
			}
			if s.tryStartSoftDetachWithChars(turn, reqFp, sidDet, modeDet, rollDet, turnStartDet, waitStart, msgCountDet, firstUserDet, cancFpDet, isCompDet, promptChars) {
				return TurnResult{}, &softDetachError{cause: ctx.Err()}
			}
		}
		turn.CancelContext()
		turn.CleanupSubscriber()
		s.CancelActiveTurn("client_disconnect")
		return TurnResult{}, ctx.Err()
	}
}

func (s *AcpProjectSession) recordArgonDegradation(sid string, deg *ArgonDegradationReport, emittedDeltas int) {
	if deg == nil || !deg.Degraded {
		return
	}
	argonDegradationDetectedTotal.Add(1)
	LogEvent("ARGON_DEGRADATION_DETECTED", fmt.Sprintf("Detected Gemini 4 Argon shadow pool routing (served=%s)", deg.ServedModel), map[string]any{
		"servedModel":   deg.ServedModel,
		"convKey":       s.ConvKey,
		"sessionId":     sid,
		"cwmEstTokens":  deg.CwmEstTokens,
		"promptTokens":  deg.PromptTokens,
		"cachedTokens":  deg.CachedTokens,
		"outputTokens":  deg.OutputTokens,
		"thoughtTokens": deg.ThoughtTokens,
		"ttftSeconds":   deg.TtftSeconds,
		"streamSeconds": deg.StreamSeconds,
		"emittedDeltas": emittedDeltas,
	})
}

func wrapDeltaFirstTimer(onDelta func(DeltaChunk), firstDeltaNs *atomic.Int64) func(DeltaChunk) {
	if onDelta == nil || firstDeltaNs == nil {
		return onDelta
	}
	return func(c DeltaChunk) {
		if (c.Type == "thinking" && c.Thinking != "") || (c.Type == "text" && c.Text != "") {
			firstDeltaNs.CompareAndSwap(0, time.Now().UnixNano())
		}
		onDelta(c)
	}
}

func resolveTurnTtftMs(turnStart time.Time, elapsedMs int, firstDeltaNs int64, res TurnResult) int {
	ttft := 0
	if firstDeltaNs > 0 {
		ttft = int((firstDeltaNs - turnStart.UnixNano()) / 1e6)
	} else {
		if !res.FirstChunkAt.IsZero() && !res.FirstChunkAt.Before(turnStart) {
			ttft = int(res.FirstChunkAt.Sub(turnStart).Milliseconds())
		} else if res.TtftMs > 0 {
			ttft = res.TtftMs
		} else {
			ttft = elapsedMs
		}
		if res.Usage != nil && res.Usage.StreamMs > 0 && elapsedMs > res.Usage.StreamMs {
			derived := elapsedMs - res.Usage.StreamMs
			if ttft <= 0 || ttft > derived {
				ttft = derived
			}
		}
	}
	if ttft < 10 && elapsedMs >= 10 {
		ttft = 10
	} else if ttft < 1 && elapsedMs > 0 {
		ttft = 1
	}
	if elapsedMs > 0 && ttft > elapsedMs {
		ttft = elapsedMs
	}
	return ttft
}

func (s *AcpProjectSession) resumeParkedTurn(ctx context.Context, matched []ToolResultInput, messages []map[string]any, onDelta func(DeltaChunk)) (TurnResult, error) {
	var firstDeltaNs atomic.Int64
	t0 := time.Now()
	return s.resumeParkedTurnTimed(ctx, matched, messages, wrapDeltaFirstTimer(onDelta, &firstDeltaNs), t0, &firstDeltaNs)
}

func formatParkedToolResultText(tr ToolResultInput, codec *ReversibleSessionCodec, emptyFallback string) string {
	body := stripRedundantSystemReminders(tr.Content)
	if body == "" && emptyFallback != "" {
		body = emptyFallback
	}
	combined := body
	if tr.SystemTail != "" {
		if combined == "" {
			combined = tr.SystemTail
		} else {
			combined = combined + "\n\n" + tr.SystemTail
		}
	}
	if codec != nil && combined != "" {
		combined = codec.EncodeOutboundText(combined)
	}
	return combined
}

func (s *AcpProjectSession) resumeParkedTurnTimed(ctx context.Context, matched []ToolResultInput, messages []map[string]any, onDelta func(DeltaChunk), t0 time.Time, firstDeltaNs *atomic.Int64) (TurnResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if t0.IsZero() {
		t0 = time.Now()
	}
	s.mu.Lock()
	s.PromptStepCount++
	s.orphanRelayHops = 0
	s.lastOrphanRelayAt = time.Time{}
	s.orphanCapLogged = false
	inFlight := s.PromptInFlight
	sid := s.SessionID
	s.mu.Unlock()

	runNewPromptResume := func() (TurnResult, error) {
		s.mu.Lock()
		s.ParkedCalls = make(map[string]*ParkedMcpCall)
		s.LastDeliveredCallIDs = nil
		s.ParkedSince = time.Time{}
		s.mu.Unlock()
		var blocks []map[string]any
		var textLines []string
		for _, tr := range matched {
			cleanTxt := formatParkedToolResultText(tr, s.Codec, "")
			textLines = append(textLines, fmt.Sprintf("[Tool Result (%s)]: %s", tr.ToolCallID, cleanTxt))
			for _, img := range tr.Images {
				blocks = append(blocks, img)
			}
		}
		textLines = append(textLines, "\nContinue the task with these tool results.")
		blocks = append(blocks, map[string]any{"type": "text", "text": strings.Join(textLines, "\n\n")})
		val, err := s.executePromptOrPark(ctx, blocks, onDelta, 0)
		if err != nil {
			return TurnResult{}, err
		}
		if val.Usage != nil && val.Usage.Degradation != nil && val.Usage.Degradation.Degraded {
			s.recordArgonDegradation(sid, val.Usage.Degradation, val.EmittedDeltas)
			s.mu.Lock()
			s.ForceRolloverNext = true
			s.ForceRolloverReason = "rollover_degraded"
			s.mu.Unlock()
		}
		elapsed := int(time.Since(t0).Milliseconds())
		var fdNs int64
		if firstDeltaNs != nil {
			fdNs = firstDeltaNs.Load()
		}
		val.TtftMs = resolveTurnTtftMs(t0, elapsed, fdNs, val)
		if DetectAntigravitySoftError(val.Text) != nil {
			s.HibernateWorker("soft_error_reset", true)
		} else if val.FailedNotice != "" {
			s.HibernateWorker("soft_error_reset", true)
		} else {
			s.mu.Lock()
			s.MessageCount = len(messages) + 1
			s.lastTurnAssistant = true
			s.cancelledHistoryFp = ""
			if fp := computeFirstUserFingerprint(messages); fp != "" {
				s.HistoryFingerprint = fp
			}
			if ctxTot := val.Usage.ContextTotal(); ctxTot > 0 {
				s.LastCachedReadTokens = ctxTot
			}
			s.mu.Unlock()
		}
		val.SessionID = sid
		val.ConvKey = s.ConvKey
		val.ElapsedMs = elapsed
		val.Mode = "parked_mcp_resume"
		s.logTurnStats("parked_mcp_resume", elapsed, val)
		if err := failedNoticeError(val); err != nil {
			return TurnResult{}, err
		}
		return val, nil
	}

	if !inFlight {
		return runNewPromptResume()
	}

	sem := promptSem
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		s.CancelActiveTurn("client_disconnect")
		return TurnResult{}, ctx.Err()
	}

	if err := circuitError(); err != nil {
		<-sem
		return TurnResult{}, err
	}
	turn := newActiveTurnStateWithCodec(onDelta, func() { <-sem }, s.Codec)
	var lateCalls []ToolCallItem
	s.mu.Lock()
	if !s.PromptInFlight {
		s.mu.Unlock()
		turn.closeDelta()
		turn.CleanupSubscriber()
		turn.releaseOnce.Do(turn.releaseSem)
		return runNewPromptResume()
	}
	s.activeTurn = turn
	for _, tr := range matched {
		if parked, ok := s.ParkedCalls[tr.ToolCallID]; ok {
			delete(s.ParkedCalls, tr.ToolCallID)
			txt := formatParkedToolResultText(tr, s.Codec, "OK")
			contentBlocks := []map[string]any{{"type": "text", "text": txt}}
			contentBlocks = append(contentBlocks, tr.Images...)
			select {
			case parked.ResultChan <- map[string]any{
				"content": contentBlocks,
				"isError": tr.IsError,
			}:
			default:
			}
		}
	}
	for id, parked := range s.ParkedCalls {
		if !parked.Delivered {
			// Late parallel tool call arrived after the 80ms batch window: keep it parked and deliver it now!
			lateCalls = append(lateCalls, parked.Call)
			continue
		}
		delete(s.ParkedCalls, id)
		select {
		case parked.ResultChan <- map[string]any{
			"content": []map[string]any{{"type": "text", "text": "Tool result was not provided by host client."}},
			"isError": true,
		}:
		default:
		}
	}
	if len(s.ParkedCalls) == 0 {
		s.ParkedSince = time.Time{}
		s.LastDeliveredCallIDs = nil
	}
	s.mu.Unlock()

	for _, lc := range lateCalls {
		s.enqueueToolCallToTurn(lc)
	}

	waitStart := time.Now()
	select {
	case val := <-turn.resolveChan:
		turn.MarkResultConsumed()
		turn.DrainAndDetachSubscriber(ctx)
		if len(val.ToolCalls) == 0 && val.StopReason != "tool_use" {
			turn.CancelContext()
		}
		turn.releaseOnce.Do(turn.releaseSem)
		if val.Usage != nil && val.Usage.Degradation != nil && val.Usage.Degradation.Degraded {
			s.recordArgonDegradation(sid, val.Usage.Degradation, val.EmittedDeltas)
			s.mu.Lock()
			s.ForceRolloverNext = true
			s.ForceRolloverReason = "rollover_degraded"
			s.mu.Unlock()
		}
		elapsed := int(time.Since(t0).Milliseconds())
		var fdNs int64
		if firstDeltaNs != nil {
			fdNs = firstDeltaNs.Load()
		}
		val.TtftMs = resolveTurnTtftMs(t0, elapsed, fdNs, val)
		if DetectAntigravitySoftError(val.Text) != nil {
			s.HibernateWorker("soft_error_reset", true)
		} else if val.FailedNotice != "" {
			s.HibernateWorker("soft_error_reset", true)
		} else {
			s.mu.Lock()
			s.MessageCount = len(messages) + 1
			s.lastTurnAssistant = true
			s.cancelledHistoryFp = ""
			if fp := computeFirstUserFingerprint(messages); fp != "" {
				s.HistoryFingerprint = fp
			}
			if ctxTot := val.Usage.ContextTotal(); ctxTot > 0 {
				s.LastCachedReadTokens = ctxTot
			}
			s.mu.Unlock()
		}
		val.SessionID = sid
		val.ConvKey = s.ConvKey
		val.ElapsedMs = elapsed
		val.Mode = "parked_mcp_resume"
		s.logTurnStats("parked_mcp_resume", elapsed, val)
		if err := failedNoticeError(val); err != nil {
			return TurnResult{}, err
		}
		return val, nil
	case err := <-turn.errChan:
		turn.MarkResultConsumed()
		turn.CleanupSubscriber()
		turn.CancelContext()
		turn.releaseOnce.Do(turn.releaseSem)
		return TurnResult{}, err
	case <-ctx.Done():
		reqFp := requestFingerprintFromContext(ctx)
		meta := turnDetachMetaFromContext(ctx)
		turnStartDet := t0
		firstFpDet := computeFirstUserFingerprint(messages)
		cancFpDet := computeMessagesSliceFingerprint(messages)
		isCompDet := false
		if meta != nil {
			if !meta.turnStart.IsZero() {
				turnStartDet = meta.turnStart
			}
			if meta.firstUserFp != "" {
				firstFpDet = meta.firstUserFp
			}
			if meta.cancelledHistFp != "" {
				cancFpDet = meta.cancelledHistFp
			}
			isCompDet = meta.isCompactionReq
		}
		if s.tryStartSoftDetach(turn, reqFp, sid, "parked_mcp_resume", "", turnStartDet, waitStart, len(messages), firstFpDet, cancFpDet, isCompDet) {
			return TurnResult{}, &softDetachError{cause: ctx.Err()}
		}
		turn.CancelContext()
		turn.CleanupSubscriber()
		s.CancelActiveTurn("client_disconnect")
		s.mu.Lock()
		s.MessageCount = len(messages)
		s.lastTurnAssistant = false
		s.cancelledHistoryFp = cancFpDet
		s.mu.Unlock()
		return TurnResult{}, ctx.Err()
	}
}

func (s *AcpProjectSession) RunTurn(ctx context.Context, messages []map[string]any, toolsCatalog []ToolDef, thoughtLevel string, onDelta func(DeltaChunk), sel *ModelSelection) (TurnResult, error) {
	if err := circuitError(); err != nil {
		return TurnResult{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var finishDeltaGuard func()
	ctx, onDelta, finishDeltaGuard = guardDeltaCallback(ctx, onDelta)
	defer finishDeltaGuard()
	turnStart := time.Now()
	if reqStart, ok := httpRequestStartFromContext(ctx); ok && !reqStart.After(turnStart) {
		turnStart = reqStart
	}
	var firstDeltaNs atomic.Int64
	onDelta = wrapDeltaFirstTimer(onDelta, &firstDeltaNs)
	turnDir := turnDirectiveFromContext(ctx)
	tailDirective := buildTurnDirectivePromptTail(turnDir, toolsCatalog)
	s.mu.Lock()
	s.LastUsedAt = turnStart
	s.IsBusy = true
	s.activeTurnToolChoice = turnDir.ToolChoice
	hasParked := len(s.ParkedCalls) > 0
	initMsgCnt := s.MessageCount
	initSys := s.SystemText
	initModel := s.ModelID
	initTools := append([]ToolDef(nil), s.InitialToolsCatalog...)
	codec := s.Codec
	s.mu.Unlock()
	if requestFingerprintFromContext(ctx) == "" {
		fpModel := initModel
		if sel != nil && sel.Model != nil && sel.Model.ID != "" {
			fpModel = sel.Model.ID
		}
		if fp := computeTurnRequestFingerprintWithDirective(fpModel, thoughtLevel, initSys, toolsCatalog, messages, turnDir.FingerprintToken()); fp != "" {
			ctx = withRequestFingerprint(ctx, fp)
		}
	}
	if codec != nil {
		codec.SeedFromToolsCatalog(initTools)
		codec.SeedFromToolsCatalog(toolsCatalog)
		if initMsgCnt > 0 && len(messages) > 0 {
			bound := initMsgCnt
			if bound > len(messages) {
				bound = len(messages)
			}
			codec.SeedFromConversationOnce(initSys, messages[:bound])
		} else if initMsgCnt == 0 {
			codec.MarkHistorySeeded()
		}
	}

	defer func() {
		s.mu.Lock()
		if !s.PromptInFlight && len(s.ParkedCalls) == 0 && len(s.RelayedCalls) == 0 {
			s.activeTurnToolChoice = TurnToolChoice{}
		}
		s.IsBusy = false
		s.LastUsedAt = time.Now()
		s.mu.Unlock()
	}()

	currentFirstFp := computeFirstUserFingerprint(messages)
	s.mu.Lock()
	isCompactionReq := s.explicitCompactionReq || isCompactionSummaryRequest(messages)
	s.explicitCompactionReq = false
	s.mu.Unlock()

	rolledOverFromParked := false
	rolloverReason := ""
	if hasParked && len(messages) > 0 {
		s.mu.Lock()
		forced := s.ForceRolloverNext
		forcedWhy := s.ForceRolloverReason
		shrank := s.MessageCount > 0 && (len(messages) < s.MessageCount || (s.lastTurnAssistant && messages[s.MessageCount-1]["role"] != "assistant"))
		cancEdited := cancelledHistoryDiverged(messages, s.MessageCount, s.lastTurnAssistant, s.cancelledHistoryFp)
		fpChanged := s.HistoryFingerprint != "" && currentFirstFp != "" && currentFirstFp != s.HistoryFingerprint
		compactedWhileParked := forced || shrank || cancEdited || fpChanged
		modelChanged := sel != nil && sel.Model != nil && sel.Model.ID != "" && s.ModelID != "" && sel.Model.ID != s.ModelID
		oldMsgCnt := s.MessageCount
		oldSid := s.SessionID
		oldModel := s.ModelID
		s.mu.Unlock()

		if compactedWhileParked || modelChanged {
			switch {
			case forced && forcedWhy != "":
				rolloverReason = forcedWhy
			case cancEdited:
				rolloverReason = "rollover_cancelled_edit"
			case shrank:
				rolloverReason = "rollover_compaction"
			case fpChanged:
				rolloverReason = "rollover_prefix"
			case modelChanged:
				rolloverReason = "rollover_model_switch"
			default:
				rolloverReason = "rollover"
			}
			if compactedWhileParked {
				LogEvent("COMPACTION_ROLLOVER", fmt.Sprintf("Conversation compacted while tool was parked (%d -> %d msgs); closing old session and rolling over", oldMsgCnt, len(messages)), map[string]any{
					"convKey":      s.ConvKey,
					"oldSessionId": oldSid,
					"newMsgCount":  len(messages),
					"reason":       rolloverReason,
				})
				s.HibernateWorker("compaction_rollover_parked", true)
			} else {
				LogEvent("COMPACTION_ROLLOVER", fmt.Sprintf("Canonical model switched while tool was parked (%s -> %s); closing old session and rolling over", oldModel, sel.Model.ID), map[string]any{
					"convKey":      s.ConvKey,
					"oldSessionId": oldSid,
					"oldModel":     oldModel,
					"newModel":     sel.Model.ID,
					"newMsgCount":  len(messages),
					"reason":       rolloverReason,
				})
				s.HibernateWorker("model_switch_parked", true)
			}
			s.mu.Lock()
			s.ForceRolloverNext = false
			s.ForceRolloverReason = ""
			s.CompactionRollovers++
			s.capacityFallbackSid = ""
			s.highTierZeroCacheStreak = 0
			s.mu.Unlock()
			hasParked = false
			rolledOverFromParked = true
		} else {
			trs := extractToolResultsFromMessages(messages)
			var matched []ToolResultInput
			lastTrMatched := false
			s.mu.Lock()
			for i, tr := range trs {
				if _, ok := s.ParkedCalls[tr.ToolCallID]; ok {
					matched = append(matched, tr)
					if i == len(trs)-1 {
						lastTrMatched = true
					}
				}
			}
			s.mu.Unlock()

			if len(matched) > 0 {
				if !lastTrMatched && len(trs) > 0 {
					tail := trs[len(trs)-1]
					if tail.TrailingUserText != "" || len(tail.TrailingUserImages) > 0 {
						attachTrailingUserInputsToToolResult(&matched[len(matched)-1], tail.TrailingUserText, tail.TrailingUserImages)
					}
				}
				var mmErr error
				matched, mmErr = resolveToolResultImages(ctx, GlobalImageFetcher, matched, ModelOrDefault(initModel))
				if mmErr != nil {
					return TurnResult{}, mmErr
				}
				var parkedToolNotice, parkedSysDelta string
				var pAdded, pRemoved, pChanged []string
				s.mu.Lock()
				s.SessionReuses++
				if s.hasPendingSystem || s.pendingSystemText != "" {
					pend := s.pendingSystemText
					s.pendingSystemText = ""
					s.hasPendingSystem = false
					if pend != s.SystemText {
						parkedSysDelta = systemPromptDelta(s.SystemText, pend)
						s.SystemText = pend
					}
					if s.pendingRawSystemText != "" || pend == "" {
						s.RawSystemText = s.pendingRawSystemText
						s.pendingRawSystemText = ""
					}
				}
				if len(s.DeclaredMcpTools) > 0 {
					parkedToolNotice, pAdded, pRemoved, pChanged = s.consumeToolCatalogLocked(toolsCatalog)
				}
				sid := s.SessionID
				s.mu.Unlock()

				appendSystemTail := func(extra string) {
					if extra == "" {
						return
					}
					last := len(matched) - 1
					if matched[last].SystemTail == "" {
						matched[last].SystemTail = extra
					} else {
						matched[last].SystemTail += "\n\n" + extra
					}
				}
				if parkedSysDelta != "" {
					appendSystemTail(parkedSysDelta)
					LogEvent("SYSTEM_PROMPT_CHANGED", "Client system prompt changed during parked MCP resume", map[string]any{
						"convKey": s.ConvKey, "deltaChars": len(parkedSysDelta),
					})
				}
				if parkedToolNotice != "" {
					appendSystemTail(parkedToolNotice)
					LogEvent("TOOLS_UPDATED_IN_PLACE", "Updated session tool catalog in-place during parked MCP resume (cache preserved)", map[string]any{
						"convKey": s.ConvKey, "sessionId": sid, "added": pAdded, "removed": pRemoved, "changed": pChanged,
					})
				}
				if parkedSysDelta != "" || parkedToolNotice != "" {
					GlobalStore.UpsertSession(s)
				}
				if tailDirective != "" {
					appendSystemTail(tailDirective)
				}
				var ids []string
				for _, m := range matched {
					ids = append(ids, m.ToolCallID)
				}
				LogEvent("PARKED_MCP_RESUME", fmt.Sprintf("Resuming %d parked MCP tool call(s)", len(matched)), map[string]any{
					"convKey":     s.ConvKey,
					"sessionId":   sid,
					"toolCallIds": ids,
				})
				notifySessionWarn(ctx, s)
				resCtx := withTurnDetachMeta(ctx, &turnDetachMeta{
					sid:             sid,
					mode:            "parked_mcp_resume",
					turnStart:       turnStart,
					msgCount:        len(messages),
					firstUserFp:     currentFirstFp,
					cancelledHistFp: computeMessagesSliceFingerprint(messages),
					isCompactionReq: isCompactionReq,
				})
				return s.resumeParkedTurnTimed(resCtx, matched, messages, onDelta, turnStart, &firstDeltaNs)
			}
		}
	}

	// Preflight Stage 2/3 remote image fetches and rollover budgets before consuming pending system/tool
	// diffs or opening/replacing ACP sessions, so 4xx validation/fetch errors leave session state intact.
	type promptPlan struct {
		useRollover   bool
		msgCnt        int
		curModel      string
		transcriptCap int
	}
	buildPrePlan := func() promptPlan {
		s.mu.Lock()
		forceNext := s.ForceRolloverNext
		msgCnt := s.MessageCount
		lastAsst := s.lastTurnAssistant
		histFp := s.HistoryFingerprint
		cancFp := s.cancelledHistoryFp
		sidNow := s.SessionID
		hibNow := s.HibernatedSessionID
		hasTurns := len(s.TurnHistory) > 0 && s.TurnHistory[len(s.TurnHistory)-1].SessionID == sidNow
		hasBridge := len(s.DeclaredMcpTools) > 0
		liveCat := s.ToolsCatalog
		liveFp := s.ToolFingerprint
		curModel := s.ModelID
		s.mu.Unlock()

		isRoll := forceNext || rolledOverFromParked
		if sidNow == "" && hibNow == "" {
			msgCnt = 0
		}
		if msgCnt > 0 {
			if len(messages) < msgCnt || (lastAsst && len(messages) >= msgCnt && messages[msgCnt-1]["role"] != "assistant") {
				isRoll = true
			} else if cancelledHistoryDiverged(messages, msgCnt, lastAsst, cancFp) {
				isRoll = true
			} else if histFp != "" && currentFirstFp != "" && currentFirstFp != histFp {
				isRoll = true
			}
		} else if sidNow != "" && hasTurns {
			isRoll = true
		}
		if !isRoll && toolCatalogNeedsRollover(hasBridge, liveCat, liveFp, toolsCatalog) {
			isRoll = true
		}
		effMsgCnt := msgCnt
		if isRoll {
			effMsgCnt = 0
		}
		effModel := curModel
		if sel != nil && sel.Model != nil && sel.Model.ID != "" {
			effModel = sel.Model.ID
		}
		mInfo := ModelOrDefault(effModel)
		isMid := effMsgCnt == 0 && len(messages) > 2
		return promptPlan{
			useRollover:   isRoll || rolledOverFromParked || isMid,
			msgCnt:        effMsgCnt,
			curModel:      mInfo.ID,
			transcriptCap: mInfo.TranscriptChars,
		}
	}

	prePlan := buildPrePlan()
	var preUnseen []map[string]any
	if prePlan.msgCnt < len(messages) {
		preUnseen = messages[prePlan.msgCnt:]
	}
	rawPromptBlocks, mmErr := resolveAndBuildPromptBlocks(ctx, GlobalImageFetcher, preUnseen, prePlan.useRollover, messages, prePlan.transcriptCap, ModelOrDefault(prePlan.curModel))
	if mmErr != nil {
		return TurnResult{}, mmErr
	}

	// System prompt changes are consumed into a tail delta so session/new's prefix stays frozen.
	s.mu.Lock()
	systemDelta := ""
	hasPersistedSession := s.SessionID != "" || s.HibernatedSessionID != ""
	if s.hasPendingSystem || s.pendingSystemText != "" {
		pend := s.pendingSystemText
		s.pendingSystemText = ""
		s.hasPendingSystem = false
		if pend != s.SystemText {
			systemDelta = systemPromptDelta(s.SystemText, pend)
			s.SystemText = pend
		}
		if s.pendingRawSystemText != "" || pend == "" {
			s.RawSystemText = s.pendingRawSystemText
			s.pendingRawSystemText = ""
		}
	} else if pendRaw := s.pendingRawSystemText; pendRaw != "" {
		s.pendingRawSystemText = ""
		s.RawSystemText = pendRaw
	}
	s.mu.Unlock()
	if systemDelta != "" {
		if hasPersistedSession {
			GlobalStore.UpsertSession(s)
		}
		LogEvent("SYSTEM_PROMPT_CHANGED", "Client system prompt changed within a conversation", map[string]any{
			"convKey": s.ConvKey, "deltaChars": len(systemDelta),
		})
	}

	origThoughtLevel := thoughtLevel
	// Decide rollover before booting/resuming or touching the model:
	// 1) A hibernated session that already needs rollover skips a wasted session/resume child spawn
	//    and goes straight to openFreshSession.
	// 2) A live session that is about to be replaced does not receive a model switch first.
	s.mu.Lock()
	hasExistingSession := s.SessionID != "" || s.HibernatedSessionID != ""
	prevForceRoll := s.ForceRolloverNext
	prevForceWhy := s.ForceRolloverReason
	isRollover := s.ForceRolloverNext
	if isRollover && rolloverReason == "" {
		if s.ForceRolloverReason != "" {
			rolloverReason = s.ForceRolloverReason
		} else {
			rolloverReason = "rollover"
		}
	}
	effCheckMsgCnt := s.MessageCount
	if !hasExistingSession {
		effCheckMsgCnt = 0
	}
	if effCheckMsgCnt > 0 {
		if len(messages) < effCheckMsgCnt || (s.lastTurnAssistant && len(messages) >= effCheckMsgCnt && messages[effCheckMsgCnt-1]["role"] != "assistant") {
			isRollover = true
			if rolloverReason == "" {
				rolloverReason = "rollover_compaction"
			}
		} else if cancelledHistoryDiverged(messages, effCheckMsgCnt, s.lastTurnAssistant, s.cancelledHistoryFp) {
			isRollover = true
			if rolloverReason == "" {
				rolloverReason = "rollover_cancelled_edit"
			}
		} else if s.HistoryFingerprint != "" && currentFirstFp != "" && currentFirstFp != s.HistoryFingerprint {
			isRollover = true
			if rolloverReason == "" {
				rolloverReason = "rollover_prefix"
			}
		}
	} else if s.SessionID != "" && len(s.TurnHistory) > 0 && s.TurnHistory[len(s.TurnHistory)-1].SessionID == s.SessionID {
		// Safety guard: if MessageCount was reset to 0 on an already-used session, never append full history onto it
		isRollover = true
		if rolloverReason == "" {
			rolloverReason = "rollover"
		}
	}
	oldSid := s.SessionID
	if oldSid == "" {
		oldSid = s.HibernatedSessionID
	}
	hasBridge := len(s.DeclaredMcpTools) > 0
	liveCat := s.ToolsCatalog
	liveFp := s.ToolFingerprint
	noSession := s.SessionID == ""
	hibBeforeBoot := s.HibernatedSessionID
	prevModelBeforeBoot := s.ModelID
	prevTierBeforeBoot := s.ThoughtLevel
	stickyMedium := sel != nil && s.capacityFallbackSid != "" &&
		(s.SessionID == s.capacityFallbackSid || s.HibernatedSessionID == s.capacityFallbackSid) &&
		!sel.ExplicitTier && sel.Model.ID == s.ModelID &&
		(sel.Tier == "high" || sel.Tier == "xhigh")
	s.mu.Unlock()

	if !isRollover && hasExistingSession && toolCatalogNeedsRollover(hasBridge, liveCat, liveFp, toolsCatalog) {
		added, _, changed := diffToolCatalogs(liveCat, toolsCatalog)
		LogEvent("TOOLS_CHANGED_ROLLOVER", "Session had no MCP bridge (or unknown catalog after restore); opening fresh session with tools", map[string]any{
			"convKey": s.ConvKey, "sessionId": oldSid, "added": added, "changed": changed,
		})
		isRollover = true
		rolloverReason = "rollover_tools"
	}

	var effSel *ModelSelection
	if sel != nil {
		tmp := *sel
		if stickyMedium && !isRollover {
			tmp.Tier = "medium"
			thoughtLevel = "medium"
		}
		effSel = &tmp
		if isRollover {
			s.setDesiredSelection(*sel)
		} else if noSession {
			s.setDesiredSelection(tmp)
		}
	}

	var toolNotice string
	if isRollover {
		s.mu.Lock()
		s.ForceRolloverNext = false
		s.ForceRolloverReason = ""
		s.CompactionRollovers++
		s.capacityFallbackSid = ""
		s.highTierZeroCacheStreak = 0
		s.mu.Unlock()
		LogEvent("COMPACTION_ROLLOVER", "Prefix changed or compacted, rolling over session", map[string]any{
			"convKey":      s.ConvKey,
			"oldSessionId": oldSid,
			"reason":       rolloverReason,
		})
		if err := s.openFreshSession(toolsCatalog, origThoughtLevel); err != nil {
			s.mu.Lock()
			if s.SessionID == "" && s.HibernatedSessionID == hibBeforeBoot && prevForceRoll {
				s.ForceRolloverNext = prevForceRoll
				s.ForceRolloverReason = prevForceWhy
			}
			s.mu.Unlock()
			return TurnResult{}, err
		}
	} else {
		if err := s.ensureBooted(toolsCatalog, thoughtLevel); err != nil {
			if noSession && hibBeforeBoot != "" && prevModelBeforeBoot != "" {
				s.mu.Lock()
				if s.SessionID == "" && s.HibernatedSessionID == hibBeforeBoot {
					s.ModelID = prevModelBeforeBoot
					s.ThoughtLevel = prevTierBeforeBoot
				}
				s.mu.Unlock()
			}
			return TurnResult{}, err
		}
		s.mu.Lock()
		curSidAfterBoot := s.SessionID
		var added, removed, changed []string
		toolNotice, added, removed, changed = s.consumeToolCatalogLocked(toolsCatalog)
		s.mu.Unlock()
		if toolNotice != "" {
			GlobalStore.UpsertSession(s)
			LogEvent("TOOLS_UPDATED_IN_PLACE", "Updated session tool catalog in-place via dsh_call_tool + prompt delta (cache preserved)", map[string]any{
				"convKey": s.ConvKey, "sessionId": curSidAfterBoot, "added": added, "removed": removed, "changed": changed,
			})
		}
		if effSel != nil {
			if err := s.applyModelSelection(*effSel); err != nil {
				return TurnResult{}, err
			}
		}
		s.mu.Lock()
		if s.MessageCount > 0 {
			s.SessionReuses++
		}
		s.mu.Unlock()
	}

	s.mu.Lock()
	msgCnt := s.MessageCount
	reuses := s.SessionReuses
	sid := s.SessionID
	wakeMethod := s.LastWakeMethod
	s.LastWakeMethod = ""
	s.mu.Unlock()

	isMidColdStart := msgCnt == 0 && len(messages) > 2
	var unseen []map[string]any
	if msgCnt < len(messages) {
		unseen = messages[msgCnt:]
	}
	s.mu.Lock()
	transcriptCap := ModelOrDefault(s.ModelID).TranscriptChars
	curModel, curTier := s.ModelID, s.ThoughtLevel
	curSys := s.SystemText
	s.mu.Unlock()
	if msgCnt > 0 && msgCnt <= len(messages) && s.Codec != nil {
		s.Codec.SeedFromConversationOnce(curSys, messages[:msgCnt])
	}
	curModelInfo := ModelOrDefault(curModel)
	postUseRollover := isRollover || rolledOverFromParked || isMidColdStart
	if msgCnt != prePlan.msgCnt || postUseRollover != prePlan.useRollover || curModelInfo.ID != prePlan.curModel {
		rawPromptBlocks, mmErr = resolveAndBuildPromptBlocks(ctx, GlobalImageFetcher, unseen, postUseRollover, messages, curModelInfo.TranscriptChars, curModelInfo)
		if mmErr != nil {
			return TurnResult{}, mmErr
		}
	}
	if msgCnt > 0 && !isRollover && !rolledOverFromParked {
		// The live/resumed session still carries the old system prompt and tool list; tell the model.
		var notes []string
		if systemDelta != "" {
			notes = append(notes, systemDelta)
		}
		if toolNotice != "" {
			notes = append(notes, toolNotice)
		}
		if len(notes) > 0 {
			rawPromptBlocks = append([]map[string]any{{"type": "text", "text": strings.Join(notes, "\n\n")}}, rawPromptBlocks...)
		}
	}
	if tailDirective != "" {
		rawPromptBlocks = appendTurnDirectiveToPromptBlocks(rawPromptBlocks, tailDirective)
	}
	promptBlocks := rawPromptBlocks
	if s.Codec != nil {
		promptBlocks = s.Codec.EncodePromptBlocks(rawPromptBlocks)
	}
	mode := "cold_start"
	if isRollover || rolledOverFromParked {
		mode = "compaction_rollover"
	} else if wakeMethod != "" {
		mode = "resumed_delta"
	} else if reuses > 0 {
		mode = "sticky_delta"
	}

	canBisectColdStart := WafAutoBisectEnabled && mode == "cold_start" && !s.isWafBisectProbe &&
		!isWafBisectInCooldown() && len(extractBisectCandidates(curSys, rawPromptBlocks)) >= 2
	s.mu.Lock()
	s.allowWafFastCancel = canBisectColdStart
	s.mu.Unlock()

	LogEvent("TURN_START", fmt.Sprintf("Sending session/prompt (%s)", mode), map[string]any{
		"convKey":          s.ConvKey,
		"sessionId":        sid,
		"model":            curModel,
		"thoughtLevel":     curTier,
		"totalMessages":    len(messages),
		"unseenDeltaCount": len(unseen),
	})

	curHistorySliceFp := computeMessagesSliceFingerprint(messages)
	notifySessionWarn(ctx, s)
	execCtx := withTurnDetachMeta(ctx, &turnDetachMeta{
		sid:             sid,
		mode:            mode,
		rolloverReason:  rolloverReason,
		turnStart:       turnStart,
		msgCount:        len(messages),
		firstUserFp:     currentFirstFp,
		cancelledHistFp: curHistorySliceFp,
		isCompactionReq: isCompactionReq,
	})
	res, err := s.executePromptOrPark(execCtx, promptBlocks, onDelta, 0)
	s.mu.Lock()
	s.allowWafFastCancel = false
	s.mu.Unlock()

	var fastCancelErr *wafFastCancelledError
	isFastCancelled := errors.As(err, &fastCancelErr)
	isInstantNotice429 := err == nil && canBisectColdStart && res.EmittedDeltas == 0 &&
		len(res.ToolCalls) == 0 && time.Since(turnStart) < 8*time.Second &&
		isBisectableSoftError(DetectAntigravitySoftError(res.Text))

	if (isFastCancelled || isInstantNotice429) && ctx.Err() == nil {
		s.HibernateWorker("waf_autobisect_reset", true)
		if healed, _ := runWafAutoBisectAndPersist(ctx, s.ConvKey, curSys, rawPromptBlocks); healed {
			s.mu.Lock()
			if s.RawSystemText != "" {
				s.SystemText = PruneClientSystemPrompt(s.RawSystemText)
			} else {
				s.SystemText = ApplyDynamicWafRules(s.SystemText)
			}
			s.mu.Unlock()
			if openErr := s.openFreshSession(toolsCatalog, thoughtLevel); openErr == nil {
				s.mu.Lock()
				newSid := s.SessionID
				s.mu.Unlock()
				rebuilt, rbErr := resolveAndBuildPromptBlocks(ctx, GlobalImageFetcher, unseen, isMidColdStart, messages, transcriptCap, curModelInfo)
				if rbErr != nil {
					return TurnResult{}, rbErr
				}
				if tailDirective != "" {
					rebuilt = appendTurnDirectiveToPromptBlocks(rebuilt, tailDirective)
				}
				if s.Codec != nil {
					rebuilt = s.Codec.EncodePromptBlocks(rebuilt)
				}
				retryCtx := withTurnDetachMeta(ctx, &turnDetachMeta{
					sid:             newSid,
					mode:            "waf_autobisect_recovery",
					rolloverReason:  "rollover_waf_healed",
					turnStart:       turnStart,
					msgCount:        len(messages),
					firstUserFp:     currentFirstFp,
					cancelledHistFp: curHistorySliceFp,
					isCompactionReq: isCompactionReq,
				})
				if retryRes, retryErr := s.executePromptOrPark(retryCtx, rebuilt, onDelta, 0); retryErr == nil {
					res = retryRes
					err = nil
					isFastCancelled = false
					sid = newSid
					mode = "waf_autobisect_recovery"
					rolloverReason = "rollover_waf_healed"
				} else {
					err = retryErr
					isFastCancelled = false
				}
			}
		}
		if isFastCancelled {
			// Auto-bisect confirmed cleanroom Probe 2 was 200 OK (not a WAF rule) or upstream is throttled.
			// Synthesize the notice-only 429 text so high-tier capacity fallback (if eligible) or standard
			// 429 SoftError handling runs cleanly without waiting 140s.
			det := strings.TrimSpace(fastCancelErr.Detail)
			if det == "" {
				det = "RESOURCE_EXHAUSTED (code 429): Resource has been exhausted (e.g. check quota)."
			}
			res = TurnResult{
				StopReason: "end_turn",
				Text:       "⚠ Agent execution terminated due to error: " + det,
			}
			err = nil
		}
	}

	if err != nil {
		if isSoftDetachedErr(err) {
			return TurnResult{}, err
		}
		if IsTosViolationError(err.Error()) {
			TripTosCircuitBreaker(err.Error())
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			s.mu.Lock()
			s.MessageCount = len(messages)
			s.lastTurnAssistant = false
			s.cancelledHistoryFp = curHistorySliceFp
			s.mu.Unlock()
			return TurnResult{}, err
		}
		s.HibernateWorker("prompt_rpc_error", true)
		return TurnResult{}, err
	}

	if res.Usage != nil && res.Usage.Degradation != nil && res.Usage.Degradation.Degraded {
		deg := res.Usage.Degradation
		s.recordArgonDegradation(sid, deg, res.EmittedDeltas)
		if res.EmittedDeltas == 0 {
			if openErr := s.openFreshSession(toolsCatalog, thoughtLevel); openErr == nil {
				s.mu.Lock()
				newSid := s.SessionID
				s.mu.Unlock()
				retryBlocks, rbErr := resolveAndBuildPromptBlocks(ctx, GlobalImageFetcher, messages, true, messages, transcriptCap, curModelInfo)
				if rbErr != nil {
					return TurnResult{}, rbErr
				}
				if tailDirective != "" {
					retryBlocks = appendTurnDirectiveToPromptBlocks(retryBlocks, tailDirective)
				}
				if s.Codec != nil {
					retryBlocks = s.Codec.EncodePromptBlocks(retryBlocks)
				}
				retryCtx := withTurnDetachMeta(ctx, &turnDetachMeta{
					sid:             newSid,
					mode:            "argon_degraded_recovery",
					rolloverReason:  "rollover_degraded",
					turnStart:       turnStart,
					msgCount:        len(messages),
					firstUserFp:     currentFirstFp,
					cancelledHistFp: curHistorySliceFp,
					isCompactionReq: isCompactionReq,
				})
				if retryRes, retryErr := s.executePromptOrPark(retryCtx, retryBlocks, onDelta, 0); retryErr == nil {
					argonDegradationRecoveredTotal.Add(1)
					LogEvent("ARGON_DEGRADATION_RECOVERED", "Recovered from Gemini 4 Argon shadow pool routing via transparent fresh-session replay", map[string]any{
						"convKey":      s.ConvKey,
						"oldSessionId": sid,
						"newSessionId": newSid,
						"servedModel":  deg.ServedModel,
					})
					res = retryRes
					sid = newSid
					mode = "argon_degraded_recovery"
					rolloverReason = "rollover_degraded"
				} else if isSoftDetachedErr(retryErr) {
					return TurnResult{}, retryErr
				} else if errors.Is(retryErr, context.Canceled) || errors.Is(retryErr, context.DeadlineExceeded) {
					s.mu.Lock()
					s.MessageCount = len(messages)
					s.lastTurnAssistant = false
					s.cancelledHistoryFp = curHistorySliceFp
					s.mu.Unlock()
					return TurnResult{}, retryErr
				} else {
					s.HibernateWorker("prompt_rpc_error", true)
					return TurnResult{}, retryErr
				}
			} else {
				s.HibernateWorker("argon_degraded_retry", true)
				return TurnResult{}, openErr
			}
		} else {
			// Text already reached the client: roll over on the next turn. RunTurn's rollover path
			// opens the fresh session synchronously, so no delayed close is needed (a delayed close
			// raced with, and killed, the next turn's new session).
			s.mu.Lock()
			s.ForceRolloverNext = true
			s.ForceRolloverReason = "rollover_degraded"
			s.mu.Unlock()
		}
	}
	if se := DetectAntigravitySoftError(res.Text); isUpstreamPoolCapacitySoftError(se) &&
		res.FailedNotice == "" && res.EmittedDeltas == 0 && len(res.ToolCalls) == 0 &&
		sel != nil && sel.Model != nil && sel.Model.Family == "gemini" && !sel.ExplicitTier &&
		(curTier == "high" || curTier == "xhigh") &&
		ctx.Err() == nil && time.Since(turnStart) < 90*time.Second {
		inPlaceRecovered := false
		if msgCnt > 0 && sid != "" {
			if tierErr := s.applyModelSelection(ModelSelection{Model: sel.Model, Tier: "medium"}); tierErr == nil {
				inPlaceCtx := withTurnDetachMeta(ctx, &turnDetachMeta{
					sid:             sid,
					mode:            mode,
					rolloverReason:  rolloverReason,
					turnStart:       turnStart,
					msgCount:        len(messages),
					firstUserFp:     currentFirstFp,
					cancelledHistFp: curHistorySliceFp,
					isCompactionReq: isCompactionReq,
				})
				retryRes, retryErr := s.executePromptOrPark(inPlaceCtx, promptBlocks, onDelta, 0)
				if retryErr == nil && DetectAntigravitySoftError(retryRes.Text) == nil && retryRes.FailedNotice == "" {
					LogEvent("HIGH_TIER_CAPACITY_FALLBACK", "Recovered from high-tier TPU capacity 429/529 via in-place medium-tier switch (cache preserved)", map[string]any{
						"convKey":      s.ConvKey,
						"oldSessionId": sid,
						"newSessionId": sid,
						"model":        curModel,
						"fromTier":     curTier,
						"toTier":       "medium",
						"inPlace":      true,
					})
					s.mu.Lock()
					s.capacityFallbackSid = sid
					s.mu.Unlock()
					res = retryRes
					curTier = "medium"
					inPlaceRecovered = true
				} else if isSoftDetachedErr(retryErr) {
					return TurnResult{}, retryErr
				} else if errors.Is(retryErr, context.Canceled) || errors.Is(retryErr, context.DeadlineExceeded) {
					s.mu.Lock()
					s.MessageCount = len(messages)
					s.lastTurnAssistant = false
					s.cancelledHistoryFp = curHistorySliceFp
					s.mu.Unlock()
					return TurnResult{}, retryErr
				}
			}
		}
		if !inPlaceRecovered {
			if openErr := s.openFreshSession(toolsCatalog, "medium"); openErr == nil {
				s.mu.Lock()
				newSid := s.SessionID
				s.mu.Unlock()
				retryBlocks, rbErr := resolveAndBuildPromptBlocks(ctx, GlobalImageFetcher, messages, true, messages, transcriptCap, curModelInfo)
				if rbErr != nil {
					return TurnResult{}, rbErr
				}
				if tailDirective != "" {
					retryBlocks = appendTurnDirectiveToPromptBlocks(retryBlocks, tailDirective)
				}
				if s.Codec != nil {
					retryBlocks = s.Codec.EncodePromptBlocks(retryBlocks)
				}
				retryCtx := withTurnDetachMeta(ctx, &turnDetachMeta{
					sid:             newSid,
					mode:            "high_capacity_fallback",
					rolloverReason:  "rollover_high_tier_429",
					turnStart:       turnStart,
					msgCount:        len(messages),
					firstUserFp:     currentFirstFp,
					cancelledHistFp: curHistorySliceFp,
					isCompactionReq: isCompactionReq,
				})
				retryRes, retryErr := s.executePromptOrPark(retryCtx, retryBlocks, onDelta, 0)
				if retryErr == nil {
					LogEvent("HIGH_TIER_CAPACITY_FALLBACK", "Recovered from high-tier TPU capacity 429/529 via fresh medium-tier session", map[string]any{
						"convKey":      s.ConvKey,
						"oldSessionId": sid,
						"newSessionId": newSid,
						"model":        curModel,
						"fromTier":     curTier,
						"toTier":       "medium",
					})
					s.mu.Lock()
					s.capacityFallbackSid = newSid
					s.mu.Unlock()
					res = retryRes
					sid = newSid
					curTier = "medium"
					mode = "high_capacity_fallback"
					rolloverReason = "rollover_high_tier_429"
				} else if isSoftDetachedErr(retryErr) {
					return TurnResult{}, retryErr
				} else if errors.Is(retryErr, context.Canceled) || errors.Is(retryErr, context.DeadlineExceeded) {
					s.mu.Lock()
					s.MessageCount = len(messages)
					s.lastTurnAssistant = false
					s.cancelledHistoryFp = curHistorySliceFp
					s.mu.Unlock()
					return TurnResult{}, retryErr
				} else {
					s.HibernateWorker("prompt_rpc_error", true)
				}
			} else {
				s.HibernateWorker("high_tier_capacity_fallback", true)
			}
		}
	}
	return s.finalizeCompletedTurn(ctx, res, turnStart, firstDeltaNs.Load(), messages, currentFirstFp, isCompactionReq, sid, mode, rolloverReason)
}

// consumeToolCatalogLocked updates the session's active tool whitelist in-place and returns any
// prompt-tail delta notice needed so the model learns about added/changed/removed tools without
// invalidating session/new's tools/list prefix cache. Caller holds s.mu.
func (s *AcpProjectSession) consumeToolCatalogLocked(newCat []ToolDef) (notice string, added, removed, changed []string) {
	aligned := make([]ToolDef, len(newCat))
	copy(aligned, newCat)
	initByName := make(map[string]string, len(s.InitialToolsCatalog))
	for _, it := range s.InitialToolsCatalog {
		if it.McpName != "" {
			initByName[it.Name] = it.McpName
		}
	}
	isLegacyBridge := sessionBridgeServerName(s.InitialToolsCatalog) == LegacyMcpBridgeName
	for i := range aligned {
		if isLegacyBridge && (aligned[i].Name == AwaitToolName || aligned[i].Name == LegacyAwaitToolName) {
			aligned[i].Name = LegacyAwaitToolName
			aligned[i].OutboundAlias = ""
			aligned[i].McpName = fmt.Sprintf("dsh_%s_%s", LegacyAwaitToolName, shortSha256(LegacyAwaitToolName)[:12])
			continue
		}
		if isLegacyBridge && (aligned[i].Name == CallToolName || aligned[i].Name == LegacyCallToolName) {
			aligned[i].Name = LegacyCallToolName
			aligned[i].OutboundAlias = ""
			aligned[i].McpName = fmt.Sprintf("dsh_%s_%s", LegacyCallToolName, shortSha256(LegacyCallToolName)[:12])
			continue
		}
		if initMcp, ok := initByName[aligned[i].Name]; ok {
			aligned[i].McpName = initMcp
		} else if isLegacyBridge && strings.HasPrefix(aligned[i].McpName, "ws_") {
			aligned[i].McpName = "dsh_" + strings.TrimPrefix(aligned[i].McpName, "ws_")
		}
	}
	refOld := s.ToolsCatalog
	if len(refOld) == 0 {
		refOld = s.InitialToolsCatalog
	}
	notice, added, removed, changed = buildToolDeltaNotice(refOld, aligned, s.DeclaredMcpTools)
	if len(added) == 0 && len(removed) == 0 && len(changed) == 0 {
		return "", nil, nil, nil
	}
	s.ToolsCatalog = aligned
	s.McpToHostMap = make(map[string]string, len(aligned)*2)
	for _, t := range aligned {
		s.McpToHostMap[t.McpName] = t.Name
	}
	for _, t := range newCat {
		if t.McpName != "" {
			s.McpToHostMap[t.McpName] = t.Name
		}
	}
	if len(s.ParkedCalls) > 0 || len(s.RelayedCalls) > 0 {
		for _, it := range s.InitialToolsCatalog {
			if (it.Name == AwaitToolName || it.Name == LegacyAwaitToolName) && it.McpName != "" {
				s.McpToHostMap[it.McpName] = it.Name
			}
		}
	}
	s.ToolFingerprint = toolCatalogFingerprint(aligned)
	return notice, added, removed, changed
}

// isUpstreamPoolCapacitySoftError identifies upstream per-tier TPU capacity throttling (429/529)
// while excluding account-level quota exhaustion ("Individual quota reached. Resets in ..."),
// which shares the Gemini quota pool across all thinking tiers.
func isUpstreamPoolCapacitySoftError(se *SoftError) bool {
	if se == nil || (se.StatusCode != http.StatusTooManyRequests && se.StatusCode != 529) {
		return false
	}
	if isAccountQuotaOrBillingExhausted(se.Message) {
		return false
	}
	return true
}

// failedNoticeError converts a turn that ended on an agy terminal notice after partial text into
// the same retryable error a notice-only turn produces.
func failedNoticeError(res TurnResult) error {
	if res.FailedNotice == "" {
		return nil
	}
	if se := DetectAntigravitySoftError("⚠ " + res.FailedNotice); se != nil {
		se.Message += " (after partial reply)"
		return se
	}
	return &SoftError{StatusCode: http.StatusServiceUnavailable, ErrorType: "api_error", Message: "Antigravity upstream failure after partial reply: " + res.FailedNotice}
}

func (s *AcpProjectSession) RunKeepalivePing(onDelta func(DeltaChunk)) TurnResult {
	s.mu.Lock()
	idleSec := int(time.Since(s.LastUsedAt).Seconds())
	estCached := s.LastCachedReadTokens
	if estCached == 0 {
		estCached = 30000
	}
	sid := s.SessionID
	s.mu.Unlock()

	LogEvent("KEEPALIVE_SKIP_BUSY", fmt.Sprintf("Session %s fast-acknowledged keepalive (0 upstream cost)", s.ConvKey), map[string]any{
		"sessionId":        sid,
		"cachedReadTokens": estCached,
		"idleSec":          idleSec,
	})
	if onDelta != nil {
		onDelta(DeltaChunk{Type: "text", Text: "ok"})
	}
	return TurnResult{
		StopReason: "end_turn",
		Text:       "ok",
		Usage:      &TurnUsage{InputTokens: 10, CachedReadTokens: estCached, OutputTokens: 1, StepsInPrompt: 1},
		SessionID:  sid,
		ConvKey:    s.ConvKey,
		ElapsedMs:  1,
		TtftMs:     1,
		Mode:       "keepalive_fast_ack",
	}
}
