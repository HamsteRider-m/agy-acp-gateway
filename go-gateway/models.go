package main

import (
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Model registry for agy ACP models and alias routing.
// Enums: step usage f9.1 numeric model enum -> thinking tier, verified 2026-11-08 from conversation DBs
// (1418 argon-medium, 1417 argon-high, 1318/1319/1320 flash high/medium/low, 1401 opus medium,
// 1402 opus high, 1403/1404/1405 sonnet low/medium/high, 342 gpt-oss; 1419 argon-low, 1400 opus-low inferred;
// 1427/1437/1438 carbon high/medium/low verified 2026-11-11 on agy 1.5.5;
// 1525/1526/1527/1528 hydrogen high/medium/low/xhigh verified 2026-11-13).

type ModelPricing struct {
	InPerM            float64 `json:"inPerM"`
	CachedPerM        float64 `json:"cachedPerM"`
	OutPerM           float64 `json:"outPerM"`
	UncachedWritePerM float64 `json:"uncachedWritePerM,omitempty"`
	MidCtxThreshold   int     `json:"midCtxThreshold,omitempty"`
	MidCtxMult        float64 `json:"midCtxMult,omitempty"`
	LongCtxThreshold  int     `json:"longCtxThreshold,omitempty"`
	LongCtxMult       float64 `json:"longCtxMult,omitempty"`
	LongCtxInMult     float64 `json:"longCtxInMult,omitempty"`
	LongCtxCrMult     float64 `json:"longCtxCrMult,omitempty"`
	LongCtxOutMult    float64 `json:"longCtxOutMult,omitempty"`
}

// Pricing is the Antigravity quota weight in USD per 1M tokens, measured 2026-11-11..13 by sending
// controlled requests and reading the official /usage pool fractions before and after each one.
// Gemini pool: Gemini 4 Argon/Carbon are charged at Gemini API list price ($2/$0.10/$10) and the
// pool holds $200 per 5h / $800 per week; Gemini 4 Hydrogen is charged at 1/4 of Carbon/Argon
// ($0.50/$0.025/$2.50); Gemini 3.8 Flash is charged at 1/3 of its list price ($0.25/$0.025/$1.25).
// Claude pool: Claude 5.5 list price (cache hit 0.05x, cache write 1.25x on warm turns, no
// long-context premium); the pool holds about $25 per 5h / $50 per week. outTok includes thinking.
type ModelInfo struct {
	ID              string         `json:"id"`
	Label           string         `json:"label"`
	Family          string         `json:"family"`
	QuotaGroup      string         `json:"quotaGroup"`
	ContextWindow   int            `json:"contextWindow"`
	TranscriptChars int            `json:"-"`
	MaxImages       int            `json:"maxImages,omitempty"`
	Enums           map[int]string `json:"-"`
	FixedTier       string         `json:"fixedTier,omitempty"`
	SupportsXHigh   bool           `json:"supportsXHigh,omitempty"`
	Pricing         ModelPricing   `json:"pricing"`
}

func effectiveModelMaxImages(m *ModelInfo) int {
	if m != nil {
		if m.Family == "claude" || m.QuotaGroup == "3p" {
			if MaxImagesClaude > 0 {
				return MaxImagesClaude
			}
			if m.MaxImages > 0 {
				return m.MaxImages
			}
			return 100
		}
		if MaxImagesGemini > 0 {
			return MaxImagesGemini
		}
		if m.MaxImages > 0 {
			return m.MaxImages
		}
	}
	if MaxImagesGemini > 0 {
		return MaxImagesGemini
	}
	return 200
}

func envPosInt(k string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(k))); err == nil && v > 0 {
		return v
	}
	return def
}

var AgyModels = []*ModelInfo{
	{
		// Offered by agy acp since 2026-11-10; also the server-side session/new default model.
		// Quota weight equals Gemini API introductory list price (flat at any context length);
		// the API price doubles on 2026-12-01 — re-run quota calibration then before changing it.
		ID: "gemini-4-carbon", Label: "Gemini 4 Carbon", Family: "gemini", QuotaGroup: "gemini",
		ContextWindow: envPosInt("AGY_CONTEXT_GEMINI", 1048576), TranscriptChars: envPosInt("AGY_TRANSCRIPT_CHARS_GEMINI", 1800000), MaxImages: 200,
		Enums:   map[int]string{1427: "high", 1437: "medium", 1438: "low"},
		Pricing: ModelPricing{InPerM: 2.0, CachedPerM: 0.10, OutPerM: 10.0},
	},
	{
		ID: "gemini-4-argon", Label: "Gemini 4 Argon", Family: "gemini", QuotaGroup: "gemini",
		ContextWindow: envPosInt("AGY_CONTEXT_GEMINI", 1048576), TranscriptChars: envPosInt("AGY_TRANSCRIPT_CHARS_GEMINI", 1800000), MaxImages: 200,
		Enums:   map[int]string{1417: "high", 1418: "medium", 1419: "low"},
		Pricing: ModelPricing{InPerM: 2.0, CachedPerM: 0.10, OutPerM: 10.0},
	},
	{
		// Offered by agy acp since 2026-11-13; supports low/medium/high/xhigh thinking tiers.
		// Measured quota weight (2026-11-13): $0.50 in / $0.025 cached / $2.50 out against the $200/5h Gemini pool.
		ID: "gemini-4-hydrogen", Label: "Gemini 4 Hydrogen", Family: "gemini", QuotaGroup: "gemini",
		ContextWindow: envPosInt("AGY_CONTEXT_GEMINI", 1048576), TranscriptChars: envPosInt("AGY_TRANSCRIPT_CHARS_GEMINI", 1800000), MaxImages: 200,
		Enums:         map[int]string{1525: "high", 1526: "medium", 1527: "low", 1528: "xhigh"},
		SupportsXHigh: true,
		Pricing:       ModelPricing{InPerM: 0.50, CachedPerM: 0.025, OutPerM: 2.50},
	},
	{
		ID: "gemini-3.8-flash", Label: "Gemini 3.8 Flash", Family: "gemini", QuotaGroup: "gemini",
		ContextWindow: envPosInt("AGY_CONTEXT_GEMINI", 1048576), TranscriptChars: envPosInt("AGY_TRANSCRIPT_CHARS_GEMINI", 1800000), MaxImages: 200,
		Enums: map[int]string{1318: "high", 1319: "medium", 1320: "low"},
		// Measured quota weight: 1/3 of the $0.75/$3.75 API list price; cache hit 0.1x input.
		Pricing: ModelPricing{InPerM: 0.25, CachedPerM: 0.025, OutPerM: 1.25},
	},
	{
		// Verified from SQLite step #2723 (857K) & #3214 (495K): Claude in Antigravity supports 1M context.
		// Quota weight = Claude 5.5 list price: cold-start input at base, warm-turn uncached input is
		// written to the prompt cache at 1.25x, cache hits 0.05x, no long-context premium.
		ID: "claude-opus-5-5", Label: "Claude Opus 5.5", Family: "claude", QuotaGroup: "3p",
		ContextWindow: envPosInt("AGY_CONTEXT_CLAUDE", 1048576), TranscriptChars: envPosInt("AGY_TRANSCRIPT_CHARS_CLAUDE", 1800000), MaxImages: 100,
		Enums: map[int]string{1400: "low", 1401: "medium", 1402: "high"},
		Pricing: ModelPricing{
			InPerM: 4.0, UncachedWritePerM: 5.0, CachedPerM: 0.20, OutPerM: 20.0,
		},
	},
	{
		ID: "claude-sonnet-5-5", Label: "Claude Sonnet 5.5", Family: "claude", QuotaGroup: "3p",
		ContextWindow: envPosInt("AGY_CONTEXT_CLAUDE", 1048576), TranscriptChars: envPosInt("AGY_TRANSCRIPT_CHARS_CLAUDE", 1800000), MaxImages: 100,
		Enums: map[int]string{1403: "low", 1404: "medium", 1405: "high"},
		Pricing: ModelPricing{
			InPerM: 2.0, UncachedWritePerM: 2.50, CachedPerM: 0.10, OutPerM: 10.0,
		},
	},
}

// RetiredModels are no longer routable or listed, but their step enums stay mapped so historical
// usage keeps its model attribution. GPT-OSS was dropped from Antigravity on 2026-11-02.
var RetiredModels = []*ModelInfo{
	{
		ID: "gpt-oss-120b-medium", Label: "GPT-OSS 120B", Family: "gpt", QuotaGroup: "3p",
		ContextWindow: 131072, TranscriptChars: 300000,
		Enums: map[int]string{342: "medium"}, FixedTier: "medium",
		Pricing: ModelPricing{InPerM: 0.15, CachedPerM: 0.015, OutPerM: 0.6},
	},
}

var UnknownModel = &ModelInfo{
	ID: "unknown", Label: "其他/旧模型", Family: "other", QuotaGroup: "gemini",
	ContextWindow: 1048576, TranscriptChars: 1800000, Enums: map[int]string{},
	Pricing: AgyModels[0].Pricing,
}

var (
	modelByID   = map[string]*ModelInfo{}
	modelByEnum = map[int]struct {
		m    *ModelInfo
		tier string
	}{}
	DefaultModelID   = "gemini-4-carbon"
	routeClaudeNames = os.Getenv("AGY_ROUTE_CLAUDE_NAMES") == "1"
	exposeTierModels = os.Getenv("AGY_EXPOSE_TIER_MODELS") == "1"
	tierSuffixRe     = regexp.MustCompile(`(?i)[-_](minimal|low|medium|high|xhigh|max|ultra)$`)
	oneMSuffixRe     = regexp.MustCompile(`\[1m\]$`)
)

func init() {
	for _, m := range AgyModels {
		modelByID[m.ID] = m
	}
	for _, m := range append(append([]*ModelInfo(nil), AgyModels...), RetiredModels...) {
		for e, t := range m.Enums {
			modelByEnum[e] = struct {
				m    *ModelInfo
				tier string
			}{m, t}
		}
	}
	if v := strings.TrimSpace(os.Getenv("AGY_DEFAULT_MODEL")); v != "" {
		if _, ok := modelByID[v]; ok {
			DefaultModelID = v
		}
	}
}

func GetModel(id string) *ModelInfo {
	clean := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(id)), "models/")
	if m, ok := modelByID[clean]; ok {
		return m
	}
	return nil
}

func ModelOrDefault(id string) *ModelInfo {
	if m := GetModel(id); m != nil {
		return m
	}
	return modelByID[DefaultModelID]
}

func ModelFromEnum(e int) (*ModelInfo, string) {
	if hit, ok := modelByEnum[e]; ok {
		return hit.m, hit.tier
	}
	return UnknownModel, ""
}

type ModelSelection struct {
	Model        *ModelInfo
	Tier         string
	Explicit     bool
	ExplicitTier bool
}

func normalizeEffortTier(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "none", "minimal", "low":
		return "low"
	case "medium":
		return "medium"
	case "high":
		return "high"
	case "xhigh", "max", "ultra":
		return "xhigh"
	default:
		return ""
	}
}

func ResolveRequestedModel(requested string, body map[string]any) ModelSelection {
	s := strings.ToLower(strings.TrimSpace(requested))
	s = strings.TrimPrefix(s, "models/")
	s = oneMSuffixRe.ReplaceAllString(s, "")
	tier := ""
	explicitTier := false
	if _, exact := modelByID[s]; !exact {
		if m := tierSuffixRe.FindStringSubmatch(s); m != nil {
			tier = normalizeEffortTier(m[1])
			explicitTier = tier != ""
			s = tierSuffixRe.ReplaceAllString(s, "")
		}
	}
	if t := clientThinkingTier(body); t != "" {
		tier = t
	}

	m := modelByID[s]
	if m == nil {
		switch {
		case strings.HasPrefix(s, "gemini-4-carbon") || s == "carbon":
			m = modelByID["gemini-4-carbon"]
		case strings.HasPrefix(s, "gemini-4-hydrogen") || s == "hydrogen":
			m = modelByID["gemini-4-hydrogen"]
		case strings.HasPrefix(s, "gemini-4") || s == "argon":
			m = modelByID["gemini-4-argon"]
		case strings.HasPrefix(s, "gemini-3.8-flash") || strings.HasPrefix(s, "gemini-2.5-flash") || strings.HasPrefix(s, "gemini-3.0-flash") || strings.HasPrefix(s, "gemini-3-flash") || s == "gemini-flash":
			m = modelByID["gemini-3.8-flash"]
		case strings.HasPrefix(s, "claude-opus-5") || s == "agy-opus":
			m = modelByID["claude-opus-5-5"]
		case strings.HasPrefix(s, "claude-sonnet-5") || s == "agy-sonnet":
			m = modelByID["claude-sonnet-5-5"]
		case routeClaudeNames && strings.Contains(s, "opus"):
			m = modelByID["claude-opus-5-5"]
		case routeClaudeNames && strings.Contains(s, "sonnet"):
			m = modelByID["claude-sonnet-5-5"]
		case routeClaudeNames && strings.Contains(s, "haiku"):
			m = modelByID["gemini-3.8-flash"]
		}
	}
	explicit := m != nil
	if m == nil {
		m = modelByID[DefaultModelID]
	}
	if m.FixedTier != "" {
		tier = m.FixedTier
	}
	if tier == "xhigh" && !m.SupportsXHigh {
		tier = "high"
	}
	if tier == "" {
		tier = "medium"
	}
	return ModelSelection{Model: m, Tier: tier, Explicit: explicit, ExplicitTier: explicitTier}
}

func geminiThinkingTier(tc map[string]any) string {
	if tc == nil {
		return ""
	}
	rawLvl, _ := tc["thinkingLevel"].(string)
	if rawLvl == "" {
		rawLvl, _ = tc["thinking_level"].(string)
	}
	if rawLvl != "" {
		lvl := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(rawLvl)), "thinking_level_")
		switch lvl {
		case "none", "minimal", "low":
			return "low"
		case "medium":
			return "medium"
		case "high":
			return "high"
		case "xhigh", "max", "ultra":
			return "xhigh"
		}
	}
	rawBudget, hasBudget := tc["thinkingBudget"]
	if !hasBudget {
		rawBudget, hasBudget = tc["thinking_budget"]
	}
	if hasBudget {
		if b, ok := toInt(rawBudget); ok {
			switch {
			case b < 0:
				return ""
			case b == 0 || b <= 4096:
				return "low"
			case b <= 16384:
				return "medium"
			case b <= 32768:
				return "high"
			default:
				return "xhigh"
			}
		}
	}
	return ""
}

func clientThinkingTier(body map[string]any) string {
	if body == nil {
		return ""
	}
	effort := ""
	if v, ok := body["reasoning_effort"].(string); ok {
		effort = v
	} else if rm, ok := body["reasoning"].(map[string]any); ok {
		effort, _ = rm["effort"].(string)
	} else if oc, ok := body["output_config"].(map[string]any); ok {
		effort, _ = oc["effort"].(string)
	}
	switch strings.ToLower(strings.TrimSpace(effort)) {
	case "none", "minimal", "low":
		return "low"
	case "medium":
		return "medium"
	case "high":
		return "high"
	case "xhigh", "max", "ultra":
		return "xhigh"
	}
	if th, ok := body["thinking"].(map[string]any); ok {
		typ, _ := th["type"].(string)
		if strings.EqualFold(typ, "disabled") {
			return "low"
		}
		if b, ok := toInt(th["budget_tokens"]); ok && b > 0 {
			switch {
			case b <= 4096:
				return "low"
			case b <= 16384:
				return "medium"
			case b <= 32768:
				return "high"
			default:
				return "xhigh"
			}
		}
	}
	if gc, ok := body["generationConfig"].(map[string]any); ok {
		if tc, okT := gc["thinkingConfig"].(map[string]any); okT {
			if t := geminiThinkingTier(tc); t != "" {
				return t
			}
		}
		if tc, okT := gc["thinking_config"].(map[string]any); okT {
			if t := geminiThinkingTier(tc); t != "" {
				return t
			}
		}
	}
	if gc, ok := body["generation_config"].(map[string]any); ok {
		if tc, okT := gc["thinkingConfig"].(map[string]any); okT {
			if t := geminiThinkingTier(tc); t != "" {
				return t
			}
		}
		if tc, okT := gc["thinking_config"].(map[string]any); okT {
			if t := geminiThinkingTier(tc); t != "" {
				return t
			}
		}
	}
	if tc, okT := body["thinkingConfig"].(map[string]any); okT {
		if t := geminiThinkingTier(tc); t != "" {
			return t
		}
	}
	if tc, okT := body["thinking_config"].(map[string]any); okT {
		if t := geminiThinkingTier(tc); t != "" {
			return t
		}
	}
	return ""
}

type PricedUsage struct {
	TierMultiplier float64
	InputCostUsd   float64
	CacheCostUsd   float64
	OutputCostUsd  float64
	ThinkCostUsd   float64
	Base1xCostUsd  float64
	CostUsd        float64
	NoCacheCostUsd float64
	SavedUsd       float64
}

func PriceUsage(m *ModelInfo, inTok, crTok, outTok, thTok, cwTok int) PricedUsage {
	p := m.Pricing
	totalCtx := inTok + crTok
	effInPerM := p.InPerM
	if p.UncachedWritePerM > 0 && crTok > 0 {
		// measured: a cold first request pays base input; warm turns write the new suffix to cache
		effInPerM = p.UncachedWritePerM
	}

	inMult, crMult, outMult, badgeMult := 1.0, 1.0, 1.0, 1.0
	if p.LongCtxThreshold > 0 && totalCtx > p.LongCtxThreshold {
		badgeMult = p.LongCtxMult
		if p.LongCtxInMult > 0 {
			inMult = p.LongCtxInMult
			crMult = p.LongCtxCrMult
			outMult = p.LongCtxOutMult
		} else {
			inMult, crMult, outMult = p.LongCtxMult, p.LongCtxMult, p.LongCtxMult
		}
	} else if p.MidCtxThreshold > 0 && totalCtx > p.MidCtxThreshold {
		badgeMult = p.MidCtxMult
		inMult, crMult, outMult = p.MidCtxMult, p.MidCtxMult, p.MidCtxMult
	}

	inputCost := (float64(inTok) * effInPerM / 1e6) * inMult
	cacheCost := (float64(crTok) * p.CachedPerM / 1e6) * crMult
	outputCost := (float64(outTok) * p.OutPerM / 1e6) * outMult
	thinkCost := (float64(thTok) * p.OutPerM / 1e6) * outMult

	base1x := (float64(inTok)*effInPerM + float64(crTok)*p.CachedPerM + float64(outTok)*p.OutPerM) / 1e6
	cost := inputCost + cacheCost + outputCost
	noCache := (float64(inTok+crTok)*p.InPerM*inMult + float64(outTok)*p.OutPerM*outMult) / 1e6
	saved := noCache - cost
	if saved < 0 {
		saved = 0
	}
	return PricedUsage{
		TierMultiplier: badgeMult,
		InputCostUsd:   inputCost,
		CacheCostUsd:   cacheCost,
		OutputCostUsd:  outputCost,
		ThinkCostUsd:   thinkCost,
		Base1xCostUsd:  base1x,
		CostUsd:        cost,
		NoCacheCostUsd: noCache,
		SavedUsd:       saved,
	}
}

func ListModelsForAPI() []map[string]any {
	out := []map[string]any{}
	for _, m := range AgyModels {
		out = append(out, map[string]any{
			"id":               m.ID,
			"object":           "model",
			"display_name":     m.Label,
			"context_window":   m.ContextWindow,
			"max_input_tokens": m.ContextWindow,
			"max_tokens":       65536,
			"owned_by":         m.Family,
		})
		if exposeTierModels && m.FixedTier == "" {
			tiers := []string{"low", "high"}
			if m.SupportsXHigh {
				tiers = []string{"low", "high", "xhigh"}
			}
			for _, t := range tiers {
				out = append(out, map[string]any{
					"id":               m.ID + "-" + t,
					"object":           "model",
					"display_name":     m.Label + " (" + t + ")",
					"context_window":   m.ContextWindow,
					"max_input_tokens": m.ContextWindow,
					"max_tokens":       65536,
					"owned_by":         m.Family,
				})
			}
		}
	}
	return out
}

func BuildGeminiModelResource(id, label string, m *ModelInfo) map[string]any {
	ctxWin := 1048576
	if m != nil && m.ContextWindow > 0 {
		ctxWin = m.ContextWindow
	}
	return map[string]any{
		"name":                       "models/" + id,
		"baseModelId":                id,
		"version":                    "001",
		"displayName":                label,
		"description":                label + " via Antigravity ACP Gateway",
		"inputTokenLimit":            ctxWin,
		"outputTokenLimit":           65536,
		"supportedGenerationMethods": []string{"generateContent", "streamGenerateContent", "countTokens"},
		"thinking":                   true,
	}
}

func ListGeminiModelsForAPI() []map[string]any {
	out := []map[string]any{}
	for _, m := range AgyModels {
		out = append(out, BuildGeminiModelResource(m.ID, m.Label, m))
		if exposeTierModels && m.FixedTier == "" {
			tiers := []string{"low", "high"}
			if m.SupportsXHigh {
				tiers = []string{"low", "high", "xhigh"}
			}
			for _, t := range tiers {
				out = append(out, BuildGeminiModelResource(m.ID+"-"+t, m.Label+" ("+t+")", m))
			}
		}
	}
	return out
}
