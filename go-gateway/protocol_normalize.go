package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	claudeWebOnlyTools = map[string]bool{
		"WebSearch":    true,
		"WebFetch":     true,
		"NotebookEdit": true,
	}
	billingHeaderRe     = regexp.MustCompile(`(?im)^x-anthropic-billing-header:[^\r\n]*$`)
	claudeCliIdentRe    = regexp.MustCompile(`(?i)You are Claude Code,\s*Anthropic's official CLI for Claude[^\r\n]*`)
	claudeSdkIdentRe    = regexp.MustCompile(`(?i)You are a Claude agent,\s*built on Anthropic's Claude Agent SDK[^\r\n]*`)
	claudeVendorNamesRe = regexp.MustCompile(`(?i)Claude Code|Claude Agent SDK|Anthropic|Claude`)
	sysReminderDumpRe   = regexp.MustCompile(`(?is)<system-reminder>\s*Codebase and user instructions are shown below.*?</system-reminder>`)
	inlineBase64ImgRe   = regexp.MustCompile(`data:image/[\w/+.-]+;base64,[A-Za-z0-9+/=]{500,}`)
	cwdPatterns         = []*regexp.Regexp{
		regexp.MustCompile(`(?i)Primary working directory:\s*([^\r\n"\\]+)`),
		regexp.MustCompile(`(?i)Working directory:\s*([^\r\n"\\]+)`),
		regexp.MustCompile(`(?i)WORKSPACE_DIR[:=\s]+([^\r\n"\\]+)`),
	}
	softErrBlockedRe = regexp.MustCompile(`(?i)^\s*The prompt could not be submitted|Generative AI Prohibited Use policy|prompt contains sensitive words`)
	softErrVerifyRe  = regexp.MustCompile(`(?im)^\s*⚠?\s*Verification Required\s*$|Verify your account to continue`)
	softErrLicenseRe = regexp.MustCompile(`(?i)(?:you\s+do\s+not\s+have\s+a\s+valid\s+license\b|gemini_enterprise_license_not_valid\b|ccpa_ineligible_tier_id\b|\(#3501\)|#3501\b)`)
	softErrTermRe    = regexp.MustCompile(`(?im)^\s*⚠\s*Agent execution terminated due to error`)
	softErrNetRe     = regexp.MustCompile(`^\s*⚠\s*There was a network issue connecting to the server, please try again\.?\s*$`)
	softErrTrafficRe = regexp.MustCompile(`^\s*⚠\s*Our servers are experiencing high traffic right now, please try again in a minute\.?\s*$`)

	upstreamPolicySafetyRe = regexp.MustCompile(
		`(?i)(?:` +
			`\b(?:PROHIBITED_CONTENT|BLOCKLIST|RECITATION|SPII|IMAGE_SAFETY)\b` +
			`|\bfinish[_\s]*reason\s*[:=]\s*["']?SAFETY["']?\b` +
			`|\bblocked\s+(?:by|due\s+to)\s+(?:safety|policy|content\s+filter|prohibited)` +
			`|\bsafety\s+(?:settings?|ratings?|filter|policy)\b` +
			`|\b(?:[a-z0-9_]+_policy_violation|bio_policy)\b` +
			`|Generative\s+AI\s+Prohibited\s+Use\s+policy` +
			`)`,
	)
	upstreamErrorSafetyTokenRe = regexp.MustCompile(`(?i)\bSAFETY\b`)
	retryHintSpanRe            = regexp.MustCompile(`(?i)(?:retry\s+in|resets?\s+in|retrydelay["':\s]+)\s*((?:\d+(?:\.\d+)?\s*(?:h|hr|hrs|hour|hours|m|min|mins|minute|minutes|s|sec|secs|second|seconds)\s*)+|\d+(?:\.\d+)?\s*s?\b)`)
	retryDurUnitRe             = regexp.MustCompile(`(?i)(\d+(?:\.\d+)?)\s*(h|hr|hrs|hour|hours|m|min|mins|minute|minutes|s|sec|secs|second|seconds)?`)
)

func isAccountQuotaOrBillingExhausted(detail string) bool {
	low := strings.ToLower(detail)
	for _, marker := range []string{
		"individual quota reached",
		"resets in",
		"spend cap",
		"spending cap",
		"spending limit",
		"prepaid",
		"depleted",
		"weekly limit",
		"weekly quota",
		"daily quota",
		"daily limit",
		"billing",
		"insufficient credit",
		"credit balance",
	} {
		if strings.Contains(low, marker) {
			return true
		}
	}
	return false
}

func isUpstreamPolicyOrSafetyBlock(text string, inErrorContext bool) bool {
	if text == "" {
		return false
	}
	if upstreamPolicySafetyRe.MatchString(text) {
		return true
	}
	return inErrorContext && upstreamErrorSafetyTokenRe.MatchString(text)
}

func extractRetryAfterHeaderValue(msg string) string {
	const fallback = "5"
	if msg == "" {
		return fallback
	}
	m := retryHintSpanRe.FindStringSubmatch(msg)
	if len(m) < 2 || strings.TrimSpace(m[1]) == "" {
		return fallback
	}
	var total float64
	matchedAny := false
	for _, part := range retryDurUnitRe.FindAllStringSubmatch(m[1], -1) {
		if len(part) < 2 {
			continue
		}
		val, err := strconv.ParseFloat(part[1], 64)
		if err != nil || val <= 0 {
			continue
		}
		matchedAny = true
		unit := strings.ToLower(strings.TrimSpace(part[2]))
		switch {
		case strings.HasPrefix(unit, "h"):
			total += val * 3600
		case strings.HasPrefix(unit, "m"):
			total += val * 60
		default:
			total += val
		}
	}
	if !matchedAny || total <= 0 {
		return fallback
	}
	sec := int(math.Ceil(total))
	if sec < 5 {
		sec = 5
	} else if sec > 3600 {
		sec = 3600
	}
	return strconv.Itoa(sec)
}

func unmarshalJSONPreserveNumbers(data []byte, dst any) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return errors.New("unexpected end of JSON input")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("invalid trailing characters after JSON value")
	}
	return nil
}

type SoftError struct {
	StatusCode int
	ErrorType  string
	Message    string
}

func (e *SoftError) Error() string { return e.Message }

func DetectAntigravitySoftError(text string) *SoftError {
	if text == "" {
		return nil
	}
	head := text
	if len(head) > 600 {
		head = head[:600]
	}
	if tosSoftRe.MatchString(text) {
		TripTosCircuitBreaker(head)
		return &SoftError{StatusCode: http.StatusServiceUnavailable, ErrorType: "tos_circuit_breaker", Message: "Antigravity ToS circuit breaker tripped: " + strings.TrimSpace(head)}
	}
	if softErrBlockedRe.MatchString(head) {
		return &SoftError{StatusCode: 400, ErrorType: "invalid_request_error", Message: "Blocked by Antigravity prompt filter: " + strings.TrimSpace(head)}
	}
	if softErrVerifyRe.MatchString(head) {
		return &SoftError{StatusCode: 503, ErrorType: "api_error", Message: "Google account verification required: " + strings.TrimSpace(head)}
	}
	if softErrNetRe.MatchString(text) {
		return &SoftError{StatusCode: http.StatusServiceUnavailable, ErrorType: "api_error", Message: "Antigravity upstream network issue: " + strings.TrimSpace(head)}
	}
	if softErrTrafficRe.MatchString(text) {
		return &SoftError{StatusCode: 529, ErrorType: "overloaded_error", Message: "Antigravity upstream overloaded: " + strings.TrimSpace(head)}
	}
	if isStatusMarker(strings.TrimSpace(head)) && softErrLicenseRe.MatchString(head) {
		return &SoftError{StatusCode: http.StatusForbidden, ErrorType: "permission_error", Message: "Antigravity account lacks a valid license (#3501): " + strings.TrimSpace(head)}
	}
	if isStatusMarker(strings.TrimSpace(head)) && isUpstreamPolicyOrSafetyBlock(head, true) {
		return &SoftError{StatusCode: http.StatusBadRequest, ErrorType: "invalid_request_error", Message: "Blocked by Antigravity safety or content policy: " + strings.TrimSpace(head)}
	}
	if softErrTermRe.MatchString(head) {
		if softErrLicenseRe.MatchString(head) {
			return &SoftError{StatusCode: http.StatusForbidden, ErrorType: "permission_error", Message: "Antigravity account lacks a valid license (#3501): " + strings.TrimSpace(head)}
		}
		if IsTosViolationError(head) {
			TripTosCircuitBreaker(head)
			return &SoftError{StatusCode: http.StatusServiceUnavailable, ErrorType: "tos_circuit_breaker", Message: "Antigravity ToS circuit breaker tripped: " + strings.TrimSpace(head)}
		}
		if isUpstreamPolicyOrSafetyBlock(head, true) {
			return &SoftError{StatusCode: http.StatusBadRequest, ErrorType: "invalid_request_error", Message: "Blocked by Antigravity safety or content policy: " + strings.TrimSpace(head)}
		}
		lowHead := strings.ToLower(head)
		if strings.Contains(lowHead, "invalid_argument") || strings.Contains(lowHead, "failed_precondition") || strings.Contains(lowHead, "code 400") || strings.Contains(lowHead, "status 400") || strings.Contains(lowHead, "400 bad request") {
			return &SoftError{StatusCode: 400, ErrorType: "invalid_request_error", Message: "Antigravity upstream invalid request: " + strings.TrimSpace(head)}
		}
		if (strings.Contains(lowHead, "model_capacity_exhausted") || strings.Contains(lowHead, "code 503") || strings.Contains(lowHead, "status 503") || strings.Contains(lowHead, "service unavailable") || strings.Contains(lowHead, "no capacity available") || strings.Contains(lowHead, "overloaded")) &&
			!strings.Contains(lowHead, "429") && !strings.Contains(lowHead, "quota") && !strings.Contains(lowHead, "resource_exhausted") {
			return &SoftError{StatusCode: 529, ErrorType: "overloaded_error", Message: "Antigravity upstream overloaded: " + strings.TrimSpace(head)}
		}
		if strings.Contains(lowHead, "429") || strings.Contains(lowHead, "quota") || strings.Contains(lowHead, "resource_exhausted") || strings.Contains(lowHead, "rate limit") || strings.Contains(lowHead, "rate_limit") || strings.Contains(lowHead, "too many requests") {
			return &SoftError{StatusCode: 429, ErrorType: "rate_limit_error", Message: "Antigravity upstream rate limit or transient failure: " + strings.TrimSpace(head)}
		}
		if strings.Contains(lowHead, "unauthenticated") || strings.Contains(lowHead, "permission_denied") || strings.Contains(lowHead, "code 401") || strings.Contains(lowHead, "code 403") || strings.Contains(lowHead, "status 401") || strings.Contains(lowHead, "status 403") || strings.Contains(lowHead, "401 unauthorized") || strings.Contains(lowHead, "403 forbidden") || strings.Contains(lowHead, "deadline_exceeded") || strings.Contains(lowHead, "code 504") || strings.Contains(lowHead, "code 500") || strings.Contains(lowHead, "code 502") || strings.Contains(lowHead, "status 504") || strings.Contains(lowHead, "status 500") || strings.Contains(lowHead, "status 502") || strings.Contains(lowHead, "internal server error") || strings.Contains(lowHead, "bad gateway") || strings.Contains(lowHead, "gateway timeout") || strings.Contains(lowHead, "internal (code") {
			return &SoftError{StatusCode: http.StatusServiceUnavailable, ErrorType: "api_error", Message: "Antigravity upstream error: " + strings.TrimSpace(head)}
		}
		return &SoftError{StatusCode: 429, ErrorType: "rate_limit_error", Message: "Antigravity upstream rate limit or transient failure: " + strings.TrimSpace(head)}
	}
	return nil
}

func classifyUpstreamError(err error) (statusCode int, errType string, retryAfter bool, msg string) {
	if err == nil {
		return http.StatusOK, "", false, ""
	}
	safeMsg := redactSecretsInString(err.Error())
	var switchErr *ModelSwitchError
	if errors.As(err, &switchErr) {
		if strings.Contains(safeMsg, "-32602") {
			return http.StatusBadRequest, "invalid_request_error", false, safeMsg
		}
		return http.StatusBadGateway, "api_error", false, safeMsg
	}
	var mmErr *MultimodalValidationError
	if errors.As(err, &mmErr) && mmErr != nil {
		code := mmErr.StatusCode
		if code <= 0 {
			code = http.StatusBadRequest
		}
		return code, "invalid_request_error", false, redactSecretsInString(mmErr.Error())
	}
	var softErr *SoftError
	if errors.As(err, &softErr) && softErr != nil {
		retry := (softErr.StatusCode == 429 || softErr.StatusCode == 503 || softErr.StatusCode == 529) && softErr.ErrorType != "tos_circuit_breaker"
		return softErr.StatusCode, softErr.ErrorType, retry, redactSecretsInString(softErr.Message)
	}
	if softErrLicenseRe.MatchString(safeMsg) {
		return http.StatusForbidden, "permission_error", false, safeMsg
	}
	if IsTosViolationError(safeMsg) {
		TripTosCircuitBreaker(safeMsg)
		return http.StatusServiceUnavailable, "tos_circuit_breaker", false, "Antigravity ToS circuit breaker tripped: " + safeMsg
	}
	if isUpstreamPolicyOrSafetyBlock(safeMsg, true) {
		return http.StatusBadRequest, "invalid_request_error", false, safeMsg
	}
	low := strings.ToLower(safeMsg)
	hasRateLimitMarker := strings.Contains(low, "429") || strings.Contains(low, "rate limit") ||
		strings.Contains(low, "rate_limit") || strings.Contains(low, "quota") || strings.Contains(low, "resource_exhausted")
	if strings.Contains(low, "invalid_argument") || strings.Contains(low, "failed_precondition") ||
		strings.Contains(low, "code 400") || strings.Contains(low, "status 400") ||
		strings.Contains(low, "400 bad request") ||
		(!hasRateLimitMarker && (strings.Contains(low, "thinking budget") ||
			strings.Contains(low, "prompt is too long") || strings.Contains(low, "context length exceeded") ||
			strings.Contains(low, "exceeds the maximum number of tokens"))) {
		return http.StatusBadRequest, "invalid_request_error", false, safeMsg
	}
	if (strings.Contains(low, "model_capacity_exhausted") || strings.Contains(low, "no capacity available") ||
		strings.Contains(low, "service unavailable") || strings.Contains(low, "code 503") ||
		strings.Contains(low, "status 503") || strings.Contains(low, "overloaded")) && !hasRateLimitMarker {
		return 529, "overloaded_error", true, safeMsg
	}
	if hasRateLimitMarker {
		return http.StatusTooManyRequests, "rate_limit_error", true, safeMsg
	}
	if strings.Contains(low, "timed out") || strings.Contains(low, "not running") || strings.Contains(low, "exited") || strings.Contains(low, "unavailable") {
		return http.StatusServiceUnavailable, "api_error", true, safeMsg
	}
	return http.StatusInternalServerError, "api_error", false, safeMsg
}

func toInt(v any) (int, bool) {
	switch x := v.(type) {
	case float64:
		return int(x), true
	case int:
		return x, true
	case int64:
		return int(x), true
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return int(i), true
		}
		if f, err := x.Float64(); err == nil {
			return int(f), true
		}
	}
	return 0, false
}

func stripClaudeAttributionAndBoilerplate(s string) string {
	return PruneClientSystemPrompt(s)
}

func stripRedundantSystemReminders(s string) string {
	if s == "" {
		return ""
	}
	return SanitizeOutboundText(sysReminderDumpRe.ReplaceAllString(s, ""))
}

func normalizeSystemText(sys any) string {
	if sys == nil {
		return ""
	}
	return PruneClientSystemPrompt(rawSystemText(sys))
}

// rawSystemText joins a system field (string or content blocks) without pruning.
func rawSystemText(sys any) string {
	switch v := sys.(type) {
	case nil:
		return ""
	case string:
		return v
	case []any:
		var parts []string
		for _, item := range v {
			switch b := item.(type) {
			case string:
				parts = append(parts, b)
			case map[string]any:
				if t, ok := b["text"].(string); ok {
					parts = append(parts, t)
				} else if raw, err := json.Marshal(b); err == nil {
					parts = append(parts, string(raw))
				}
			}
		}
		return strings.Join(parts, "\n")
	default:
		if raw, err := json.Marshal(v); err == nil {
			return string(raw)
		}
		return ""
	}
}

func extractCwdFromSystem(sysText string, messages []map[string]any) string {
	limit := len(messages)
	if limit > 4 {
		limit = 4
	}
	var initParts []string
	for _, m := range messages[:limit] {
		if t := strings.TrimSpace(formatSingleMessageText(m)); t != "" {
			initParts = append(initParts, t)
		}
	}
	combined := sysText + "\n" + strings.Join(initParts, "\n")
	for _, pat := range cwdPatterns {
		m := pat.FindStringSubmatch(combined)
		if len(m) > 1 {
			cand := strings.TrimSpace(m[1])
			if st, err := os.Stat(cand); err == nil && st.IsDir() {
				return cand
			}
		}
	}
	return DefaultCwd
}

// parseThoughtLevel: medium is the full-quota 1M Gemini tier ("high" can 429 on bursts);
// explicit -low/-high suffix or reasoning_effort is honoured (see models.go).
func parseThoughtLevel(modelStr string, body map[string]any) string {
	return ResolveRequestedModel(modelStr, body).Tier
}

func normalizeDisplayModel(reqModel string, body map[string]any) string {
	return ResolveRequestedModel(reqModel, body).Model.ID
}

func sanitizeSchemaNode(node any) any {
	switch v := node.(type) {
	case []any:
		out := make([]any, len(v))
		for i, elem := range v {
			out[i] = sanitizeSchemaNode(elem)
		}
		return out
	case map[string]any:
		out := make(map[string]any)
		for k, val := range v {
			switch k {
			case "pattern", "prefixItems", "$schema", "additionalProperties", "propertyNames", "unevaluatedProperties", "const", "default", "examples", "title":
				continue
			case "$ref":
				out["type"] = "object"
				continue
			case "anyOf", "oneOf", "allOf":
				if arr, ok := val.([]any); ok && len(arr) > 0 {
					var picked any
					for _, sub := range arr {
						if sm, okM := sub.(map[string]any); okM && sm["type"] != "null" {
							picked = sub
							break
						}
					}
					if picked == nil {
						picked = arr[0]
					}
					if pm, okP := sanitizeSchemaNode(picked).(map[string]any); okP {
						for pk, pv := range pm {
							out[pk] = pv
						}
					}
				}
				continue
			case "type":
				if tArr, okA := val.([]any); okA {
					nonNull := "string"
					for _, tItem := range tArr {
						if ts, okS := tItem.(string); okS && ts != "null" {
							nonNull = ts
							break
						}
					}
					out["type"] = nonNull
					continue
				}
			case "required":
				switch rArr := val.(type) {
				case []any:
					var reqs []string
					seenReq := make(map[string]bool, len(rArr))
					for _, item := range rArr {
						if rs, okS := item.(string); okS && !seenReq[rs] {
							seenReq[rs] = true
							reqs = append(reqs, rs)
						}
					}
					sort.Strings(reqs)
					out["required"] = reqs
					continue
				case []string:
					var reqs []string
					seenReq := make(map[string]bool, len(rArr))
					for _, rs := range rArr {
						if !seenReq[rs] {
							seenReq[rs] = true
							reqs = append(reqs, rs)
						}
					}
					sort.Strings(reqs)
					out["required"] = reqs
					continue
				}
			}
			out[k] = sanitizeSchemaNode(val)
		}
		if out["type"] == "array" && out["items"] == nil {
			out["items"] = map[string]any{"type": "string"}
		}
		if desc, ok := out["description"].(string); ok {
			d := strings.TrimSpace(SanitizeOutboundText(desc))
			if len(d) > 200 {
				d = truncateRunes(d, 200)
			}
			out["description"] = d
		}
		return out
	default:
		return node
	}
}

func sanitizeToolsCatalog(rawTools any) []ToolDef {
	arr, ok := rawTools.([]any)
	if !ok || len(arr) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	seenAlias := make(map[string]bool)
	var catalog []ToolDef

	for _, item := range arr {
		t, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := t["name"].(string)
		if name == "" {
			if fn, okF := t["function"].(map[string]any); okF {
				name, _ = fn["name"].(string)
			}
		}
		name = strings.TrimSpace(name)
		if name == "" || seen[name] || claudeWebOnlyTools[name] {
			continue
		}
		tType, _ := t["type"].(string)
		if tType != "" && tType != "custom" && tType != "function" && t["input_schema"] == nil && t["parameters"] == nil {
			continue
		}
		seen[name] = true

		rawSchema := t["input_schema"]
		if rawSchema == nil {
			rawSchema = t["parameters"]
		}
		if rawSchema == nil {
			if fn, okF := t["function"].(map[string]any); okF {
				rawSchema = fn["parameters"]
			}
		}
		if rawSchema == nil {
			rawSchema = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		sanitized, _ := sanitizeSchemaNode(rawSchema).(map[string]any)
		if sanitized == nil {
			sanitized = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		props, _ := sanitized["properties"].(map[string]any)
		if props == nil {
			props = make(map[string]any)
		}
		delete(props, "toolSummary")

		var reqList []string
		reqSeen := make(map[string]bool)
		appendReq := func(rk string) {
			if rk != "toolSummary" && !reqSeen[rk] {
				if _, hasProp := props[rk]; hasProp {
					reqSeen[rk] = true
					reqList = append(reqList, rk)
				}
			}
		}
		switch rawReq := sanitized["required"].(type) {
		case []string:
			for _, rk := range rawReq {
				appendReq(rk)
			}
		case []any:
			for _, rItem := range rawReq {
				if rk, okS := rItem.(string); okS {
					appendReq(rk)
				}
			}
		}
		sort.Strings(reqList)

		cleanSchema := map[string]any{
			"type":       "object",
			"properties": props,
		}
		if len(reqList) > 0 {
			cleanSchema["required"] = reqList
		}

		rawDesc, _ := t["description"].(string)
		if rawDesc == "" {
			if fn, okF := t["function"].(map[string]any); okF {
				rawDesc, _ = fn["description"].(string)
			}
		}
		rawDesc = strings.TrimSpace(SanitizeOutboundText(rawDesc))
		if idx := strings.IndexByte(rawDesc, '\n'); idx >= 0 {
			rawDesc = strings.TrimSpace(rawDesc[:idx])
		}
		if len(rawDesc) > 300 {
			rawDesc = truncateRunes(rawDesc, 300)
		}
		outboundAlias := NeutralizeToolIdentifier(name)
		if outboundAlias == "" {
			outboundAlias = "ws_tool"
		}
		if seenAlias[outboundAlias] {
			outboundAlias = outboundAlias + "_" + shortSha256(name)[:4]
		}
		seenAlias[outboundAlias] = true

		if rawDesc == "" {
			rawDesc = "Execute host tool " + outboundAlias
		}

		catalog = append(catalog, ToolDef{
			Name:          name,
			OutboundAlias: outboundAlias,
			McpName:       mcpToolName(name),
			Description:   rawDesc,
			Parameters:    cleanSchema,
		})
	}

	if len(catalog) > 0 {
		if !seen[AwaitToolName] {
			catalog = append(catalog, ToolDef{
				Name:        AwaitToolName,
				McpName:     mcpToolName(AwaitToolName),
				Description: "Wait for the result of a harness tool call that reported it is still running.",
				Parameters: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"call_id": map[string]any{"type": "string", "description": "The call id from the still-running notice."},
					},
					"required": []string{"call_id"},
				},
			})
		}
		if !seen[CallToolName] {
			catalog = append(catalog, ToolDef{
				Name:        CallToolName,
				McpName:     mcpToolName(CallToolName),
				Description: "Invoke any harness tool by exact name when its direct tool declaration is absent.",
				Parameters: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"name":      map[string]any{"type": "string", "description": "Exact host tool name."},
						"arguments": map[string]any{"type": "object", "description": "Arguments object."},
					},
					"required": []string{"name"},
				},
			})
		}
	}
	return catalog
}

func extractMediaDescriptor(b map[string]any) (map[string]any, bool) {
	if b == nil {
		return nil, false
	}
	bType, _ := b["type"].(string)
	switch bType {
	case "image":
		if dataStr, _ := b["data"].(string); dataStr != "" {
			mimeStr, _ := b["mimeType"].(string)
			if mimeStr == "" {
				mimeStr, _ = b["media_type"].(string)
			}
			if mimeStr == "" {
				mimeStr = "image/png"
			}
			return map[string]any{
				"type":     "image",
				"mimeType": mimeStr,
				"data":     dataStr,
			}, true
		}
		if src, okS := b["source"].(map[string]any); okS && src["type"] == "base64" {
			dataStr, _ := src["data"].(string)
			mimeStr, _ := src["media_type"].(string)
			if mimeStr == "" {
				mimeStr = "image/png"
			}
			if dataStr != "" {
				return map[string]any{
					"type":     "image",
					"mimeType": mimeStr,
					"data":     dataStr,
				}, true
			}
		}
	case "image_ref":
		if uStr, _ := b["url"].(string); strings.TrimSpace(uStr) != "" {
			return map[string]any{
				"type": "image_ref",
				"url":  strings.TrimSpace(uStr),
			}, true
		}
	case "image_url", "input_image":
		var urlStr string
		switch u := b["image_url"].(type) {
		case string:
			urlStr = u
		case map[string]any:
			urlStr, _ = u["url"].(string)
		}
		if urlStr == "" {
			urlStr, _ = b["url"].(string)
		}
		if strings.HasPrefix(urlStr, "data:") {
			if comma := strings.IndexByte(urlStr, ','); comma > 5 {
				hdr := urlStr[5:comma]
				dataPart := urlStr[comma+1:]
				mimeStr := strings.Split(hdr, ";")[0]
				if mimeStr == "" {
					mimeStr = "image/png"
				}
				return map[string]any{
					"type":     "image",
					"mimeType": mimeStr,
					"data":     dataPart,
				}, true
			}
		} else if strings.TrimSpace(urlStr) != "" {
			return map[string]any{
				"type": "image_ref",
				"url":  strings.TrimSpace(urlStr),
			}, true
		}
	}
	return nil, false
}

func extractImageBlocksFromMessage(m map[string]any) []map[string]any {
	if m == nil {
		return nil
	}
	var imgs []map[string]any
	walkMessageMediaBlocks(m, func(b map[string]any, _ bool) {
		if desc, ok := extractMediaDescriptor(b); ok {
			imgs = append(imgs, desc)
		}
	})
	return imgs
}

func formatMediaPlaceholder(b map[string]any) string {
	bType, _ := b["type"].(string)
	if bType == "image" {
		mimeStr, _ := b["mimeType"].(string)
		if mimeStr == "" {
			if src, okS := b["source"].(map[string]any); okS {
				mimeStr, _ = src["media_type"].(string)
			}
		}
		if mimeStr == "" {
			mimeStr = "image"
		}
		kb := inlineImageSummaryKB(b)
		return fmt.Sprintf("[Image attachment (%s, ~%dKB binary omitted in text history)]", mimeStr, kb)
	}
	return "[Remote image attachment omitted in text history]"
}

func formatToolResultContentAsTextWithNotes(content any, consumeNote func(b map[string]any) string) string {
	switch v := content.(type) {
	case string:
		return SanitizeOutboundText(inlineBase64ImgRe.ReplaceAllString(v, "[base64 image omitted]"))
	case []any:
		var parts []string
		for _, item := range v {
			c, ok := item.(map[string]any)
			if !ok {
				continue
			}
			cType, _ := c["type"].(string)
			switch cType {
			case "text", "input_text", "output_text":
				t, _ := c["text"].(string)
				parts = append(parts, stripRedundantSystemReminders(t))
			case "refusal":
				t, _ := c["refusal"].(string)
				if t == "" {
					t, _ = c["text"].(string)
				}
				parts = append(parts, stripRedundantSystemReminders(t))
			case "image", "image_ref", "image_url", "input_image":
				if consumeNote != nil {
					if note := consumeNote(c); note != "" {
						parts = append(parts, note)
					}
				} else {
					parts = append(parts, formatMediaPlaceholder(c))
				}
			case "tool_result":
				id, _ := c["tool_use_id"].(string)
				sub := formatToolResultContentAsTextWithNotes(c["content"], consumeNote)
				if id != "" {
					parts = append(parts, fmt.Sprintf("[Tool Result (%s)]: %s", id, sub))
				} else if sub != "" {
					parts = append(parts, sub)
				}
			default:
				if raw, err := json.Marshal(SanitizeStructuredValue(c)); err == nil {
					parts = append(parts, string(raw))
				}
			}
		}
		return strings.Join(parts, "\n")
	case []map[string]any:
		asAny := make([]any, 0, len(v))
		for _, item := range v {
			asAny = append(asAny, item)
		}
		return formatToolResultContentAsTextWithNotes(asAny, consumeNote)
	case map[string]any:
		return formatToolResultContentAsTextWithNotes([]any{v}, consumeNote)
	default:
		if raw, err := json.Marshal(SanitizeStructuredValue(v)); err == nil {
			return string(raw)
		}
		return ""
	}
}

func formatToolResultContentAsText(content any) string {
	return formatToolResultContentAsTextWithNotes(content, nil)
}

func formatSingleMessageTextWithMediaNotes(m map[string]any, notes []string) string {
	if m == nil {
		return ""
	}
	noteIdx := 0
	nextHistoryNote := func(_ map[string]any) string {
		if notes == nil {
			return ""
		}
		if noteIdx < len(notes) {
			s := notes[noteIdx]
			noteIdx++
			return s
		}
		return ""
	}
	var consumeToolNote func(b map[string]any) string
	if notes != nil {
		consumeToolNote = nextHistoryNote
	}

	formatBlocks := func(blocks []any) string {
		var parts []string
		for _, item := range blocks {
			b, ok := item.(map[string]any)
			if !ok {
				continue
			}
			bType, _ := b["type"].(string)
			switch bType {
			case "thinking", "redacted_thinking":
				continue
			case "image", "image_ref", "image_url", "input_image":
				if note := nextHistoryNote(b); note != "" {
					parts = append(parts, note)
				}
				continue
			case "text", "input_text", "output_text":
				t, _ := b["text"].(string)
				if s := stripRedundantSystemReminders(t); s != "" {
					parts = append(parts, s)
				}
			case "refusal":
				t, _ := b["refusal"].(string)
				if t == "" {
					t, _ = b["text"].(string)
				}
				if s := stripRedundantSystemReminders(t); s != "" {
					parts = append(parts, s)
				}
			case "tool_result":
				id, _ := b["tool_use_id"].(string)
				c := formatToolResultContentAsTextWithNotes(b["content"], consumeToolNote)
				parts = append(parts, fmt.Sprintf("[Tool Result (%s)]: %s", id, c))
			case "tool_use":
				name, _ := b["name"].(string)
				id, _ := b["id"].(string)
				inBytes, _ := json.Marshal(SanitizeStructuredValue(b["input"]))
				parts = append(parts, fmt.Sprintf("[Tool Call (%s, id=%s)]: %s", NeutralizeToolIdentifier(name), id, string(inBytes)))
			default:
				if raw, err := json.Marshal(SanitizeStructuredValue(b)); err == nil {
					parts = append(parts, string(raw))
				}
			}
		}
		return strings.Join(parts, "\n")
	}

	switch content := m["content"].(type) {
	case string:
		return stripRedundantSystemReminders(content)
	case []any:
		return formatBlocks(content)
	case []map[string]any:
		asAny := make([]any, 0, len(content))
		for _, item := range content {
			asAny = append(asAny, item)
		}
		return formatBlocks(asAny)
	case map[string]any:
		return formatBlocks([]any{content})
	default:
		if raw, err := json.Marshal(SanitizeStructuredValue(content)); err == nil {
			return string(raw)
		}
		return ""
	}
}

func formatSingleMessageText(m map[string]any) string {
	return formatSingleMessageTextWithMediaNotes(m, nil)
}

func extractToolResultTextAndMedia(val any) (string, []map[string]any) {
	var parts []string
	var imgs []map[string]any
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case nil:
			return
		case string:
			if x != "" {
				parts = append(parts, x)
			}
		case []any:
			for _, sub := range x {
				walk(sub)
			}
		case []map[string]any:
			for _, sub := range x {
				walk(sub)
			}
		case map[string]any:
			ct, _ := x["type"].(string)
			switch ct {
			case "text", "input_text", "output_text":
				if ts, _ := x["text"].(string); ts != "" {
					parts = append(parts, ts)
				}
			case "refusal":
				ts, _ := x["refusal"].(string)
				if ts == "" {
					ts, _ = x["text"].(string)
				}
				if ts != "" {
					parts = append(parts, ts)
				}
			case "image", "image_ref", "image_url", "input_image":
				if desc, ok := extractMediaDescriptor(x); ok {
					imgs = append(imgs, desc)
				}
			case "tool_result":
				walk(x["content"])
			default:
				if raw, err := json.Marshal(x); err == nil {
					parts = append(parts, string(raw))
				}
			}
		default:
			if raw, err := json.Marshal(x); err == nil {
				parts = append(parts, string(raw))
			}
		}
	}
	walk(val)
	return strings.Join(parts, "\n"), imgs
}

func formatAttachedUserSteeringText(extra string) string {
	clean := stripRedundantSystemReminders(extra)
	if strings.TrimSpace(clean) == "" {
		return ""
	}
	trimmed := trimBlankOuterLines(extra)
	if strings.HasPrefix(clean, "<workspace-context>") && strings.HasSuffix(clean, "</workspace-context>") {
		return trimmed
	}
	return "[User message]\n" + trimmed
}

func attachTrailingUserInputsToToolResult(dst *ToolResultInput, extraText string, extraImgs []map[string]any) {
	if dst == nil {
		return
	}
	formatted := formatAttachedUserSteeringText(extraText)
	if formatted != "" {
		if dst.Content == "" {
			dst.Content = formatted
		} else {
			dst.Content += "\n\n" + formatted
		}
		if dst.TrailingUserText == "" {
			dst.TrailingUserText = extraText
		} else {
			dst.TrailingUserText += "\n\n" + extraText
		}
	}
	if len(extraImgs) > 0 {
		dst.Images = append(dst.Images, extraImgs...)
		dst.TrailingUserImages = append(dst.TrailingUserImages, extraImgs...)
	}
}

func extractToolResultsFromMessages(messages []map[string]any) []ToolResultInput {
	if len(messages) == 0 {
		return nil
	}
	start := latestTurnStartIndex(messages)
	var results []ToolResultInput
	var extraTexts []string
	var extraImgs []map[string]any

	collectBlockMap := func(b map[string]any) {
		if b == nil {
			return
		}
		bType, _ := b["type"].(string)
		switch bType {
		case "tool_result":
			tuID, _ := b["tool_use_id"].(string)
			if tuID == "" {
				return
			}
			txt, toolImgs := extractToolResultTextAndMedia(b["content"])
			isErr, _ := b["is_error"].(bool)
			results = append(results, ToolResultInput{
				ToolCallID: tuID,
				Content:    txt,
				Images:     toolImgs,
				IsError:    isErr,
			})
		case "thinking", "redacted_thinking", "tool_use":
			return
		case "text", "input_text", "output_text":
			if t, _ := b["text"].(string); strings.TrimSpace(stripRedundantSystemReminders(t)) != "" {
				extraTexts = append(extraTexts, t)
			}
		case "refusal":
			t, _ := b["refusal"].(string)
			if t == "" {
				t, _ = b["text"].(string)
			}
			if strings.TrimSpace(stripRedundantSystemReminders(t)) != "" {
				extraTexts = append(extraTexts, t)
			}
		default:
			if desc, okD := extractMediaDescriptor(b); okD {
				extraImgs = append(extraImgs, desc)
			} else if raw, err := json.Marshal(b); err == nil && len(raw) > 2 {
				extraTexts = append(extraTexts, string(raw))
			}
		}
	}

	for i := start; i < len(messages); i++ {
		msg := messages[i]
		if msg == nil {
			continue
		}
		role, _ := msg["role"].(string)
		if role == "assistant" {
			continue
		}
		if role == "tool" {
			tcID, _ := msg["tool_call_id"].(string)
			if tcID != "" {
				txt, toolImgs := extractToolResultTextAndMedia(msg["content"])
				results = append(results, ToolResultInput{
					ToolCallID: tcID,
					Content:    txt,
					Images:     toolImgs,
				})
			}
			continue
		}
		switch content := msg["content"].(type) {
		case string:
			if strings.TrimSpace(stripRedundantSystemReminders(content)) != "" {
				extraTexts = append(extraTexts, content)
			}
		case []any:
			for _, item := range content {
				switch x := item.(type) {
				case map[string]any:
					collectBlockMap(x)
				case string:
					if strings.TrimSpace(stripRedundantSystemReminders(x)) != "" {
						extraTexts = append(extraTexts, x)
					}
				}
			}
		case []map[string]any:
			for _, item := range content {
				collectBlockMap(item)
			}
		case map[string]any:
			collectBlockMap(content)
		}
	}

	if len(results) == 0 {
		return nil
	}
	if len(extraTexts) > 0 || len(extraImgs) > 0 {
		attachTrailingUserInputsToToolResult(&results[len(results)-1], strings.Join(extraTexts, "\n\n"), extraImgs)
	}
	return results
}

var volatileFirstTurnTagRe = regexp.MustCompile(`(?s)<(?:system-reminder|workspace-context|environment_details)>.*?</(?:system-reminder|workspace-context|environment_details)>`)

func computeFirstUserFingerprint(messages []map[string]any) string {
	if len(messages) == 0 {
		return ""
	}
	firstAsst := -1
	for i, m := range messages {
		if m["role"] == "assistant" {
			firstAsst = i
			break
		}
	}
	limit := firstAsst
	if limit < 0 {
		limit = 2
		if limit > len(messages) {
			limit = len(messages)
		}
	}
	var parts []string
	for _, m := range messages[:limit] {
		role, _ := m["role"].(string)
		rawTxt := strings.TrimSpace(formatSingleMessageText(m))
		coreTxt := strings.TrimSpace(volatileFirstTurnTagRe.ReplaceAllString(rawTxt, ""))
		imgs := imageFingerprintTokens(m)
		effTxt := rawTxt
		if coreTxt != "" || len(imgs) > 0 {
			effTxt = coreTxt
		}
		seg := role + ":" + effTxt
		if len(imgs) > 0 {
			seg += "|media:" + strings.Join(imgs, ",")
		}
		parts = append(parts, seg)
	}
	return shortSha256(strings.Join(parts, "||"))
}

// compactionHeadChars bounds where a compaction instruction may appear: it must open the final
// user text block, so a conversation that merely quotes the instruction is not treated as one.
const compactionHeadChars = 600

func isCompactionSummaryRequest(messages []map[string]any) bool {
	text := lastUserTextBlock(messages)
	if text == "" {
		return false
	}
	head := text
	if len(head) > compactionHeadChars {
		head = head[:compactionHeadChars]
	}
	head = strings.ToLower(head)
	return strings.Contains(head, "create a detailed summary of the conversation") ||
		strings.Contains(head, "summarize this conversation")
}

// lastUserTextBlock returns the final non-empty text block of a trailing user message with
// system reminders removed, or "" when the conversation does not end with user text.
func lastUserTextBlock(messages []map[string]any) string {
	if len(messages) == 0 {
		return ""
	}
	last := messages[len(messages)-1]
	if role, _ := last["role"].(string); role != "user" {
		return ""
	}
	switch c := last["content"].(type) {
	case string:
		return strings.TrimSpace(anySystemReminderRe.ReplaceAllString(c, ""))
	case []any:
		for i := len(c) - 1; i >= 0; i-- {
			b, ok := c[i].(map[string]any)
			if !ok {
				continue
			}
			if t, _ := b["type"].(string); t == "text" || t == "input_text" {
				raw, _ := b["text"].(string)
				if text := strings.TrimSpace(anySystemReminderRe.ReplaceAllString(raw, "")); text != "" {
					return text
				}
			}
		}
	case []map[string]any:
		for i := len(c) - 1; i >= 0; i-- {
			if t, _ := c[i]["type"].(string); t == "text" || t == "input_text" {
				raw, _ := c[i]["text"].(string)
				if text := strings.TrimSpace(anySystemReminderRe.ReplaceAllString(raw, "")); text != "" {
					return text
				}
			}
		}
	}
	return ""
}

func isFailedErrorTurnMessage(m map[string]any) bool {
	role, _ := m["role"].(string)
	if role != "assistant" {
		return false
	}
	txt := strings.TrimSpace(formatSingleMessageText(m))
	if strings.HasPrefix(txt, "⚠ Agent execution terminated due to error") {
		return true
	}
	if _, ok := parseDynamicTerminalErrorLine(txt, ""); ok {
		return true
	}
	return isStatusMarker(txt) && DetectAntigravitySoftError(txt) != nil
}

func buildPromptBlocks(unseenMessages []map[string]any, isRollover bool, allMessages []map[string]any, maxChars int) []map[string]any {
	blocks, _ := resolveAndBuildPromptBlocks(context.Background(), GlobalImageFetcher, unseenMessages, isRollover, allMessages, maxChars, nil)
	return blocks
}

func estimateConversationChars(sysText string, messages []map[string]any) int {
	total := len(sysText)
	for _, m := range messages {
		total += len(formatSingleMessageText(m))
		if total >= 16000 {
			return total
		}
	}
	return total
}

func isBackgroundUtilityCall(sysText string, tools []ToolDef, body map[string]any) bool {
	return isBackgroundUtilityCallWithContext(nil, sysText, tools, nil, body)
}

func isBackgroundUtilityCallWithContext(r *http.Request, sysText string, tools []ToolDef, messages []map[string]any, body map[string]any) bool {
	if maxTok, ok := toInt(body["max_tokens"]); ok && maxTok == 1 {
		return true
	}
	if sug, spin := detectClientUtilityProbe(messages); sug || spin {
		return true
	}
	if len(messages) >= 3 || estimateConversationChars(sysText, messages) >= 16000 {
		return false
	}
	if len(tools) == 0 && !strings.Contains(sysText, "Primary working directory") && isClaudeCodeClient(r, body) {
		return true
	}
	return false
}

const (
	suggestionProbeMarker = "[SUGGESTION MODE:"
	spinnerProbeMarker    = "Describe your most recent action in 3-5 words"
	// Claude Code's spinner probe is about 1-2K chars; longer blocks are conversation content.
	spinnerProbeMaxChars = 4000
)

var anySystemReminderRe = regexp.MustCompile(`(?s)<system-reminder>.*?</system-reminder>`)

// detectClientUtilityProbe recognises Claude Code's prompt-suggestion and spinner-summary probes.
// Only the final non-empty text block of a trailing user message counts and it must START with
// the marker, so a conversation that quotes these strings anywhere else is never answered locally.
// The spinner probe puts recent context first and its instruction on the final line, so for it
// the final line of a short block may also carry the marker.
func detectClientUtilityProbe(messages []map[string]any) (suggestion, spinner bool) {
	text := lastUserTextBlock(messages)
	spinner = strings.HasPrefix(text, spinnerProbeMarker)
	if !spinner && len(text) <= spinnerProbeMaxChars {
		lastLine := text
		if i := strings.LastIndexByte(text, '\n'); i >= 0 {
			lastLine = strings.TrimSpace(text[i+1:])
		}
		spinner = strings.HasPrefix(lastLine, spinnerProbeMarker)
	}
	return strings.HasPrefix(text, suggestionProbeMarker), spinner
}

// isClaudeCodeClient reports whether the request carries Claude Code's (or the Agent SDK's)
// identity. A bare max_tokens=1 request is only treated as a quota probe for these clients;
// for anyone else it is a legitimate one-token request and goes to the model.
func isClaudeCodeClient(r *http.Request, body map[string]any) bool {
	sys := rawSystemText(body["system"])
	if claudeCliIdentRe.MatchString(sys) || claudeSdkIdentRe.MatchString(sys) {
		return true
	}
	if r != nil && strings.HasPrefix(strings.ToLower(r.Header.Get("User-Agent")), "claude-cli/") {
		return true
	}
	return false
}

var userIDSessionUUIDRe = regexp.MustCompile(`(?i)session_([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`)

func extractExplicitSessionAndAgent(r *http.Request, body map[string]any) (string, string) {
	var explicit, agentID string
	if r != nil {
		for _, hdr := range []string{
			"x-claude-code-session-id",
			"x-pi-session-id",
			"x-session-id",
			"session-id",
			"session_id",
			"thread-id",
			"x-conversation-id",
			"conversation_id",
			"openai-conversation-id",
			"x-client-session-id",
		} {
			if v := strings.TrimSpace(r.Header.Get(hdr)); v != "" {
				explicit = v
				break
			}
		}
		agentID = strings.TrimSpace(r.Header.Get("x-claude-code-agent-id"))
	}
	if explicit == "" {
		if pck, ok := body["prompt_cache_key"].(string); ok && strings.TrimSpace(pck) != "" {
			explicit = strings.TrimSpace(pck)
		}
	}
	if meta, ok := body["metadata"].(map[string]any); ok {
		if explicit == "" {
			if s, okS := meta["session_id"].(string); okS && strings.TrimSpace(s) != "" {
				explicit = strings.TrimSpace(s)
			} else if c, okC := meta["conversation_id"].(string); okC && strings.TrimSpace(c) != "" {
				explicit = strings.TrimSpace(c)
			}
		}
		if agentID == "" {
			if a, okA := meta["agent_id"].(string); okA && strings.TrimSpace(a) != "" {
				agentID = strings.TrimSpace(a)
			}
		}
		if explicit == "" {
			if uidStr, okU := meta["user_id"].(string); okU && strings.TrimSpace(uidStr) != "" {
				uidStr = strings.TrimSpace(uidStr)
				if strings.HasPrefix(uidStr, "{") {
					var parsedUID map[string]any
					if json.Unmarshal([]byte(uidStr), &parsedUID) == nil {
						if sid, okS := parsedUID["session_id"].(string); okS && strings.TrimSpace(sid) != "" {
							explicit = strings.TrimSpace(sid)
						}
						if agentID == "" {
							if aid, okA := parsedUID["agent_id"].(string); okA && strings.TrimSpace(aid) != "" {
								agentID = strings.TrimSpace(aid)
							}
						}
					}
				}
				if explicit == "" {
					if m := userIDSessionUUIDRe.FindStringSubmatch(uidStr); len(m) > 1 {
						explicit = m[1]
					}
				}
			}
		}
	}
	if explicit == "" {
		if usrStr, okU := body["user"].(string); okU && strings.TrimSpace(usrStr) != "" {
			if m := userIDSessionUUIDRe.FindStringSubmatch(strings.TrimSpace(usrStr)); len(m) > 1 {
				explicit = m[1]
			}
		}
	}
	return explicit, agentID
}

func messagesContainToolBlocks(messages []map[string]any) bool {
	for _, m := range messages {
		if role, _ := m["role"].(string); role == "tool" {
			return true
		}
		if arr, ok := m["content"].([]any); ok {
			for _, item := range arr {
				if bm, okM := item.(map[string]any); okM {
					if t, _ := bm["type"].(string); t == "tool_use" || t == "tool_result" {
						return true
					}
				}
			}
		}
	}
	return false
}

func deriveConversationKey(r *http.Request, body map[string]any, sysText string, tools []ToolDef, messages []map[string]any) string {
	utilKeyFromPrompt := func() string {
		var firstMsgBytes []byte
		if len(messages) > 0 {
			firstMsgBytes, _ = json.Marshal(messages[0])
		}
		return "util:" + shortSha256(truncateRunes(sysText, 512)+"||"+truncateRunes(string(firstMsgBytes), 512))
	}
	if r != nil {
		reqClass := strings.ToLower(strings.TrimSpace(r.Header.Get("x-claude-code-request-class")))
		if reqClass == "utility" || reqClass == "background" || reqClass == "title" || reqClass == "suggestion" {
			return utilKeyFromPrompt()
		}
	}
	if maxTok, ok := toInt(body["max_tokens"]); ok && maxTok == 1 && !messagesContainToolBlocks(messages) {
		return utilKeyFromPrompt()
	}

	firstFp := computeFirstUserFingerprint(messages)
	if len(firstFp) > 8 {
		firstFp = firstFp[:8]
	}

	explicit, agentID := extractExplicitSessionAndAgent(r, body)
	if explicit != "" {
		if agentID != "" {
			return fmt.Sprintf("sid:%s:ag:%s:u:%s", explicit, agentID, firstFp)
		}
		return fmt.Sprintf("sid:%s:u:%s", explicit, firstFp)
	}

	if isBackgroundUtilityCallWithContext(r, sysText, tools, messages, body) && !messagesContainToolBlocks(messages) {
		return utilKeyFromPrompt()
	}

	sysPrefix := sysText
	if len(sysPrefix) > 4096 {
		sysPrefix = sysPrefix[:4096]
	}
	if agentID != "" {
		return fmt.Sprintf("fp:%s:ag:%s:u:%s", shortSha256(sysPrefix), agentID, firstFp)
	}
	return fmt.Sprintf("fp:%s:u:%s", shortSha256(sysPrefix), firstFp)
}

type TurnToolChoice struct {
	Mode           string
	Allowed        map[string]bool
	AllowedOrdered []string
}

type TurnPromptDirective struct {
	ToolChoice       TurnToolChoice
	StructuredOutput string
}

type turnDirectiveContextKey struct{}

func withTurnDirective(ctx context.Context, dir TurnPromptDirective) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, turnDirectiveContextKey{}, dir)
}

func turnDirectiveFromContext(ctx context.Context) TurnPromptDirective {
	if ctx == nil {
		return TurnPromptDirective{}
	}
	dir, _ := ctx.Value(turnDirectiveContextKey{}).(TurnPromptDirective)
	return dir
}

func (d TurnPromptDirective) IsEmpty() bool {
	return (d.ToolChoice.Mode == "" || d.ToolChoice.Mode == "auto") && len(d.ToolChoice.Allowed) == 0 && d.StructuredOutput == ""
}

func (d TurnPromptDirective) FingerprintToken() string {
	if d.IsEmpty() {
		return ""
	}
	return d.ToolChoice.Mode + "|" + strings.Join(d.ToolChoice.AllowedOrdered, ",") + "|" + d.StructuredOutput
}

func parseClientToolChoice(raw any) TurnToolChoice {
	if raw == nil {
		return TurnToolChoice{}
	}
	addAllowed := func(tc *TurnToolChoice, name string) {
		n := strings.TrimSpace(name)
		if n == "" {
			return
		}
		if tc.Allowed == nil {
			tc.Allowed = make(map[string]bool)
		}
		if !tc.Allowed[n] {
			tc.Allowed[n] = true
			tc.AllowedOrdered = append(tc.AllowedOrdered, n)
		}
	}
	switch v := raw.(type) {
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "none":
			return TurnToolChoice{Mode: "none"}
		case "any", "required":
			return TurnToolChoice{Mode: "required"}
		default:
			return TurnToolChoice{}
		}
	case map[string]any:
		typ := strings.ToLower(strings.TrimSpace(stringField(v, "type", "")))
		switch typ {
		case "none":
			return TurnToolChoice{Mode: "none"}
		case "auto":
			return TurnToolChoice{}
		case "any", "required":
			return TurnToolChoice{Mode: "required"}
		case "tool", "function", "custom":
			var tc TurnToolChoice
			tc.Mode = "tool"
			name := strings.TrimSpace(stringField(v, "name", ""))
			if name == "" {
				if fn, ok := v["function"].(map[string]any); ok {
					name = strings.TrimSpace(stringField(fn, "name", ""))
				}
			}
			if name == "" {
				if cu, ok := v["custom"].(map[string]any); ok {
					name = strings.TrimSpace(stringField(cu, "name", ""))
				}
			}
			addAllowed(&tc, name)
			if len(tc.AllowedOrdered) == 0 {
				return TurnToolChoice{Mode: "required"}
			}
			return tc
		case "allowed_tools":
			var tc TurnToolChoice
			mode := strings.ToLower(strings.TrimSpace(stringField(v, "mode", "")))
			if mode == "none" {
				return TurnToolChoice{Mode: "none"}
			}
			if arr, ok := v["tools"].([]any); ok {
				for _, item := range arr {
					if tm, okM := item.(map[string]any); okM {
						n := strings.TrimSpace(stringField(tm, "name", ""))
						if n == "" {
							if fn, okF := tm["function"].(map[string]any); okF {
								n = strings.TrimSpace(stringField(fn, "name", ""))
							}
						}
						addAllowed(&tc, n)
					} else if s, okS := item.(string); okS {
						addAllowed(&tc, s)
					}
				}
			}
			sort.Strings(tc.AllowedOrdered)
			if mode == "required" || mode == "any" {
				if len(tc.AllowedOrdered) == 1 {
					tc.Mode = "tool"
				} else {
					tc.Mode = "required"
				}
			} else if len(tc.AllowedOrdered) > 0 {
				tc.Mode = "allowed"
			}
			return tc
		}
	}
	return TurnToolChoice{}
}

func sanitizeStructuredOutputSchema(node any) any {
	switch v := node.(type) {
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = sanitizeStructuredOutputSchema(item)
		}
		return out
	case []map[string]any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = sanitizeStructuredOutputSchema(item)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, val := range v {
			switch k {
			case "enum", "const", "required":
				out[k] = val
			case "properties", "$defs", "definitions", "patternProperties", "dependentSchemas":
				if subMap, okM := val.(map[string]any); okM {
					cleanSub := make(map[string]any, len(subMap))
					for propKey, propSchema := range subMap {
						cleanSub[propKey] = sanitizeStructuredOutputSchema(propSchema)
					}
					out[k] = cleanSub
				} else {
					out[k] = sanitizeStructuredOutputSchema(val)
				}
			case "description", "title":
				if s, okS := val.(string); okS {
					out[k] = strings.TrimSpace(SanitizeOutboundText(s))
				} else {
					out[k] = sanitizeStructuredOutputSchema(val)
				}
			default:
				out[k] = sanitizeStructuredOutputSchema(val)
			}
		}
		return out
	default:
		return node
	}
}

func formatStructuredOutputSchemaHint(fmtMap map[string]any) string {
	if fmtMap == nil {
		return ""
	}
	fType := strings.ToLower(strings.TrimSpace(stringField(fmtMap, "type", "")))
	switch fType {
	case "json_object":
		return "[Structured Output Requirement: Respond with a single valid raw JSON object only (no markdown code fences, no preamble, and no trailing explanation).]"
	case "json_schema":
		var schema any
		if js, ok := fmtMap["json_schema"].(map[string]any); ok {
			schema = js["schema"]
			if schema == nil {
				schema = js["json_schema"]
			}
		}
		if schema == nil {
			schema = fmtMap["schema"]
		}
		if schema != nil {
			if sb, err := json.Marshal(sanitizeStructuredOutputSchema(schema)); err == nil && len(sb) > 0 && string(sb) != "null" {
				return "[Structured Output Requirement: Respond ONLY with valid raw JSON (no markdown code fences, no preamble, and no trailing explanation) strictly conforming to this JSON Schema: " + string(sb) + "]"
			}
		}
		return "[Structured Output Requirement: Respond ONLY with valid raw JSON (no markdown code fences, no preamble, and no trailing explanation).]"
	}
	return ""
}

func extractStructuredOutputInstruction(body map[string]any) string {
	if body == nil {
		return ""
	}
	// 1. Anthropic /v1/messages: output_config.format or output_format
	if oc, ok := body["output_config"].(map[string]any); ok {
		if fmtMap, okF := oc["format"].(map[string]any); okF {
			if h := formatStructuredOutputSchemaHint(fmtMap); h != "" {
				return h
			}
		}
	}
	if of, ok := body["output_format"].(map[string]any); ok {
		if h := formatStructuredOutputSchemaHint(of); h != "" {
			return h
		}
	}
	// 2. OpenAI /v1/chat/completions: response_format
	switch rf := body["response_format"].(type) {
	case string:
		if strings.EqualFold(strings.TrimSpace(rf), "json_object") {
			return "[Structured Output Requirement: Respond with a single valid raw JSON object only (no markdown code fences, no preamble, and no trailing explanation).]"
		}
	case map[string]any:
		if h := formatStructuredOutputSchemaHint(rf); h != "" {
			return h
		}
	}
	// 3. OpenAI /v1/responses: text.format
	if tm, ok := body["text"].(map[string]any); ok {
		if fmtMap, okF := tm["format"].(map[string]any); okF {
			if h := formatStructuredOutputSchemaHint(fmtMap); h != "" {
				return h
			}
		}
	}
	return ""
}

func extractTurnPromptDirective(body map[string]any) TurnPromptDirective {
	if body == nil {
		return TurnPromptDirective{}
	}
	return TurnPromptDirective{
		ToolChoice:       parseClientToolChoice(body["tool_choice"]),
		StructuredOutput: extractStructuredOutputInstruction(body),
	}
}

func buildTurnDirectivePromptTail(dir TurnPromptDirective, toolsCatalog []ToolDef) string {
	var parts []string
	bridgeSrv := sessionBridgeServerName(toolsCatalog)
	byHost := make(map[string]ToolDef, len(toolsCatalog))
	for _, t := range toolsCatalog {
		byHost[t.Name] = t
	}
	formatToolRef := func(hostName string) string {
		if td, ok := byHost[hostName]; ok && td.McpName != "" {
			return fmt.Sprintf("`%s` (`mcp_%s_%s`)", td.OutboundName(), bridgeSrv, td.McpName)
		}
		return fmt.Sprintf("`%s`", NeutralizeToolIdentifier(hostName))
	}

	switch dir.ToolChoice.Mode {
	case "none":
		if len(toolsCatalog) > 0 {
			parts = append(parts, "[Turn Constraint: tool_choice=none — Do NOT invoke any tools on this turn; respond directly in assistant text.]")
		}
	case "tool":
		if len(dir.ToolChoice.AllowedOrdered) > 0 {
			name := dir.ToolChoice.AllowedOrdered[0]
			parts = append(parts, fmt.Sprintf("[Turn Constraint: tool_choice forces tool %s — You MUST invoke ONLY %s right now with arguments matching its schema, and do not call any other tool.]", formatToolRef(name), formatToolRef(name)))
		}
	case "required":
		if len(dir.ToolChoice.AllowedOrdered) > 0 {
			refs := make([]string, len(dir.ToolChoice.AllowedOrdered))
			for i, n := range dir.ToolChoice.AllowedOrdered {
				refs[i] = formatToolRef(n)
			}
			parts = append(parts, fmt.Sprintf("[Turn Constraint: tool_choice=required — You MUST invoke at least one of these allowed tools on this turn: %s.]", strings.Join(refs, ", ")))
		} else if len(toolsCatalog) > 0 {
			parts = append(parts, "[Turn Constraint: tool_choice=required — You MUST invoke at least one declared workspace tool on this turn before answering.]")
		}
	case "allowed":
		if len(dir.ToolChoice.AllowedOrdered) > 0 {
			refs := make([]string, len(dir.ToolChoice.AllowedOrdered))
			for i, n := range dir.ToolChoice.AllowedOrdered {
				refs[i] = formatToolRef(n)
			}
			parts = append(parts, fmt.Sprintf("[Turn Constraint: Only these tools are permitted on this turn: %s.]", strings.Join(refs, ", ")))
		}
	}
	if dir.StructuredOutput != "" {
		parts = append(parts, dir.StructuredOutput)
	}
	return strings.Join(parts, "\n")
}

func appendTurnDirectiveToPromptBlocks(blocks []map[string]any, tail string) []map[string]any {
	if tail == "" {
		return blocks
	}
	out := make([]map[string]any, len(blocks))
	copy(out, blocks)
	for i := len(out) - 1; i >= 0; i-- {
		if out[i]["type"] == "text" {
			cp := make(map[string]any, len(out[i]))
			for k, v := range out[i] {
				cp[k] = v
			}
			prev, _ := cp["text"].(string)
			if strings.TrimSpace(prev) == "" {
				cp["text"] = tail
			} else {
				cp["text"] = prev + "\n\n" + tail
			}
			out[i] = cp
			return out
		}
	}
	return append(out, map[string]any{"type": "text", "text": tail})
}
