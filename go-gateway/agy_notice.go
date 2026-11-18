package main

import (
	"regexp"
	"strconv"
	"strings"
)

var retryApiErrorLineRe = regexp.MustCompile(`(?i)^\s*⚠\s*API error \(attempt (\d+)\)(?::\s*(.*))?$`)

// agy 1.5.8+ formats unhandled terminal step errors dynamically as "\n⚠ %s\n" with stopReason=end_turn
// instead of always emitting the static "Agent execution terminated due to error." sentence.
var agyDynamicTerminalErrRe = regexp.MustCompile(
	`^(?:(?i:error):\s*)?(?:` +
		`(?:RESOURCE_EXHAUSTED|MODEL_CAPACITY_EXHAUSTED|INVALID_ARGUMENT|PERMISSION_DENIED|UNAUTHENTICATED|UNAVAILABLE|DEADLINE_EXCEEDED|INTERNAL|ABORTED|FAILED_PRECONDITION|NOT_FOUND|ALREADY_EXISTS|OUT_OF_RANGE|UNIMPLEMENTED|DATA_LOSS|UNKNOWN)\s*\(code\s*\d{3}\)\s*:` +
		`|(?:RESOURCE_EXHAUSTED|MODEL_CAPACITY_EXHAUSTED|INVALID_ARGUMENT|PERMISSION_DENIED|DEADLINE_EXCEEDED|FAILED_PRECONDITION|OUT_OF_RANGE|DATA_LOSS)\s*:` +
		`|[A-Z][A-Z0-9_]{2,}\s*\(code\s+[45]\d{2}\)\s*:` +
		`|(?i:(?:HTTP(?:/\d(?:\.\d)?)?\s+)?[45]\d{2}\s+(?:RESOURCE_EXHAUSTED|MODEL_CAPACITY_EXHAUSTED|INVALID_ARGUMENT|PERMISSION_DENIED|UNAUTHENTICATED|UNAVAILABLE|DEADLINE_EXCEEDED|INTERNAL|Bad Request|Unauthorized|Forbidden|Too Many Requests|Internal Server Error|Bad Gateway|Service Unavailable|Gateway Timeout)\b)` +
		`|(?i:rpc\s+error:\s*code\s*=|api\s+error:\s*\S|request\s+failed\s+with\s+status\s+[45]\d{2}\b)` +
		`|(?i:individual\s+quota\s+reached\b|no\s+capacity\s+available\s+for\s+model\b|this\s+service\s+has\s+been\s+disabled\s+in\s+this\s+account\b)` +
		`|(?i:you\s+do\s+not\s+have\s+a\s+valid\s+license\b|gemini_enterprise_license_not_valid\b|ccpa_ineligible_tier_id\b|[^\r\n]*#3501\b)` +
		`|(?i:finish[_\s]*reason\s*[:=]\s*["']?(?:SAFETY|PROHIBITED_CONTENT|BLOCKLIST|RECITATION|SPII)\b|(?:[a-z0-9_]+_policy_violation|bio_policy|prohibited_content)\b|blocked\s+(?:by|due\s+to)\s+(?:safety|policy|content\s+filter)\b)` +
		`)`,
)

func sanitizeNoticeDetail(raw string) string {
	det := strings.TrimSpace(redactSecretsInString(raw))
	det = strings.Join(strings.Fields(det), " ")
	return truncateRunes(det, 240)
}

func parseRetryNoticeLine(line string) (int, string, bool) {
	m := retryApiErrorLineRe.FindStringSubmatch(strings.TrimSpace(line))
	if len(m) == 0 {
		return 0, "", false
	}
	att, _ := strconv.Atoi(m[1])
	det := ""
	if len(m) > 2 {
		det = sanitizeNoticeDetail(m[2])
	}
	return att, det, true
}

func parseDynamicTerminalErrorLine(line, lastRetryDetail string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if !isStatusMarker(trimmed) {
		return "", false
	}
	rawBody := strings.TrimSpace(strings.TrimPrefix(trimmed, "⚠"))
	if rawBody == "" {
		return "", false
	}
	clean := sanitizeNoticeDetail(rawBody)
	if clean == "" {
		return "", false
	}
	if lastRetryDetail != "" {
		if clean == lastRetryDetail || (len(clean) >= 12 && len(lastRetryDetail) >= 12 && (strings.HasPrefix(clean, lastRetryDetail) || strings.HasPrefix(lastRetryDetail, clean))) {
			return clean, true
		}
	}
	if agyDynamicTerminalErrRe.MatchString(rawBody) {
		return clean, true
	}
	return "", false
}

func formatTerminalNoticeWithDetail(notice, retryDetail string) string {
	if notice == "" || retryDetail == "" || notice != agyNoticeTerminated {
		return notice
	}
	return strings.TrimSuffix(notice, ".") + ": " + retryDetail
}

// agy streams some terminal step failures as plain agent_message_chunk text instead of an RPC error.
// The texts below are copied verbatim from the agy-acp-900k 1.5.5 binary.
const (
	agyNoticeNetwork     = "There was a network issue connecting to the server, please try again."
	agyNoticeHighTraffic = "Our servers are experiencing high traffic right now, please try again in a minute."
	agyNoticeTerminated  = "Agent execution terminated due to error."
)

var agyTerminalNotices = []string{agyNoticeNetwork, agyNoticeHighTraffic, agyNoticeTerminated}

type noticeVerdict int

const (
	noticeEmit noticeVerdict = iota // not (or no longer possibly) an agy notice: stream it
	noticeHold                      // may still become an agy notice: keep it out of the stream
	noticeDrop                      // agy notice: never show it to the client
)

// stripNoticeMarker removes agy's warning prefix ("⚠", optionally followed by "Error:").
// Emoji warnings ("⚠️" with U+FE0F) come from model prose and are never treated as marked.
func stripNoticeMarker(raw string) (body string, marked bool) {
	t := strings.TrimSpace(raw)
	if !isStatusMarker(t) {
		return t, false
	}
	t = strings.TrimSpace(strings.TrimPrefix(t, "⚠"))
	if len(t) >= 6 && strings.EqualFold(t[:6], "error:") {
		t = strings.TrimSpace(t[6:])
	}
	return t, true
}

// classifyAgyNotice decides what to do with message text buffered since the start of a turn.
// notice is the canonical agy text when raw starts with a terminal notice; rest is any text that
// follows a ⚠-marked notice (agy retried internally and recovered) and must still be streamed.
// Unmarked text is only treated as a notice when the whole turn text equals it, so a model reply
// that quotes the sentence is never swallowed.
func classifyAgyNotice(raw string, final bool) (v noticeVerdict, notice, rest string) {
	if retryNoticeRe.MatchString(raw) {
		return noticeDrop, "", ""
	}
	body, marked := stripNoticeMarker(raw)
	if marked && !final && (body == "" || strings.HasPrefix("error:", strings.ToLower(body))) {
		return noticeHold, "", ""
	}
	if marked && !final && strings.HasPrefix("api error (attempt", strings.ToLower(body)) {
		return noticeHold, "", ""
	}
	for _, n := range agyTerminalNotices {
		bare := strings.TrimSuffix(n, ".")
		switch {
		case marked && strings.HasPrefix(body, n):
			return noticeDrop, n, strings.TrimLeft(body[len(n):], " \r\n")
		case body == n || body == bare:
			if (marked && body == n) || final {
				return noticeDrop, n, ""
			}
			return noticeHold, "", ""
		case !final && body != "" && strings.HasPrefix(n, body):
			return noticeHold, "", ""
		}
	}
	return noticeEmit, "", ""
}

// agyInfoNotices are ⚠ status lines agy emits while it keeps working (P6, 2026-11-11 probe:
// the turn continued and ended with end_turn). They are dropped and never mark a failure.
var agyInfoNotices = []string{
	"The stream was interrupted. Please continue the task you were working on.",
}

// KnownAgyNoticeTemplates lists every ⚠ status text the gateway recognises. The upgrader
// compares it against the templates found in a candidate binary (O10).
func KnownAgyNoticeTemplates() []string {
	out := append([]string{}, agyTerminalNotices...)
	out = append(out, agyInfoNotices...)
	return append(out, "API error (attempt N)", "Agent execution terminated due to error.", "\n⚠ %s\n")
}

// isStatusMarker reports whether a line opens with agy's warning sign. "⚠️" (with the emoji
// variation selector) is how models write warnings and is not treated as a status line.
func isStatusMarker(line string) bool {
	return strings.HasPrefix(line, "⚠") && !strings.HasPrefix(line, "⚠\ufe0f")
}

// classifyStatusLine decides what to do with one (possibly incomplete) line that may be an agy
// status line. complete means the line ended (newline seen or the turn finished).
func classifyStatusLine(line string, complete, opening bool) (v noticeVerdict, notice string, info bool) {
	if retryApiErrorLineRe.MatchString(line) {
		if !complete {
			return noticeHold, "", false
		}
		return noticeDrop, "", true
	}
	if retryNoticeRe.MatchString(line) {
		if !complete && isStatusMarker(strings.TrimSpace(line)) {
			return noticeHold, "", false
		}
		return noticeDrop, "", true
	}
	body, marked := stripNoticeMarker(line)
	if marked {
		for _, n := range agyInfoNotices {
			if strings.HasPrefix(body, n) {
				return noticeDrop, "", true
			}
			if !complete && strings.HasPrefix(n, body) {
				return noticeHold, "", false
			}
		}
	}
	if !marked && !opening {
		return noticeEmit, "", false
	}
	cv, cn, rest := classifyAgyNotice(line, complete)
	if cv == noticeDrop && strings.TrimSpace(rest) != "" {
		// a notice and unrelated text on the same line: keep the text visible
		return noticeEmit, "", false
	}
	if cv == noticeEmit && marked && !complete {
		// unknown ⚠ line: wait for the end of the line before deciding
		return noticeHold, "", false
	}
	return cv, cn, false
}

func classifyTurnStatusLine(line string, complete, opening bool, lastRetryDetail string) (v noticeVerdict, notice, detail string, info bool) {
	v, notice, info = classifyStatusLine(line, complete, opening)
	if v == noticeEmit && complete {
		if det, ok := parseDynamicTerminalErrorLine(line, lastRetryDetail); ok {
			return noticeDrop, agyNoticeTerminated, det, false
		}
	}
	return v, notice, "", info
}

// acceptTextLocked filters agy status lines out of the streamed reply. Caller holds t.mu.
// Every line that starts with ⚠ is examined (not only the opening text): retry and info lines
// are dropped, terminal failure notices are dropped and remembered, and normal text after a
// terminal notice clears it (agy recovered). Unmarked text is only treated as a notice when it
// is the whole reply, so prose quoting the sentence is never swallowed.
// It returns the text to append to the turn and stream.
func (t *activeTurnState) acceptTextLocked(text string) string {
	buf := t.noticeHold + text
	t.noticeHold = ""
	var out strings.Builder
	for buf != "" {
		if !t.midLine {
			trimmed := strings.TrimLeft(buf, " \t\r\n")
			ws := buf[:len(buf)-len(trimmed)]
			if trimmed == "" {
				t.noticeHold = buf // whitespace may precede a status line
				break
			}
			opening := !t.noticeSettled
			if isStatusMarker(trimmed) || opening {
				nl := strings.IndexByte(trimmed, '\n')
				line, rest, complete := trimmed, "", false
				if nl >= 0 {
					line, rest, complete = trimmed[:nl], trimmed[nl+1:], true
				}
				v, notice, detail, info := classifyTurnStatusLine(line, complete, opening, t.lastRetryDetail)
				switch v {
				case noticeHold:
					t.noticeHold = buf
					return out.String()
				case noticeDrop:
					if notice != "" {
						t.noticeText = notice
						t.noticeFailed = true
						if detail != "" {
							t.lastRetryDetail = detail
						}
					} else if info {
						t.recordDroppedInfoLineLocked(line)
					}
					if out.Len() > 0 || t.emittedText {
						out.WriteString(ws)
					}
					buf = rest
					continue
				}
				t.noticeSettled = true
				if !complete {
					out.WriteString(ws + line)
					t.midLine = true
					t.markNormalLocked(line)
					buf = ""
					continue
				}
				out.WriteString(ws + line + "\n")
				t.markNormalLocked(line)
				buf = rest
				continue
			}
			out.WriteString(ws)
			buf = trimmed
			t.midLine = true
		}
		nl := strings.IndexByte(buf, '\n')
		if nl < 0 {
			out.WriteString(buf)
			t.markNormalLocked(buf)
			buf = ""
			continue
		}
		out.WriteString(buf[:nl+1])
		t.markNormalLocked(buf[:nl])
		buf = buf[nl+1:]
		t.midLine = false
	}
	if out.Len() > 0 {
		t.emittedText = true
	}
	return out.String()
}

func (t *activeTurnState) recordDroppedInfoLineLocked(line string) {
	t.noticeInfo++
	if att, det, ok := parseRetryNoticeLine(line); ok {
		t.apiRetryCount++
		if att > 0 {
			t.lastRetryAttempt = att
		}
		if det != "" {
			t.lastRetryDetail = det
		}
	}
}

// markNormalLocked records model content: a terminal notice followed by real text was recovered.
func (t *activeTurnState) markNormalLocked(s string) {
	if strings.TrimSpace(s) != "" {
		t.noticeSettled = true
		t.noticeFailed = false
		t.lastRetryDetail = ""
	}
}

// finishNoticeLocked resolves any held text when the turn ends. Caller holds t.mu.
// It returns held text that turned out to be a normal reply and must be kept.
func (t *activeTurnState) finishNoticeLocked() string {
	held := t.noticeHold
	t.noticeHold = ""
	if strings.TrimSpace(held) == "" {
		t.noticeSettled = true
		return ""
	}
	trimmed := strings.TrimLeft(held, " \t\r\n")
	ws := held[:len(held)-len(trimmed)]
	v, notice, detail, info := classifyTurnStatusLine(trimmed, true, !t.noticeSettled, t.lastRetryDetail)
	t.noticeSettled = true
	if v == noticeDrop {
		if notice != "" {
			t.noticeText = notice
			t.noticeFailed = true
			if detail != "" {
				t.lastRetryDetail = detail
			}
		} else if info {
			t.recordDroppedInfoLineLocked(trimmed)
		}
		return ""
	}
	t.markNormalLocked(trimmed)
	if !t.emittedText {
		ws = ""
	}
	t.emittedText = true
	return ws + trimmed
}

// noticeOnlyText returns the text a turn reports when agy produced nothing but a terminal notice,
// so DetectAntigravitySoftError turns it into a retryable error instead of a 200 reply.
func noticeOnlyText(text, notice string, toolCalls int) string {
	if strings.TrimSpace(text) == "" && toolCalls == 0 && notice != "" {
		return "⚠ " + notice
	}
	return text
}
