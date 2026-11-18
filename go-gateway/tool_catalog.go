package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Tool catalog and system prompt change handling for reused ACP sessions.
//
// agy pulls the MCP tools/list once at session/new (probe P5, agy 1.5.5), and any change to the
// tools declaration at the head of the prompt invalidates the upstream implicit prefix cache across
// the entire conversation history. Therefore (review R3, consumeToolDelta):
//   - sessions opened WITHOUT dsh-bridge (0 tools) roll over once if tools appear later, so
//     dsh-bridge and dsh_call_tool are mounted;
//   - sessions that ALREADY have dsh-bridge keep their initial tools/list declaration stable to
//     preserve the prefix cache, enforce the current catalog as a strict whitelist on both direct
//     tools/call and dsh_call_tool, and inject a compact [Host tool update] delta at the prompt
//     tail so newly added (e.g. Claude Code deferred MCP tools), updated, or removed tools take
//     effect immediately without a cold-start rollover;
//   - system prompt changes are likewise injected as a prompt-tail delta without a cold start.

const toolDeltaMaxChars = 20000

// toolCatalogFingerprint hashes name, description and normalized schema of every tool.
func toolCatalogFingerprint(cat []ToolDef) string {
	if len(cat) == 0 {
		return shortSha256("")
	}
	parts := make([]string, 0, len(cat))
	for _, t := range cat {
		parts = append(parts, toolDefDigest(t))
	}
	sort.Strings(parts)
	return shortSha256(strings.Join(parts, "\n"))
}

// legacyToolFingerprint is the pre-2026-11-11 names-only fingerprint still stored for sessions
// persisted by older builds; it lets those sessions resume once after an upgrade.
func legacyToolFingerprint(cat []ToolDef) string {
	names := make([]string, 0, len(cat))
	for _, t := range cat {
		names = append(names, t.Name)
	}
	return shortSha256(strings.Join(names, ","))
}

func toolDefDigest(t ToolDef) string {
	schema, _ := json.Marshal(t.Parameters) // map keys are emitted sorted
	return t.Name + "\x00" + t.Description + "\x00" + string(schema)
}

func isInternalBridgeTool(name string) bool {
	return name == AwaitToolName || name == CallToolName || name == LegacyAwaitToolName || name == LegacyCallToolName
}

func sessionBridgeServerName(cat []ToolDef) string {
	for _, t := range cat {
		if strings.HasPrefix(t.McpName, "dsh_") {
			return LegacyMcpBridgeName
		}
		if strings.HasPrefix(t.McpName, "ws_") {
			return McpBridgeName
		}
	}
	return McpBridgeName
}

func sessionHelperMcpName(cat []ToolDef, wantAwait bool) string {
	isLegacy := sessionBridgeServerName(cat) == LegacyMcpBridgeName
	for _, t := range cat {
		if t.McpName == "" {
			continue
		}
		if isLegacy && !strings.HasPrefix(t.McpName, "dsh_") {
			continue
		}
		if !isLegacy && !strings.HasPrefix(t.McpName, "ws_") {
			continue
		}
		if wantAwait && (t.Name == AwaitToolName || t.Name == LegacyAwaitToolName) {
			return t.McpName
		}
		if !wantAwait && (t.Name == CallToolName || t.Name == LegacyCallToolName) {
			return t.McpName
		}
	}
	if isLegacy {
		if wantAwait {
			return fmt.Sprintf("dsh_%s_%s", LegacyAwaitToolName, shortSha256(LegacyAwaitToolName)[:12])
		}
		return fmt.Sprintf("dsh_%s_%s", LegacyCallToolName, shortSha256(LegacyCallToolName)[:12])
	}
	if wantAwait {
		return mcpToolName(AwaitToolName)
	}
	return mcpToolName(CallToolName)
}

func stripBridgeMcpPrefix(raw string) string {
	switch {
	case strings.HasPrefix(raw, "mcp_"+McpBridgeName+"_"):
		return strings.TrimPrefix(raw, "mcp_"+McpBridgeName+"_")
	case strings.HasPrefix(raw, "mcp_"+LegacyMcpBridgeName+"_"):
		return strings.TrimPrefix(raw, "mcp_"+LegacyMcpBridgeName+"_")
	default:
		return raw
	}
}

// diffToolCatalogs compares two catalogs by host tool name, ignoring internal dsh-bridge helpers.
func diffToolCatalogs(oldCat, newCat []ToolDef) (added, removed, changed []string) {
	oldBy := make(map[string]string, len(oldCat))
	for _, t := range oldCat {
		if !isInternalBridgeTool(t.Name) {
			oldBy[t.Name] = toolDefDigest(t)
		}
	}
	newBy := make(map[string]bool, len(newCat))
	for _, t := range newCat {
		if isInternalBridgeTool(t.Name) {
			continue
		}
		newBy[t.Name] = true
		prev, ok := oldBy[t.Name]
		switch {
		case !ok:
			added = append(added, t.Name)
		case prev != toolDefDigest(t):
			changed = append(changed, t.Name)
		}
	}
	for name := range oldBy {
		if !newBy[name] {
			removed = append(removed, name)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)
	return added, removed, changed
}

// toolCatalogNeedsRollover reports whether a session must be replaced to serve newCat.
// A session that already mounted dsh-bridge (hasBridge == true) can serve any subsequent tool
// addition, removal, or schema update in-place via dsh_call_tool + prompt-tail delta. Only a
// 0-tool session gaining tools (no MCP bridge mounted) or a restored session with an unknown old
// catalog and mismatched fingerprint requires a fresh session.
func toolCatalogNeedsRollover(hasBridge bool, oldCat []ToolDef, oldFp string, newCat []ToolDef) bool {
	if oldCat == nil {
		if oldFp == "" {
			return len(newCat) > 0
		}
		return oldFp != toolCatalogFingerprint(newCat) && oldFp != legacyToolFingerprint(newCat)
	}
	if !hasBridge && len(newCat) > 0 {
		return true
	}
	return false
}

// buildToolDeltaNotice describes added, changed, and removed tools for prompt-tail injection while
// keeping session/new's tools/list declaration untouched to protect the upstream implicit cache.
func buildToolDeltaNotice(oldCat, newCat []ToolDef, declared map[string]bool) (notice string, added, removed, changed []string) {
	added, removed, changed = diffToolCatalogs(oldCat, newCat)
	if len(added) == 0 && len(removed) == 0 && len(changed) == 0 {
		return "", nil, nil, nil
	}
	newByName := make(map[string]ToolDef, len(newCat))
	for _, t := range newCat {
		newByName[t.Name] = t
	}
	refCat := oldCat
	if len(refCat) == 0 {
		refCat = newCat
	}
	bridgeSrv := sessionBridgeServerName(refCat)
	mcpPrefix := "mcp_" + bridgeSrv + "_"
	callHelperMcp := mcpPrefix + sessionHelperMcpName(refCat, false)

	var sections []string
	if len(removed) > 0 {
		outRemoved := make([]string, len(removed))
		for i, rn := range removed {
			outRemoved[i] = NeutralizeToolIdentifier(rn)
		}
		sections = append(sections, fmt.Sprintf("These tools are no longer available in this session and calls to them will fail: %s.", strings.Join(outRemoved, ", ")))
	}
	if len(added) > 0 {
		var dynamicLines, reEnabledLines []string
		for _, name := range added {
			t := newByName[name]
			outName := t.OutboundName()
			schemaBytes, _ := json.Marshal(t.Parameters)
			if declared[name] {
				reEnabledLines = append(reEnabledLines, fmt.Sprintf("- %s (%s%s): %s | parameters: %s", outName, mcpPrefix, t.McpName, t.Description, string(schemaBytes)))
			} else {
				dynamicLines = append(dynamicLines, fmt.Sprintf("- %s: %s | parameters: %s", outName, t.Description, string(schemaBytes)))
			}
		}
		if len(dynamicLines) > 0 {
			sections = append(sections, fmt.Sprintf("Newly available tools in this session (invoke via %s with {\"name\": \"<tool_name>\", \"arguments\": {...}}):\n%s", callHelperMcp, strings.Join(dynamicLines, "\n")))
		}
		if len(reEnabledLines) > 0 {
			sections = append(sections, "Re-enabled tools in this session:\n"+strings.Join(reEnabledLines, "\n"))
		}
	}
	if len(changed) > 0 {
		var changedLines []string
		for _, name := range changed {
			t := newByName[name]
			outName := t.OutboundName()
			schemaBytes, _ := json.Marshal(t.Parameters)
			via := mcpPrefix + t.McpName
			if !declared[name] {
				via = callHelperMcp
			}
			changedLines = append(changedLines, fmt.Sprintf("- %s (%s): %s | parameters: %s", outName, via, t.Description, string(schemaBytes)))
		}
		sections = append(sections, "Updated tool definitions in this session:\n"+strings.Join(changedLines, "\n"))
	}

	out := "[Host tool update] " + strings.Join(sections, "\n")
	if len(out) > toolDeltaMaxChars {
		out = truncateRunes(out, toolDeltaMaxChars)
	}
	return out, added, removed, changed
}

// resolveAllowedHostTool maps an MCP tool name from agy to the host tool name, accepting only
// tools of the session's current catalog. Unknown names are rejected instead of being forwarded.
func resolveAllowedHostTool(mcpToHost map[string]string, rawName string) (string, bool) {
	if h, ok := mcpToHost[rawName]; ok {
		return h, true
	}
	trimmed := stripBridgeMcpPrefix(rawName)
	if h, ok := mcpToHost[trimmed]; ok {
		return h, true
	}
	return "", false
}

// allowedHostToolName validates a host tool name requested through ws_call_tool / dsh_call_tool.
// It accepts the host name itself, its neutralized outbound alias, or its MCP alias, and never the
// bridge's own helper tools.
func allowedHostToolName(mcpToHost map[string]string, requested string, catalogs ...[]ToolDef) (string, bool) {
	requested = strings.TrimSpace(stripBridgeMcpPrefix(strings.TrimSpace(requested)))
	if requested == "" {
		return "", false
	}
	if h, ok := mcpToHost[requested]; ok {
		requested = h
	}
	if isInternalBridgeTool(requested) {
		return "", false
	}
	for _, cat := range catalogs {
		for _, t := range cat {
			if isInternalBridgeTool(t.Name) {
				continue
			}
			if t.Name == requested || t.OutboundName() == requested {
				return t.Name, true
			}
		}
	}
	for _, h := range mcpToHost {
		if isInternalBridgeTool(h) {
			continue
		}
		if h == requested || NeutralizeToolIdentifier(h) == requested {
			return h, true
		}
	}
	return "", false
}

func mcpToolError(text string) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": true,
	}
}

const systemDeltaMaxChars = 20000

// systemPromptDelta describes a client system prompt change for injection into the turn prompt.
// Both sides are compared after PruneClientSystemPrompt, i.e. as agy would receive them.
func systemPromptDelta(oldSys, newSys string) string {
	oldP, newP := PruneClientSystemPrompt(oldSys), PruneClientSystemPrompt(newSys)
	if oldP == newP {
		return ""
	}
	oldLines := map[string]int{}
	for _, l := range strings.Split(oldP, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			oldLines[l]++
		}
	}
	newLines := map[string]int{}
	var added []string
	for _, l := range strings.Split(newP, "\n") {
		if l = strings.TrimSpace(l); l == "" {
			continue
		}
		newLines[l]++
		if newLines[l] > oldLines[l] {
			added = append(added, l)
		}
	}
	var removed []string
	seen := map[string]int{}
	for _, l := range strings.Split(oldP, "\n") {
		if l = strings.TrimSpace(l); l == "" {
			continue
		}
		seen[l]++
		if seen[l] > newLines[l] {
			removed = append(removed, l)
		}
	}
	if len(added) == 0 && len(removed) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("[Host instructions updated] The workspace context changed since the session started. Where they differ, these lines take precedence over the earlier workspace context.")
	if len(added) > 0 {
		b.WriteString("\nAdded or changed:\n")
		b.WriteString(strings.Join(added, "\n"))
	}
	if len(removed) > 0 {
		b.WriteString("\nNo longer in effect:\n")
		b.WriteString(strings.Join(removed, "\n"))
	}
	out := b.String()
	if len(out) > systemDeltaMaxChars {
		out = "[Host instructions updated] The full current workspace context follows and replaces the earlier one.\n" + truncateRunes(newP, systemDeltaMaxChars)
	}
	return out
}
