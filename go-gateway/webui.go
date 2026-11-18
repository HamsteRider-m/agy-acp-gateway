package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"strings"
	"sync"
)

//go:embed webui/dashboard.html
var dashboardHTMLTemplate string

//go:embed webui/lucide-icons.json
var lucideIconsJSON string

var (
	dashboardOnce    sync.Once
	dashboardHTML    string
	dashboardBuildID string
)

func initDashboardAssets() {
	dashboardOnce.Do(func() {
		sum := sha256.Sum256([]byte(dashboardHTMLTemplate + "\n" + lucideIconsJSON))
		dashboardBuildID = hex.EncodeToString(sum[:6])
		rendered := strings.Replace(dashboardHTMLTemplate, "/*__UI_BUILD__*/", `const UI_BUILD_ID = "`+dashboardBuildID+`";`, 1)
		dashboardHTML = strings.Replace(rendered, "/*__LUCIDE__*/", "const ICONS = "+lucideIconsJSON+";", 1)
	})
}

func DashboardBuildID() string {
	initDashboardAssets()
	return dashboardBuildID
}

// RenderDashboardHTML returns the embedded UI with Lucide icons (ISC, see webui/LICENSE-lucide.txt) inlined.
func RenderDashboardHTML() string {
	initDashboardAssets()
	return dashboardHTML
}
