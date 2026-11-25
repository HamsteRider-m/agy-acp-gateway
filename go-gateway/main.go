package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	gwcfg "agy-acp-gateway-go/internal/config"
)

func main() {
	gwcfg.InitProcessGCDefaults()
	// container first-run: make sure the default workspace and log dir exist
	_ = os.MkdirAll(DefaultCwd, 0755)
	_ = os.MkdirAll(filepath.Dir(GatewayLogFile), 0700)
	if authConfigErr != nil {
		LogEvent("AUTH_CONFIG_ERR", authConfigErr.Error(), nil)
	}
	GlobalAccountManager.Init()
	syncPrimaryPromptSemBeforeServe()
	gw := NewGatewayServer()
	if !isChildAccountWorker() {
		GlobalAccountManager.SetPrimaryOccupiedSlotsFn(gw.CountOccupiedWorkerSlots)
	}

	// Pre-warm SQLite index asynchronously so the first dashboard poll is instant, then release temp buffers to OS
	go func() {
		gwSids := getKnownGatewaySids()
		convDir := ConversationsDir()
		appConvDir := AppConversationsDir()
		if GlobalStore.IsReady() {
			if convDir != "" {
				GlobalStore.SyncUsageStepsFromDir(convDir, gwSids)
			}
			if appConvDir != "" {
				GlobalStore.SyncUsageStepsFromSourceDir(appConvDir, "APP", "AGY_APP", "Antigravity App", gwSids)
			}
		} else {
			_ = readFallbackStepsFromDir(convDir, "HOST", "AGY_CLI", "AGY CLI", gwSids)
			if appConvDir != "" {
				_ = readFallbackStepsFromDir(appConvDir, "APP", "AGY_APP", "Antigravity App", gwSids)
			}
		}
		runtime.GC()
		debug.FreeOSMemory()
	}()

	srv18890 := gatewayHTTPServer(fmt.Sprintf("%s:%d", ListenHost, GatewayPort), gw.GatewayOnlyHandler())
	srv18891 := gatewayHTTPServer(fmt.Sprintf("%s:%d", ListenHost, DashboardPort), gw.DashboardOnlyHandler())
	servers := []*http.Server{srv18890, srv18891}

	var srv18890Loopback *http.Server
	var srv18891Loopback *http.Server
	if needsLoopbackGatewayListener(ListenHost) {
		// Internal agy-acp-900k workers connect to ws-bridge MCP on 127.0.0.1:<GatewayPort>,
		// and local health/metrics scripts may query 127.0.0.1:<DashboardPort>.
		srv18890Loopback = gatewayHTTPServer(fmt.Sprintf("127.0.0.1:%d", GatewayPort), gw.GatewayOnlyHandler())
		srv18891Loopback = gatewayHTTPServer(fmt.Sprintf("127.0.0.1:%d", DashboardPort), gw.DashboardOnlyHandler())
		servers = append(servers, srv18890Loopback, srv18891Loopback)
	}

	go func() {
		var modelIDs []string
		for _, m := range AgyModels {
			modelIDs = append(modelIDs, m.ID)
		}
		LogEvent("GATEWAY_READY", fmt.Sprintf("Go gateway listening on http://%s:%d & :%d", ListenHost, GatewayPort, DashboardPort), map[string]any{
			"engine":               "Go native",
			"defaultModel":         DefaultModelID,
			"models":               modelIDs,
			"authEnabled":          authEnabled(),
			"maxLiveWorkers":       effectiveMaxLiveWorkers(),
			"maxConcurrentPrompts": MaxConcurrentPrompts,
			"pureApiHome":          PureApiHome,
			"logFile":              GatewayLogFile,
			"loopbackBridge":       srv18890Loopback != nil,
		})
		if err := srv18890.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "18890 listen error: %v\n", err)
			os.Exit(1)
		}
	}()

	go func() {
		if err := srv18891.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "18891 listen error: %v\n", err)
			os.Exit(1)
		}
	}()

	if srv18890Loopback != nil {
		go func() {
			if err := srv18890Loopback.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				fmt.Fprintf(os.Stderr, "18890 loopback listen error: %v\n", err)
			}
		}()
	}
	if srv18891Loopback != nil {
		go func() {
			if err := srv18891Loopback.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				fmt.Fprintf(os.Stderr, "18891 loopback listen error: %v\n", err)
			}
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	drainTimeout := 6 * time.Second
	if isChildAccountWorker() {
		drainTimeout = 4 * time.Second
	}
	if sec := gwcfg.Current().DrainTimeoutSec; sec > 0 {
		drainTimeout = time.Duration(sec) * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
	defer cancel()
	if err := drainHTTPServers(ctx, servers...); err != nil {
		LogEvent("HTTP_DRAIN_TIMEOUT", "Grace period expired; remaining connections closed", nil)
	}
	gw.Close()
	GlobalAccountManager.StopAll()
	GlobalEngine.StopEngine()
	GlobalStore.Close()
}

func needsLoopbackGatewayListener(listenHost string) bool {
	h := strings.TrimSpace(strings.Trim(listenHost, "[]"))
	switch strings.ToLower(h) {
	case "", "127.0.0.1", "localhost", "::1", "0.0.0.0", "::":
		return false
	default:
		return true
	}
}
