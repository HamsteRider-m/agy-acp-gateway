package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type slotBackend struct {
	name         string
	apiTarget    string
	dashTarget   string
	apiProxy     *httputil.ReverseProxy
	dashProxy    *httputil.ReverseProxy
	inFlightAPI  atomic.Int64
	inFlightDash atomic.Int64
}

type switchboard struct {
	activeFile string
	blue       *slotBackend
	green      *slotBackend

	reloadMu   sync.Mutex
	active     atomic.Pointer[slotBackend]
	reloadedAt atomic.Int64
	lastModNs  int64
	lastSize   int64
}

func envStr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 65535 {
			return n
		}
	}
	return def
}

func needsLoopbackListener(listenHost string) bool {
	h := strings.TrimSpace(strings.Trim(listenHost, "[]"))
	switch strings.ToLower(h) {
	case "", "127.0.0.1", "localhost", "::1", "0.0.0.0", "::":
		return false
	default:
		return true
	}
}

func newSlotProxy(rawTarget string, slotName string) (*httputil.ReverseProxy, error) {
	u, err := url.Parse(strings.TrimSpace(rawTarget))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid backend URL %q: %v", rawTarget, err)
	}
	tr := &http.Transport{
		Proxy:                 nil,
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 0,
		DisableCompression:    true,
	}
	rp := httputil.NewSingleHostReverseProxy(u)
	baseDirector := rp.Director
	rp.Director = func(req *http.Request) {
		origHost := req.Host
		baseDirector(req)
		// Preserve incoming Host, Origin, Authorization, and X-Forwarded-* headers intact for CSRF / sameOrigin checks.
		if origHost != "" {
			req.Host = origHost
		}
	}
	rp.FlushInterval = -1
	rp.Transport = tr
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, proxyErr error) {
		if errors.Is(proxyErr, context.Canceled) {
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":    false,
			"error": fmt.Sprintf("blue-green upstream (%s) unavailable: %v", slotName, proxyErr),
		})
	}
	return rp, nil
}

func newSlotBackend(name, apiRaw, dashRaw string) (*slotBackend, error) {
	apiP, err := newSlotProxy(apiRaw, name+":api")
	if err != nil {
		return nil, err
	}
	dashP, err := newSlotProxy(dashRaw, name+":dash")
	if err != nil {
		return nil, err
	}
	return &slotBackend{
		name:       name,
		apiTarget:  apiRaw,
		dashTarget: dashRaw,
		apiProxy:   apiP,
		dashProxy:  dashP,
	}, nil
}

func newSwitchboard(activeFile, blueAPI, blueDash, greenAPI, greenDash string) (*switchboard, error) {
	b, err := newSlotBackend("blue", blueAPI, blueDash)
	if err != nil {
		return nil, err
	}
	g, err := newSlotBackend("green", greenAPI, greenDash)
	if err != nil {
		return nil, err
	}
	sb := &switchboard{
		activeFile: activeFile,
		blue:       b,
		green:      g,
	}
	if _, err := sb.loadInitial(); err != nil {
		return nil, err
	}
	return sb, nil
}

func (sb *switchboard) slotByName(name string) (*slotBackend, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "blue":
		return sb.blue, nil
	case "green":
		return sb.green, nil
	default:
		return nil, fmt.Errorf("invalid slot %q (must be blue or green)", name)
	}
}

func (sb *switchboard) loadInitial() (*slotBackend, error) {
	sb.reloadMu.Lock()
	defer sb.reloadMu.Unlock()
	raw, err := os.ReadFile(sb.activeFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			sb.active.Store(sb.blue)
			sb.reloadedAt.Store(time.Now().Unix())
			return sb.blue, nil
		}
		return nil, fmt.Errorf("read active-slot %q: %w", sb.activeFile, err)
	}
	slot, err := sb.slotByName(string(raw))
	if err != nil {
		return nil, err
	}
	if st, statErr := os.Stat(sb.activeFile); statErr == nil {
		sb.lastModNs = st.ModTime().UnixNano()
		sb.lastSize = st.Size()
	}
	sb.active.Store(slot)
	sb.reloadedAt.Store(time.Now().Unix())
	return slot, nil
}

func (sb *switchboard) reloadFromFile() (*slotBackend, error) {
	sb.reloadMu.Lock()
	defer sb.reloadMu.Unlock()
	raw, err := os.ReadFile(sb.activeFile)
	if err != nil {
		return sb.active.Load(), fmt.Errorf("read active-slot %q: %w", sb.activeFile, err)
	}
	slot, err := sb.slotByName(string(raw))
	if err != nil {
		return sb.active.Load(), err
	}
	if st, statErr := os.Stat(sb.activeFile); statErr == nil {
		sb.lastModNs = st.ModTime().UnixNano()
		sb.lastSize = st.Size()
	}
	sb.active.Store(slot)
	sb.reloadedAt.Store(time.Now().Unix())
	return slot, nil
}

func (sb *switchboard) maybeReloadIfChanged() {
	st, err := os.Stat(sb.activeFile)
	if err != nil {
		return
	}
	sb.reloadMu.Lock()
	changed := st.ModTime().UnixNano() != sb.lastModNs || st.Size() != sb.lastSize
	sb.reloadMu.Unlock()
	if changed {
		_, _ = sb.reloadFromFile()
	}
}

func (sb *switchboard) serveAPI(w http.ResponseWriter, r *http.Request) {
	s := sb.active.Load()
	s.inFlightAPI.Add(1)
	defer s.inFlightAPI.Add(-1)
	s.apiProxy.ServeHTTP(w, r)
}

func (sb *switchboard) serveDash(w http.ResponseWriter, r *http.Request) {
	s := sb.active.Load()
	s.inFlightDash.Add(1)
	defer s.inFlightDash.Add(-1)
	s.dashProxy.ServeHTTP(w, r)
}

func (sb *switchboard) statusMap() map[string]any {
	cur := sb.active.Load()
	return map[string]any{
		"ok":         true,
		"activeSlot": cur.name,
		"apiTarget":  cur.apiTarget,
		"dashTarget": cur.dashTarget,
		"reloadedAt": time.Unix(sb.reloadedAt.Load(), 0).UTC().Format(time.RFC3339),
		"pid":        os.Getpid(),
		"inFlight": map[string]int64{
			"blueApi":   sb.blue.inFlightAPI.Load(),
			"blueDash":  sb.blue.inFlightDash.Load(),
			"greenApi":  sb.green.inFlightAPI.Load(),
			"greenDash": sb.green.inFlightDash.Load(),
		},
	}
}

func (sb *switchboard) adminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(sb.statusMap())
	})
	mux.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if _, err := sb.reloadFromFile(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":    false,
				"error": err.Error(),
			})
			return
		}
		_ = json.NewEncoder(w).Encode(sb.statusMap())
	})
	return mux
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
	}
}

func main() {
	listenHost := envStr("AGY_BG_LISTEN_HOST", "100.83.81.104")
	apiPort := envInt("AGY_BG_API_PORT", 18890)
	dashPort := envInt("AGY_BG_DASH_PORT", 18891)
	adminPort := envInt("AGY_BG_ADMIN_PORT", 18959)
	activeFile := envStr("AGY_BG_ACTIVE_FILE", "/Users/maygo/Projects/agy-acp-gateway/runtime/active-slot")
	blueAPI := envStr("AGY_BG_BLUE_API", "http://127.0.0.1:18950")
	blueDash := envStr("AGY_BG_BLUE_DASH", "http://127.0.0.1:18951")
	greenAPI := envStr("AGY_BG_GREEN_API", "http://127.0.0.1:18960")
	greenDash := envStr("AGY_BG_GREEN_DASH", "http://127.0.0.1:18961")

	sb, err := newSwitchboard(activeFile, blueAPI, blueDash, greenAPI, greenDash)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bg-proxy init error: %v\n", err)
		os.Exit(1)
	}

	apiHandler := http.HandlerFunc(sb.serveAPI)
	dashHandler := http.HandlerFunc(sb.serveDash)

	servers := []*http.Server{
		newHTTPServer(fmt.Sprintf("%s:%d", listenHost, apiPort), apiHandler),
		newHTTPServer(fmt.Sprintf("%s:%d", listenHost, dashPort), dashHandler),
		newHTTPServer(fmt.Sprintf("127.0.0.1:%d", adminPort), sb.adminHandler()),
	}
	if needsLoopbackListener(listenHost) {
		servers = append(servers,
			newHTTPServer(fmt.Sprintf("127.0.0.1:%d", apiPort), apiHandler),
			newHTTPServer(fmt.Sprintf("127.0.0.1:%d", dashPort), dashHandler),
		)
	}

	errCh := make(chan error, len(servers))
	for _, srv := range servers {
		s := srv
		go func() {
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("%s: %w", s.Addr, err)
			}
		}()
	}

	cur := sb.active.Load()
	fmt.Printf("agy-bg-proxy listening on %s:%d/%d (admin 127.0.0.1:%d) -> active=%s (%s, %s)\n",
		listenHost, apiPort, dashPort, adminPort, cur.name, cur.apiTarget, cur.dashTarget)

	stopTicker := make(chan struct{})
	go func() {
		tk := time.NewTicker(500 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-tk.C:
				sb.maybeReloadIfChanged()
			case <-stopTicker:
				return
			}
		}
	}()

	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	go func() {
		for range hupCh {
			if next, rErr := sb.reloadFromFile(); rErr != nil {
				fmt.Fprintf(os.Stderr, "bg-proxy SIGHUP reload rejected: %v\n", rErr)
			} else {
				fmt.Printf("bg-proxy reloaded -> active=%s\n", next.name)
			}
		}
	}()

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case listenErr := <-errCh:
		fmt.Fprintf(os.Stderr, "bg-proxy listen error: %v\n", listenErr)
		os.Exit(1)
	case <-sigCh:
	}

	close(stopTicker)
	signal.Stop(hupCh)
	close(hupCh)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, srv := range servers {
		s := srv
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.Shutdown(ctx)
		}()
	}
	wg.Wait()
}
