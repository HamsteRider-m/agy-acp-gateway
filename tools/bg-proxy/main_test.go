package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSwitchoverPreservesInFlightSSEAndRoutesNewToGreen(t *testing.T) {
	tmp := t.TempDir()
	activeFile := filepath.Join(tmp, "active-slot")
	if err := os.WriteFile(activeFile, []byte("blue\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	blueStarted := make(chan struct{})
	releaseBlue := make(chan struct{})
	blueSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		fmt.Fprintf(w, "data: chunk-1\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		close(blueStarted)
		<-releaseBlue
		fmt.Fprintf(w, "data: chunk-2\n\n")
		if flusher != nil {
			flusher.Flush()
		}
	}))
	defer blueSrv.Close()

	greenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"slot":"green","ok":true}`))
	}))
	defer greenSrv.Close()

	sb, err := newSwitchboard(activeFile, blueSrv.URL, blueSrv.URL, greenSrv.URL, greenSrv.URL)
	if err != nil {
		t.Fatal(err)
	}

	frontAPI := httptest.NewServer(http.HandlerFunc(sb.serveAPI))
	defer frontAPI.Close()
	adminSrv := httptest.NewServer(sb.adminHandler())
	defer adminSrv.Close()

	// Start slow SSE request to Blue.
	sseResp, err := http.Get(frontAPI.URL + "/v1/chat/completions")
	if err != nil {
		t.Fatalf("GET front SSE: %v", err)
	}
	defer sseResp.Body.Close()

	select {
	case <-blueStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for blue stream start")
	}

	reader := bufio.NewReader(sseResp.Body)
	line1, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(line1, "chunk-1") {
		t.Fatalf("expected immediate chunk-1 while held open, got %q err=%v", line1, err)
	}

	// Verify blueApi inFlight is 1 while stream is open.
	if got := sb.blue.inFlightAPI.Load(); got != 1 {
		t.Fatalf("expected blue inFlightAPI=1, got %d", got)
	}

	// Switch active-slot -> green and POST /reload.
	if err := os.WriteFile(activeFile, []byte("green\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	relResp, err := http.Post(adminSrv.URL+"/reload", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /reload: %v", err)
	}
	relResp.Body.Close()
	if relResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on reload, got %d", relResp.StatusCode)
	}

	// New request immediately hits Green.
	newResp, err := http.Get(frontAPI.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET green: %v", err)
	}
	newBody, _ := io.ReadAll(newResp.Body)
	newResp.Body.Close()
	if newResp.StatusCode != http.StatusOK || !strings.Contains(string(newBody), `"slot":"green"`) {
		t.Fatalf("expected green response, got status=%d body=%s", newResp.StatusCode, newBody)
	}

	// Release Blue stream and assert remaining chunks arrive intact and inFlight drops back to 0.
	close(releaseBlue)
	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read rest of SSE: %v", err)
	}
	if !strings.Contains(string(rest), "chunk-2") {
		t.Fatalf("expected chunk-2 in drained blue stream, got %q", string(rest))
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if sb.blue.inFlightAPI.Load() == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := sb.blue.inFlightAPI.Load(); got != 0 {
		t.Fatalf("expected blue inFlightAPI=0 after stream finished, got %d", got)
	}
}

func TestReverseProxyPreservesOriginAndForwardedHeaders(t *testing.T) {
	tmp := t.TempDir()
	activeFile := filepath.Join(tmp, "active-slot")
	_ = os.WriteFile(activeFile, []byte("blue\n"), 0o600)

	var seenHost, seenOrigin, seenXFH, seenXFP, seenReqWith, seenAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHost = r.Host
		seenOrigin = r.Header.Get("Origin")
		seenXFH = r.Header.Get("X-Forwarded-Host")
		seenXFP = r.Header.Get("X-Forwarded-Proto")
		seenReqWith = r.Header.Get("X-Agy-Requested-With")
		seenAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	sb, err := newSwitchboard(activeFile, backend.URL, backend.URL, backend.URL, backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	frontDash := httptest.NewServer(http.HandlerFunc(sb.serveDash))
	defer frontDash.Close()

	req, _ := http.NewRequest(http.MethodPost, frontDash.URL+"/api/accounts/oauth/start", nil)
	req.Host = "127.0.0.1:18891"
	req.Header.Set("Origin", "https://agy.home.gomay.de")
	req.Header.Set("X-Forwarded-Host", "agy.home.gomay.de")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Agy-Requested-With", "dashboard")
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if seenHost != "127.0.0.1:18891" ||
		seenOrigin != "https://agy.home.gomay.de" ||
		seenXFH != "agy.home.gomay.de" ||
		seenXFP != "https" ||
		seenReqWith != "dashboard" ||
		seenAuth != "Basic dXNlcjpwYXNz" {
		t.Fatalf("header mismatch: host=%q origin=%q xfh=%q xfp=%q reqWith=%q auth=%q",
			seenHost, seenOrigin, seenXFH, seenXFP, seenReqWith, seenAuth)
	}
}

func TestRollbackAndInvalidSlotRejected(t *testing.T) {
	tmp := t.TempDir()
	activeFile := filepath.Join(tmp, "active-slot")
	_ = os.WriteFile(activeFile, []byte("green\n"), 0o600)

	blueSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("blue"))
	}))
	defer blueSrv.Close()
	greenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("green"))
	}))
	defer greenSrv.Close()

	sb, err := newSwitchboard(activeFile, blueSrv.URL, blueSrv.URL, greenSrv.URL, greenSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	adminSrv := httptest.NewServer(sb.adminHandler())
	defer adminSrv.Close()

	// Invalid slot must return 400 and leave green active.
	_ = os.WriteFile(activeFile, []byte("purple\n"), 0o600)
	respBad, err := http.Post(adminSrv.URL+"/reload", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	respBad.Body.Close()
	if respBad.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid slot, got %d", respBad.StatusCode)
	}
	if got := sb.active.Load().name; got != "green" {
		t.Fatalf("expected active slot to stay green, got %s", got)
	}

	// Rollback to blue must succeed.
	_ = os.WriteFile(activeFile, []byte("blue\n"), 0o600)
	respOK, err := http.Post(adminSrv.URL+"/reload", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	_ = json.NewDecoder(respOK.Body).Decode(&st)
	respOK.Body.Close()
	if respOK.StatusCode != http.StatusOK || st["activeSlot"] != "blue" {
		t.Fatalf("expected rollback to blue, got code=%d body=%+v", respOK.StatusCode, st)
	}
}
