package main_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func freePort() int {
	l, _ := net.Listen("tcp", ":0")
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitHTTP(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("service at %s not ready", url)
}

func startMonitor(t *testing.T, env []string) string {
	t.Helper()
	binPath := t.TempDir() + "/monitor"
	build := exec.Command("go", "build", "-o", binPath, "./cmd/monitor")
	build.Dir = "."
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build monitor: %v", err)
	}
	cmd := exec.Command(binPath)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start monitor: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill() })
	return binPath
}

func TestMonitor_StartAndReady(t *testing.T) {
	port := freePort()
	startMonitor(t, []string{
		fmt.Sprintf("PORT=%d", port),
		"HEALTH_INTERVAL_SECS=60", // long interval so it doesn't actually ping during test
		"POLL_INTERVAL_SECS=60",
	})

	baseURL := fmt.Sprintf("http://localhost:%d", port)
	if err := waitHTTP(baseURL+"/ready", 8*time.Second); err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get(baseURL + "/ready")
	if err != nil {
		t.Fatalf("ready: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ready status %d: %s", resp.StatusCode, body)
	}
	if string(body) != "ready" {
		t.Fatalf("expected 'ready', got %q", body)
	}
	t.Log("Ready endpoint OK")
}

func TestMonitor_HealthEndpoint(t *testing.T) {
	port := freePort()
	startMonitor(t, []string{
		fmt.Sprintf("PORT=%d", port),
		"COORDINATOR_ADDR=localhost:50051",
		"POLICY_ADDR=localhost:50052",
		"GATEWAY_ADDR=localhost:8080",
		"HEALTH_INTERVAL_SECS=60",
		"POLL_INTERVAL_SECS=60",
	})

	baseURL := fmt.Sprintf("http://localhost:%d", port)
	if err := waitHTTP(baseURL+"/ready", 8*time.Second); err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status %d", resp.StatusCode)
	}

	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Fatalf("expected status=ok, got %v", body)
	}
	if body["coordinator"] != "localhost:50051" {
		t.Fatalf("unexpected coordinator addr: %s", body["coordinator"])
	}
	t.Logf("Health endpoint OK: %v", body)
}

func TestMonitor_PrometheusMetricsEndpoint(t *testing.T) {
	port := freePort()
	startMonitor(t, []string{
		fmt.Sprintf("PORT=%d", port),
		"HEALTH_INTERVAL_SECS=60",
		"POLL_INTERVAL_SECS=60",
	})

	baseURL := fmt.Sprintf("http://localhost:%d", port)
	if err := waitHTTP(baseURL+"/ready", 8*time.Second); err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get(baseURL + "/metrics")
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics status %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	text := string(body)

	// Verify our custom metrics are registered and exposed
	expectedMetrics := []string{
		"kosh_dkg_started_total",
		"kosh_dkg_completed_total",
		"kosh_dkg_failed_total",
		"kosh_sign_started_total",
		"kosh_sign_completed_total",
		"kosh_sign_failed_total",
		"kosh_service_up",
		"kosh_party_phase",
		"kosh_bb_key_count",
	}

	for _, name := range expectedMetrics {
		if !strings.Contains(text, name) {
			t.Errorf("metric %q not found in /metrics output", name)
		}
	}
	t.Logf("Prometheus /metrics OK: all %d custom metrics present", len(expectedMetrics))
}

func TestMonitor_MetricsHaveCorrectTypes(t *testing.T) {
	port := freePort()
	startMonitor(t, []string{
		fmt.Sprintf("PORT=%d", port),
		"HEALTH_INTERVAL_SECS=60",
		"POLL_INTERVAL_SECS=60",
	})

	baseURL := fmt.Sprintf("http://localhost:%d", port)
	if err := waitHTTP(baseURL+"/ready", 8*time.Second); err != nil {
		t.Fatal(err)
	}

	resp, _ := http.Get(baseURL + "/metrics")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	text := string(body)

	// Counters must be TYPE counter
	counters := []string{"kosh_dkg_started_total", "kosh_sign_completed_total"}
	for _, c := range counters {
		if !strings.Contains(text, "# TYPE "+c+" counter") {
			t.Errorf("%s should be TYPE counter", c)
		}
	}

	// Gauges must be TYPE gauge
	gauges := []string{"kosh_service_up", "kosh_party_phase", "kosh_bb_key_count"}
	for _, g := range gauges {
		if !strings.Contains(text, "# TYPE "+g+" gauge") {
			t.Errorf("%s should be TYPE gauge", g)
		}
	}
	t.Log("Metric types correct: counters are counter, gauges are gauge")
}
