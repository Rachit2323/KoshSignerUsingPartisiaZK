package main_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

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

func waitTCP(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("tcp %s not ready", addr)
}

type proc struct{ cmd *exec.Cmd }

func (p *proc) kill() { p.cmd.Process.Kill() }

// buildPartyBin compiles the kosh-party Rust binary using cargo and returns its path.
func buildPartyBin(t *testing.T, partyDir string) string {
	t.Helper()
	// Use the workspace root to build
	root := partyDir + "/../.."
	cmd := exec.Command("cargo", "build", "--release", "-p", "kosh-party")
	cmd.Dir = root
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("cargo build kosh-party: %v", err)
	}
	return root + "/target/release/kosh-party"
}

// startBin starts a pre-built binary with the given env (no compilation step).
func startBin(t *testing.T, binPath string, env []string) *proc {
	t.Helper()
	cmd := exec.Command(binPath)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", binPath, err)
	}
	t.Cleanup(func() { cmd.Process.Kill() })
	return &proc{cmd}
}

func buildAndStart(t *testing.T, dir, bin string, env []string) *proc {
	t.Helper()
	binPath := t.TempDir() + "/" + bin
	build := exec.Command("go", "build", "-o", binPath, "./cmd/"+bin)
	build.Dir = dir
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build %s: %v", bin, err)
	}
	cmd := exec.Command(binPath)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", bin, err)
	}
	t.Cleanup(func() { cmd.Process.Kill() })
	return &proc{cmd}
}

// ─── Test setup ───────────────────────────────────────────────────────────────

type testEnv struct {
	baseURL string
	token   string
	client  *http.Client
}

func startAll(t *testing.T) *testEnv {
	t.Helper()

	coordPort := freePort()
	policyPort := freePort()
	p1Port := freePort()
	p2Port := freePort()
	p3Port := freePort()
	gwPort := freePort()

	coordDir := "../kosh-coordinator"
	policyDir := "../kosh-policy"
	partyDir := "../kosh-party" // Rust crate — built via cargo, not go build
	gwDir := "."
	_ = gwDir

	// Start coordinator
	buildAndStart(t, coordDir, "coordinator", []string{fmt.Sprintf("PORT=%d", coordPort)})
	if err := waitTCP(fmt.Sprintf("localhost:%d", coordPort), 8*time.Second); err != nil {
		t.Fatal(err)
	}

	// Start policy
	buildAndStart(t, policyDir, "policy", []string{
		fmt.Sprintf("PORT=%d", policyPort),
		"POLICY_FILE=",
	})
	if err := waitTCP(fmt.Sprintf("localhost:%d", policyPort), 8*time.Second); err != nil {
		t.Fatal(err)
	}

	// Build kosh-party Rust binary once then start 3 instances
	partyBin := buildPartyBin(t, partyDir)
	coordAddr := fmt.Sprintf("http://localhost:%d", coordPort)
	for i, port := range []int{p1Port, p2Port, p3Port} {
		startBin(t, partyBin, []string{
			fmt.Sprintf("PORT=%d", port),
			fmt.Sprintf("PARTY_INDEX=%d", i+1),
			"NUM_PARTIES=3",
			fmt.Sprintf("COORDINATOR_ADDR=%s", coordAddr),
			"KEYSTORE_ADDR=http://localhost:50070",
			"PQC_ADDR=http://localhost:50080",
			"CHAIN_RELAY_ADDR=http://localhost:50053",
			"RUST_LOG=error",
		})
		if err := waitTCP(fmt.Sprintf("localhost:%d", port), 10*time.Second); err != nil {
			t.Fatal(err)
		}
	}

	// Start gateway
	buildAndStart(t, ".", "gateway", []string{
		fmt.Sprintf("PORT=%d", gwPort),
		"JWT_SECRET=test-secret",
		fmt.Sprintf("COORDINATOR_ADDR=localhost:%d", coordPort),
		fmt.Sprintf("POLICY_ADDR=localhost:%d", policyPort),
		fmt.Sprintf("PARTY_1_ADDR=localhost:%d", p1Port),
		fmt.Sprintf("PARTY_2_ADDR=localhost:%d", p2Port),
		fmt.Sprintf("PARTY_3_ADDR=localhost:%d", p3Port),
	})
	baseURL := fmt.Sprintf("http://localhost:%d", gwPort)
	if err := waitHTTP(baseURL+"/api/v1/health", 8*time.Second); err != nil {
		t.Fatal(err)
	}

	// Get a JWT token
	req, _ := http.NewRequest("POST", baseURL+"/api/v1/token", nil)
	req.Header.Set("X-API-Key", "test-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer resp.Body.Close()
	var tokResp map[string]string
	json.NewDecoder(resp.Body).Decode(&tokResp)
	token := tokResp["token"]
	if token == "" {
		t.Fatal("no token returned")
	}

	return &testEnv{
		baseURL: baseURL,
		token:   token,
		client:  &http.Client{Timeout: 60 * time.Second},
	}
}

func (e *testEnv) do(method, path string, body any) *http.Response {
	var bodyReader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.baseURL+path, bodyReader)
	req.Header.Set("Authorization", "Bearer "+e.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		panic(err)
	}
	return resp
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestGateway_Health(t *testing.T) {
	gwPort := freePort()
	coordPort := freePort()
	policyPort := freePort()

	buildAndStart(t, "../kosh-coordinator", "coordinator", []string{fmt.Sprintf("PORT=%d", coordPort)})
	waitTCP(fmt.Sprintf("localhost:%d", coordPort), 8*time.Second)
	buildAndStart(t, "../kosh-policy", "policy", []string{fmt.Sprintf("PORT=%d", policyPort), "POLICY_FILE="})
	waitTCP(fmt.Sprintf("localhost:%d", policyPort), 8*time.Second)

	buildAndStart(t, ".", "gateway", []string{
		fmt.Sprintf("PORT=%d", gwPort),
		"JWT_SECRET=test-secret",
		fmt.Sprintf("COORDINATOR_ADDR=localhost:%d", coordPort),
		fmt.Sprintf("POLICY_ADDR=localhost:%d", policyPort),
		// Dummy party addresses — not used for health check
		"PARTY_1_ADDR=localhost:9991",
		"PARTY_2_ADDR=localhost:9992",
		"PARTY_3_ADDR=localhost:9993",
	})
	baseURL := fmt.Sprintf("http://localhost:%d", gwPort)
	if err := waitHTTP(baseURL+"/api/v1/health", 8*time.Second); err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get(baseURL + "/api/v1/health")
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
		t.Fatalf("unexpected health body: %v", body)
	}
	t.Log("Health OK")
}

func TestGateway_TokenIssueAndAuth(t *testing.T) {
	gwPort := freePort()
	coordPort := freePort()
	policyPort := freePort()

	buildAndStart(t, "../kosh-coordinator", "coordinator", []string{fmt.Sprintf("PORT=%d", coordPort)})
	waitTCP(fmt.Sprintf("localhost:%d", coordPort), 8*time.Second)
	buildAndStart(t, "../kosh-policy", "policy", []string{fmt.Sprintf("PORT=%d", policyPort), "POLICY_FILE="})
	waitTCP(fmt.Sprintf("localhost:%d", policyPort), 8*time.Second)

	buildAndStart(t, ".", "gateway", []string{
		fmt.Sprintf("PORT=%d", gwPort),
		"JWT_SECRET=test-secret",
		fmt.Sprintf("COORDINATOR_ADDR=localhost:%d", coordPort),
		fmt.Sprintf("POLICY_ADDR=localhost:%d", policyPort),
		"PARTY_1_ADDR=localhost:9991",
		"PARTY_2_ADDR=localhost:9992",
		"PARTY_3_ADDR=localhost:9993",
	})
	baseURL := fmt.Sprintf("http://localhost:%d", gwPort)
	waitHTTP(baseURL+"/api/v1/health", 8*time.Second)

	// Get token
	req, _ := http.NewRequest("POST", baseURL+"/api/v1/token", nil)
	req.Header.Set("X-API-Key", "mykey")
	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	var tok map[string]string
	json.NewDecoder(resp.Body).Decode(&tok)
	if tok["token"] == "" {
		t.Fatal("no token")
	}
	t.Logf("Token issued: %s...", tok["token"][:20])

	// Access protected endpoint with token
	req2, _ := http.NewRequest("GET", baseURL+"/api/v1/policies", nil)
	req2.Header.Set("Authorization", "Bearer "+tok["token"])
	resp2, _ := http.DefaultClient.Do(req2)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("policies with valid token: got %d", resp2.StatusCode)
	}

	// Access without token — must get 401
	resp3, _ := http.Get(baseURL + "/api/v1/policies")
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", resp3.StatusCode)
	}
	t.Log("JWT auth OK: protected route returns 401 without token, 200 with token")
}

func TestGateway_PolicyCRUD(t *testing.T) {
	gwPort := freePort()
	coordPort := freePort()
	policyPort := freePort()

	buildAndStart(t, "../kosh-coordinator", "coordinator", []string{fmt.Sprintf("PORT=%d", coordPort)})
	waitTCP(fmt.Sprintf("localhost:%d", coordPort), 8*time.Second)
	buildAndStart(t, "../kosh-policy", "policy", []string{fmt.Sprintf("PORT=%d", policyPort), "POLICY_FILE="})
	waitTCP(fmt.Sprintf("localhost:%d", policyPort), 8*time.Second)

	buildAndStart(t, ".", "gateway", []string{
		fmt.Sprintf("PORT=%d", gwPort),
		"JWT_SECRET=test-secret",
		fmt.Sprintf("COORDINATOR_ADDR=localhost:%d", coordPort),
		fmt.Sprintf("POLICY_ADDR=localhost:%d", policyPort),
		"PARTY_1_ADDR=localhost:9991",
		"PARTY_2_ADDR=localhost:9992",
		"PARTY_3_ADDR=localhost:9993",
	})
	baseURL := fmt.Sprintf("http://localhost:%d", gwPort)
	waitHTTP(baseURL+"/api/v1/health", 8*time.Second)

	// Get token
	req, _ := http.NewRequest("POST", baseURL+"/api/v1/token", nil)
	req.Header.Set("X-API-Key", "k")
	resp, _ := http.DefaultClient.Do(req)
	var tok map[string]string
	json.NewDecoder(resp.Body).Decode(&tok)
	resp.Body.Close()

	env := &testEnv{baseURL: baseURL, token: tok["token"], client: &http.Client{Timeout: 30 * time.Second}}

	// POST /api/v1/policies
	addResp := env.do("POST", "/api/v1/policies", map[string]any{
		"name":              "cfo-required",
		"tx_tag":            "treasury",
		"mandatory_parties": []int{2},
		"min_threshold":     2,
	})
	defer addResp.Body.Close()
	if addResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(addResp.Body)
		t.Fatalf("add policy: %d %s", addResp.StatusCode, body)
	}
	var addBody map[string]any
	json.NewDecoder(addResp.Body).Decode(&addBody)
	policyID := addBody["id"]
	t.Logf("POST /api/v1/policies → id=%v", policyID)

	// GET /api/v1/policies
	listResp := env.do("GET", "/api/v1/policies", nil)
	defer listResp.Body.Close()
	var listBody map[string]any
	json.NewDecoder(listResp.Body).Decode(&listBody)
	policies := listBody["policies"].([]any)
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	t.Logf("GET /api/v1/policies → %d policies", len(policies))

	// DELETE /api/v1/policies/:id
	delResp := env.do("DELETE", fmt.Sprintf("/api/v1/policies/%v", policyID), nil)
	defer delResp.Body.Close()
	if delResp.StatusCode != http.StatusOK {
		t.Fatalf("delete policy: %d", delResp.StatusCode)
	}
	t.Log("DELETE /api/v1/policies OK")
}

func TestGateway_DKGEndToEnd(t *testing.T) {
	env := startAll(t)

	resp := env.do("POST", "/api/v1/keys", map[string]any{
		"key_id":      42,
		"num_parties": 3,
		"threshold":   2,
	})
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DKG: got %d: %s", resp.StatusCode, body)
	}

	var result map[string]any
	json.Unmarshal(body, &result)
	if result["status"] != "complete" {
		t.Fatalf("DKG status not complete: %v", result)
	}
	pk := result["combined_pk_hex"].(string)
	if len(pk) == 0 {
		t.Fatal("combined_pk_hex empty")
	}
	t.Logf("POST /api/v1/keys → combined_pk=%s...", pk[:10])
}
