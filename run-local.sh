#!/bin/bash
# Run all KoshSigner microservices + frontend dev server locally.
# Usage: bash run-local.sh
set -e

REPO="$(cd "$(dirname "$0")" && pwd)"
SERVICES="$REPO/services"

echo "=== Starting KoshSigner locally ==="
echo "    Press Ctrl+C to stop all processes."
echo ""

# ── Kill any leftover processes on our ports ──────────────────────────────────
echo "Clearing old processes on ports 50051 50052 50060 50061 50062 8080 9090..."
pkill -f "kosh-party" 2>/dev/null || true
pkill -f "kosh-coordinator" 2>/dev/null || true
pkill -f "kosh-policy" 2>/dev/null || true
pkill -f "kosh-gateway" 2>/dev/null || true
pkill -f "kosh-monitor" 2>/dev/null || true
lsof -ti:50051,50052,50060,50061,50062,8080,9090 2>/dev/null | xargs kill -9 2>/dev/null || true
sleep 2

cleanup() {
  echo ""
  echo "=== Shutting down... ==="
  kill $(jobs -p) 2>/dev/null || true
  pkill -f "kosh-party" 2>/dev/null || true
  pkill -f "kosh-coordinator" 2>/dev/null || true
  pkill -f "kosh-gateway" 2>/dev/null || true
  pkill -f "kosh-policy" 2>/dev/null || true
  pkill -f "kosh-monitor" 2>/dev/null || true
  lsof -ti:50051,50052,50060,50061,50062,8080,9090 2>/dev/null | xargs kill -9 2>/dev/null || true
  wait 2>/dev/null || true
  echo "All stopped."
}
trap cleanup EXIT INT TERM

# ── Install frontend deps if needed ──────────────────────────────────────────
if [ ! -d "$REPO/frontend/node_modules" ]; then
  echo "Installing frontend dependencies..."
  (cd "$REPO/frontend" && npm install --silent)
fi

# ── Go services ───────────────────────────────────────────────────────────────
echo "[1/8] kosh-coordinator  (gRPC :50051)"
(cd "$SERVICES/kosh-coordinator" && go run ./cmd/coordinator 2>&1 | sed 's/^/[coord] /') &

sleep 1  # coordinator must be up before policy connects

echo "[2/8] kosh-policy       (gRPC :50052)"
(cd "$SERVICES/kosh-policy" && go run ./cmd/policy 2>&1 | sed 's/^/[policy] /') &

echo "[3/8] kosh-monitor      (HTTP :9090)"
(cd "$SERVICES/kosh-monitor" && go run ./cmd/monitor 2>&1 | sed 's/^/[monitor] /') &

echo "[4/8] kosh-gateway      (HTTP :8080)"
(cd "$SERVICES/kosh-gateway" && go run ./cmd/gateway 2>&1 | sed 's/^/[gateway] /') &

sleep 1  # let gateway bind before starting parties

# ── Rust party daemons (already compiled — use pre-built binary) ──────────────
PARTY_BIN="$REPO/target/release/kosh-party"
if [ ! -f "$PARTY_BIN" ]; then
  echo "Building kosh-party (first run — takes ~60s)..."
  (cd "$REPO" && cargo build -p kosh-party --release 2>&1 | tail -3)
fi

echo "[5/8] kosh-party #1     (gRPC :50060)"
PARTY_INDEX=1 PORT=50060 COORDINATOR_ADDR=http://localhost:50051 "$PARTY_BIN" 2>&1 | sed 's/^/[party1] /' &

echo "[6/8] kosh-party #2     (gRPC :50061)"
PARTY_INDEX=2 PORT=50061 COORDINATOR_ADDR=http://localhost:50051 "$PARTY_BIN" 2>&1 | sed 's/^/[party2] /' &

echo "[7/8] kosh-party #3     (gRPC :50062)"
PARTY_INDEX=3 PORT=50062 COORDINATOR_ADDR=http://localhost:50051 "$PARTY_BIN" 2>&1 | sed 's/^/[party3] /' &

sleep 2  # wait for all backend services before Vite starts

# ── Frontend ──────────────────────────────────────────────────────────────────
echo "[8/8] frontend          (Vite  http://localhost:5173)"
(cd "$REPO/frontend" && npx vite 2>&1 | sed 's/^/[vite] /') &

echo ""
echo "=== All services started ==="
echo "    Frontend: http://localhost:5173"
echo "    Gateway:  http://localhost:8080/api/v1/health"
echo "    Metrics:  http://localhost:9090/metrics"
echo ""

wait
