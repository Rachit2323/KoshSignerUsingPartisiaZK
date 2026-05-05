#!/bin/bash
# Run all KoshSigner microservices + frontend dev server locally.
# Usage: bash run-local.sh
set -e

REPO="$(cd "$(dirname "$0")" && pwd)"
SERVICES="$REPO/services"

echo "=== Starting KoshSigner locally ==="
echo "    Press Ctrl+C to stop all processes."
echo ""

cleanup() {
  echo ""
  echo "=== Shutting down... ==="
  kill $(jobs -p) 2>/dev/null
  wait
  echo "All stopped."
}
trap cleanup EXIT INT TERM

# ── Go services ───────────────────────────────────────────────────────────────
echo "[1/8] kosh-coordinator  (gRPC :50051)"
(cd "$SERVICES/kosh-coordinator" && go run ./cmd/coordinator) &

sleep 1  # Give coordinator a head start before policy connects

echo "[2/8] kosh-policy       (gRPC :50052)"
(cd "$SERVICES/kosh-policy" && go run ./cmd/policy) &

echo "[3/8] kosh-monitor      (HTTP :9090)"
(cd "$SERVICES/kosh-monitor" && go run ./cmd/monitor) &

echo "[4/8] kosh-gateway      (HTTP :8080)"
(cd "$SERVICES/kosh-gateway" && go run ./cmd/gateway) &

# ── Rust party daemons ────────────────────────────────────────────────────────
echo "[5/8] kosh-party #1     (gRPC :50060)"
(cd "$REPO" && PARTY_ID=1 PARTY_PORT=50060 COORD_ADDR=localhost:50051 cargo run -p kosh-party --release 2>&1) &

echo "[6/8] kosh-party #2     (gRPC :50061)"
(cd "$REPO" && PARTY_ID=2 PARTY_PORT=50061 COORD_ADDR=localhost:50051 cargo run -p kosh-party --release 2>&1) &

echo "[7/8] kosh-party #3     (gRPC :50062)"
(cd "$REPO" && PARTY_ID=3 PARTY_PORT=50062 COORD_ADDR=localhost:50051 cargo run -p kosh-party --release 2>&1) &

sleep 3  # Wait for backend services before starting the UI

# ── Frontend ──────────────────────────────────────────────────────────────────
echo "[8/8] frontend          (Vite  http://localhost:5173)"
(cd "$REPO/frontend" && npm run dev) &

echo ""
echo "=== All services started ==="
echo "    Frontend: http://localhost:5173"
echo "    Gateway:  http://localhost:8080/api/v1/health"
echo "    Metrics:  http://localhost:9090/metrics"
echo ""

wait
