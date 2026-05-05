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
pkill -f "kosh-chain-relay" 2>/dev/null || true
lsof -ti:50051,50052,50053,50060,50061,50062,8080,9090 2>/dev/null | xargs kill -9 2>/dev/null || true
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
  pkill -f "kosh-chain-relay" 2>/dev/null || true
  lsof -ti:50051,50052,50053,50060,50061,50062,8080,9090 2>/dev/null | xargs kill -9 2>/dev/null || true
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

# ── kosh-chain-relay (Partisia blockchain client) ─────────────────────────────
RELAY_BIN="$REPO/target/release/kosh-chain-relay"
if [ ! -f "$RELAY_BIN" ]; then
  echo "Building kosh-chain-relay (first run)..."
  (cd "$REPO" && cargo build -p kosh-chain-relay --release 2>&1 | tail -3)
fi

echo "[5/9] kosh-chain-relay  (gRPC :50053)"
SIGNER_ADDRESS="${SIGNER_ADDRESS:-03a1e8aba3ba45c1e42d01f688768436cb2b572de0}" \
PARTISIA_SENDER_KEY="${PARTISIA_SENDER_KEY:-}" \
PARTISIA_SENDER_ADDRESS="${PARTISIA_SENDER_ADDRESS:-}" \
PORT=50053 "$RELAY_BIN" 2>&1 | sed 's/^/[relay] /' &

sleep 1

# ── Party shared config ────────────────────────────────────────────────────────
# KEYSTORE_MASTER_KEY: 64 hex chars (32 bytes). Generates one if not set.
if [ -z "$KEYSTORE_MASTER_KEY" ]; then
  KEYSTORE_MASTER_KEY=$(openssl rand -hex 32)
  echo "  Generated KEYSTORE_MASTER_KEY=$KEYSTORE_MASTER_KEY (set as env var to persist)"
fi

PARTY_COMMON="COORDINATOR_ADDR=http://localhost:50051 \
  CHAIN_RELAY_ADDR=http://localhost:50053 \
  SIGNER_ADDRESS=${SIGNER_ADDRESS:-} \
  KEYSTORE_DIR=$REPO/.kosh-shares \
  KEYSTORE_MASTER_KEY=$KEYSTORE_MASTER_KEY"

echo "[6/9] kosh-party #1     (gRPC :50060)"
eval "PARTY_INDEX=1 PORT=50060 $PARTY_COMMON '$PARTY_BIN'" 2>&1 | sed 's/^/[party1] /' &

echo "[7/9] kosh-party #2     (gRPC :50061)"
eval "PARTY_INDEX=2 PORT=50061 $PARTY_COMMON '$PARTY_BIN'" 2>&1 | sed 's/^/[party2] /' &

echo "[8/9] kosh-party #3     (gRPC :50062)"
eval "PARTY_INDEX=3 PORT=50062 $PARTY_COMMON '$PARTY_BIN'" 2>&1 | sed 's/^/[party3] /' &

sleep 2  # wait for all backend services before Vite starts

# ── Frontend ──────────────────────────────────────────────────────────────────
echo "[9/9] frontend          (Vite  http://localhost:5173)"
(cd "$REPO/frontend" && npx vite 2>&1 | sed 's/^/[vite] /') &

echo ""
echo "=== All services started ==="
echo "    Frontend: http://localhost:5173"
echo "    Gateway:  http://localhost:8080/api/v1/health"
echo "    Metrics:  http://localhost:9090/metrics"
echo ""

wait
