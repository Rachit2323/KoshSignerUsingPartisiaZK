#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Kosh Signer — single-command launcher
#  Usage: bash start.sh
#  All service logs print to the terminal AND are saved to ./logs/
# ─────────────────────────────────────────────────────────────────────────────
set -eo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

# ── Hardcoded config ──────────────────────────────────────────────────────────
SIGNER_ADDRESS="0353980c937b95faac89ee9af366471b64d9206f2e"
PARTISIA_KEY="cea538ce0bc3b7f4bcbb3bbea6eb2d26d76c9ddeab77938128ffb46828d42822"
PARTISIA_ADDR="0070df8630bd853487c025e6e2b0eac733aa79481d"
KEYSTORE_MASTER_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
KEYSTORE_DIR="$ROOT/.kosh-shares"
PARTISIA_NODE_URLS="https://node1.testnet.partisiablockchain.com,https://node2.testnet.partisiablockchain.com,https://node3.testnet.partisiablockchain.com,https://node4.testnet.partisiablockchain.com"
LOG_DIR="$ROOT/logs"

# ── Colors ────────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

klog() { echo -e "${BOLD}[kosh]${RESET} $*"; }
ok()   { echo -e "${GREEN}  ✓ $*${RESET}"; }
inf()  { echo -e "${CYAN}  → $*${RESET}"; }

# ── Cleanup: kill entire process group ───────────────────────────────────────
cleanup() {
  echo ""
  klog "Shutting down all services..."
  trap - INT TERM EXIT
  kill -- -$$ 2>/dev/null || true
  wait 2>/dev/null || true
  klog "All stopped."
}
trap cleanup INT TERM EXIT

# ── Kill stale processes on kosh ports ───────────────────────────────────────
klog "Killing stale processes on kosh ports..."
for port in 50051 50052 50053 50060 50061 50062 8080 9090 5173; do
  pids=$(lsof -ti tcp:"$port" 2>/dev/null || true)
  if [ -n "$pids" ]; then
    echo "$pids" | xargs kill -9 2>/dev/null || true
    inf "Killed stale process on :$port"
  fi
done
sleep 1

# ── Build Rust binaries ───────────────────────────────────────────────────────
klog "Building Rust binaries..."
cargo build -p kosh-chain-relay -p kosh-party 2>&1 | tail -3
ok "Rust build done"

# ── Prepare log directory ─────────────────────────────────────────────────────
mkdir -p "$LOG_DIR"
klog "Logs → $LOG_DIR/"

# ── Helper: start a service, print prefixed output AND save to log file ───────
start_service() {
  local label="$1"
  local color="$2"
  shift 2
  local log="$LOG_DIR/${label}.log"
  # Run service; tee to log file; prefix each line with colored label on terminal
  { "$@" 2>&1 | tee "$log" | awk -v lbl="$label" -v c="$color" -v r="$RESET" \
      '{ print c"["lbl"]"r" "$0; fflush() }'; } &
  inf "$label started → $log"
}

# ── 1. Coordinator ────────────────────────────────────────────────────────────
klog "[1/8] kosh-coordinator :50051"
start_service "coord" "\033[0;34m" \
  bash -c "cd '$ROOT/services/kosh-coordinator' && go run ./cmd/coordinator"
sleep 1

# ── 2. Policy ─────────────────────────────────────────────────────────────────
klog "[2/8] kosh-policy :50052"
start_service "policy" "\033[0;35m" \
  bash -c "cd '$ROOT/services/kosh-policy' && go run ./cmd/policy"
sleep 1

# ── 3. Chain Relay ────────────────────────────────────────────────────────────
klog "[3/8] kosh-chain-relay :50053"
start_service "relay" "\033[0;33m" \
  bash -c "
    export RUST_LOG=info
    export PARTISIA_NODE_URLS='$PARTISIA_NODE_URLS'
    export PARTISIA_SENDER_KEY_1='$PARTISIA_KEY'
    export PARTISIA_SENDER_ADDRESS_1='$PARTISIA_ADDR'
    export PARTISIA_SENDER_KEY_2='$PARTISIA_KEY'
    export PARTISIA_SENDER_ADDRESS_2='$PARTISIA_ADDR'
    export PARTISIA_SENDER_KEY_3='$PARTISIA_KEY'
    export PARTISIA_SENDER_ADDRESS_3='$PARTISIA_ADDR'
    '$ROOT/target/debug/kosh-chain-relay'
  "
sleep 1

# ── 4. Party 1 ────────────────────────────────────────────────────────────────
klog "[4/8] kosh-party 1 :50060"
start_service "party1" "\033[0;36m" \
  bash -c "
    export RUST_LOG=info PARTY_INDEX=1 PORT=50060
    export COORDINATOR_ADDR='http://localhost:50051'
    export CHAIN_RELAY_ADDR='http://localhost:50053'
    export SIGNER_ADDRESS='$SIGNER_ADDRESS'
    export PARTISIA_SENDER_ADDRESS='$PARTISIA_ADDR'
    export KEYSTORE_DIR='$KEYSTORE_DIR'
    export KEYSTORE_MASTER_KEY='$KEYSTORE_MASTER_KEY'
    '$ROOT/target/debug/kosh-party'
  "
sleep 0.5

# ── 5. Party 2 ────────────────────────────────────────────────────────────────
klog "[5/8] kosh-party 2 :50061"
start_service "party2" "\033[0;36m" \
  bash -c "
    export RUST_LOG=info PARTY_INDEX=2 PORT=50061
    export COORDINATOR_ADDR='http://localhost:50051'
    export CHAIN_RELAY_ADDR='http://localhost:50053'
    export SIGNER_ADDRESS='$SIGNER_ADDRESS'
    export PARTISIA_SENDER_ADDRESS='$PARTISIA_ADDR'
    export KEYSTORE_DIR='$KEYSTORE_DIR'
    export KEYSTORE_MASTER_KEY='$KEYSTORE_MASTER_KEY'
    '$ROOT/target/debug/kosh-party'
  "
sleep 0.5

# ── 6. Party 3 ────────────────────────────────────────────────────────────────
klog "[6/8] kosh-party 3 :50062"
start_service "party3" "\033[0;36m" \
  bash -c "
    export RUST_LOG=info PARTY_INDEX=3 PORT=50062
    export COORDINATOR_ADDR='http://localhost:50051'
    export CHAIN_RELAY_ADDR='http://localhost:50053'
    export SIGNER_ADDRESS='$SIGNER_ADDRESS'
    export PARTISIA_SENDER_ADDRESS='$PARTISIA_ADDR'
    export KEYSTORE_DIR='$KEYSTORE_DIR'
    export KEYSTORE_MASTER_KEY='$KEYSTORE_MASTER_KEY'
    '$ROOT/target/debug/kosh-party'
  "
sleep 1

# ── 7. Gateway ────────────────────────────────────────────────────────────────
klog "[7/8] kosh-gateway :8080"
start_service "gateway" "\033[0;32m" \
  bash -c "
    export PORT=8080
    export COORDINATOR_ADDR='localhost:50051'
    export POLICY_ADDR='localhost:50052'
    export PARTY_1_ADDR='localhost:50060'
    export PARTY_2_ADDR='localhost:50061'
    export PARTY_3_ADDR='localhost:50062'
    export WEBAUTHN_RP_ID='localhost'
    export WEBAUTHN_ORIGIN='http://localhost:5173'
    export JWT_SECRET='dev-secret-change-in-production'
    cd '$ROOT/services/kosh-gateway' && go run ./cmd/gateway
  "
sleep 1

# ── 8. Frontend ───────────────────────────────────────────────────────────────
klog "[8/8] frontend :5173"
start_service "vite" "\033[1;37m" \
  bash -c "cd '$ROOT/frontend' && npm run dev"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Kosh Signer is running!${RESET}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════════${RESET}"
echo -e "  ${CYAN}Frontend →${RESET} http://localhost:5173"
echo -e "  ${CYAN}Gateway  →${RESET} http://localhost:8080"
echo -e "  ${CYAN}Logs     →${RESET} $LOG_DIR/"
echo ""
echo -e "  Press ${BOLD}Ctrl+C${RESET} to stop everything."
echo ""

wait
