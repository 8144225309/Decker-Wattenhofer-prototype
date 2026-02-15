#!/bin/bash
# tools/run_demo.sh — SuperScalar Full Lifecycle Demo
#
# Comprehensive demo runner that walks through the SuperScalar protocol
# with colored, annotated output. Starts bitcoind if needed.
#
# Usage:
#   bash tools/run_demo.sh              # default: --basic
#   bash tools/run_demo.sh --basic      # factory creation + payments + close
#   bash tools/run_demo.sh --breach     # + broadcast revoked commitment → penalty
#   bash tools/run_demo.sh --rotation   # + full factory rotation (Factory 0 → 1)
#   bash tools/run_demo.sh --all        # run all demos sequentially
#   bash tools/run_demo.sh --dashboard  # launch dashboard after demo

set -e

# ---------------------------------------------------------------------------
# Color definitions
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
banner() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}  ${BOLD}$1${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

step() {
    echo -e "  ${YELLOW}▶${NC} ${BOLD}$1${NC}"
}

explain() {
    echo ""
    while IFS= read -r line; do
        echo -e "    ${CYAN}${line}${NC}"
    done <<< "$1"
    echo ""
}

ok() {
    echo -e "  ${GREEN}✓${NC} $1"
}

fail() {
    echo -e "  ${RED}✗${NC} $1"
}

wait_for_pid() {
    local pid=$1 label=$2
    local dots=0
    while kill -0 "$pid" 2>/dev/null; do
        dots=$((dots + 1))
        if [ $((dots % 4)) -eq 0 ]; then
            printf "\r  ${DIM}  waiting for %s%s${NC}   " "$label" "$(printf '.%.0s' $(seq 1 $((dots / 4 % 4 + 1))))"
        fi
        sleep 1
    done
    printf "\r                                              \r"
    wait "$pid" 2>/dev/null
    return $?
}

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/../build"
export LD_LIBRARY_PATH="$BUILD_DIR/_deps/secp256k1-zkp-build/src:$BUILD_DIR/_deps/cjson-build"

LSP_BIN="$BUILD_DIR/superscalar_lsp"
CLIENT_BIN="$BUILD_DIR/superscalar_client"

PORT=9735
AMOUNT=100000

CLIENT1_KEY="2222222222222222222222222222222222222222222222222222222222222222"
CLIENT2_KEY="3333333333333333333333333333333333333333333333333333333333333333"
CLIENT3_KEY="4444444444444444444444444444444444444444444444444444444444444444"
CLIENT4_KEY="5555555555555555555555555555555555555555555555555555555555555555"

PIDS=()
STARTED_BITCOIND=0

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
MODE_BASIC=0; MODE_BREACH=0; MODE_ROTATION=0; LAUNCH_DASHBOARD=0

if [ $# -eq 0 ]; then
    MODE_BASIC=1
fi

for arg in "$@"; do
    case $arg in
        --basic)     MODE_BASIC=1 ;;
        --breach)    MODE_BREACH=1 ;;
        --rotation)  MODE_ROTATION=1 ;;
        --all)       MODE_BASIC=1; MODE_BREACH=1; MODE_ROTATION=1 ;;
        --dashboard) LAUNCH_DASHBOARD=1 ;;
        --help|-h)
            echo "Usage: bash tools/run_demo.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --basic       Factory creation + payments + close (default)"
            echo "  --breach      Revoked commitment broadcast → penalty TX"
            echo "  --rotation    Full factory rotation (Factory 0 → Factory 1)"
            echo "  --all         Run all demos sequentially"
            echo "  --dashboard   Launch web dashboard after demo"
            echo "  --help        Show this help"
            exit 0 ;;
        *)
            echo "Unknown option: $arg (try --help)"
            exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
cleanup() {
    echo ""
    step "Cleaning up..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    if [ "$STARTED_BITCOIND" = "1" ]; then
        bitcoin-cli -regtest stop 2>/dev/null || true
        ok "Stopped bitcoind"
    fi
    ok "Cleanup complete"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Splash
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}${BLUE}"
echo "  ╔═══════════════════════════════════════════════════════════╗"
echo "  ║   SuperScalar — Full Lifecycle Demo                      ║"
echo "  ║   First Implementation of ZmnSCPxj's Design              ║"
echo "  ╠═══════════════════════════════════════════════════════════╣"
echo "  ║   Protocol:  N+1-of-N+1 MuSig2 + Decker-Wattenhofer     ║"
echo "  ║   Parties:   1 LSP + 4 clients (5-of-5 factory)          ║"
echo "  ║   Funding:   ${AMOUNT} sats on-chain                       ║"
echo "  ╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

MODES=""
[ "$MODE_BASIC" = "1" ] && MODES="${MODES} basic"
[ "$MODE_BREACH" = "1" ] && MODES="${MODES} breach"
[ "$MODE_ROTATION" = "1" ] && MODES="${MODES} rotation"
echo -e "  ${DIM}Demos:${NC}${BOLD}${MODES}${NC}"
echo ""

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
banner "Pre-flight Checks"

if [ ! -f "$LSP_BIN" ] || [ ! -f "$CLIENT_BIN" ]; then
    fail "Binaries not found at $BUILD_DIR"
    echo "  Build first: cd build && cmake .. && make -j\$(nproc)"
    exit 1
fi
ok "Binaries found"

if ! command -v bitcoin-cli >/dev/null 2>&1; then
    fail "bitcoin-cli not in PATH"
    exit 1
fi
ok "bitcoin-cli available"

# ---------------------------------------------------------------------------
# Start bitcoind if needed
# ---------------------------------------------------------------------------
if ! bitcoin-cli -regtest getblockchaininfo >/dev/null 2>&1; then
    step "Starting bitcoind -regtest..."
    bitcoind -regtest -daemon -fallbackfee=0.00001 -txindex=1 2>/dev/null
    STARTED_BITCOIND=1
    sleep 2
    if ! bitcoin-cli -regtest getblockchaininfo >/dev/null 2>&1; then
        fail "Could not start bitcoind"
        exit 1
    fi
    ok "bitcoind started"
else
    ok "bitcoind already running"
fi

# Ensure wallet exists
if ! bitcoin-cli -regtest -rpcwallet=superscalar_lsp getbalance >/dev/null 2>&1; then
    bitcoin-cli -regtest createwallet superscalar_lsp >/dev/null 2>&1 || true
    ok "Created wallet 'superscalar_lsp'"
fi

# Fund wallet if needed
BALANCE=$(bitcoin-cli -regtest -rpcwallet=superscalar_lsp getbalance 2>/dev/null || echo "0")
if [ "$(echo "$BALANCE < 1" | bc 2>/dev/null || echo 1)" = "1" ]; then
    step "Funding wallet..."
    ADDR=$(bitcoin-cli -regtest -rpcwallet=superscalar_lsp getnewaddress 2>/dev/null)
    bitcoin-cli -regtest generatetoaddress 101 "$ADDR" >/dev/null 2>&1
    ok "Mined 101 blocks, wallet funded"
fi

# ---------------------------------------------------------------------------
# Helper: run a single demo scenario
# ---------------------------------------------------------------------------
run_lsp_clients() {
    local lsp_flags="$1"
    local label="$2"
    local lsp_pid c1_pid c2_pid c3_pid c4_pid

    step "Starting LSP: $LSP_BIN --regtest --port $PORT --clients 4 --amount $AMOUNT $lsp_flags"
    $LSP_BIN --regtest --port $PORT --clients 4 --amount $AMOUNT $lsp_flags &
    lsp_pid=$!
    PIDS+=($lsp_pid)
    sleep 2

    step "Starting 4 clients..."
    $CLIENT_BIN --seckey $CLIENT1_KEY --port $PORT --daemon &
    c1_pid=$!; PIDS+=($c1_pid); sleep 0.3
    $CLIENT_BIN --seckey $CLIENT2_KEY --port $PORT --daemon &
    c2_pid=$!; PIDS+=($c2_pid); sleep 0.3
    $CLIENT_BIN --seckey $CLIENT3_KEY --port $PORT --daemon &
    c3_pid=$!; PIDS+=($c3_pid); sleep 0.3
    $CLIENT_BIN --seckey $CLIENT4_KEY --port $PORT --daemon &
    c4_pid=$!; PIDS+=($c4_pid)

    wait_for_pid "$lsp_pid" "$label"
    local exit_code=$?

    # Clean up clients
    kill $c1_pid $c2_pid $c3_pid $c4_pid 2>/dev/null || true
    wait $c1_pid $c2_pid $c3_pid $c4_pid 2>/dev/null || true

    # Remove from PIDS array
    PIDS=("${PIDS[@]/$lsp_pid}")
    PIDS=("${PIDS[@]/$c1_pid}")
    PIDS=("${PIDS[@]/$c2_pid}")
    PIDS=("${PIDS[@]/$c3_pid}")
    PIDS=("${PIDS[@]/$c4_pid}")

    return $exit_code
}

TOTAL_PASS=0; TOTAL_FAIL=0

# ---------------------------------------------------------------------------
# Demo 1: Basic — Factory + Payments + Close
# ---------------------------------------------------------------------------
if [ "$MODE_BASIC" = "1" ]; then
    banner "Demo: Basic Factory Lifecycle"

    explain "This demo creates a 5-of-5 MuSig2 channel factory with 1 LSP and
4 clients. The factory is funded with a single on-chain transaction,
4 channels are established inside it, payments flow between clients
(with real SHA256 preimage validation), and finally the factory is
cooperatively closed with a single on-chain transaction.

Factory creation takes 3 round-trips:
  PROPOSE → NONCES → PSIGS → READY"

    if run_lsp_clients "--demo" "basic demo"; then
        ok "Basic demo completed successfully"
        TOTAL_PASS=$((TOTAL_PASS + 1))
    else
        fail "Basic demo failed (exit code: $?)"
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
    fi

    # Mine a block to confirm the close tx
    bitcoin-cli -regtest generatetoaddress 1 "$(bitcoin-cli -regtest -rpcwallet=superscalar_lsp getnewaddress 2>/dev/null)" >/dev/null 2>&1 || true
    sleep 1
fi

# ---------------------------------------------------------------------------
# Demo 2: Breach — Revoked Commitment + Penalty TX
# ---------------------------------------------------------------------------
if [ "$MODE_BREACH" = "1" ]; then
    banner "Demo: Breach Detection & Penalty"

    explain "This demo tests the watchtower's breach detection. After normal
factory operation, a revoked commitment transaction is broadcast.
The watchtower detects the breach and broadcasts a penalty
transaction, sweeping the cheater's funds.

The watchtower monitors old_commitments in the database and
compares against mempool/chain transactions every 5 seconds."

    if run_lsp_clients "--demo --breach-test" "breach demo"; then
        ok "Breach demo completed successfully"
        TOTAL_PASS=$((TOTAL_PASS + 1))
    else
        EXIT_CODE=$?
        if [ $EXIT_CODE -eq 0 ]; then
            ok "Breach demo completed"
            TOTAL_PASS=$((TOTAL_PASS + 1))
        else
            fail "Breach demo failed (exit code: $EXIT_CODE)"
            TOTAL_FAIL=$((TOTAL_FAIL + 1))
        fi
    fi

    bitcoin-cli -regtest generatetoaddress 1 "$(bitcoin-cli -regtest -rpcwallet=superscalar_lsp getnewaddress 2>/dev/null)" >/dev/null 2>&1 || true
    sleep 1
fi

# ---------------------------------------------------------------------------
# Demo 3: Factory Rotation (Factory 0 → Factory 1)
# ---------------------------------------------------------------------------
if [ "$MODE_ROTATION" = "1" ]; then
    banner "Demo: Factory Rotation + PTLC Key Turnover"

    explain "This demo shows the full factory rotation lifecycle:

  1. Factory 0 is created and payments flow normally
  2. PTLC key turnover extracts client secret keys via adaptor sigs
  3. Factory 0 is closed (LSP can sign alone with extracted keys)
  4. Factory 1 is created as the replacement
  5. Payments resume in Factory 1
  6. Factory 1 is cooperatively closed

This is the laddering mechanism that gives SuperScalar its name:
overlapping factory lifetimes ensure zero downtime for clients."

    if run_lsp_clients "--demo --test-rotation" "rotation demo"; then
        ok "Rotation demo completed successfully"
        TOTAL_PASS=$((TOTAL_PASS + 1))
    else
        fail "Rotation demo failed (exit code: $?)"
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
    fi

    bitcoin-cli -regtest generatetoaddress 1 "$(bitcoin-cli -regtest -rpcwallet=superscalar_lsp getnewaddress 2>/dev/null)" >/dev/null 2>&1 || true
    sleep 1
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
banner "Summary"

echo -e "  ${GREEN}Passed:${NC} ${BOLD}$TOTAL_PASS${NC}"
echo -e "  ${RED}Failed:${NC} ${BOLD}$TOTAL_FAIL${NC}"
echo ""

if [ "$TOTAL_FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}All demos passed!${NC}"
else
    echo -e "  ${YELLOW}${BOLD}Some demos failed — check output above.${NC}"
fi

echo ""
echo -e "  ${DIM}What was demonstrated:${NC}"
[ "$MODE_BASIC" = "1" ]    && echo -e "    ${CYAN}•${NC} Factory creation (5-of-5 MuSig2, single on-chain UTXO)"
[ "$MODE_BASIC" = "1" ]    && echo -e "    ${CYAN}•${NC} In-factory payments with real preimage validation"
[ "$MODE_BASIC" = "1" ]    && echo -e "    ${CYAN}•${NC} Cooperative close (single on-chain transaction)"
[ "$MODE_BREACH" = "1" ]   && echo -e "    ${CYAN}•${NC} Watchtower breach detection and penalty TX broadcast"
[ "$MODE_ROTATION" = "1" ] && echo -e "    ${CYAN}•${NC} PTLC key turnover via adaptor signatures"
[ "$MODE_ROTATION" = "1" ] && echo -e "    ${CYAN}•${NC} Factory rotation (Factory 0 → Factory 1, zero downtime)"
echo ""

# ---------------------------------------------------------------------------
# Optional: launch dashboard
# ---------------------------------------------------------------------------
if [ "$LAUNCH_DASHBOARD" = "1" ]; then
    banner "Launching Dashboard"
    step "Starting dashboard in demo mode on port 8080..."
    python3 "$SCRIPT_DIR/dashboard.py" --demo --port 8080 &
    DASH_PID=$!
    PIDS+=($DASH_PID)
    sleep 1
    ok "Dashboard running at http://localhost:8080"
    echo -e "  ${DIM}Press Ctrl+C to stop${NC}"
    wait $DASH_PID 2>/dev/null || true
fi

# Disarm trap for clean exit
trap - EXIT
if [ "$STARTED_BITCOIND" = "1" ]; then
    bitcoin-cli -regtest stop 2>/dev/null || true
fi

exit $TOTAL_FAIL
