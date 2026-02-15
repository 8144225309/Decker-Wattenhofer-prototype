#!/bin/bash
# SuperScalar Signet Setup Script
# Sets up bitcoind (signet), two CLN nodes, and SuperScalar for end-to-end testing.
#
# Usage: bash tools/signet_setup.sh [step]
#   Steps: bitcoind, sync, wallet, cln, channel, build, bridge, lsp, client, status
#   No argument = run all steps interactively

set -e

# === Paths ===
BTCBIN="/home/obscurity/superscalar-ln/bin"
CLNBIN="/home/obscurity/cln-test-8849/lightning"
BTCCLI="$BTCBIN/bitcoin-cli -signet -rpcuser=superscalar -rpcpassword=superscalar123"
CLNCLI_A="$CLNBIN/cli/lightning-cli --lightning-dir=/tmp/cln-a"
CLNCLI_B="$CLNBIN/cli/lightning-cli --lightning-dir=/tmp/cln-b"
BTCDATA="/tmp/bitcoin-signet"
CLNA_DIR="/tmp/cln-a"
CLNB_DIR="/tmp/cln-b"
SUPERSCALAR_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$SUPERSCALAR_DIR/build"

# === Colors ===
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# === Step 1: Start bitcoind ===
start_bitcoind() {
    info "Starting bitcoind (signet)..."
    mkdir -p "$BTCDATA"
    cat > "$BTCDATA/bitcoin.conf" <<EOF
signet=1
txindex=1
server=1
rpcuser=superscalar
rpcpassword=superscalar123
[signet]
rpcport=38332
EOF

    if $BTCCLI getblockchaininfo &>/dev/null; then
        info "bitcoind already running"
    else
        $BTCBIN/bitcoind -signet -datadir="$BTCDATA" -daemon
        info "bitcoind started, waiting for RPC..."
        for i in $(seq 1 30); do
            if $BTCCLI getblockchaininfo &>/dev/null; then
                info "bitcoind RPC ready"
                break
            fi
            sleep 1
        done
    fi
}

# === Step 2: Wait for sync ===
wait_for_sync() {
    info "Waiting for signet sync..."
    while true; do
        IBD=$($BTCCLI getblockchaininfo 2>/dev/null | grep '"initialblockdownload"' | grep -o 'true\|false')
        HEIGHT=$($BTCCLI getblockchaininfo 2>/dev/null | grep '"blocks"' | grep -o '[0-9]*')
        if [ "$IBD" = "false" ]; then
            info "Synced! Block height: $HEIGHT"
            break
        fi
        echo "  syncing... height=$HEIGHT"
        sleep 10
    done
}

# === Step 3: Create wallet and show funding address ===
setup_wallet() {
    info "Setting up wallet..."
    $BTCCLI createwallet "superscalar_lsp" 2>/dev/null || \
        $BTCCLI loadwallet "superscalar_lsp" 2>/dev/null || true

    ADDR=$($BTCCLI -rpcwallet=superscalar_lsp getnewaddress "" bech32m)
    BAL=$($BTCCLI -rpcwallet=superscalar_lsp getbalance)

    info "Wallet address: $ADDR"
    info "Current balance: $BAL BTC"

    if [ "$(echo "$BAL < 0.001" | bc -l 2>/dev/null || echo 1)" = "1" ]; then
        warn "Insufficient balance. Fund from signet faucet:"
        warn "  https://signetfaucet.com/"
        warn "  Address: $ADDR"
        warn "Then re-run this step."
    fi
}

# === Step 4: Start CLN nodes ===
start_cln() {
    info "Starting CLN nodes..."

    # Node B (vanilla, no plugin)
    mkdir -p "$CLNB_DIR"
    if $CLNCLI_B getinfo &>/dev/null; then
        info "CLN Node B already running"
    else
        $CLNBIN/lightningd/lightningd \
            --network=signet \
            --lightning-dir="$CLNB_DIR" \
            --bitcoin-cli="$BTCBIN/bitcoin-cli" \
            --bitcoin-rpcuser=superscalar \
            --bitcoin-rpcpassword=superscalar123 \
            --bitcoin-rpcport=38332 \
            --addr=127.0.0.1:9737 \
            --daemon
        info "CLN Node B started (port 9737)"
    fi

    # Node A (with SuperScalar plugin)
    mkdir -p "$CLNA_DIR"
    if $CLNCLI_A getinfo &>/dev/null; then
        info "CLN Node A already running"
    else
        $CLNBIN/lightningd/lightningd \
            --network=signet \
            --lightning-dir="$CLNA_DIR" \
            --bitcoin-cli="$BTCBIN/bitcoin-cli" \
            --bitcoin-rpcuser=superscalar \
            --bitcoin-rpcpassword=superscalar123 \
            --bitcoin-rpcport=38332 \
            --addr=127.0.0.1:9738 \
            --plugin="$SUPERSCALAR_DIR/tools/cln_plugin.py" \
            --superscalar-bridge-host=127.0.0.1 \
            --superscalar-bridge-port=9736 \
            --superscalar-lightning-cli="$CLNBIN/cli/lightning-cli --lightning-dir=$CLNA_DIR" \
            --daemon
        info "CLN Node A started (port 9738, with SuperScalar plugin)"
    fi

    sleep 2
    info "Node A ID: $($CLNCLI_A getinfo | grep '"id"' | head -1 | cut -d'"' -f4)"
    info "Node B ID: $($CLNCLI_B getinfo | grep '"id"' | head -1 | cut -d'"' -f4)"
}

# === Step 5: Open channel A -> B ===
open_channel() {
    info "Opening channel from Node A to Node B..."

    # Fund Node A
    ADDR_A=$($CLNCLI_A newaddr | grep '"bech32"' | cut -d'"' -f4)
    info "Node A funding address: $ADDR_A"

    BAL_A=$($BTCCLI -rpcwallet=superscalar_lsp getbalance)
    info "Wallet balance: $BAL_A BTC"

    # Send 0.01 BTC to Node A
    TXID=$($BTCCLI -rpcwallet=superscalar_lsp sendtoaddress "$ADDR_A" 0.01)
    info "Funded Node A: txid=$TXID"
    info "Waiting for confirmation (signet ~10 min)..."

    while true; do
        CONF=$($BTCCLI -rpcwallet=superscalar_lsp gettransaction "$TXID" 2>/dev/null | grep '"confirmations"' | grep -o '[0-9]*' || echo 0)
        if [ "${CONF:-0}" -ge 1 ]; then
            info "Funding confirmed ($CONF confirmations)"
            break
        fi
        echo "  waiting... conf=$CONF"
        sleep 30
    done

    # Connect A to B
    NODE_B_ID=$($CLNCLI_B getinfo | grep '"id"' | head -1 | cut -d'"' -f4)
    $CLNCLI_A connect "$NODE_B_ID@127.0.0.1:9737" || true
    info "Connected A -> B"

    # Open channel (500k sats)
    $CLNCLI_A fundchannel "$NODE_B_ID" 500000
    info "Channel opening tx broadcast, waiting for 6 confirmations..."

    while true; do
        CHAN=$($CLNCLI_A listpeerchannels 2>/dev/null | grep '"state"' | head -1 | cut -d'"' -f4)
        if [ "$CHAN" = "CHANNELD_NORMAL" ]; then
            info "Channel ready!"
            break
        fi
        echo "  channel state: $CHAN"
        sleep 30
    done
}

# === Step 6: Build SuperScalar ===
build_superscalar() {
    info "Building SuperScalar..."
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    cmake ..
    make -j$(nproc)
    info "Build complete"
}

# === Step 7: Start bridge ===
start_bridge() {
    info "Starting SuperScalar bridge..."
    cd "$BUILD_DIR"
    if pgrep -f "superscalar_bridge" &>/dev/null; then
        info "Bridge already running"
    else
        LD_LIBRARY_PATH=_deps/secp256k1-zkp-build/src:_deps/cjson-build \
            ./superscalar_bridge --lsp-port 9735 --plugin-port 9736 &
        BRIDGE_PID=$!
        info "Bridge started (PID=$BRIDGE_PID)"
        sleep 1
    fi
}

# === Step 8: Start LSP ===
start_lsp() {
    info "Starting SuperScalar LSP..."
    cd "$BUILD_DIR"
    if pgrep -f "superscalar_lsp" &>/dev/null; then
        info "LSP already running"
    else
        LD_LIBRARY_PATH=_deps/secp256k1-zkp-build/src:_deps/cjson-build \
            ./superscalar_lsp \
                --network signet \
                --cli-path "$BTCBIN/bitcoin-cli" \
                --rpcuser superscalar \
                --rpcpassword superscalar123 \
                --port 9735 \
                --clients 1 \
                --amount 50000 \
                --daemon \
                --keyfile /tmp/lsp.key \
                --passphrase superscalar &
        LSP_PID=$!
        info "LSP started (PID=$LSP_PID)"
    fi
}

# === Step 9: Start client ===
start_client() {
    info "Starting SuperScalar client..."
    cd "$BUILD_DIR"
    if pgrep -f "superscalar_client" &>/dev/null; then
        info "Client already running"
    else
        LD_LIBRARY_PATH=_deps/secp256k1-zkp-build/src:_deps/cjson-build \
            ./superscalar_client \
                --keyfile /tmp/c1.key \
                --passphrase superscalar \
                --port 9735 \
                --daemon &
        CLIENT_PID=$!
        info "Client started (PID=$CLIENT_PID)"
    fi
}

# === Status ===
show_status() {
    echo ""
    echo "=== SuperScalar Signet Status ==="
    echo ""

    # bitcoind
    if $BTCCLI getblockchaininfo &>/dev/null; then
        HEIGHT=$($BTCCLI getblockchaininfo | grep '"blocks"' | grep -o '[0-9]*')
        echo "  bitcoind:     RUNNING (height=$HEIGHT)"
    else
        echo "  bitcoind:     STOPPED"
    fi

    # CLN nodes
    if $CLNCLI_A getinfo &>/dev/null; then
        echo "  CLN Node A:   RUNNING"
    else
        echo "  CLN Node A:   STOPPED"
    fi

    if $CLNCLI_B getinfo &>/dev/null; then
        echo "  CLN Node B:   RUNNING"
    else
        echo "  CLN Node B:   STOPPED"
    fi

    # SuperScalar processes
    if pgrep -f "superscalar_bridge" &>/dev/null; then
        echo "  Bridge:       RUNNING"
    else
        echo "  Bridge:       STOPPED"
    fi

    if pgrep -f "superscalar_lsp" &>/dev/null; then
        echo "  LSP:          RUNNING"
    else
        echo "  LSP:          STOPPED"
    fi

    if pgrep -f "superscalar_client" &>/dev/null; then
        echo "  Client:       RUNNING"
    else
        echo "  Client:       STOPPED"
    fi

    echo ""
    echo "=== Test Commands ==="
    echo "  Create invoice on Node B:"
    echo "    $CLNCLI_B invoice 10000 \"test1\" \"test\""
    echo ""
    echo "  Check invoice status:"
    echo "    $CLNCLI_B listinvoices \"test1\""
    echo ""
}

# === Main ===
case "${1:-}" in
    bitcoind)   start_bitcoind ;;
    sync)       wait_for_sync ;;
    wallet)     setup_wallet ;;
    cln)        start_cln ;;
    channel)    open_channel ;;
    build)      build_superscalar ;;
    bridge)     start_bridge ;;
    lsp)        start_lsp ;;
    client)     start_client ;;
    status)     show_status ;;
    *)
        info "SuperScalar Signet Setup"
        info "========================"
        echo ""
        info "Steps to set up signet environment:"
        echo "  1. bash $0 bitcoind   - Start bitcoind"
        echo "  2. bash $0 sync       - Wait for sync"
        echo "  3. bash $0 wallet     - Create wallet & show funding address"
        echo "  4. bash $0 cln        - Start CLN Node A + Node B"
        echo "  5. bash $0 channel    - Fund Node A & open channel to Node B"
        echo "  6. bash $0 build      - Build SuperScalar"
        echo "  7. bash $0 bridge     - Start bridge daemon"
        echo "  8. bash $0 lsp        - Start SuperScalar LSP"
        echo "  9. bash $0 client     - Start SuperScalar client"
        echo "  10. bash $0 status    - Show status of all services"
        echo ""
        info "Run steps 1-9 in order. Step 3 requires funding from signet faucet."
        ;;
esac
