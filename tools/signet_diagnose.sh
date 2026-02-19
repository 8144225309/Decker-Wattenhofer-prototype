#!/bin/bash
# SuperScalar Signet Diagnostic & Recovery Tools
#
# Subcommands for inspecting chain state, factory/channel/watchtower DB state,
# and emergency fee bumping on signet.
#
# Usage: bash tools/signet_diagnose.sh <subcommand> [args]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Source .env if it exists
if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    . "$SCRIPT_DIR/.env"
    set +a
fi

BTCBIN="${BTCBIN:-$(dirname "$(command -v bitcoin-cli 2>/dev/null || echo /usr/local/bin/bitcoin-cli)")}"
DATADIR="${DATADIR:-/tmp/superscalar-signet}"
RPCUSER="${RPCUSER:-superscalar}"
RPCPASS="${RPCPASS:-superscalar123}"
RPCPORT="${RPCPORT:-38332}"
LSPDB="$DATADIR/lsp.db"

# Derived DB paths
CLIENT_DBS=()
for i in 1 2 3 4; do
    CLIENT_DBS+=("$DATADIR/client${i}.db")
done

# ==========================================================================
# Helpers
# ==========================================================================

btc() {
    "$BTCBIN/bitcoin-cli" -signet -rpcuser="$RPCUSER" -rpcpassword="$RPCPASS" -rpcport="$RPCPORT" "$@"
}

btc_wallet() {
    btc -rpcwallet=superscalar_lsp "$@"
}

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

header()  { echo ""; echo -e "${BOLD}${CYAN}=== $* ===${NC}"; echo ""; }
info()    { echo -e "${GREEN}  ✓${NC} $*"; }
warn()    { echo -e "${YELLOW}  ⚠${NC} $*"; }
fail()    { echo -e "${RED}  ✗${NC} $*"; }
step()    { echo -e "${BOLD}  →${NC} $*"; }
detail()  { echo -e "${DIM}    $*${NC}"; }

# ==========================================================================
# mempool — List all mempool txs with fee rates and ages
# ==========================================================================

cmd_mempool() {
    header "Mempool Status"

    if ! btc getblockchaininfo &>/dev/null; then
        fail "bitcoind is not running."
        exit 1
    fi

    MEMPOOL_SIZE=$(btc getmempoolinfo | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('size',0))")
    MEMPOOL_BYTES=$(btc getmempoolinfo | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('bytes',0))")
    info "Mempool: $MEMPOOL_SIZE txs, $MEMPOOL_BYTES bytes"

    if [ "$MEMPOOL_SIZE" = "0" ]; then
        detail "Mempool is empty"
        return
    fi

    step "Listing mempool transactions..."
    btc getrawmempool true | python3 -c "
import json, sys, time
data = json.load(sys.stdin)
now = time.time()
entries = []
for txid, info in data.items():
    fee = info.get('fees', {}).get('base', info.get('fee', 0))
    vsize = info.get('vsize', info.get('size', 1))
    rate = (fee * 1e8) / vsize if vsize > 0 else 0
    age_s = now - info.get('time', now)
    entries.append((txid, rate, age_s, vsize))
entries.sort(key=lambda x: -x[1])  # sort by fee rate desc
print(f'  {\"TXID\":>20s}  {\"sat/vB\":>8s}  {\"vSize\":>6s}  {\"Age\":>8s}')
print(f'  {\"-\"*20}  {\"-\"*8}  {\"-\"*6}  {\"-\"*8}')
for txid, rate, age, vsize in entries[:20]:
    age_str = f'{int(age)}s' if age < 60 else f'{int(age/60)}m'
    print(f'  {txid[:20]}  {rate:>8.1f}  {vsize:>6d}  {age_str:>8s}')
if len(entries) > 20:
    print(f'  ... and {len(entries)-20} more')
" 2>/dev/null || fail "Could not parse mempool"
}

# ==========================================================================
# tx TXID — Show a specific tx's status
# ==========================================================================

cmd_tx() {
    local TXID="${2:-}"
    if [ -z "$TXID" ]; then
        fail "Usage: $0 tx <TXID>"
        exit 1
    fi

    header "Transaction: ${TXID:0:20}..."

    if ! btc getblockchaininfo &>/dev/null; then
        fail "bitcoind is not running."
        exit 1
    fi

    # Check mempool first
    MEMPOOL_ENTRY=$(btc getmempoolentry "$TXID" 2>/dev/null || echo "")
    if [ -n "$MEMPOOL_ENTRY" ]; then
        info "Status: IN MEMPOOL (unconfirmed)"
        echo "$MEMPOOL_ENTRY" | python3 -c "
import json, sys
d = json.load(sys.stdin)
fee = d.get('fees', {}).get('base', d.get('fee', 0))
vsize = d.get('vsize', d.get('size', 0))
rate = (fee * 1e8) / vsize if vsize > 0 else 0
print(f'    Fee:      {fee*1e8:.0f} sat')
print(f'    vSize:    {vsize} vB')
print(f'    Fee rate: {rate:.1f} sat/vB')
print(f'    Depends:  {d.get(\"depends\", [])}')
" 2>/dev/null
    else
        # Try gettransaction (wallet tx)
        btc_wallet loadwallet superscalar_lsp 2>/dev/null || true
        TX_INFO=$(btc_wallet gettransaction "$TXID" 2>/dev/null || echo "")
        if [ -n "$TX_INFO" ]; then
            echo "$TX_INFO" | python3 -c "
import json, sys
d = json.load(sys.stdin)
conf = d.get('confirmations', 0)
fee = abs(d.get('fee', 0))
amount = d.get('amount', 0)
print(f'    Status:        {\"CONFIRMED\" if conf > 0 else \"UNCONFIRMED\"} ({conf} conf)')
print(f'    Amount:        {amount} BTC')
print(f'    Fee:           {fee} BTC ({fee*1e8:.0f} sat)')
if d.get('blockhash'):
    print(f'    Block:         {d[\"blockhash\"][:20]}...')
" 2>/dev/null
        else
            # Try getrawtransaction (any tx with -txindex)
            RAW_INFO=$(btc getrawtransaction "$TXID" true 2>/dev/null || echo "")
            if [ -n "$RAW_INFO" ]; then
                echo "$RAW_INFO" | python3 -c "
import json, sys
d = json.load(sys.stdin)
conf = d.get('confirmations', 0)
vsize = d.get('vsize', d.get('size', 0))
print(f'    Status:        {\"CONFIRMED\" if conf > 0 else \"UNCONFIRMED\"} ({conf} conf)')
print(f'    vSize:         {vsize} vB')
if d.get('blockhash'):
    print(f'    Block:         {d[\"blockhash\"][:20]}...')
" 2>/dev/null
            else
                fail "Transaction not found in wallet, mempool, or blockchain"
            fi
        fi
    fi
}

# ==========================================================================
# factory-state — Read LSP SQLite DB
# ==========================================================================

cmd_factory_state() {
    header "Factory & Channel State (LSP DB)"

    if [ ! -f "$LSPDB" ]; then
        fail "LSP database not found: $LSPDB"
        exit 1
    fi

    python3 -c "
import sqlite3, sys

db = sqlite3.connect('file:$LSPDB?mode=ro', uri=True)
db.row_factory = sqlite3.Row

# Factories
print('  Factories:')
try:
    rows = db.execute('SELECT * FROM factories').fetchall()
    if not rows:
        print('    (none)')
    for r in rows:
        d = dict(r)
        print(f'    Factory #{d.get(\"id\",\"?\")}:')
        for k, v in d.items():
            if k != 'id':
                val = str(v)[:60] if v else '(null)'
                print(f'      {k:20s} = {val}')
except Exception as e:
    print(f'    error: {e}')

print()

# Channels
print('  Channels:')
try:
    rows = db.execute('SELECT * FROM channels').fetchall()
    if not rows:
        print('    (none)')
    for r in rows:
        d = dict(r)
        cid = d.get('id', '?')
        local = d.get('local_amount', 0)
        remote = d.get('remote_amount', 0)
        commit = d.get('commitment_number', 0)
        print(f'    Channel #{cid}: local={local} remote={remote} commit={commit}')
except Exception as e:
    print(f'    error: {e}')

print()

# DW state
print('  DW State:')
try:
    rows = db.execute('SELECT * FROM dw_state').fetchall()
    if not rows:
        print('    (none)')
    for r in rows:
        d = dict(r)
        print(f'    ', dict(d))
except sqlite3.OperationalError:
    print('    (table not found)')
except Exception as e:
    print(f'    error: {e}')

print()

# Watchtower (old_commitments)
print('  Watchtower (old_commitments):')
try:
    count = db.execute('SELECT COUNT(*) FROM old_commitments').fetchone()[0]
    print(f'    {count} stored commitment(s)')
except sqlite3.OperationalError:
    print('    (table not found)')
except Exception as e:
    print(f'    error: {e}')

db.close()
" 2>/dev/null || fail "Could not read LSP database"
}

# ==========================================================================
# jit-state — Read all client DBs for JIT channel state
# ==========================================================================

cmd_jit_state() {
    header "JIT Channel State (Client DBs)"

    for i in 1 2 3 4; do
        local DBFILE="$DATADIR/client${i}.db"
        echo -e "  ${BOLD}Client $i${NC} ($DBFILE)"
        if [ ! -f "$DBFILE" ]; then
            detail "(database not found)"
            continue
        fi

        python3 -c "
import sqlite3
db = sqlite3.connect('file:$DBFILE?mode=ro', uri=True)
db.row_factory = sqlite3.Row
try:
    rows = db.execute('SELECT * FROM channels').fetchall()
    if not rows:
        print('    No channels')
    for r in rows:
        d = dict(r)
        print(f'    Channel: local={d.get(\"local_amount\",0)} remote={d.get(\"remote_amount\",0)} commit={d.get(\"commitment_number\",0)}')
except Exception as e:
    print(f'    error: {e}')

# Check for JIT-specific tables
try:
    rows = db.execute(\"SELECT name FROM sqlite_master WHERE type='table'\").fetchall()
    tables = [r[0] for r in rows]
    jit_tables = [t for t in tables if 'jit' in t.lower()]
    if jit_tables:
        print(f'    JIT tables: {jit_tables}')
        for t in jit_tables:
            count = db.execute(f'SELECT COUNT(*) FROM \"{t}\"').fetchone()[0]
            print(f'      {t}: {count} row(s)')
except Exception as e:
    pass

db.close()
" 2>/dev/null || fail "Could not read client $i database"
        echo ""
    done
}

# ==========================================================================
# watchtower-state — Read old_commitments from all DBs
# ==========================================================================

cmd_watchtower_state() {
    header "Watchtower State (all DBs)"

    # LSP
    echo -e "  ${BOLD}LSP${NC}"
    if [ -f "$LSPDB" ]; then
        python3 -c "
import sqlite3
db = sqlite3.connect('file:$LSPDB?mode=ro', uri=True)
try:
    count = db.execute('SELECT COUNT(*) FROM old_commitments').fetchone()[0]
    print(f'    old_commitments: {count}')
except:
    print('    (no old_commitments table)')
db.close()
" 2>/dev/null
    else
        detail "(database not found)"
    fi
    echo ""

    # Clients
    for i in 1 2 3 4; do
        local DBFILE="$DATADIR/client${i}.db"
        echo -e "  ${BOLD}Client $i${NC}"
        if [ -f "$DBFILE" ]; then
            python3 -c "
import sqlite3
db = sqlite3.connect('file:$DBFILE?mode=ro', uri=True)
try:
    count = db.execute('SELECT COUNT(*) FROM old_commitments').fetchone()[0]
    print(f'    old_commitments: {count}')
    if count > 0:
        rows = db.execute('SELECT * FROM old_commitments ORDER BY rowid DESC LIMIT 3').fetchall()
        for r in rows:
            print(f'      {dict(zip([d[0] for d in db.execute(\"SELECT * FROM old_commitments\").description], r))}')
except:
    print('    (no old_commitments table)')
db.close()
" 2>/dev/null
        else
            detail "(database not found)"
        fi
        echo ""
    done
}

# ==========================================================================
# bump TXID — CPFP fee bump using wallet UTXOs
# ==========================================================================

cmd_bump() {
    local TXID="${2:-}"
    if [ -z "$TXID" ]; then
        fail "Usage: $0 bump <TXID>"
        exit 1
    fi

    header "Emergency Fee Bump (CPFP) for ${TXID:0:20}..."

    if ! btc getblockchaininfo &>/dev/null; then
        fail "bitcoind is not running."
        exit 1
    fi

    btc loadwallet superscalar_lsp 2>/dev/null || true

    # Check if tx is in mempool
    if ! btc getmempoolentry "$TXID" &>/dev/null; then
        fail "Transaction is not in mempool (already confirmed or not found)"
        exit 1
    fi

    # Use bumpfee if available (Bitcoin Core 0.14+)
    step "Attempting bumpfee..."
    RESULT=$(btc_wallet bumpfee "$TXID" 2>&1 || echo "BUMP_FAILED")
    if echo "$RESULT" | grep -q "BUMP_FAILED"; then
        warn "bumpfee failed (tx may not be ours). Try manual CPFP."
        detail "Manual CPFP: find an output you control, spend it with a high fee."
        detail "  bitcoin-cli -signet -rpcwallet=superscalar_lsp listunspent"
        detail "  bitcoin-cli -signet -rpcwallet=superscalar_lsp sendtoaddress <addr> <amount> \"\" \"\" true true null \"unset\" null 25"
    else
        info "Fee bump submitted!"
        echo "$RESULT" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(f'    New TXID: {d.get(\"txid\", \"?\")}')
    print(f'    New fee:  {d.get(\"fee\", \"?\")} BTC')
except:
    pass
" 2>/dev/null
    fi
}

# ==========================================================================
# Help
# ==========================================================================

cmd_help() {
    echo ""
    echo -e "${BOLD}${CYAN}=== SuperScalar Signet Diagnostics ===${NC}"
    echo ""
    echo -e "${BOLD}Chain inspection:${NC}"
    echo "   bash $0 mempool            List mempool txs with fee rates and ages"
    echo "   bash $0 tx <TXID>          Show tx confirmations, mempool status, fee"
    echo ""
    echo -e "${BOLD}Database inspection:${NC}"
    echo "   bash $0 factory-state      LSP factory/channel/DW/watchtower state"
    echo "   bash $0 jit-state          JIT channel state from all client DBs"
    echo "   bash $0 watchtower-state   Old commitments from all DBs"
    echo ""
    echo -e "${BOLD}Recovery:${NC}"
    echo "   bash $0 bump <TXID>        CPFP fee bump for stuck mempool tx"
    echo ""
    echo -e "${BOLD}Configuration:${NC}"
    echo "  Sources tools/.env if present. Data directory: $DATADIR"
    echo ""
}

# ==========================================================================
# Main dispatch
# ==========================================================================

case "${1:-}" in
    mempool)           cmd_mempool ;;
    tx)                cmd_tx "$@" ;;
    factory-state)     cmd_factory_state ;;
    jit-state)         cmd_jit_state ;;
    watchtower-state)  cmd_watchtower_state ;;
    bump)              cmd_bump "$@" ;;
    help|--help|-h)    cmd_help ;;
    *)                 cmd_help ;;
esac
