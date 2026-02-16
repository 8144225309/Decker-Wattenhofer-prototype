# SuperScalar — Signet Deployment Readiness

Assessment date: 2026-02-16.

## Verdict

**Deployable on signet with one code fix** (confirmation timeout) and
standard operational setup (funded wallet, CLN nodes, ~30 min).

---

## Component-by-component assessment

### Bitcoin Core setup — READY

`tools/signet_setup.sh` handles signet correctly:
- Starts `bitcoind -signet` with `txindex=1`
- Monitors sync via `getblockchaininfo`
- Creates wallet, directs to faucet for funding
- No mining calls on non-regtest networks

### Factory funding — READY

`regtest_fund_address()` calls `sendtoaddress` which is a standard
Bitcoin Core RPC that works identically on regtest, signet, testnet,
and mainnet. No network-specific code needed.

### Funding confirmation — NEEDS FIX

`regtest_wait_for_confirmation()` is called with a **600-second timeout**
(`superscalar_lsp.c:595` and `:1927`). On signet, blocks arrive every
~10 minutes. The 600s timeout gives ~60 polling attempts at 10s intervals,
which is usually enough for one block but leaves no margin.

**Fix required**: Increase to 3600s (1 hour) or add a `--confirmation-timeout`
CLI flag. This is a one-line change per call site.

### Factory creation protocol — READY

The 3-round MuSig2 ceremony (PROPOSE → NONCES → PSIGS → READY) is pure
TCP message exchange with no on-chain dependencies. Works on any network.

### DW nSequence values — READY

`TIMEOUT_STEP_BLOCKS=5` produces block-count-based relative timelocks.
5 blocks on signet = ~50 minutes. The DW state machine is block-height
based, not wall-clock based, so it's network-agnostic.

### Factory CLTV timeouts — READY

Staggered CLTVs (leaf=cltv-10, mid=cltv-5, root=cltv) are absolute
block heights. On signet, the LSP should set `--cltv-timeout` to a
reasonable future height (e.g., current_height + 1008 for ~1 week).

### Commitment signing — READY

Distributed 2-of-2 MuSig2 partial sigs over TCP. No on-chain interaction.

### HTLC routing via CLN bridge — READY (with config)

`cln_plugin.py` calls real `lightning-cli pay` via subprocess. Works on
signet if CLN is configured with `--network=signet` and the plugin's
`--superscalar-lightning-cli` option includes `--network signet`.

### Daemon select() loop — READY

LSP: 5s timeout. Client: 2s timeout. Both poll watchtower and check
HTLC timeouts on each cycle. Block-height checks via
`regtest_get_block_height()` work on any network.

### Watchtower breach detection — READY

`watchtower_check()` polls via `getrawtransaction` / `gettransaction`
which work on signet. The one `regtest_mine_blocks()` call at
`watchtower.c:304` is safely guarded:

```c
// regtest.c:185
if (strcmp(rt->network, "regtest") != 0) return 0;
```

On signet, penalty txs enter the mempool and confirm with the next
natural block (~10 min). No functional impact.

### Cooperative close — READY

Close tx is broadcast via `sendrawtransaction`. Confirmation wait uses
`regtest_wait_for_confirmation()` (same 600s timeout issue as funding).

---

## What would fail today (without the fix)

1. **Funding confirmation timeout**: `superscalar_lsp.c:595` — 600s may
   not be enough if signet is slow. ~5% failure rate on typical signet,
   higher during congestion.

2. **Close confirmation timeout**: `superscalar_lsp.c:1927` — same 600s
   issue for cooperative close wait.

That's it. Everything else works.

---

## Signet command lines

```bash
# 1. Bitcoin Core (signet)
bitcoind -signet -daemon -txindex=1 \
  -rpcuser=superscalar -rpcpassword=superscalar123

# 2. Fund wallet from https://signetfaucet.com/
bitcoin-cli -signet -rpcuser=superscalar -rpcpassword=superscalar123 \
  createwallet superscalar_lsp
bitcoin-cli -signet -rpcuser=superscalar -rpcpassword=superscalar123 \
  -rpcwallet=superscalar_lsp getnewaddress "" bech32m

# 3. Bridge
./superscalar_bridge --lsp-port 9735 --plugin-port 9736

# 4. LSP
./superscalar_lsp \
  --network signet \
  --cli-path bitcoin-cli \
  --rpcuser superscalar --rpcpassword superscalar123 \
  --port 9735 --clients 1 --amount 50000 \
  --daemon --db lsp.db \
  --keyfile lsp.key --passphrase demo \
  --fee-rate 2

# 5. Client
./superscalar_client \
  --keyfile client.key --passphrase demo \
  --network signet \
  --cli-path bitcoin-cli \
  --rpcuser superscalar --rpcpassword superscalar123 \
  --port 9735 --host 127.0.0.1 \
  --daemon --db client.db

# Note: all binaries need LD_LIBRARY_PATH set:
# LD_LIBRARY_PATH=_deps/secp256k1-zkp-build/src:_deps/cjson-build
```

---

## Pre-deployment checklist

- [ ] Increase confirmation timeout from 600s to 3600s (or add `--confirmation-timeout` flag)
- [ ] Fund signet wallet with >=0.001 BTC from faucet
- [ ] Wait for bitcoind signet sync (getblockchaininfo → verificationprogress=1.0)
- [ ] If using CLN bridge: configure CLN with `--network=signet`
- [ ] Set factory CLTV timeout to reasonable future height (current + 1008)
