# Road to Signet

What it takes to run SuperScalar on Bitcoin signet today.

---

## Current state

161 unit tests + 20 regtest integration tests, all passing. Every
transaction is real (MuSig2 Schnorr, taproot key-path/script-path,
BIP-68 nSequence). Bitcoin Core validates every signature when these
txs are broadcast on regtest. The protocol mechanics are network-agnostic.

## The one code fix

### Confirmation timeout: 600s → 3600s

Two call sites hardcode a 600-second (10-minute) timeout for
`regtest_wait_for_confirmation()`. Signet blocks arrive every ~10 minutes
on average, so 600s leaves no margin for slow blocks.

```
superscalar_lsp.c:595  — funding tx confirmation wait
superscalar_lsp.c:1927 — cooperative close confirmation wait
```

Fix: change `600` to `3600` at both sites. One line each.

---

## What works on signet today (no changes needed)

| Component | Why it works | Key code |
|---|---|---|
| Factory funding | `sendtoaddress` is standard RPC, network-agnostic | `regtest.c:197` |
| Factory MuSig2 signing | Pure TCP message exchange, no chain interaction | `lsp.c:116-365` |
| DW nSequence delays | Block-count based (BIP-68), not wall-clock | `dw_state.c:14-17` |
| CLTV timeout trees | Absolute block heights, network-agnostic | `factory.c:410-427` |
| Commitment signing | Distributed 2-of-2 MuSig2 partial sigs over wire | `channel.c:718-878` |
| HTLC lifecycle | In-channel state machine, no chain calls | `channel.c:1050+` |
| Daemon select() loop | 5s LSP / 2s client timeout, polls watchtower | `lsp_channels.c:1288` |
| Watchtower detection | `getrawtransaction` works on signet with txindex | `watchtower.c:244+` |
| Penalty broadcast | `sendrawtransaction` is network-agnostic | `watchtower.c:330` |
| Mining guard | `regtest_mine_blocks()` returns 0 on non-regtest | `regtest.c:185` |
| Cooperative close | `sendrawtransaction` + standard RPC | `lsp.c:close path` |
| CLN bridge | `lightning-cli pay` works if CLN is on signet | `cln_plugin.py:162` |
| Fee estimation | `--fee-rate` flag, no network dependency | `fee.c:11-14` |

## What needs operator attention (not code fixes)

### 1. Signet wallet must be pre-funded

The LSP calls `sendtoaddress` to fund the factory. On regtest this is
free (coinbase). On signet you need real signet coins from a faucet
(https://signetfaucet.com/). Default `--amount 50000` sats per channel
needs ~0.001 BTC total for a 4-client factory.

### 2. txindex=1 required

The watchtower uses `getrawtransaction` to detect breaches. This RPC
requires `txindex=1` in `bitcoin.conf`. Without it, watchtower
detection silently fails for transactions not in the node's wallet.

### 3. CLTV timeout must be set to a future block height

The factory CLTV timeout determines when timeout-sig-tree recovery
becomes possible. On signet, set it to `current_height + 1008` (~1 week)
or higher. If set below the current height, timeout scripts activate
immediately.

There is no auto-calculation from current block height — the operator
must set `--cltv-timeout` manually or accept the default.

### 4. CLN must be configured for signet

The bridge plugin calls `lightning-cli pay`. If CLN is running on a
different network than the SuperScalar LSP, payments fail silently.
Pass `--network signet` to both CLN and the plugin's
`--superscalar-lightning-cli` option.

### 5. Channel opening takes ~60 minutes

CLN channel open on signet requires funding tx + 6 confirmations
(~6 blocks × 10 min = 60 min). The `signet_setup.sh` script handles
this, but it's the slowest step in deployment.

## Uncertainty (things I can't verify without running on signet)

1. **Signet faucet availability** — faucet may be down or rate-limited.
   Alternative: mine your own signet coins with `bitcoin-util grind`.

2. **getrawtransaction reliability** — if txindex isn't fully built yet
   (still syncing), watchtower queries return errors. The watchtower
   handles this gracefully (skips the check) but won't detect breaches
   until sync completes.

3. **CLN signet plugin interop** — the plugin has been tested on regtest
   but not on signet. The code is identical; the risk is configuration
   mismatch, not logic bugs.

4. **Block time variance** — signet blocks can occasionally be >20 minutes
   apart. The 3600s timeout handles this, but very long gaps could cause
   the LSP to print timeout warnings before eventually succeeding.

## Deployment command lines

```bash
# 1. Bitcoin Core
bitcoind -signet -daemon -txindex=1 \
  -rpcuser=superscalar -rpcpassword=superscalar123

# 2. Fund wallet
bitcoin-cli -signet -rpcuser=superscalar -rpcpassword=superscalar123 \
  createwallet superscalar_lsp
bitcoin-cli -signet -rpcuser=superscalar -rpcpassword=superscalar123 \
  -rpcwallet=superscalar_lsp getnewaddress "" bech32m
# → send signet coins to this address, wait for 1 confirmation

# 3. Build
cd build && cmake .. && make -j$(nproc)
export LD_LIBRARY_PATH=_deps/secp256k1-zkp-build/src:_deps/cjson-build

# 4. Bridge (if using CLN)
./superscalar_bridge --lsp-port 9735 --plugin-port 9736

# 5. LSP
./superscalar_lsp \
  --network signet \
  --cli-path bitcoin-cli \
  --rpcuser superscalar --rpcpassword superscalar123 \
  --port 9735 --clients 1 --amount 50000 \
  --daemon --db lsp.db \
  --keyfile lsp.key --passphrase demo \
  --fee-rate 2

# 6. Client
./superscalar_client \
  --keyfile client.key --passphrase demo \
  --network signet \
  --cli-path bitcoin-cli \
  --rpcuser superscalar --rpcpassword superscalar123 \
  --port 9735 --host 127.0.0.1 \
  --daemon --db client.db
```

## Pre-flight checklist

- [ ] Patch confirmation timeout: 600 → 3600 at `superscalar_lsp.c:595` and `:1927`
- [ ] `bitcoind -signet` running and fully synced (`verificationprogress: 1.0`)
- [ ] `txindex=1` enabled in bitcoin.conf
- [ ] Wallet funded with ≥0.001 BTC (confirmed)
- [ ] If using CLN bridge: both CLN nodes on `--network=signet` with open channel
- [ ] Factory CLTV timeout set to reasonable future height
