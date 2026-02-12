# SuperScalar

First implementation of [ZmnSCPxj's SuperScalar design](https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories/1143) — laddered timeout-tree-structured Decker-Wattenhofer channel factories for Bitcoin.

## What This Is

A Bitcoin channel factory protocol combining:

- **Decker-Wattenhofer invalidation** — alternating kickoff/state transaction layers with decrementing nSequence relative timelocks
- **Timeout-sig-trees** — N-of-N MuSig2 key-path spending with CLTV timeout script-path fallback
- **Poon-Dryja payment channels** — standard Lightning channels at leaf outputs with HTLCs
- **LSP + N clients** architecture — not symmetric N-of-N; the LSP participates in all branches

No consensus changes or soft forks required. Runs on Bitcoin today.

## Build (WSL)

```
cd superscalar && mkdir -p build && cd build
cmake .. && make -j$(nproc)
```

Dependencies (auto-fetched via CMake FetchContent):
- [secp256k1-zkp](https://github.com/BlockstreamResearch/secp256k1-zkp) — MuSig2, Schnorr signatures, extrakeys
- [cJSON](https://github.com/DaveGamble/cJSON) — JSON parsing for bitcoin-cli output

## Test

72 tests (60 unit + 12 regtest integration).

```bash
# unit tests (no bitcoind needed)
LD_LIBRARY_PATH=./_deps/secp256k1-zkp-build/src:_deps/cjson-build ./test_superscalar --unit

# integration tests (needs bitcoind -regtest)
bitcoind -regtest -daemon -rpcuser=rpcuser -rpcpassword=rpcpass -fallbackfee=0.00001 -txindex=1
LD_LIBRARY_PATH=./_deps/secp256k1-zkp-build/src:_deps/cjson-build ./test_superscalar --regtest
bitcoin-cli -regtest -rpcuser=rpcuser -rpcpassword=rpcpass stop

# all tests
LD_LIBRARY_PATH=./_deps/secp256k1-zkp-build/src:_deps/cjson-build ./test_superscalar --all
```

## Modules

| Module | File | Purpose |
|--------|------|---------|
| `dw_state` | dw_state.c | nSequence state machine, odometer-style multi-layer counter |
| `musig` | musig.c | MuSig2 key aggregation, 2-round signing, split-round protocol, nonce pools |
| `tx_builder` | tx_builder.c | Raw Bitcoin tx serialization, BIP-341 key-path sighash, witness finalization |
| `tapscript` | tapscript.c | TapLeaf/TapBranch hashing, CLTV timeout scripts, script-path sighash, control blocks |
| `factory` | factory.c | Factory tree: build, sign, advance, timeout-sig-tree outputs, cooperative close |
| `shachain` | shachain.c | BOLT #3 shachain algorithm, compact storage, epoch-to-index mapping |
| `channel` | channel.c | Poon-Dryja channels: commitment txs, revocation, penalty, HTLCs, cooperative close |
| `regtest` | regtest.c | bitcoin-cli subprocess harness for integration testing |
| `util` | util.c | SHA-256, tagged hashing (BIP-340/341), hex encoding, byte utilities |

## Architecture

### Factory Tree (LSP + 4 Clients)

```
                    funding UTXO (5-of-5)
                          |
                   kickoff_root (5-of-5, nSeq=disabled)
                          |
                    state_root (5-of-5, nSeq=DW layer 0)
                    /                    \
         kickoff_left (3-of-3)    kickoff_right (3-of-3)
         {LSP, A, B}              {LSP, C, D}
         nSeq=disabled            nSeq=disabled
              |                        |
        state_left (3-of-3)      state_right (3-of-3)
        nSeq=DW layer 1          nSeq=DW layer 1
        /     |     \            /     |     \
     chan_A  chan_B  L_stock   chan_C  chan_D  L_stock
```

- **6 transactions** in the tree, all pre-signed cooperatively via MuSig2
- **Alternating kickoff/state layers** prevents the cascade problem
- **Leaf outputs**: 2 Poon-Dryja payment channels + 1 LSP liquidity stock per branch
- **L-stock outputs**: Shachain-based invalidation with burn path for old states

### Decker-Wattenhofer Invalidation

Newer states get shorter relative timelocks, so they always confirm first:

```
State 0 (oldest): nSequence = 432 blocks  <- trapped behind newer states
State 1:          nSequence = 288 blocks
State 2:          nSequence = 144 blocks
State 3 (newest): nSequence = 0 blocks    <- confirms immediately
```

Multi-layer counter works like an odometer: 2 layers x 4 states = 16 epochs.

### Timeout-Sig-Trees

State transaction outputs include a taproot script tree with a CLTV timeout fallback:

```
Output key = TapTweak(internal_key, merkle_root)
  Key path:    MuSig2(subset N-of-N)  — cooperative spend
  Script path: <cltv_timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP <LSP_pubkey> OP_CHECKSIG
```

If clients disappear, the LSP can unilaterally recover funds after the timeout expires.

### Payment Channels

Each leaf channel is a standard Poon-Dryja Lightning channel:

```
Commitment TX (held by each party):
  Input:  leaf output (2-of-2 MuSig key-path)
  Output 0: to_local  (revocable with per-commitment point)
  Output 1: to_remote (immediate)
  Output 2+: HTLC outputs (offered/received)
```

- **Revocation**: Shachain-derived per-commitment secrets
- **Penalty**: Full channel balance to counterparty on breach
- **HTLCs**: 2-leaf taproot trees (success + timeout paths, or revocation + claim)
- **Cooperative close**: Single key-path spend bypassing commitment structure

## Implementation Status

### Phase 0: DW Invalidation
- Multi-layer odometer counter (BIP-68 nSequence)
- Layer exhaustion detection and state advancement

### Phase 1: Factory Transaction Tree
- 6-node alternating kickoff/state tree topology
- MuSig2 N-of-N signing with taproot key-path tweak
- Full on-chain broadcast and confirmation on regtest

### Phase 2: Timeout-Sig-Trees
- CLTV timeout script construction (BIP-341 tapscript)
- TapLeaf hashing, merkle root, taproot output tweaking
- Script-path sighash and control block construction
- LSP timeout spend via script-path witness on regtest

### Phase 3a: Split-Round MuSig2
- Nonce pool pre-generation (up to 256 nonces per client)
- Nonce/partial-sig serialization for offline clients
- 3-phase split-round signing orchestration
- N-of-N split-round signing (tested with 5 participants)

### Phase 4: Shachain + L-Output Invalidation
- BOLT #3 shachain generation and compact storage (49 elements)
- Epoch-to-index mapping for factory states
- Burn transaction construction for L-stock outputs
- Shachain secret verification on insert

### Phase 5: Poon-Dryja Payment Channels
- Channel initialization from factory leaf outputs
- Per-commitment point/secret generation (shachain-based)
- Commitment transaction construction and signing
- Key derivation (simple + revocation keys)
- Penalty transaction for breach enforcement
- Regtest: unilateral close with on-chain confirmation

### Phase 6: HTLC Outputs
- Offered/Received HTLC scripts (2-leaf taproot trees)
- HTLC-success and HTLC-timeout transaction paths
- HTLC penalty transactions (revocation spending)
- HTLC commitment transaction integration
- Regtest: HTLC success (preimage reveal) and timeout (CLTV expiry)

### Phase 7: Cooperative Close
- Factory-level cooperative close (single tx, bypasses entire tree)
- Channel-level cooperative close (key-path spend, no timelocks)
- Arbitrary output distribution with negotiated balances
- Regtest: factory coop close + channel coop close after balance shift

### Future: Phase 8 — Laddering
- PTLC key turnover (adaptor signatures, scalar = client private key)
- Factory lifecycle (30-day active + 3-day dying)
- Rolling factory creation with client migration
- CTV upgrade path (replace N-of-N emulation with covenant)

## License

MIT
