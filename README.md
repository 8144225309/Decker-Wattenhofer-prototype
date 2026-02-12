# SuperScalar

First implementation of [ZmnSCPxj's SuperScalar design](https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories/1143) — laddered timeout-tree-structured Decker-Wattenhofer channel factories for Bitcoin.

## What This Is

A Bitcoin channel factory protocol combining:

- **Decker-Wattenhofer invalidation** — alternating kickoff/state transaction layers with decrementing nSequence relative timelocks
- **Timeout-sig-trees** — N-of-N MuSig2 key-path spending with CLTV timeout script-path fallback
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

```bash
# unit tests (no bitcoind needed)
LD_LIBRARY_PATH=./_deps/secp256k1-zkp-build/src:_deps/cjson-build ./test_superscalar --unit

# integration tests (needs bitcoind -regtest)
bitcoind -regtest -daemon -rpcuser=rpcuser -rpcpassword=rpcpass
LD_LIBRARY_PATH=./_deps/secp256k1-zkp-build/src:_deps/cjson-build ./test_superscalar --regtest
bitcoin-cli -regtest stop

# all tests
LD_LIBRARY_PATH=./_deps/secp256k1-zkp-build/src:_deps/cjson-build ./test_superscalar --all
```

## Modules

| Module | File | Purpose |
|--------|------|---------|
| `dw_state` | dw_state.c | nSequence state machine, odometer-style multi-layer counter |
| `musig` | musig.c | MuSig2 key aggregation + 2-round signing with taproot tweaking |
| `tx_builder` | tx_builder.c | Raw Bitcoin tx serialization, BIP-341 key-path sighash, witness finalization |
| `tapscript` | tapscript.c | TapLeaf/TapBranch hashing, CLTV timeout scripts, script-path sighash, control blocks |
| `factory` | factory.c | 6-node factory tree: build, sign, advance DW counter, timeout-sig-tree outputs |
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

### Decker-Wattenhofer Invalidation

Newer states get shorter relative timelocks, so they always confirm first:

```
State 0 (oldest): nSequence = 432 blocks  <- trapped behind newer states
State 1:          nSequence = 288 blocks
State 2:          nSequence = 144 blocks
State 3 (newest): nSequence = 0 blocks    <- confirms immediately
```

Multi-layer counter works like an odometer: 2 layers x 4 states = 16 epochs.

### Timeout-Sig-Trees (Phase 2)

State transaction outputs include a taproot script tree with a CLTV timeout fallback:

```
Output key = TapTweak(internal_key, merkle_root)
  Key path:    MuSig2(subset N-of-N)  — cooperative spend
  Script path: <cltv_timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP <LSP_pubkey> OP_CHECKSIG
```

If clients disappear, the LSP can unilaterally recover funds after the timeout expires. This is the core safety mechanism: the LSP is never stuck with locked capital indefinitely.

- **state_root outputs** (feeding kickoff_left/kickoff_right) get the taptree
- **kickoff outputs** remain pure key-path (circuit breaker)
- **leaf outputs** remain pure key-path (Poon-Dryja channels are a future phase)

## Implementation Status

### Phase 1: DW Factory Tree
- 6-node alternating kickoff/state tree topology
- MuSig2 N-of-N signing with taproot key-path tweak
- Multi-layer DW counter with odometer advancement
- Full on-chain broadcast and confirmation on regtest

### Phase 2: Timeout-Sig-Trees
- CLTV timeout script construction (BIP-341 tapscript)
- TapLeaf hashing, merkle root computation
- Taproot output tweaking with script tree
- Script-path sighash (BIP-341 spend_type=0x02)
- Control block construction for single-leaf trees
- LSP timeout spend via script-path witness on regtest
- Key-path cooperative spending still works with taptree present

### Future Phases
- Poon-Dryja payment channels at leaf outputs
- PTLC key turnover (scalar = client private key)
- Shachain-based L-output invalidation
- Factory laddering (30-day active + 3-day dying lifecycle)
- CTV upgrade path (replace N-of-N emulation with covenant)
