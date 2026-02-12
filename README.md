# SuperScalar Phase 0

Decker-Wattenhofer decrementing-nSequence invalidation on Bitcoin regtest.
Part of [ZmnSCPxj's SuperScalar design](https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories/1143).

## Build (WSL)

```
cd superscalar && mkdir build && cd build
cmake .. && make -j$(nproc)
```

## Test

```
# unit tests (no bitcoind needed)
LD_LIBRARY_PATH=./_deps/secp256k1-zkp-build/src:_deps/cjson-build ./test_superscalar --unit

# integration tests (needs bitcoind -regtest)
bitcoind -regtest -daemon -rpcuser=rpcuser -rpcpassword=rpcpass
LD_LIBRARY_PATH=./_deps/secp256k1-zkp-build/src:_deps/cjson-build ./test_superscalar --regtest
bitcoin-cli -regtest stop
```

## Modules

- `dw_state` — nSequence state machine, decrementing relative timelocks
- `musig` — MuSig2 key aggregation + 2-round signing (secp256k1-zkp)
- `tx_builder` — raw Bitcoin tx serialization, BIP-341 taproot sighash
- `regtest` — bitcoin-cli subprocess harness
- `util` — SHA-256, hex, byte helpers

## How it works

Each state transaction spends the factory UTXO with a relative timelock (nSequence, BIP-68).
Newer states get shorter timelocks, so the newest always confirms first.

```
State 0 (oldest): nSequence = 576 blocks
State 1:          nSequence = 432 blocks
State 2:          nSequence = 288 blocks
State 3 (newest): nSequence = 144 blocks  <- confirms first
```

Multiple layers work like an odometer: 3 layers x 4 states = 64 total state changes.
