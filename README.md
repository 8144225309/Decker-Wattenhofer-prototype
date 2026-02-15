# SuperScalar

First implementation of [ZmnSCPxj's SuperScalar design](https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories/1143) — laddered timeout-tree-structured Decker-Wattenhofer channel factories for Bitcoin.

## What This Is

A Bitcoin channel factory protocol combining:

- **Decker-Wattenhofer invalidation** — alternating kickoff/state transaction layers with decrementing nSequence relative timelocks
- **Timeout-sig-trees** — N-of-N MuSig2 key-path spending with CLTV timeout script-path fallback
- **Poon-Dryja payment channels** — standard Lightning channels at leaf outputs with HTLCs
- **LSP + N clients** architecture — not symmetric N-of-N; the LSP participates in all branches

No consensus changes or soft forks required. Runs on Bitcoin today.

## Build

```
cd superscalar && mkdir -p build && cd build
cmake .. && make -j$(nproc)
```

Dependencies (auto-fetched via CMake FetchContent):
- [secp256k1-zkp](https://github.com/BlockstreamResearch/secp256k1-zkp) — MuSig2, Schnorr signatures, extrakeys
- [cJSON](https://github.com/DaveGamble/cJSON) — JSON parsing for bitcoin-cli output

System dependency:
- SQLite3 — persistence layer

## Test

152 tests (133 unit + 19 regtest integration).

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
| `adaptor` | adaptor.c | MuSig2 adaptor signatures, PTLC key turnover protocol |
| `ladder` | ladder.c | Ladder manager: overlapping factory lifecycle, key turnover tracking, migration |
| `wire` | wire.c | TCP transport, length-prefixed JSON framing, 39 message types, message logging callback |
| `lsp` | lsp.c | LSP server: accept clients, factory creation ceremony, cooperative close |
| `client` | client.c | Client: connect to LSP, factory ceremony, channel operations, factory rotation, close |
| `lsp_channels` | lsp_channels.c | LSP channel manager: HTLC forwarding, event loop, balance-aware close, watchtower, multi-factory monitoring |
| `regtest` | regtest.c | bitcoin-cli subprocess harness for integration testing |
| `util` | util.c | SHA-256, tagged hashing (BIP-340/341), hex encoding, byte utilities |
| `persist` | persist.c | SQLite3 persistence: 16 tables (factories, channels, HTLCs, revocations, nonce pools, old commitments, wire messages, tree nodes, ladder factories, dw counter, departed clients, invoices, HTLC origins, client invoices, id counters) |
| `bridge` | bridge.c | CLN bridge daemon for Lightning Network connectivity |
| `fee` | fee.c | Configurable fee estimation: penalty, HTLC, and factory tx fee computation |
| `watchtower` | watchtower.c | Breach detection: monitors chain for revoked commitments, builds and broadcasts penalty txs |
| `keyfile` | keyfile.c | Encrypted keyfile: AES-256-CBC key storage with passphrase-derived encryption |

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

### Watchtower

Monitors the blockchain for revoked commitment transactions:

- Tracks old commitment txids after each `REVOKE_AND_ACK`
- Polls chain every 5 seconds during daemon mode
- On breach detection: builds penalty tx, broadcasts it, claims full channel balance
- Persists watched commitments in SQLite for crash recovery

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

### Phase 8a: Adaptor Signatures
- MuSig2 adaptor signature wrappers (adapt, extract, nonce parity)
- Pre-signatures that require a secret scalar to become valid Schnorr signatures
- Taproot-compatible adaptor signatures (key-path with tweak)

### Phase 8b: PTLC Key Turnover
- Atomic key reveal: client adapts pre-signature with private key, LSP extracts it
- LSP "sockpuppet" signing: uses extracted key to sign as departed client
- Factory cooperative close using extracted keys (all clients departed)
- Regtest: fund factory, PTLC key turnover, LSP coop-closes with extracted keys

### Phase 8c: Factory Lifecycle
- State machine: ACTIVE (30 days) -> DYING (3 days) -> EXPIRED
- Block-height queries: blocks until dying, blocks until expired
- Distribution transaction (inverted timelock default): pre-signed nLockTime tx defaults funds to clients after CLTV timeout
- Regtest: distribution tx rejected before timeout, accepted after mining past nLockTime

### Phase 8d: Ladder Manager
- Multi-factory orchestration with overlapping lifecycles
- Per-client key turnover tracking and departure recording
- Cooperative close construction using extracted keys for all departed clients
- Regtest: full migration demo (fund F1 -> PTLC exit -> close F1 -> fund F2)
- Regtest: distribution tx fallback when clients don't exit

### Phase 9: Wire Protocol
- TCP transport with length-prefixed JSON message framing
- 22 base message types: HELLO handshake, factory creation, channel operations, cooperative close
- LSP + N client architecture with HELLO/HELLO_ACK handshake
- Factory creation over wire: 3 round-trips (PROPOSE → NONCES → PSIGS → READY)
- Cooperative close over wire: 2 round-trips on funding output's N+1 key
- Standalone binaries: `superscalar_lsp` and `superscalar_client`
- Regtest: full TCP factory creation + cooperative close with forked client processes

### Phase 10: Channel Operations + PoC Hardening
- 7 channel wire message types: CHANNEL_READY, ADD_HTLC, COMMITMENT_SIGNED, REVOKE_AND_ACK, FULFILL_HTLC, FAIL_HTLC, CLOSE_REQUEST
- LSP channel manager with HTLC forwarding (sender → LSP → recipient)
- Client channel handlers with callback-based session loop
- Full HTLC payment round-trip: ADD_HTLC → COMMIT_SIGNED → REVOKE_AND_ACK → FULFILL
- Multi-payment support: scripted action sequences (SEND/RECV) per client
- Select()-based LSP event loop handling messages from any client
- Balance-aware cooperative close: outputs reflect actual channel balances after payments
- Input validation, network hardening, memory safety, graceful shutdown
- Standalone LSP/client binaries with CLI argument parsing

### Phase 12: Real Commitment Signatures
- MuSig2 partial signatures replace dummy signatures for commitment txs
- Nonce pool management for distributed 2-of-2 signing

### Phase 13: Persistence (SQLite)
- 16 database tables: factories, factory_participants, channels, revocation_secrets, htlcs, nonce_pools, old_commitments, wire_messages, tree_nodes, ladder_factories, dw_counter_state, departed_clients, invoice_registry, htlc_origins, client_invoices, id_counters
- `--db PATH` flag on both LSP and client binaries
- Full state round-trip: save and reload factory, channel, HTLC, and nonce pool state

### Phase 14: CLN Bridge
- Bridge daemon (`superscalar_bridge`) connecting SuperScalar to CLN
- 8 MSG_BRIDGE_* wire messages (0x40-0x47) for HTLC forwarding
- Invoice registry for routing inbound payments to correct client
- CLN plugin (`tools/cln_plugin.py`) with htlc_accepted hook + superscalar-pay RPC

### Phase 15: Daemon Mode
- `--daemon` flag for long-lived LSP and client processes
- Select()-based daemon loop with 5-second timeout and graceful shutdown
- MSG_REGISTER_INVOICE (0x38): clients register payment hashes with LSP
- Client auto-fulfillment of received HTLCs with preimage lookup

### Phase 16: Client Reconnection
- MSG_RECONNECT (0x48) + MSG_RECONNECT_ACK (0x49) wire messages
- LSP daemon loop: listen socket in select(), pubkey-matched reconnection
- Client reconnect from persisted state with nonce re-exchange
- Retry loop with 5-second backoff on disconnect

### Phase 17: Demo Polish
- MSG_CREATE_INVOICE (0x4A) + MSG_INVOICE_CREATED (0x4B) wire messages
- Client-side invoice store: random preimage → SHA256 → payment_hash
- LSP-orchestrated client-to-client payments with real preimage validation
- `--demo` flag: scripted 4-payment demo sequence with balance reporting

### Phase 18: Watchtower + Fee Estimation
- **Fee estimation module** (`fee.c`): configurable `--fee-rate` (sat/kvB), replaces all hardcoded 500-sat fees
  - Penalty tx: ~152 vB, HTLC tx: ~180 vB, factory tx: ~50+43*n vB
  - Integrated into channel.c (4 fee sites) and factory.c (tree build)
- **Watchtower** (`watchtower.c`): breach detection and penalty enforcement
  - Monitors chain for revoked commitment txids every 5s in daemon loop
  - Builds and broadcasts penalty txs via `channel_build_penalty_tx()`
  - Old commitment tracking persisted in `old_commitments` SQLite table
  - Integrated into LSP daemon loop via `lsp_channel_mgr_t.watchtower`
- **Persistence**: new `old_commitments` table (7th table) for watchtower state
- **Regtest helper**: `regtest_get_raw_tx()` for tx hex retrieval
- 134/134 tests pass (115 unit + 19 regtest)

### Phase 19: Encrypted Transport
- ChaCha20-Poly1305 AEAD encryption (RFC 7539)
- HMAC-SHA256 key derivation (RFC 4231)
- Noise-style XX handshake: ephemeral ECDH + static key exchange
- All wire messages encrypted after handshake with rotating nonces

### Phase 20: Signet Interop
- `--network` flag (regtest/signet/testnet/mainnet), `--cli-path`, `--rpcuser`, `--rpcpassword`
- Signet-aware funding: balance check + confirmation wait instead of mining
- Bridge integration in daemon loop: message-type dispatch (BRIDGE_HELLO vs RECONNECT)
- CLN plugin: real `lightning-cli pay` via subprocess + `superscalar-pay` RPC
- `tools/signet_setup.sh`: subcommand-based signet infrastructure setup (14 commands)

### Phase 21: Web Dashboard + Signet Setup Rewrite
- `tools/dashboard.py`: stdlib-only Python3 web dashboard (http.server + sqlite3 + subprocess)
  - Dark theme, 7 tabs (Overview, Factory, Channels, Protocol Log, Lightning, Watchtower, Events)
  - 4 data collectors (processes, bitcoin, databases, CLN), auto-refresh
  - `--demo` mode with simulated data for UI preview
- `tools/signet_setup.sh`: rewritten with 14 subcommands, colored output, python3 JSON parsing

### Phase 22: Persist In-Memory State + Dashboard Exposure
- **Wire message logging**: callback mechanism in `wire_send()`/`wire_recv()`, fd-to-peer-label map, all 36 message types named
- **3 new SQLite tables**: `wire_messages` (protocol log), `tree_nodes` (factory tree topology), `ladder_factories` (lifecycle state)
- **Dashboard Protocol Log tab**: color-coded message categories (channel/factory/bridge/close/invoice/error)
- **Dashboard tree visualization**: interactive factory tree node layout + detail table
- **Dashboard ladder section**: factory lifecycle progress bars (ACTIVE → DYING → EXPIRED)
- 137/137 tests pass (118 unit + 19 regtest)

### Phase 23: Persistence Hardening
- **6 new SQLite tables**: dw_counter_state, departed_clients, invoice_registry, htlc_origins, client_invoices, id_counters
- **14 new persist functions**: save/load/deactivate for DW counter epochs, departed client keys, invoice registry, HTLC origin tracking, client invoices, ID counters
- **LSP wiring**: persist invoice registration, HTLC origin tracking, fulfillment deactivation, DW counter save on factory creation, startup reload from DB
- **Client wiring**: persist client invoices on creation, deactivate on preimage consumption, reload on daemon startup
- **Dashboard**: 6 new queries, demo data, and display sections for all new tables
- 143/143 tests pass (124 unit + 19 regtest)

### Tier 1: Demo Protections
- `--breach-test`: broadcast revoked commitment after demo, trigger penalty tx
- `--test-expiry`: mine past CLTV timeout, recover via timeout script path
- `--test-distrib`: mine past CLTV, broadcast pre-signed distribution tx
- `--test-turnover`: PTLC key turnover for all clients (local keypairs), cooperative close
- Factory lifecycle integration: `factory_set_lifecycle()` on factory creation, state monitoring in daemon loop
- 146/146 tests pass (127 unit + 19 regtest)

### Tier 2: Daemon Feature Wiring
- Ladder manager wired into LSP daemon loop: block-height polling, state transition logging
- Distribution tx construction and auto-broadcast on FACTORY_EXPIRED
- Departed client persistence: `persist_save_departed_client()` for crash recovery
- DW counter advancement logged and persisted during daemon block monitoring
- 149/149 tests pass (130 unit + 19 regtest)

### Tier 3: Factory Rotation + PTLC Wire Protocol
- **3 new PTLC wire messages**: MSG_PTLC_PRESIG (0x4C), MSG_PTLC_ADAPTED_SIG (0x4D), MSG_PTLC_COMPLETE (0x4E)
- **PTLC key turnover over wire**: LSP sends adaptor pre-signature, client adapts with secret key, LSP extracts key
- **Factory rotation**: `client_do_factory_rotation()` — condensed factory creation without HELLO handshake
- **Client daemon handling**: MSG_PTLC_PRESIG (adapt + send sig) and MSG_FACTORY_PROPOSE (rotation) in daemon callback
- **Multi-factory monitoring**: daemon loop tracks all ladder factory slots, not just factories[0]
- **`--test-rotation` flag**: full SuperScalar lifecycle demo:
  Factory 0 → payments → PTLC turnover over wire → ladder close → Factory 1 creation → payment → cooperative close
- 152/152 tests pass (133 unit + 19 regtest)

## License

MIT
