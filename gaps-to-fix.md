# SuperScalar PoC — Gap Audit

Audit date: 2026-02-15. **All gaps closed: 2026-02-16.**

---

## 1. Real Basepoint Exchange — DONE

Each side generates random 32-byte basepoint secrets via `/dev/urandom`,
exchanges only pubkeys over the wire. Persisted in `channel_basepoints`
SQLite table. `channel_generate_random_basepoints()` replaces deterministic
`SHA256(pubkey || tag)` derivation.

## 2. Client-Side Watchtower — DONE

Client daemon initializes its own `watchtower_t` with regtest/fee/DB.
LSP sends `MSG_LSP_REVOKE_AND_ACK (0x50)` at all 9 revocation sites.
Client receives, stores via `channel_receive_revocation()`, registers with
`watchtower_watch_revoked_commitment()`. `watchtower_check()` runs on
select() timeout. Factory-level breach detection also added
(`WATCH_FACTORY_NODE` entry type).

## 3. Dynamic Commitment Fee — DONE

Commitment fee is now computed as `(154 + n_htlcs * 43) * fee_rate / 1000`
in both `lsp_channels.c` and `client.c`. Both sides agree on HTLC count at
signing time. Commit `2d8c509`.

## 4. Independent Shachain Seeds — DONE

Per-commitment secrets are now generated randomly, not derived from pubkeys.
Each side has private secrets; only `per_commitment_point` (pubkey) is shared.

## 5. HTLC Penalty Outputs — DONE

Watchtower sweeps both `to_local` AND HTLC outputs on breach. Per-commitment
HTLC snapshots stored in `old_commitment_htlcs` table. 9 LSP call sites
snapshot HTLC state before channel ops. Commit `03ded41`.

## 6. Timeout-Sig-Tree (Staggered Multi-Level Timeouts) — DONE

All 5 non-root factory nodes get timeout taptrees with staggered CLTVs
(`TIMEOUT_STEP_BLOCKS=5`: leaf=cltv-10, mid=cltv-5, root=cltv). Fixed
cltv_timeout ordering bug in `lsp_run_factory_creation()`. Multi-level
recovery demonstrated in `--test-expiry`. Commit `29cc45d`.

## 7. Client Breach Demo Mode — DONE

`run_demo.sh --client-breach` starts LSP with `--cheat-daemon`, 4 clients
detect breach and broadcast penalty. Colored output shows which clients
caught the cheat. Commit `8ffd20e`.

---

## What's Real

All of these components are fully realistic and broadcastable on regtest/signet:

- Factory funding TX (real P2TR on-chain UTXO)
- Factory tree MuSig2 signing (real distributed 5-of-5 over wire)
- DW tree nSequence/nLockTime (enforced by Bitcoin Core)
- Staggered timeout-sig-trees (multi-level CLTV taptrees on all factory nodes)
- Commitment tx structure (real P2TR + CSV taptree + HTLC outputs)
- Commitment signing (real distributed 2-of-2 MuSig2 partial sigs)
- Dynamic commitment fees (based on active HTLC count)
- Revocation key derivation (real BOLT#3 two-scalar math)
- Penalty tx signing (real Schnorr sig on derived revocation key)
- HTLC penalty sweeps (revoked HTLC outputs swept alongside to_local)
- Bidirectional revocation (LSP + client exchange secrets)
- Client-side watchtower (breach detection + penalty from client perspective)
- Factory-level breach detection (old state → latest state response)
- PTLC adaptor signatures (real secp256k1-zkp adaptor extraction)
- Factory rotation with PTLC key turnover (Factory 0 → Factory 1)
- Random basepoint secrets (per-channel, persisted in SQLite)

---

## Out of Scope (PoC boundaries)

These are known limitations that are intentional design boundaries for a
research prototype, not bugs or missing features.

### A. No inter-factory routing

Multi-hop payments across factory boundaries (factory A → factory B) are
not implemented. The PoC covers single-factory and ladder-within-one-LSP
topologies. Cross-factory routing would require a gossip/relay protocol
and pathfinding, which is production-scope work.

### B. No long-lived daemon stress tests

No multi-hour soak tests for memory leaks, fd exhaustion, reconnection
storms, or HTLC throughput under load. The daemon loop is correct for
demo-length runs. Production would need valgrind/ASAN profiling and
sustained-load test harnesses.

### C. No CI-automated signet/regtest regression

Regtest tests skip silently when `bitcoind` is not running. A CI pipeline
that provisions `bitcoind -regtest` and runs `--all` would catch regressions
in on-chain test paths. Currently all 20 regtest tests pass locally but
are not enforced in automation.
