# SuperScalar: Scaling Lightning with Multi-Party Channel Factories

> One on-chain UTXO, many off-chain channels — no new opcodes required.

Based on [ZmnSCPxj's SuperScalar design](https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories/1143) (Sept 2024).

---

## The Problem

Today, an LSP serving N clients needs N separate on-chain transactions to open
N channels. Each channel locks up a UTXO and costs a mining fee. This doesn't
scale — an LSP with 1,000 clients needs 1,000 on-chain opens.

## The SuperScalar Solution

Put all N channels inside a single **channel factory** backed by 1 on-chain UTXO.
The factory is a tree of pre-signed transactions that can be updated off-chain
using the Decker-Wattenhofer (DW) state machine.

```
                    Standard LN                 SuperScalar
               ┌──────────────────┐     ┌──────────────────────┐
 On-chain      │  N separate      │     │  1 funding UTXO      │
 footprint     │  funding TXs     │     │  (N+1-of-N+1 MuSig2) │
               └──────────────────┘     └──────────────────────┘
 Channel       │  N UTXOs locked   │     │  N channels inside   │
 capacity      │  independently    │     │  shared tree          │
               └──────────────────┘     └──────────────────────┘
```

---

## Factory Tree Structure

The single funding UTXO fans out into a binary tree of pre-signed transactions.
Leaf nodes are individual payment channels between the LSP and each client.

```
 [Funding UTXO: 5-of-5 MuSig2]
          │
    [Kickoff TX]              ← spendable immediately (nSequence=final)
          │
    [State TX: epoch 7/15]    ← nSequence timeout encodes DW counter
       ┌──┴──┐
   [Left]    [Right]          ← subtree kickoffs (3-of-3 each)
    3-of-3    3-of-3
    ┌─┴─┐     ┌─┴─┐
  CH0   CH1  CH2   CH3       ← standard LN commitment transactions
  LSP   LSP  LSP   LSP
  ↕C1   ↕C2  ↕C3   ↕C4
```

Key properties:
- **Root**: N+1-of-N+1 MuSig2 (LSP + all clients must sign)
- **Subtrees**: Subsets of signers — only the LSP + relevant clients
- **Leaves**: Normal 2-of-2 channels with HTLCs, revocations, etc.
- **DW counter**: `nSequence` encodes which state is current; older states
  have longer timeouts, so the latest state confirms first

---

## Factory Lifecycle & Laddering

Factories have a finite lifetime (set by CLTV timeout). **Laddering** overlaps
factory lifetimes so clients always have an active channel:

```
 Factory 0: [═══════ ACTIVE ═══════|~~~ DYING ~~~|✗ expired]
 Factory 1:          [═══════ ACTIVE ═══════|~~~ DYING ~~~|✗]
                     ↑
               overlap = no downtime for clients
```

- **ACTIVE**: Normal payments flow. DW epochs advance off-chain.
- **DYING**: No new HTLCs. Clients are prompted to move to next factory.
- **Expired**: CLTV timeout reached. Unilateral close becomes possible.

The transition from Factory 0 → Factory 1 uses **PTLC key turnover** to
extract departing client secret keys, enabling the LSP to close Factory 0
without needing cooperation from clients who have already moved on.

---

## PTLC Key Turnover

When a client moves to a new factory, the LSP extracts the client's private
key for the old factory using adaptor signatures:

```
 LSP                              Client
  │                                  │
  │  ── PTLC_PRESIG ──────────►    │  LSP sends adaptor signature
  │     (presig tweaked by          │  locked to client's pubkey
  │      client's pubkey)           │
  │                                  │
  │  ◄── PTLC_ADAPTED_SIG ────    │  Client adapts signature,
  │     (reveals secret key         │  revealing their secret key
  │      in the process)            │  to the LSP
  │                                  │
  │  ── PTLC_COMPLETE ────────►    │  LSP confirms extraction
  │                                  │
```

With the extracted key, the LSP can produce all signatures needed to close
the old factory unilaterally — no client cooperation required.

---

## Payment Flow

Payments between clients are routed through the LSP, identical to standard
Lightning HTLC forwarding:

```
 Client 1 (sender)           LSP                Client 2 (receiver)
       │                       │                        │
       │ ── UPDATE_ADD_HTLC ──►│                        │
       │ ── COMMITMENT_SIGNED ►│                        │
       │ ◄─ REVOKE_AND_ACK ───│                        │
       │                       │── UPDATE_ADD_HTLC ────►│
       │                       │── COMMITMENT_SIGNED ──►│
       │                       │◄─ REVOKE_AND_ACK ─────│
       │                       │◄─ UPDATE_FULFILL_HTLC─│
       │                       │◄─ COMMITMENT_SIGNED ──│
       │                       │── REVOKE_AND_ACK ────►│
       │ ◄─ UPDATE_FULFILL ───│                        │
       │ ◄─ COMMITMENT_SIGNED─│                        │
       │ ── REVOKE_AND_ACK ──►│                        │
       │                       │                        │
```

Each hop validates SHA256(preimage) == payment_hash before forwarding.

---

## Comparison: SuperScalar vs Standard LN

| Property              | Standard LN (1:1)       | SuperScalar Factory       |
|-----------------------|-------------------------|---------------------------|
| On-chain txs to open  | N (one per client)      | 1 (shared funding UTXO)   |
| Signature scheme       | 2-of-2 MuSig2          | N+1-of-N+1 MuSig2 (root) |
| State updates          | Per-channel             | Tree-wide DW epochs       |
| Channel lifetime       | Unlimited               | Bounded (CLTV timeout)    |
| Unilateral close       | 1 tx per channel        | Tree of pre-signed txs    |
| Client independence    | Full                    | Requires LSP availability |
| Breach protection      | Standard revocations    | Revocations + watchtower  |
| Upgrade path           | —                       | CTV can replace MuSig2    |

---

## System Architecture

```
 ┌─────────────┐       ┌──────────┐       ┌──────────────────────┐
 │ CLN Node A  │──────►│  Bridge  │──────►│         LSP          │
 │  (plugin)   │◄──────│  daemon  │◄──────│  (factory + channels │
 └─────────────┘       └──────────┘       │   + DW state machine │
                                          │   + watchtower)       │
 ┌─────────────┐                          │        ┌───────┐     │
 │ CLN Node B  │◄── Lightning Network ──► │        │  WT   │     │
 └─────────────┘                          │        └───────┘     │
                                          └──┬───┬───┬───┬───────┘
                                             │   │   │   │
                                            C1  C2  C3  C4
                                          (daemon clients)
```

- **LSP**: Creates factories, routes payments, manages DW state
- **Clients**: Connect to LSP, hold channel state, send/receive payments
- **Bridge**: Translates between CLN wire protocol and SuperScalar protocol
- **Watchtower**: Monitors for revoked commitments, broadcasts penalty txs
- **CLN Plugin**: Intercepts `htlc_accepted`, forwards into SuperScalar

Wire protocol: TCP + length-prefixed JSON, 39 message types.
Factory creation: 3 round-trips (PROPOSE → NONCES → PSIGS → READY).
