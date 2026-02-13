#ifndef SUPERSCALAR_CHANNEL_H
#define SUPERSCALAR_CHANNEL_H

#include "types.h"
#include "musig.h"
#include "shachain.h"
#include "tapscript.h"
#include "tx_builder.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#define CHANNEL_DEFAULT_CSV_DELAY 144  /* ~1 day */
#define MAX_HTLCS 16

typedef enum { HTLC_OFFERED, HTLC_RECEIVED } htlc_direction_t;
typedef enum { HTLC_STATE_ACTIVE, HTLC_STATE_FULFILLED, HTLC_STATE_FAILED } htlc_state_t;

typedef struct {
    htlc_direction_t direction;
    htlc_state_t state;
    uint64_t amount_sats;
    unsigned char payment_hash[32];
    unsigned char payment_preimage[32];  /* filled on fulfill */
    uint32_t cltv_expiry;
    uint64_t id;
} htlc_t;

typedef struct {
    secp256k1_context *ctx;

    /* Funding output (from factory leaf state tx) */
    unsigned char funding_txid[32];
    uint32_t funding_vout;
    uint64_t funding_amount;
    unsigned char funding_spk[34];
    size_t funding_spk_len;

    /* Funding keys (order matters for MuSig keyagg) */
    secp256k1_pubkey local_funding_pubkey;
    secp256k1_pubkey remote_funding_pubkey;
    unsigned char local_funding_secret[32];
    musig_keyagg_t funding_keyagg;
    secp256k1_keypair local_funding_keypair;

    /* Local basepoints + secrets */
    secp256k1_pubkey local_payment_basepoint;
    unsigned char local_payment_basepoint_secret[32];
    secp256k1_pubkey local_delayed_payment_basepoint;
    unsigned char local_delayed_payment_basepoint_secret[32];
    secp256k1_pubkey local_revocation_basepoint;
    unsigned char local_revocation_basepoint_secret[32];
    secp256k1_pubkey local_htlc_basepoint;
    unsigned char local_htlc_basepoint_secret[32];

    /* Remote basepoints (public only) */
    secp256k1_pubkey remote_payment_basepoint;
    secp256k1_pubkey remote_delayed_payment_basepoint;
    secp256k1_pubkey remote_revocation_basepoint;
    secp256k1_pubkey remote_htlc_basepoint;

    /* Per-commitment state */
    unsigned char shachain_seed[32];
    shachain_t received_secrets;
    uint64_t commitment_number;

    /* Balance (satoshis) */
    uint64_t local_amount;
    uint64_t remote_amount;

    /* HTLCs */
    htlc_t htlcs[MAX_HTLCS];
    size_t n_htlcs;
    uint64_t next_htlc_id;

    /* Config */
    uint32_t to_self_delay;

    /* MuSig2 signer index: 0 or 1 in the canonical 2-of-2 keyagg order.
       Needed for distributed signing (Phase 12). */
    int local_funding_signer_idx;

    /* Nonce pools for commitment signing (Phase 12) */
    musig_nonce_pool_t  local_nonce_pool;
    unsigned char       remote_pubnonces_ser[MUSIG_NONCE_POOL_MAX][66];
    size_t              remote_nonce_count;
    size_t              remote_nonce_next;
} channel_t;

/* --- Key derivation (BOLT #3) --- */

/* Simple: derived = basepoint + SHA256(per_commitment_point || basepoint) * G */
int channel_derive_pubkey(const secp256k1_context *ctx, secp256k1_pubkey *derived,
                           const secp256k1_pubkey *basepoint,
                           const secp256k1_pubkey *per_commitment_point);

/* Two-scalar: revocation_key = rb*H1 + pcp*H2 */
int channel_derive_revocation_pubkey(const secp256k1_context *ctx,
                                      secp256k1_pubkey *derived,
                                      const secp256k1_pubkey *revocation_basepoint,
                                      const secp256k1_pubkey *per_commitment_point);

/* Private key version of simple derivation */
int channel_derive_privkey(const secp256k1_context *ctx, unsigned char *derived32,
                            const unsigned char *base_secret32,
                            const secp256k1_pubkey *per_commitment_point);

/* Private key version of revocation derivation */
int channel_derive_revocation_privkey(const secp256k1_context *ctx,
                                       unsigned char *derived32,
                                       const unsigned char *revocation_basepoint_secret32,
                                       const unsigned char *per_commitment_secret32,
                                       const secp256k1_pubkey *revocation_basepoint,
                                       const secp256k1_pubkey *per_commitment_point);

/* --- Channel lifecycle --- */

int channel_init(channel_t *ch, secp256k1_context *ctx,
                  const unsigned char *local_funding_secret32,
                  const secp256k1_pubkey *local_funding_pubkey,
                  const secp256k1_pubkey *remote_funding_pubkey,
                  const unsigned char *funding_txid, uint32_t funding_vout,
                  uint64_t funding_amount,
                  const unsigned char *funding_spk, size_t funding_spk_len,
                  uint64_t local_amount, uint64_t remote_amount,
                  uint32_t to_self_delay);

void channel_set_local_basepoints(channel_t *ch,
                                    const unsigned char *payment_secret32,
                                    const unsigned char *delayed_payment_secret32,
                                    const unsigned char *revocation_secret32);

void channel_set_remote_basepoints(channel_t *ch,
                                     const secp256k1_pubkey *payment,
                                     const secp256k1_pubkey *delayed_payment,
                                     const secp256k1_pubkey *revocation);

void channel_set_shachain_seed(channel_t *ch, const unsigned char *seed32);

int channel_get_per_commitment_point(const channel_t *ch, uint64_t commitment_num,
                                      secp256k1_pubkey *point_out);

int channel_get_per_commitment_secret(const channel_t *ch, uint64_t commitment_num,
                                       unsigned char *secret_out32);

/* --- Commitment TX --- */

int channel_build_commitment_tx(const channel_t *ch,
                                  tx_buf_t *unsigned_tx_out,
                                  unsigned char *txid_out32);

int channel_sign_commitment(const channel_t *ch,
                              tx_buf_t *signed_tx_out,
                              const tx_buf_t *unsigned_tx,
                              const secp256k1_keypair *remote_keypair);

/* --- Distributed commitment signing (Phase 12) --- */

/* Initialize nonce pool for channel commitment signing.
   Generates 'count' nonce pairs and stores in ch->local_nonce_pool. */
int channel_init_nonce_pool(channel_t *ch, size_t count);

/* Store peer's serialized pubnonces (received via MSG_CHANNEL_NONCES). */
int channel_set_remote_pubnonces(channel_t *ch,
                                   const unsigned char pubnonces[][66],
                                   size_t count);

/* Create partial sig for current commitment tx.
   Draws next nonce from local pool, uses peer's pubnonce at same index.
   Returns partial_sig (32 bytes serialized) and nonce_index used. */
int channel_create_commitment_partial_sig(
    channel_t *ch,
    unsigned char *partial_sig32_out,
    uint32_t *nonce_index_out);

/* Verify peer's partial sig and aggregate into full 64-byte Schnorr sig.
   Uses nonce at peer_nonce_index from both pools. */
int channel_verify_and_aggregate_commitment_sig(
    channel_t *ch,
    const unsigned char *peer_partial_sig32,
    uint32_t peer_nonce_index,
    unsigned char *full_sig64_out);

/* --- Revocation + Penalty --- */

int channel_get_revocation_secret(const channel_t *ch, uint64_t old_commitment_num,
                                    unsigned char *secret_out32);

int channel_receive_revocation(channel_t *ch, uint64_t commitment_num,
                                 const unsigned char *secret32);

int channel_build_penalty_tx(const channel_t *ch,
                               tx_buf_t *penalty_tx_out,
                               const unsigned char *commitment_txid,
                               uint32_t to_local_vout,
                               uint64_t to_local_amount,
                               const unsigned char *to_local_spk,
                               size_t to_local_spk_len,
                               uint64_t old_commitment_num);

/* --- Cooperative close --- */

int channel_build_cooperative_close_tx(
    const channel_t *ch,
    tx_buf_t *close_tx_out,
    unsigned char *txid_out32,   /* can be NULL */
    const secp256k1_keypair *remote_keypair,
    const tx_output_t *outputs,
    size_t n_outputs);

/* --- Channel update --- */

int channel_update(channel_t *ch, int64_t delta_sats);

void channel_update_funding(channel_t *ch,
                              const unsigned char *new_funding_txid,
                              uint32_t new_funding_vout,
                              uint64_t new_funding_amount,
                              const unsigned char *new_funding_spk,
                              size_t new_funding_spk_len);

/* --- HTLC basepoints --- */

void channel_set_local_htlc_basepoint(channel_t *ch,
                                        const unsigned char *htlc_secret32);

void channel_set_remote_htlc_basepoint(channel_t *ch,
                                         const secp256k1_pubkey *htlc_basepoint);

/* --- HTLC operations --- */

int channel_add_htlc(channel_t *ch, htlc_direction_t direction,
                      uint64_t amount_sats, const unsigned char *payment_hash32,
                      uint32_t cltv_expiry, uint64_t *htlc_id_out);

int channel_fulfill_htlc(channel_t *ch, uint64_t htlc_id,
                           const unsigned char *preimage32);

int channel_fail_htlc(channel_t *ch, uint64_t htlc_id);

/* --- HTLC resolution transactions --- */

int channel_build_htlc_success_tx(const channel_t *ch, tx_buf_t *signed_tx_out,
    const unsigned char *commitment_txid, uint32_t htlc_vout,
    uint64_t htlc_amount, const unsigned char *htlc_spk, size_t htlc_spk_len,
    size_t htlc_index);

int channel_build_htlc_timeout_tx(const channel_t *ch, tx_buf_t *signed_tx_out,
    const unsigned char *commitment_txid, uint32_t htlc_vout,
    uint64_t htlc_amount, const unsigned char *htlc_spk, size_t htlc_spk_len,
    size_t htlc_index);

int channel_build_htlc_penalty_tx(const channel_t *ch, tx_buf_t *penalty_tx_out,
    const unsigned char *commitment_txid, uint32_t htlc_vout,
    uint64_t htlc_amount, const unsigned char *htlc_spk, size_t htlc_spk_len,
    uint64_t old_commitment_num, size_t htlc_index);

#endif /* SUPERSCALAR_CHANNEL_H */
