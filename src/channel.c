#include "superscalar/channel.h"
#include <string.h>
#include <stdlib.h>

extern void sha256(const unsigned char *, size_t, unsigned char *);
extern void sha256_tagged(const char *, const unsigned char *, size_t,
                           unsigned char *);
extern void reverse_bytes(unsigned char *, size_t);

/* ---- Key derivation (BOLT #3) ---- */

/* Simple: derived = basepoint + SHA256(per_commitment_point || basepoint) * G */
int channel_derive_pubkey(const secp256k1_context *ctx, secp256k1_pubkey *derived,
                           const secp256k1_pubkey *basepoint,
                           const secp256k1_pubkey *per_commitment_point) {
    unsigned char pcp_ser[33], bp_ser[33];
    size_t len = 33;

    if (!secp256k1_ec_pubkey_serialize(ctx, pcp_ser, &len, per_commitment_point,
                                        SECP256K1_EC_COMPRESSED))
        return 0;
    len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, bp_ser, &len, basepoint,
                                        SECP256K1_EC_COMPRESSED))
        return 0;

    /* tweak = SHA256(per_commitment_point || basepoint) */
    unsigned char hash_input[66];
    memcpy(hash_input, pcp_ser, 33);
    memcpy(hash_input + 33, bp_ser, 33);

    unsigned char tweak[32];
    sha256(hash_input, 66, tweak);

    /* derived = basepoint + tweak * G */
    *derived = *basepoint;
    if (!secp256k1_ec_pubkey_tweak_add(ctx, derived, tweak))
        return 0;

    return 1;
}

/* Two-scalar revocation:
   revocation_key = revocation_basepoint * SHA256(rb || pcp)
                  + per_commitment_point * SHA256(pcp || rb) */
int channel_derive_revocation_pubkey(const secp256k1_context *ctx,
                                      secp256k1_pubkey *derived,
                                      const secp256k1_pubkey *revocation_basepoint,
                                      const secp256k1_pubkey *per_commitment_point) {
    unsigned char rb_ser[33], pcp_ser[33];
    size_t len = 33;

    if (!secp256k1_ec_pubkey_serialize(ctx, rb_ser, &len, revocation_basepoint,
                                        SECP256K1_EC_COMPRESSED))
        return 0;
    len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, pcp_ser, &len, per_commitment_point,
                                        SECP256K1_EC_COMPRESSED))
        return 0;

    /* h1 = SHA256(rb || pcp) */
    unsigned char buf[66];
    memcpy(buf, rb_ser, 33);
    memcpy(buf + 33, pcp_ser, 33);
    unsigned char h1[32];
    sha256(buf, 66, h1);

    /* h2 = SHA256(pcp || rb) */
    memcpy(buf, pcp_ser, 33);
    memcpy(buf + 33, rb_ser, 33);
    unsigned char h2[32];
    sha256(buf, 66, h2);

    /* term1 = revocation_basepoint * h1 */
    secp256k1_pubkey term1 = *revocation_basepoint;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &term1, h1))
        return 0;

    /* term2 = per_commitment_point * h2 */
    secp256k1_pubkey term2 = *per_commitment_point;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &term2, h2))
        return 0;

    /* revocation_key = term1 + term2 */
    const secp256k1_pubkey *terms[2] = { &term1, &term2 };
    if (!secp256k1_ec_pubkey_combine(ctx, derived, terms, 2))
        return 0;

    return 1;
}

/* Private key: derived_secret = base_secret + SHA256(pcp || basepoint) */
int channel_derive_privkey(const secp256k1_context *ctx, unsigned char *derived32,
                            const unsigned char *base_secret32,
                            const secp256k1_pubkey *per_commitment_point) {
    /* Compute basepoint from base_secret */
    secp256k1_pubkey basepoint;
    if (!secp256k1_ec_pubkey_create(ctx, &basepoint, base_secret32))
        return 0;

    unsigned char pcp_ser[33], bp_ser[33];
    size_t len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, pcp_ser, &len, per_commitment_point,
                                        SECP256K1_EC_COMPRESSED))
        return 0;
    len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, bp_ser, &len, &basepoint,
                                        SECP256K1_EC_COMPRESSED))
        return 0;

    unsigned char hash_input[66];
    memcpy(hash_input, pcp_ser, 33);
    memcpy(hash_input + 33, bp_ser, 33);

    unsigned char tweak[32];
    sha256(hash_input, 66, tweak);

    /* derived = base_secret + tweak */
    memcpy(derived32, base_secret32, 32);
    if (!secp256k1_ec_seckey_tweak_add(ctx, derived32, tweak))
        return 0;

    return 1;
}

/* Revocation privkey: rb_secret * h1 + pcp_secret * h2 */
int channel_derive_revocation_privkey(const secp256k1_context *ctx,
                                       unsigned char *derived32,
                                       const unsigned char *revocation_basepoint_secret32,
                                       const unsigned char *per_commitment_secret32,
                                       const secp256k1_pubkey *revocation_basepoint,
                                       const secp256k1_pubkey *per_commitment_point) {
    unsigned char rb_ser[33], pcp_ser[33];
    size_t len = 33;

    if (!secp256k1_ec_pubkey_serialize(ctx, rb_ser, &len, revocation_basepoint,
                                        SECP256K1_EC_COMPRESSED))
        return 0;
    len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, pcp_ser, &len, per_commitment_point,
                                        SECP256K1_EC_COMPRESSED))
        return 0;

    /* h1 = SHA256(rb || pcp) */
    unsigned char buf[66];
    memcpy(buf, rb_ser, 33);
    memcpy(buf + 33, pcp_ser, 33);
    unsigned char h1[32];
    sha256(buf, 66, h1);

    /* h2 = SHA256(pcp || rb) */
    memcpy(buf, pcp_ser, 33);
    memcpy(buf + 33, rb_ser, 33);
    unsigned char h2[32];
    sha256(buf, 66, h2);

    /* term1 = rb_secret * h1 */
    unsigned char term1[32];
    memcpy(term1, revocation_basepoint_secret32, 32);
    if (!secp256k1_ec_seckey_tweak_mul(ctx, term1, h1))
        return 0;

    /* term2 = pcp_secret * h2 */
    unsigned char term2[32];
    memcpy(term2, per_commitment_secret32, 32);
    if (!secp256k1_ec_seckey_tweak_mul(ctx, term2, h2))
        return 0;

    /* derived = term1 + term2 */
    memcpy(derived32, term1, 32);
    if (!secp256k1_ec_seckey_tweak_add(ctx, derived32, term2))
        return 0;

    memset(term1, 0, 32);
    memset(term2, 0, 32);
    return 1;
}

/* ---- Channel state ---- */

int channel_init(channel_t *ch, secp256k1_context *ctx,
                  const unsigned char *local_funding_secret32,
                  const secp256k1_pubkey *local_funding_pubkey,
                  const secp256k1_pubkey *remote_funding_pubkey,
                  const unsigned char *funding_txid, uint32_t funding_vout,
                  uint64_t funding_amount,
                  const unsigned char *funding_spk, size_t funding_spk_len,
                  uint64_t local_amount, uint64_t remote_amount,
                  uint32_t to_self_delay) {
    memset(ch, 0, sizeof(*ch));
    ch->ctx = ctx;

    ch->local_funding_pubkey = *local_funding_pubkey;
    ch->remote_funding_pubkey = *remote_funding_pubkey;
    memcpy(ch->local_funding_secret, local_funding_secret32, 32);

    if (!secp256k1_keypair_create(ctx, &ch->local_funding_keypair,
                                    local_funding_secret32))
        return 0;

    /* MuSig key aggregation: order = [local, remote] */
    secp256k1_pubkey pks[2] = { *local_funding_pubkey, *remote_funding_pubkey };
    if (!musig_aggregate_keys(ctx, &ch->funding_keyagg, pks, 2))
        return 0;

    memcpy(ch->funding_txid, funding_txid, 32);
    ch->funding_vout = funding_vout;
    ch->funding_amount = funding_amount;
    memcpy(ch->funding_spk, funding_spk, funding_spk_len);
    ch->funding_spk_len = funding_spk_len;

    ch->local_amount = local_amount;
    ch->remote_amount = remote_amount;
    ch->to_self_delay = to_self_delay;
    ch->commitment_number = 0;

    shachain_init(&ch->received_secrets);

    return 1;
}

void channel_set_local_basepoints(channel_t *ch,
                                    const unsigned char *payment_secret32,
                                    const unsigned char *delayed_payment_secret32,
                                    const unsigned char *revocation_secret32) {
    memcpy(ch->local_payment_basepoint_secret, payment_secret32, 32);
    secp256k1_ec_pubkey_create(ch->ctx, &ch->local_payment_basepoint,
                                payment_secret32);

    memcpy(ch->local_delayed_payment_basepoint_secret,
           delayed_payment_secret32, 32);
    secp256k1_ec_pubkey_create(ch->ctx, &ch->local_delayed_payment_basepoint,
                                delayed_payment_secret32);

    memcpy(ch->local_revocation_basepoint_secret, revocation_secret32, 32);
    secp256k1_ec_pubkey_create(ch->ctx, &ch->local_revocation_basepoint,
                                revocation_secret32);
}

void channel_set_remote_basepoints(channel_t *ch,
                                     const secp256k1_pubkey *payment,
                                     const secp256k1_pubkey *delayed_payment,
                                     const secp256k1_pubkey *revocation) {
    ch->remote_payment_basepoint = *payment;
    ch->remote_delayed_payment_basepoint = *delayed_payment;
    ch->remote_revocation_basepoint = *revocation;
}

void channel_set_shachain_seed(channel_t *ch, const unsigned char *seed32) {
    memcpy(ch->shachain_seed, seed32, 32);
}

int channel_get_per_commitment_point(const channel_t *ch, uint64_t commitment_num,
                                      secp256k1_pubkey *point_out) {
    uint64_t index = ((UINT64_C(1) << 48) - 1) - commitment_num;
    unsigned char secret[32];
    shachain_from_seed(ch->shachain_seed, index, secret);

    int ok = secp256k1_ec_pubkey_create(ch->ctx, point_out, secret);
    memset(secret, 0, 32);
    return ok;
}

int channel_get_per_commitment_secret(const channel_t *ch, uint64_t commitment_num,
                                       unsigned char *secret_out32) {
    uint64_t index = ((UINT64_C(1) << 48) - 1) - commitment_num;
    shachain_from_seed(ch->shachain_seed, index, secret_out32);
    return 1;
}

/* ---- Commitment TX ---- */

int channel_build_commitment_tx(const channel_t *ch,
                                  tx_buf_t *unsigned_tx_out,
                                  unsigned char *txid_out32) {
    /* 1. Derive per_commitment_point */
    secp256k1_pubkey pcp;
    if (!channel_get_per_commitment_point(ch, ch->commitment_number, &pcp))
        return 0;

    /* 2. Derive revocation pubkey (from remote's revocation_basepoint + our pcp) */
    secp256k1_pubkey revocation_pubkey;
    if (!channel_derive_revocation_pubkey(ch->ctx, &revocation_pubkey,
                                            &ch->remote_revocation_basepoint, &pcp))
        return 0;

    /* 3. Derive delayed_payment pubkey */
    secp256k1_pubkey delayed_pubkey;
    if (!channel_derive_pubkey(ch->ctx, &delayed_pubkey,
                                &ch->local_delayed_payment_basepoint, &pcp))
        return 0;

    /* 4. Derive remote_payment pubkey */
    secp256k1_pubkey remote_payment_pubkey;
    if (!channel_derive_pubkey(ch->ctx, &remote_payment_pubkey,
                                &ch->remote_payment_basepoint, &pcp))
        return 0;

    /* 5. Build to-local output: P2TR(revocation_key, csv_script) */
    secp256k1_xonly_pubkey revocation_xonly;
    secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &revocation_xonly, NULL,
                                        &revocation_pubkey);

    secp256k1_xonly_pubkey delayed_xonly;
    secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &delayed_xonly, NULL,
                                        &delayed_pubkey);

    tapscript_leaf_t csv_leaf;
    tapscript_build_csv_delay(&csv_leaf, ch->to_self_delay, &delayed_xonly,
                               ch->ctx);

    unsigned char merkle_root[32];
    tapscript_merkle_root(merkle_root, &csv_leaf, 1);

    secp256k1_xonly_pubkey to_local_tweaked;
    if (!tapscript_tweak_pubkey(ch->ctx, &to_local_tweaked, NULL,
                                 &revocation_xonly, merkle_root))
        return 0;

    tx_output_t outputs[2];

    /* to-local */
    build_p2tr_script_pubkey(outputs[0].script_pubkey, &to_local_tweaked);
    outputs[0].script_pubkey_len = 34;
    outputs[0].amount_sats = ch->local_amount;

    /* 6. Build to-remote output: P2TR(remote_payment_key) with key-path-only */
    secp256k1_xonly_pubkey remote_xonly;
    secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &remote_xonly, NULL,
                                        &remote_payment_pubkey);

    /* Key-path-only tweak: TapTweak(key, empty) */
    unsigned char internal_ser[32];
    secp256k1_xonly_pubkey_serialize(ch->ctx, internal_ser, &remote_xonly);
    unsigned char tweak[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak);

    secp256k1_pubkey remote_tweaked_full;
    if (!secp256k1_xonly_pubkey_tweak_add(ch->ctx, &remote_tweaked_full,
                                            &remote_xonly, tweak))
        return 0;
    secp256k1_xonly_pubkey remote_tweaked;
    secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &remote_tweaked, NULL,
                                        &remote_tweaked_full);

    build_p2tr_script_pubkey(outputs[1].script_pubkey, &remote_tweaked);
    outputs[1].script_pubkey_len = 34;
    outputs[1].amount_sats = ch->remote_amount;

    /* 7. Build unsigned tx */
    if (!build_unsigned_tx(unsigned_tx_out, txid_out32,
                            ch->funding_txid, ch->funding_vout,
                            0xFFFFFFFE, outputs, 2))
        return 0;

    /* Convert display-order txid to internal byte order (wire format),
       matching factory convention where node->txid is wire format. */
    if (txid_out32)
        reverse_bytes(txid_out32, 32);

    return 1;
}

int channel_sign_commitment(const channel_t *ch,
                              tx_buf_t *signed_tx_out,
                              const tx_buf_t *unsigned_tx,
                              const secp256k1_keypair *remote_keypair) {
    /* Compute sighash */
    unsigned char sighash[32];
    if (!compute_taproot_sighash(sighash, unsigned_tx->data, unsigned_tx->len,
                                  0, ch->funding_spk, ch->funding_spk_len,
                                  ch->funding_amount, 0xFFFFFFFE))
        return 0;

    /* Sign with MuSig2 (all-local for testing) */
    secp256k1_keypair kps[2];
    kps[0] = ch->local_funding_keypair;
    kps[1] = *remote_keypair;

    musig_keyagg_t keyagg_copy = ch->funding_keyagg;
    unsigned char sig64[64];
    if (!musig_sign_taproot(ch->ctx, sig64, sighash, kps, 2, &keyagg_copy, NULL))
        return 0;

    /* Finalize */
    if (!finalize_signed_tx(signed_tx_out, unsigned_tx->data, unsigned_tx->len,
                              sig64))
        return 0;

    return 1;
}

/* ---- Revocation + Penalty ---- */

int channel_get_revocation_secret(const channel_t *ch, uint64_t old_commitment_num,
                                    unsigned char *secret_out32) {
    return channel_get_per_commitment_secret(ch, old_commitment_num, secret_out32);
}

int channel_receive_revocation(channel_t *ch, uint64_t commitment_num,
                                 const unsigned char *secret32) {
    uint64_t index = ((UINT64_C(1) << 48) - 1) - commitment_num;
    return shachain_insert(&ch->received_secrets, index, secret32);
}

int channel_build_penalty_tx(const channel_t *ch,
                               tx_buf_t *penalty_tx_out,
                               const unsigned char *commitment_txid,
                               uint32_t to_local_vout,
                               uint64_t to_local_amount,
                               const unsigned char *to_local_spk,
                               size_t to_local_spk_len,
                               uint64_t old_commitment_num) {
    /* 1. Retrieve per_commitment_secret from received_secrets */
    uint64_t index = ((UINT64_C(1) << 48) - 1) - old_commitment_num;
    unsigned char pcp_secret[32];
    if (!shachain_derive(&ch->received_secrets, index, pcp_secret))
        return 0;

    /* 2. Compute per_commitment_point from secret */
    secp256k1_pubkey pcp;
    if (!secp256k1_ec_pubkey_create(ch->ctx, &pcp, pcp_secret))
        return 0;

    /* 3. Derive revocation privkey:
       Uses our revocation_basepoint_secret + their per_commitment_secret */
    unsigned char revocation_privkey[32];
    if (!channel_derive_revocation_privkey(ch->ctx, revocation_privkey,
                                             ch->local_revocation_basepoint_secret,
                                             pcp_secret,
                                             &ch->local_revocation_basepoint, &pcp))
        return 0;

    /* 4. Derive delayed_payment pubkey (needed to reconstruct taptree) */
    secp256k1_pubkey delayed_pubkey;
    if (!channel_derive_pubkey(ch->ctx, &delayed_pubkey,
                                &ch->remote_delayed_payment_basepoint, &pcp))
        return 0;

    /* 5. Rebuild CSV tapscript leaf + merkle root */
    secp256k1_xonly_pubkey delayed_xonly;
    secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &delayed_xonly, NULL,
                                        &delayed_pubkey);

    tapscript_leaf_t csv_leaf;
    tapscript_build_csv_delay(&csv_leaf, ch->to_self_delay, &delayed_xonly,
                               ch->ctx);

    unsigned char merkle_root[32];
    tapscript_merkle_root(merkle_root, &csv_leaf, 1);

    /* 6. Compute taproot tweak for the revocation key */
    secp256k1_pubkey revocation_pubkey;
    if (!secp256k1_ec_pubkey_create(ch->ctx, &revocation_pubkey, revocation_privkey))
        return 0;

    secp256k1_xonly_pubkey revocation_xonly;
    secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &revocation_xonly, NULL,
                                        &revocation_pubkey);

    unsigned char internal_ser[32];
    secp256k1_xonly_pubkey_serialize(ch->ctx, internal_ser, &revocation_xonly);

    unsigned char tweak_data[64];
    memcpy(tweak_data, internal_ser, 32);
    memcpy(tweak_data + 32, merkle_root, 32);
    unsigned char tweak[32];
    sha256_tagged("TapTweak", tweak_data, 64, tweak);

    /* Create keypair and apply taproot tweak */
    secp256k1_keypair tweaked_kp;
    if (!secp256k1_keypair_create(ch->ctx, &tweaked_kp, revocation_privkey))
        return 0;
    if (!secp256k1_keypair_xonly_tweak_add(ch->ctx, &tweaked_kp, tweak))
        return 0;

    /* 7. Build penalty tx output: P2TR(local_payment_basepoint) key-path-only */
    secp256k1_xonly_pubkey local_pay_xonly;
    secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &local_pay_xonly, NULL,
                                        &ch->local_payment_basepoint);

    /* Key-path-only tweak for output */
    unsigned char out_internal_ser[32];
    secp256k1_xonly_pubkey_serialize(ch->ctx, out_internal_ser, &local_pay_xonly);
    unsigned char out_tweak[32];
    sha256_tagged("TapTweak", out_internal_ser, 32, out_tweak);

    secp256k1_pubkey out_tweaked_full;
    if (!secp256k1_xonly_pubkey_tweak_add(ch->ctx, &out_tweaked_full,
                                            &local_pay_xonly, out_tweak))
        return 0;
    secp256k1_xonly_pubkey out_tweaked;
    secp256k1_xonly_pubkey_from_pubkey(ch->ctx, &out_tweaked, NULL,
                                        &out_tweaked_full);

    /* Fee: 500 sats */
    uint64_t penalty_amount = to_local_amount > 500 ? to_local_amount - 500 : 0;

    tx_output_t output;
    build_p2tr_script_pubkey(output.script_pubkey, &out_tweaked);
    output.script_pubkey_len = 34;
    output.amount_sats = penalty_amount;

    /* 8. Build unsigned penalty tx */
    tx_buf_t unsigned_tx;
    tx_buf_init(&unsigned_tx, 256);
    unsigned char penalty_txid[32];
    if (!build_unsigned_tx(&unsigned_tx, penalty_txid,
                            commitment_txid, to_local_vout,
                            0xFFFFFFFE, &output, 1)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* 9. Compute key-path sighash + sign */
    unsigned char sighash[32];
    if (!compute_taproot_sighash(sighash, unsigned_tx.data, unsigned_tx.len,
                                  0, to_local_spk, to_local_spk_len,
                                  to_local_amount, 0xFFFFFFFE)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    unsigned char sig64[64];
    if (!secp256k1_schnorrsig_sign32(ch->ctx, sig64, sighash, &tweaked_kp, NULL)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    /* 10. Finalize */
    if (!finalize_signed_tx(penalty_tx_out, unsigned_tx.data, unsigned_tx.len,
                              sig64)) {
        tx_buf_free(&unsigned_tx);
        return 0;
    }

    tx_buf_free(&unsigned_tx);
    memset(revocation_privkey, 0, 32);
    memset(pcp_secret, 0, 32);
    return 1;
}

/* ---- Channel update ---- */

int channel_update(channel_t *ch, int64_t delta_sats) {
    /* Positive delta: local pays remote. Negative: remote pays local. */
    if (delta_sats > 0 && (uint64_t)delta_sats > ch->local_amount)
        return 0;
    if (delta_sats < 0 && (uint64_t)(-delta_sats) > ch->remote_amount)
        return 0;

    ch->local_amount = (uint64_t)((int64_t)ch->local_amount - delta_sats);
    ch->remote_amount = (uint64_t)((int64_t)ch->remote_amount + delta_sats);
    ch->commitment_number++;
    return 1;
}

void channel_update_funding(channel_t *ch,
                              const unsigned char *new_funding_txid,
                              uint32_t new_funding_vout,
                              uint64_t new_funding_amount,
                              const unsigned char *new_funding_spk,
                              size_t new_funding_spk_len) {
    memcpy(ch->funding_txid, new_funding_txid, 32);
    ch->funding_vout = new_funding_vout;
    ch->funding_amount = new_funding_amount;
    memcpy(ch->funding_spk, new_funding_spk, new_funding_spk_len);
    ch->funding_spk_len = new_funding_spk_len;
}
