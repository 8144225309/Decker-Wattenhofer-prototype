#include "superscalar/musig.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

extern void sha256(const unsigned char *, size_t, unsigned char *);

static int fill_random(unsigned char *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return 0;
    size_t n = fread(buf, 1, len, f);
    fclose(f);
    return n == len ? 1 : 0;
}

int musig_aggregate_keys(
    const secp256k1_context *ctx,
    musig_keyagg_t *out,
    const secp256k1_pubkey *pubkeys,
    size_t n_pubkeys
) {
    const secp256k1_pubkey **ptrs = (const secp256k1_pubkey **)malloc(
        n_pubkeys * sizeof(secp256k1_pubkey *));
    if (!ptrs) return 0;

    for (size_t i = 0; i < n_pubkeys; i++)
        ptrs[i] = &pubkeys[i];

    int ret = secp256k1_musig_pubkey_agg(
        ctx, NULL, &out->agg_pubkey, &out->cache, ptrs, n_pubkeys
    );

    free(ptrs);
    return ret;
}

int musig_sign_all_local(
    const secp256k1_context *ctx,
    unsigned char *sig64_out,
    const unsigned char *msg32,
    const secp256k1_keypair *keypairs,
    size_t n_signers,
    const musig_keyagg_t *keyagg
) {
    int ret = 0;

    secp256k1_musig_secnonce *secnonces = (secp256k1_musig_secnonce *)calloc(
        n_signers, sizeof(secp256k1_musig_secnonce));
    secp256k1_musig_pubnonce *pubnonces = (secp256k1_musig_pubnonce *)calloc(
        n_signers, sizeof(secp256k1_musig_pubnonce));
    const secp256k1_musig_pubnonce **pubnonce_ptrs = (const secp256k1_musig_pubnonce **)malloc(
        n_signers * sizeof(secp256k1_musig_pubnonce *));
    secp256k1_musig_partial_sig *partial_sigs = (secp256k1_musig_partial_sig *)calloc(
        n_signers, sizeof(secp256k1_musig_partial_sig));
    const secp256k1_musig_partial_sig **psig_ptrs = (const secp256k1_musig_partial_sig **)malloc(
        n_signers * sizeof(secp256k1_musig_partial_sig *));

    if (!secnonces || !pubnonces || !pubnonce_ptrs || !partial_sigs || !psig_ptrs)
        goto cleanup;

    /* Generate nonces */
    for (size_t i = 0; i < n_signers; i++) {
        unsigned char session_id[32];
        unsigned char seckey[32];
        secp256k1_pubkey pk;

        if (!fill_random(session_id, 32))
            goto cleanup;
        if (!secp256k1_keypair_sec(ctx, seckey, &keypairs[i]))
            goto cleanup;
        if (!secp256k1_keypair_pub(ctx, &pk, &keypairs[i]))
            goto cleanup;

        if (!secp256k1_musig_nonce_gen(ctx, &secnonces[i], &pubnonces[i],
                                        session_id, seckey, &pk, msg32,
                                        &keyagg->cache, NULL))
            goto cleanup;

        memset(seckey, 0, 32);
        memset(session_id, 0, 32);
        pubnonce_ptrs[i] = &pubnonces[i];
    }

    /* Aggregate nonces */
    secp256k1_musig_aggnonce aggnonce;
    if (!secp256k1_musig_nonce_agg(ctx, &aggnonce, pubnonce_ptrs, n_signers))
        goto cleanup;

    /* Process -> session */
    secp256k1_musig_session session;
    if (!secp256k1_musig_nonce_process(ctx, &session, &aggnonce,
                                        msg32, &keyagg->cache, NULL))
        goto cleanup;

    /* Partial sign */
    for (size_t i = 0; i < n_signers; i++) {
        if (!secp256k1_musig_partial_sign(ctx, &partial_sigs[i],
                                           &secnonces[i], &keypairs[i],
                                           &keyagg->cache, &session))
            goto cleanup;
        psig_ptrs[i] = &partial_sigs[i];
    }

    /* Aggregate into final Schnorr sig */
    if (!secp256k1_musig_partial_sig_agg(ctx, sig64_out, &session,
                                          psig_ptrs, n_signers))
        goto cleanup;

    ret = 1;

cleanup:
    free(secnonces);
    free(pubnonces);
    free(pubnonce_ptrs);
    free(partial_sigs);
    free(psig_ptrs);
    return ret;
}

int musig_sign_taproot(
    const secp256k1_context *ctx,
    unsigned char *sig64_out,
    const unsigned char *msg32,
    const secp256k1_keypair *keypairs,
    size_t n_signers,
    musig_keyagg_t *keyagg,
    const unsigned char *merkle_root
) {
    unsigned char internal_key_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_key_ser, &keyagg->agg_pubkey))
        return 0;

    /* TapTweak = tagged_hash("TapTweak", internal_key [|| merkle_root]) */
    unsigned char tweak[32];
    {
        unsigned char tag_hash[32];
        sha256((const unsigned char *)"TapTweak", 8, tag_hash);

        size_t tweak_data_len = 64 + 32 + (merkle_root ? 32 : 0);
        unsigned char *tweak_data = (unsigned char *)malloc(tweak_data_len);
        memcpy(tweak_data, tag_hash, 32);
        memcpy(tweak_data + 32, tag_hash, 32);
        memcpy(tweak_data + 64, internal_key_ser, 32);
        if (merkle_root)
            memcpy(tweak_data + 96, merkle_root, 32);
        sha256(tweak_data, tweak_data_len, tweak);
        free(tweak_data);
    }

    /* Tweak the keyagg cache, then sign normally */
    secp256k1_pubkey tweaked_agg;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_agg,
                                                 &keyagg->cache, tweak))
        return 0;

    return musig_sign_all_local(ctx, sig64_out, msg32, keypairs, n_signers, keyagg);
}
