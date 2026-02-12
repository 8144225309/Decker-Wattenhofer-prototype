#include "superscalar/musig.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

static const unsigned char test_seckey1[32] = {
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
};

static const unsigned char test_seckey2[32] = {
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
};

static const unsigned char test_msg[32] = {
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
};

int test_musig_aggregate_keys(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    TEST_ASSERT(ctx != NULL, "context creation");

    secp256k1_keypair kp1, kp2;
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kp1, test_seckey1), "keypair1");
    TEST_ASSERT(secp256k1_keypair_create(ctx, &kp2, test_seckey2), "keypair2");

    secp256k1_pubkey pubkeys[2];
    secp256k1_keypair_pub(ctx, &pubkeys[0], &kp1);
    secp256k1_keypair_pub(ctx, &pubkeys[1], &kp2);

    musig_keyagg_t keyagg;
    TEST_ASSERT(musig_aggregate_keys(ctx, &keyagg, pubkeys, 2), "key aggregation");

    unsigned char agg_ser[32];
    TEST_ASSERT(secp256k1_xonly_pubkey_serialize(ctx, agg_ser, &keyagg.agg_pubkey),
                "serialize aggregate key");

    int all_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (agg_ser[i] != 0) { all_zero = 0; break; }
    }
    TEST_ASSERT(!all_zero, "aggregate key should not be zero");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_musig_sign_verify(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_keypair kps[2];
    secp256k1_keypair_create(ctx, &kps[0], test_seckey1);
    secp256k1_keypair_create(ctx, &kps[1], test_seckey2);

    secp256k1_pubkey pubkeys[2];
    secp256k1_keypair_pub(ctx, &pubkeys[0], &kps[0]);
    secp256k1_keypair_pub(ctx, &pubkeys[1], &kps[1]);

    musig_keyagg_t keyagg;
    TEST_ASSERT(musig_aggregate_keys(ctx, &keyagg, pubkeys, 2), "key aggregation");

    unsigned char sig[64];
    TEST_ASSERT(musig_sign_all_local(ctx, sig, test_msg, kps, 2, &keyagg),
                "MuSig2 signing");

    TEST_ASSERT(secp256k1_schnorrsig_verify(ctx, sig, test_msg, 32, &keyagg.agg_pubkey),
                "signature verification");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_musig_wrong_message(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_keypair kps[2];
    secp256k1_keypair_create(ctx, &kps[0], test_seckey1);
    secp256k1_keypair_create(ctx, &kps[1], test_seckey2);

    secp256k1_pubkey pubkeys[2];
    secp256k1_keypair_pub(ctx, &pubkeys[0], &kps[0]);
    secp256k1_keypair_pub(ctx, &pubkeys[1], &kps[1]);

    musig_keyagg_t keyagg;
    musig_aggregate_keys(ctx, &keyagg, pubkeys, 2);

    unsigned char sig[64];
    musig_sign_all_local(ctx, sig, test_msg, kps, 2, &keyagg);

    unsigned char wrong_msg[32];
    memset(wrong_msg, 0x42, 32);
    TEST_ASSERT(!secp256k1_schnorrsig_verify(ctx, sig, wrong_msg, 32, &keyagg.agg_pubkey),
                "wrong message should fail verification");

    secp256k1_context_destroy(ctx);
    return 1;
}

int test_musig_taproot_sign(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_keypair kps[2];
    secp256k1_keypair_create(ctx, &kps[0], test_seckey1);
    secp256k1_keypair_create(ctx, &kps[1], test_seckey2);

    secp256k1_pubkey pubkeys[2];
    secp256k1_keypair_pub(ctx, &pubkeys[0], &kps[0]);
    secp256k1_keypair_pub(ctx, &pubkeys[1], &kps[1]);

    musig_keyagg_t keyagg;
    musig_aggregate_keys(ctx, &keyagg, pubkeys, 2);

    /* key-path only, no script tree */
    unsigned char sig[64];
    TEST_ASSERT(musig_sign_taproot(ctx, sig, test_msg, kps, 2, &keyagg, NULL),
                "taproot signing");

    /* To verify, we need the tweaked output key: P + H("TapTweak" || P) * G.
     * musig_sign_taproot modifies keyagg in place, so re-aggregate. */
    musig_keyagg_t keyagg2;
    musig_aggregate_keys(ctx, &keyagg2, pubkeys, 2);

    unsigned char internal_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &keyagg2.agg_pubkey);

    extern void sha256_tagged(const char *, const unsigned char *, size_t, unsigned char *);
    unsigned char tweak[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak);

    secp256k1_pubkey tweaked_pk;
    secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &keyagg2.cache, tweak);

    secp256k1_xonly_pubkey tweaked_xonly;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk);

    TEST_ASSERT(secp256k1_schnorrsig_verify(ctx, sig, test_msg, 32, &tweaked_xonly),
                "taproot sig verification against tweaked key");

    secp256k1_context_destroy(ctx);
    return 1;
}
