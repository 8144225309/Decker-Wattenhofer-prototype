#include "superscalar/persist.h"
#include "superscalar/factory.h"
#include "superscalar/musig.h"
#include "superscalar/channel.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void sha256(const unsigned char *, size_t, unsigned char *);
extern void sha256_tagged(const char *, const unsigned char *, size_t,
                           unsigned char *);

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

#define TEST_ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { \
        printf("  FAIL: %s (line %d): %s (got %ld, expected %ld)\n", \
               __func__, __LINE__, msg, (long)(a), (long)(b)); \
        return 0; \
    } \
} while(0)

static const unsigned char seckeys[5][32] = {
    { [0 ... 31] = 0x10 },
    { [0 ... 31] = 0x21 },
    { [0 ... 31] = 0x32 },
    { [0 ... 31] = 0x43 },
    { [0 ... 31] = 0x54 },
};

static secp256k1_context *test_ctx(void) {
    return secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

/* ---- Test 1: Open/close in-memory database ---- */

int test_persist_open_close(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open in-memory");
    TEST_ASSERT(db.db != NULL, "db handle");
    persist_close(&db);
    TEST_ASSERT(db.db == NULL, "db closed");
    return 1;
}

/* ---- Test 2: Channel save/load round-trip ---- */

int test_persist_channel_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    secp256k1_context *ctx = test_ctx();
    secp256k1_pubkey pk_local, pk_remote;
    secp256k1_ec_pubkey_create(ctx, &pk_local, seckeys[0]);
    secp256k1_ec_pubkey_create(ctx, &pk_remote, seckeys[1]);

    unsigned char fake_txid[32] = {0};
    fake_txid[0] = 0xDD;
    unsigned char fake_spk[34];
    memset(fake_spk, 0xAA, 34);

    channel_t ch;
    TEST_ASSERT(channel_init(&ch, ctx, seckeys[0], &pk_local, &pk_remote,
                              fake_txid, 1, 100000, fake_spk, 34,
                              50000, 50000, 144), "channel_init");

    /* Simulate some updates */
    ch.local_amount = 45000;
    ch.remote_amount = 55000;
    ch.commitment_number = 3;

    /* Save */
    TEST_ASSERT(persist_save_channel(&db, &ch, 0, 0), "save channel");

    /* Load */
    uint64_t local, remote, commit;
    TEST_ASSERT(persist_load_channel_state(&db, 0, &local, &remote, &commit),
                "load channel");
    TEST_ASSERT_EQ(local, 45000, "local_amount");
    TEST_ASSERT_EQ(remote, 55000, "remote_amount");
    TEST_ASSERT_EQ(commit, 3, "commitment_number");

    /* Update balance */
    TEST_ASSERT(persist_update_channel_balance(&db, 0, 40000, 60000, 4),
                "update balance");

    TEST_ASSERT(persist_load_channel_state(&db, 0, &local, &remote, &commit),
                "load updated");
    TEST_ASSERT_EQ(local, 40000, "updated local");
    TEST_ASSERT_EQ(remote, 60000, "updated remote");
    TEST_ASSERT_EQ(commit, 4, "updated commit");

    secp256k1_context_destroy(ctx);
    persist_close(&db);
    return 1;
}

/* ---- Test 3: Revocation secret save/load ---- */

int test_persist_revocation_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    /* Generate proper shachain secrets from a seed */
    unsigned char seed[32];
    memset(seed, 0x42, 32);

    unsigned char sec0[32], sec1[32], sec2[32];
    uint64_t idx0 = ((UINT64_C(1) << 48) - 1) - 0;
    uint64_t idx1 = ((UINT64_C(1) << 48) - 1) - 1;
    uint64_t idx2 = ((UINT64_C(1) << 48) - 1) - 2;

    shachain_from_seed(seed, idx0, sec0);
    shachain_from_seed(seed, idx1, sec1);
    shachain_from_seed(seed, idx2, sec2);

    TEST_ASSERT(persist_save_revocation(&db, 0, 0, sec0), "save rev 0");
    TEST_ASSERT(persist_save_revocation(&db, 0, 1, sec1), "save rev 1");
    TEST_ASSERT(persist_save_revocation(&db, 0, 2, sec2), "save rev 2");

    /* Load into shachain */
    shachain_t chain;
    TEST_ASSERT(persist_load_revocations(&db, 0, &chain), "load revocations");

    /* Verify we can derive the secrets back */
    unsigned char derived[32];
    TEST_ASSERT(shachain_derive(&chain, idx0, derived), "derive 0");
    TEST_ASSERT(memcmp(derived, sec0, 32) == 0, "secret 0 matches");
    TEST_ASSERT(shachain_derive(&chain, idx1, derived), "derive 1");
    TEST_ASSERT(memcmp(derived, sec1, 32) == 0, "secret 1 matches");
    TEST_ASSERT(shachain_derive(&chain, idx2, derived), "derive 2");
    TEST_ASSERT(memcmp(derived, sec2, 32) == 0, "secret 2 matches");

    persist_close(&db);
    return 1;
}

/* ---- Test 4: HTLC save/load round-trip ---- */

int test_persist_htlc_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    htlc_t h1 = {0};
    h1.direction = HTLC_OFFERED;
    h1.state = HTLC_STATE_ACTIVE;
    h1.amount_sats = 5000;
    memset(h1.payment_hash, 0xAB, 32);
    h1.cltv_expiry = 500;
    h1.id = 0;

    htlc_t h2 = {0};
    h2.direction = HTLC_RECEIVED;
    h2.state = HTLC_STATE_FULFILLED;
    h2.amount_sats = 3000;
    memset(h2.payment_hash, 0xCD, 32);
    memset(h2.payment_preimage, 0xEF, 32);
    h2.cltv_expiry = 600;
    h2.id = 1;

    TEST_ASSERT(persist_save_htlc(&db, 0, &h1), "save htlc 1");
    TEST_ASSERT(persist_save_htlc(&db, 0, &h2), "save htlc 2");

    htlc_t loaded[16];
    size_t count = persist_load_htlcs(&db, 0, loaded, 16);
    TEST_ASSERT_EQ(count, 2, "htlc count");

    TEST_ASSERT_EQ(loaded[0].id, 0, "htlc 0 id");
    TEST_ASSERT_EQ(loaded[0].direction, HTLC_OFFERED, "htlc 0 direction");
    TEST_ASSERT_EQ(loaded[0].state, HTLC_STATE_ACTIVE, "htlc 0 state");
    TEST_ASSERT_EQ(loaded[0].amount_sats, 5000, "htlc 0 amount");
    TEST_ASSERT_EQ(loaded[0].cltv_expiry, 500, "htlc 0 cltv");
    TEST_ASSERT(memcmp(loaded[0].payment_hash, h1.payment_hash, 32) == 0,
                "htlc 0 hash");

    TEST_ASSERT_EQ(loaded[1].id, 1, "htlc 1 id");
    TEST_ASSERT_EQ(loaded[1].direction, HTLC_RECEIVED, "htlc 1 direction");
    TEST_ASSERT_EQ(loaded[1].state, HTLC_STATE_FULFILLED, "htlc 1 state");
    TEST_ASSERT_EQ(loaded[1].amount_sats, 3000, "htlc 1 amount");
    TEST_ASSERT(memcmp(loaded[1].payment_preimage, h2.payment_preimage, 32) == 0,
                "htlc 1 preimage");

    persist_close(&db);
    return 1;
}

/* ---- Test 5: Factory save/load round-trip ---- */

int test_persist_factory_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    secp256k1_context *ctx = test_ctx();
    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++)
        secp256k1_ec_pubkey_create(ctx, &pks[i], seckeys[i]);

    /* Build factory */
    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, pks, 5);

    unsigned char internal_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey);
    unsigned char tweak[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak);
    musig_keyagg_t ka_copy = ka;
    secp256k1_pubkey tweaked_pk;
    secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &ka_copy.cache, tweak);
    secp256k1_xonly_pubkey tweaked_xonly;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk);
    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &tweaked_xonly);

    factory_t f;
    factory_init_from_pubkeys(&f, ctx, pks, 5, 10, 4);
    unsigned char fake_txid[32] = {0};
    fake_txid[0] = 0xDD;
    factory_set_funding(&f, fake_txid, 0, 1000000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");

    /* Save factory */
    TEST_ASSERT(persist_save_factory(&db, &f, ctx, 0), "save factory");

    /* Load factory into new struct */
    factory_t f2;
    TEST_ASSERT(persist_load_factory(&db, 0, &f2, ctx), "load factory");

    /* Verify */
    TEST_ASSERT_EQ(f2.n_participants, 5, "n_participants");
    TEST_ASSERT_EQ(f2.step_blocks, 10, "step_blocks");
    TEST_ASSERT_EQ(f2.funding_amount_sats, 1000000, "funding_amount");
    TEST_ASSERT_EQ(f2.n_nodes, f.n_nodes, "n_nodes");

    /* Verify txids match (the tree was rebuilt, so all node txids should match) */
    for (size_t i = 0; i < f.n_nodes; i++) {
        TEST_ASSERT(memcmp(f.nodes[i].txid, f2.nodes[i].txid, 32) == 0,
                    "node txid matches");
    }

    factory_free(&f);
    factory_free(&f2);
    secp256k1_context_destroy(ctx);
    persist_close(&db);
    return 1;
}

/* ---- Test 6: Nonce pool save/load round-trip ---- */

int test_persist_nonce_pool_round_trip(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    /* Save some fake pool data */
    unsigned char pool_data[128];
    memset(pool_data, 0x42, sizeof(pool_data));

    TEST_ASSERT(persist_save_nonce_pool(&db, 0, "local", pool_data, 128, 5),
                "save nonce pool");

    /* Load it back */
    unsigned char loaded[256];
    size_t data_len, next_idx;
    TEST_ASSERT(persist_load_nonce_pool(&db, 0, "local", loaded, 256,
                                          &data_len, &next_idx),
                "load nonce pool");
    TEST_ASSERT_EQ(data_len, 128, "data_len");
    TEST_ASSERT_EQ(next_idx, 5, "next_index");
    TEST_ASSERT(memcmp(loaded, pool_data, 128) == 0, "pool data matches");

    persist_close(&db);
    return 1;
}

/* ---- Test 7: Multiple channels in same database ---- */

int test_persist_multi_channel(void) {
    persist_t db;
    TEST_ASSERT(persist_open(&db, NULL), "open");

    secp256k1_context *ctx = test_ctx();
    secp256k1_pubkey pk_local, pk_remote;
    secp256k1_ec_pubkey_create(ctx, &pk_local, seckeys[0]);
    secp256k1_ec_pubkey_create(ctx, &pk_remote, seckeys[1]);

    unsigned char fake_txid[32] = {0};
    unsigned char fake_spk[34];
    memset(fake_spk, 0xAA, 34);

    /* Save 4 channels with different balances */
    for (uint32_t i = 0; i < 4; i++) {
        channel_t ch;
        fake_txid[0] = (unsigned char)(0xDD + i);
        channel_init(&ch, ctx, seckeys[0], &pk_local, &pk_remote,
                      fake_txid, i, 100000, fake_spk, 34,
                      50000 - i * 1000, 50000 + i * 1000, 144);
        ch.commitment_number = i;
        TEST_ASSERT(persist_save_channel(&db, &ch, 0, i), "save channel");
    }

    /* Load each and verify */
    for (uint32_t i = 0; i < 4; i++) {
        uint64_t local, remote, commit;
        TEST_ASSERT(persist_load_channel_state(&db, i, &local, &remote, &commit),
                    "load channel");
        TEST_ASSERT_EQ(local, 50000 - i * 1000, "local_amount");
        TEST_ASSERT_EQ(remote, 50000 + i * 1000, "remote_amount");
        TEST_ASSERT_EQ(commit, i, "commitment_number");
    }

    secp256k1_context_destroy(ctx);
    persist_close(&db);
    return 1;
}
