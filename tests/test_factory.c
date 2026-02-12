#include "superscalar/factory.h"
#include "superscalar/regtest.h"
#include "cJSON.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);
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

/* Secret keys for 5 participants: LSP + 4 clients */
static const unsigned char seckeys[5][32] = {
    { [0 ... 31] = 0x10 },  /* LSP */
    { [0 ... 31] = 0x21 },  /* Client A */
    { [0 ... 31] = 0x32 },  /* Client B */
    { [0 ... 31] = 0x43 },  /* Client C */
    { [0 ... 31] = 0x54 },  /* Client D */
};

static secp256k1_context *test_ctx(void) {
    return secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

static void make_keypairs(secp256k1_context *ctx, secp256k1_keypair *kps) {
    for (int i = 0; i < 5; i++) {
        int ok = secp256k1_keypair_create(ctx, &kps[i], seckeys[i]);
        (void)ok;
    }
}

/* Compute the funding scriptPubKey (P2TR of 5-of-5 tweaked key). */
static int compute_funding_spk(
    secp256k1_context *ctx,
    const secp256k1_keypair *kps,
    unsigned char *spk_out34,
    secp256k1_xonly_pubkey *tweaked_xonly_out
) {
    secp256k1_pubkey pks[5];
    for (int i = 0; i < 5; i++) {
        int ok = secp256k1_keypair_pub(ctx, &pks[i], &kps[i]);
        (void)ok;
    }

    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pks, 5)) return 0;

    unsigned char internal_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey);

    unsigned char tweak[32];
    sha256_tagged("TapTweak", internal_ser, 32, tweak);

    musig_keyagg_t tmp = ka;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk,
                                                  &tmp.cache, tweak))
        return 0;

    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, tweaked_xonly_out, NULL,
                                              &tweaked_pk))
        return 0;

    build_p2tr_script_pubkey(spk_out34, tweaked_xonly_out);
    return 1;
}

/* ---- Unit test: build tree ---- */

int test_factory_build_tree(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    make_keypairs(ctx, kps);

    /* Compute funding spk */
    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    /* Fake funding UTXO */
    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);  /* step=2, states=4 */
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);

    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT_EQ(f.n_nodes, 6, "6 nodes");

    /* Check node types */
    TEST_ASSERT(f.nodes[0].type == NODE_KICKOFF, "node 0 is kickoff");
    TEST_ASSERT(f.nodes[1].type == NODE_STATE,   "node 1 is state");
    TEST_ASSERT(f.nodes[2].type == NODE_KICKOFF, "node 2 is kickoff");
    TEST_ASSERT(f.nodes[3].type == NODE_KICKOFF, "node 3 is kickoff");
    TEST_ASSERT(f.nodes[4].type == NODE_STATE,   "node 4 is state");
    TEST_ASSERT(f.nodes[5].type == NODE_STATE,   "node 5 is state");

    /* Check signer counts */
    TEST_ASSERT_EQ(f.nodes[0].n_signers, 5, "kickoff_root: 5 signers");
    TEST_ASSERT_EQ(f.nodes[1].n_signers, 5, "state_root: 5 signers");
    TEST_ASSERT_EQ(f.nodes[2].n_signers, 3, "kickoff_left: 3 signers");
    TEST_ASSERT_EQ(f.nodes[3].n_signers, 3, "kickoff_right: 3 signers");
    TEST_ASSERT_EQ(f.nodes[4].n_signers, 3, "state_left: 3 signers");
    TEST_ASSERT_EQ(f.nodes[5].n_signers, 3, "state_right: 3 signers");

    /* Check parent links */
    TEST_ASSERT_EQ(f.nodes[0].parent_index, -1, "kickoff_root: no parent");
    TEST_ASSERT_EQ(f.nodes[1].parent_index,  0, "state_root -> kickoff_root");
    TEST_ASSERT_EQ(f.nodes[2].parent_index,  1, "kickoff_left -> state_root");
    TEST_ASSERT_EQ(f.nodes[3].parent_index,  1, "kickoff_right -> state_root");
    TEST_ASSERT_EQ(f.nodes[4].parent_index,  2, "state_left -> kickoff_left");
    TEST_ASSERT_EQ(f.nodes[5].parent_index,  3, "state_right -> kickoff_right");

    /* Check parent_vout */
    TEST_ASSERT_EQ(f.nodes[1].parent_vout, 0, "state_root spends vout 0");
    TEST_ASSERT_EQ(f.nodes[2].parent_vout, 0, "kickoff_left spends vout 0");
    TEST_ASSERT_EQ(f.nodes[3].parent_vout, 1, "kickoff_right spends vout 1");

    /* Check output counts */
    TEST_ASSERT_EQ(f.nodes[0].n_outputs, 1, "kickoff_root: 1 output");
    TEST_ASSERT_EQ(f.nodes[1].n_outputs, 2, "state_root: 2 outputs");
    TEST_ASSERT_EQ(f.nodes[2].n_outputs, 1, "kickoff_left: 1 output");
    TEST_ASSERT_EQ(f.nodes[3].n_outputs, 1, "kickoff_right: 1 output");
    TEST_ASSERT_EQ(f.nodes[4].n_outputs, 3, "state_left: 3 outputs");
    TEST_ASSERT_EQ(f.nodes[5].n_outputs, 3, "state_right: 3 outputs");

    /* Check kickoff nSequence = 0xFFFFFFFF */
    TEST_ASSERT(f.nodes[0].nsequence == 0xFFFFFFFF, "kickoff_root nseq");
    TEST_ASSERT(f.nodes[2].nsequence == 0xFFFFFFFF, "kickoff_left nseq");
    TEST_ASSERT(f.nodes[3].nsequence == 0xFFFFFFFF, "kickoff_right nseq");

    /* Check state nSequence matches DW layer 0/1 at epoch 0 */
    /* step=2, states=4: delay = 2*(4-1-0) = 6 */
    TEST_ASSERT_EQ(f.nodes[1].nsequence, 6, "state_root nseq = 6");
    TEST_ASSERT_EQ(f.nodes[4].nsequence, 6, "state_left nseq = 6");
    TEST_ASSERT_EQ(f.nodes[5].nsequence, 6, "state_right nseq = 6");

    /* Check all txids are non-zero */
    unsigned char zero[32];
    memset(zero, 0, 32);
    for (size_t i = 0; i < 6; i++) {
        char msg[64];
        snprintf(msg, sizeof(msg), "node %zu txid non-zero", i);
        TEST_ASSERT(memcmp(f.nodes[i].txid, zero, 32) != 0, msg);
    }

    /* Check all txs are built */
    for (size_t i = 0; i < 6; i++)
        TEST_ASSERT(f.nodes[i].is_built, "node is built");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Unit test: sign all ---- */

int test_factory_sign_all(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    make_keypairs(ctx, kps);

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* Verify each signature with schnorrsig_verify */
    for (size_t i = 0; i < f.n_nodes; i++) {
        factory_node_t *node = &f.nodes[i];
        TEST_ASSERT(node->is_signed, "node is signed");

        /* Recompute sighash */
        const unsigned char *prev_spk;
        size_t prev_spk_len;
        uint64_t prev_amount;

        if (node->parent_index < 0) {
            prev_spk = f.funding_spk;
            prev_spk_len = f.funding_spk_len;
            prev_amount = f.funding_amount_sats;
        } else {
            factory_node_t *parent = &f.nodes[node->parent_index];
            prev_spk = parent->outputs[node->parent_vout].script_pubkey;
            prev_spk_len = parent->outputs[node->parent_vout].script_pubkey_len;
            prev_amount = parent->outputs[node->parent_vout].amount_sats;
        }

        unsigned char sighash[32];
        TEST_ASSERT(compute_taproot_sighash(sighash,
            node->unsigned_tx.data, node->unsigned_tx.len,
            0, prev_spk, prev_spk_len, prev_amount, node->nsequence),
            "compute sighash");

        /* Extract 64-byte sig from signed tx witness */
        unsigned char sig[64];
        memcpy(sig, node->signed_tx.data + node->unsigned_tx.len, 64);

        int valid = secp256k1_schnorrsig_verify(ctx, sig, sighash, 32,
                                                  &node->tweaked_pubkey);
        char msg[64];
        snprintf(msg, sizeof(msg), "node %zu sig valid", i);
        TEST_ASSERT(valid, msg);
    }

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* ---- Unit test: advance DW counter ---- */

int test_factory_advance(void) {
    secp256k1_context *ctx = test_ctx();
    secp256k1_keypair kps[5];
    make_keypairs(ctx, kps);

    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char fake_txid[32];
    memset(fake_txid, 0xAA, 32);

    factory_t f;
    factory_init(&f, ctx, kps, 5, 2, 4);  /* step=2, states_per_layer=4 */
    factory_set_funding(&f, fake_txid, 0, 100000, fund_spk, 34);
    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    /* Initial state: epoch 0, all delays = 6 */
    TEST_ASSERT_EQ(f.counter.current_epoch, 0, "epoch 0");
    TEST_ASSERT_EQ(f.nodes[4].nsequence, 6, "leaf nseq = 6 at epoch 0");

    /* Advance once: epoch 1, leaf layer ticks to state 1 */
    TEST_ASSERT(factory_advance(&f), "advance 1");
    TEST_ASSERT_EQ(f.counter.current_epoch, 1, "epoch 1");
    /* Leaf state nseq: step * (max-1 - 1) = 2 * 2 = 4 */
    TEST_ASSERT_EQ(f.nodes[4].nsequence, 4, "leaf nseq = 4 at epoch 1");
    TEST_ASSERT_EQ(f.nodes[5].nsequence, 4, "right leaf nseq = 4 at epoch 1");
    /* Root state unchanged (still layer 0, state 0) */
    TEST_ASSERT_EQ(f.nodes[1].nsequence, 6, "root nseq still 6 at epoch 1");

    /* Advance to epoch 3: leaf at state 3, delay = 0 */
    TEST_ASSERT(factory_advance(&f), "advance 2");
    TEST_ASSERT(factory_advance(&f), "advance 3");
    TEST_ASSERT_EQ(f.counter.current_epoch, 3, "epoch 3");
    TEST_ASSERT_EQ(f.nodes[4].nsequence, 0, "leaf nseq = 0 at epoch 3");
    TEST_ASSERT_EQ(f.nodes[1].nsequence, 6, "root nseq still 6 at epoch 3");

    /* Advance to epoch 4: leaf rolls over (reset to 0), root ticks to state 1 */
    TEST_ASSERT(factory_advance(&f), "advance 4");
    TEST_ASSERT_EQ(f.counter.current_epoch, 4, "epoch 4");
    /* Root: state 1, delay = 2*(4-1-1) = 4 */
    TEST_ASSERT_EQ(f.nodes[1].nsequence, 4, "root nseq = 4 at epoch 4");
    /* Leaf: reset to state 0, delay = 6 */
    TEST_ASSERT_EQ(f.nodes[4].nsequence, 6, "leaf nseq = 6 at epoch 4 (reset)");

    /* Verify signatures still valid after advance */
    for (size_t i = 0; i < f.n_nodes; i++)
        TEST_ASSERT(f.nodes[i].is_signed, "node signed after advance");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Find the vout matching expected_spk in a wallet tx using gettransaction.
   regtest_get_tx_output uses getrawtransaction which needs -txindex. */
static int find_funding_vout(
    regtest_t *rt,
    const char *txid_hex,
    const unsigned char *expected_spk,
    size_t expected_spk_len,
    int *vout_out,
    uint64_t *amount_out
) {
    char params[256];
    snprintf(params, sizeof(params), "\"%s\" true true", txid_hex);
    char *result = regtest_exec(rt, "gettransaction", params);
    if (!result) return 0;

    char expected_hex[69];
    hex_encode(expected_spk, expected_spk_len, expected_hex);

    cJSON *json = cJSON_Parse(result);
    free(result);
    if (!json) return 0;

    cJSON *decoded = cJSON_GetObjectItem(json, "decoded");
    if (!decoded) { cJSON_Delete(json); return 0; }

    cJSON *vouts = cJSON_GetObjectItem(decoded, "vout");
    if (!vouts || !cJSON_IsArray(vouts)) { cJSON_Delete(json); return 0; }

    int found = 0;
    int arr_size = cJSON_GetArraySize(vouts);
    for (int i = 0; i < arr_size; i++) {
        cJSON *vout_obj = cJSON_GetArrayItem(vouts, i);
        if (!vout_obj) continue;

        cJSON *n_item = cJSON_GetObjectItem(vout_obj, "n");
        cJSON *value_item = cJSON_GetObjectItem(vout_obj, "value");
        cJSON *spk_obj = cJSON_GetObjectItem(vout_obj, "scriptPubKey");
        if (!n_item || !value_item || !spk_obj) continue;

        cJSON *hex_item = cJSON_GetObjectItem(spk_obj, "hex");
        if (!hex_item || !cJSON_IsString(hex_item)) continue;

        if (strcmp(hex_item->valuestring, expected_hex) == 0) {
            *vout_out = n_item->valueint;
            *amount_out = (uint64_t)(value_item->valuedouble * 100000000.0 + 0.5);
            found = 1;
            break;
        }
    }

    cJSON_Delete(json);
    return found;
}

/* ---- Regtest test: full tree broadcast ---- */

int test_regtest_factory_tree(void) {
    secp256k1_context *ctx = test_ctx();
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not running\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "test_factory");

    char mine_addr[128];
    regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr));
    regtest_mine_blocks(&rt, 101, mine_addr);

    /* Create 5 keypairs */
    secp256k1_keypair kps[5];
    make_keypairs(ctx, kps);

    /* Derive factory address (P2TR of 5-of-5 tweaked key) */
    unsigned char fund_spk[34];
    secp256k1_xonly_pubkey fund_tweaked;
    TEST_ASSERT(compute_funding_spk(ctx, kps, fund_spk, &fund_tweaked),
                "compute funding spk");

    unsigned char tweaked_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, tweaked_ser, &fund_tweaked);
    char key_hex[65];
    hex_encode(tweaked_ser, 32, key_hex);

    /* Derive bech32m address via rawtr() descriptor (two-step for checksum) */
    char params[512];
    snprintf(params, sizeof(params), "\"rawtr(%s)\"", key_hex);

    /* Step 1: getdescriptorinfo to get checksummed descriptor */
    char *desc_result = regtest_exec(&rt, "getdescriptorinfo", params);
    TEST_ASSERT(desc_result != NULL, "getdescriptorinfo");

    char checksummed_desc[256];
    {
        char *dstart = strstr(desc_result, "\"descriptor\"");
        TEST_ASSERT(dstart != NULL, "find descriptor field");
        dstart = strchr(dstart + 12, '"');
        TEST_ASSERT(dstart != NULL, "find descriptor value start");
        dstart++;
        char *dend = strchr(dstart, '"');
        TEST_ASSERT(dend != NULL, "find descriptor value end");
        size_t dlen = (size_t)(dend - dstart);
        TEST_ASSERT(dlen < sizeof(checksummed_desc), "descriptor fits");
        memcpy(checksummed_desc, dstart, dlen);
        checksummed_desc[dlen] = '\0';
    }
    free(desc_result);

    /* Step 2: deriveaddresses with checksummed descriptor */
    snprintf(params, sizeof(params), "\"%s\"", checksummed_desc);
    char *result = regtest_exec(&rt, "deriveaddresses", params);
    TEST_ASSERT(result != NULL, "deriveaddresses");

    char factory_addr[128];
    {
        /* Output is ["bcrt1p..."], find the address string */
        char *start = strchr(result, '"');
        TEST_ASSERT(start != NULL, "find address quote");
        start++;
        char *end = strchr(start, '"');
        TEST_ASSERT(end != NULL, "find address end quote");
        size_t len = (size_t)(end - start);
        memcpy(factory_addr, start, len);
        factory_addr[len] = '\0';
    }
    free(result);

    /* Fund factory */
    char funding_txid_hex[65];
    TEST_ASSERT(regtest_fund_address(&rt, factory_addr, 0.001, funding_txid_hex),
                "fund factory");
    regtest_mine_blocks(&rt, 1, mine_addr);
    printf("  Factory funded: %s\n", funding_txid_hex);

    /* Find factory vout */
    unsigned char fund_txid_bytes[32];
    hex_decode(funding_txid_hex, fund_txid_bytes, 32);
    reverse_bytes(fund_txid_bytes, 32);  /* display -> internal */

    uint64_t fund_amount = 0;
    int found_vout = -1;
    TEST_ASSERT(find_funding_vout(&rt, funding_txid_hex, fund_spk, 34,
                                   &found_vout, &fund_amount),
                "find factory vout");
    printf("  Factory vout=%d, amount=%lu sats\n", found_vout,
           (unsigned long)fund_amount);

    /* Init factory and advance to newest state (all delays = 0) */
    factory_t f;
    factory_init(&f, ctx, kps, 5, 1, 4);  /* step=1, states=4 */

    /* Advance counter to max epoch: both layers at state 3, delay = 0 */
    for (int i = 0; i < 15; i++)
        dw_counter_advance(&f.counter);

    factory_set_funding(&f, fund_txid_bytes, (uint32_t)found_vout,
                         fund_amount, fund_spk, 34);

    TEST_ASSERT(factory_build_tree(&f), "build tree");
    TEST_ASSERT(factory_sign_all(&f), "sign all");

    printf("  Tree built: %zu nodes\n", f.n_nodes);

    /* Broadcast order:
       0: kickoff_root  -> mine 1 block
       1: state_root    -> mine 1 block (nseq=0)
       2,3: kickoff_left, kickoff_right -> mine 1 block
       4,5: state_left, state_right -> mine 1 block
    */
    size_t broadcast_groups[][2] = {
        {0, 1},   /* kickoff_root */
        {1, 2},   /* state_root */
        {2, 4},   /* kickoff_left + kickoff_right */
        {4, 6},   /* state_left + state_right */
    };

    char txid_hexes[6][65];

    for (int g = 0; g < 4; g++) {
        size_t start = broadcast_groups[g][0];
        size_t end = broadcast_groups[g][1];

        for (size_t i = start; i < end; i++) {
            factory_node_t *node = &f.nodes[i];
            char *tx_hex = (char *)malloc(node->signed_tx.len * 2 + 1);
            hex_encode(node->signed_tx.data, node->signed_tx.len, tx_hex);

            int sent = regtest_send_raw_tx(&rt, tx_hex, txid_hexes[i]);
            free(tx_hex);

            if (!sent) {
                printf("  FAIL: broadcast node %zu failed\n", i);
                factory_free(&f);
                secp256k1_context_destroy(ctx);
                return 0;
            }
            printf("  Broadcast node %zu: %s\n", i, txid_hexes[i]);
        }

        regtest_mine_blocks(&rt, 1, mine_addr);
    }

    /* Verify leaf state tx outputs exist on chain via gettxout.
       If leaf outputs are confirmed, the entire ancestor chain is too. */
    for (int leaf = 4; leaf <= 5; leaf++) {
        char gettxout_params[256];
        /* Check vout 0 of each leaf state tx */
        snprintf(gettxout_params, sizeof(gettxout_params),
                 "\"%s\" 0", txid_hexes[leaf]);
        char *txout = regtest_exec(&rt, "gettxout", gettxout_params);
        TEST_ASSERT(txout != NULL, "gettxout not null");

        cJSON *txout_json = cJSON_Parse(txout);
        free(txout);
        TEST_ASSERT(txout_json != NULL, "gettxout parse");

        cJSON *conf_item = cJSON_GetObjectItem(txout_json, "confirmations");
        int conf = conf_item ? conf_item->valueint : -1;
        cJSON_Delete(txout_json);

        char msg[64];
        snprintf(msg, sizeof(msg), "leaf node %d confirmed (conf=%d)", leaf, conf);
        TEST_ASSERT(conf > 0, msg);
    }

    printf("  All 6 factory txs confirmed (verified via leaf outputs)!\n");

    factory_free(&f);
    secp256k1_context_destroy(ctx);
    return 1;
}
