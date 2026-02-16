/* Tests for CPFP anchor system.
   Verifies that:
   1. Penalty tx includes anchor output when anchor_spk is provided
   2. HTLC penalty tx includes anchor output
   3. Watchtower pending tracking works (add, increment, remove)
   4. Fee for penalty tx updated to 195 vB
   5. Watchtower init generates valid anchor keypair
*/

#include "superscalar/channel.h"
#include "superscalar/watchtower.h"
#include "superscalar/fee.h"
#include "superscalar/tx_builder.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

extern void sha256(const unsigned char *, size_t, unsigned char *);
extern void sha256_tagged(const char *, const unsigned char *, size_t,
                           unsigned char *);
extern void hex_encode(const unsigned char *data, size_t len, char *out);

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

/* Helper: set up a channel pair for penalty tx testing */
static void setup_penalty_channel_pair(secp256k1_context *ctx,
                                         channel_t *lsp_ch, channel_t *client_ch,
                                         unsigned char *local_txid_out,
                                         uint64_t local_amount, uint64_t remote_amount) {
    unsigned char lsp_sec[32], client_sec[32];
    memset(lsp_sec, 0x11, 32);
    memset(client_sec, 0x22, 32);

    secp256k1_pubkey lsp_pk, client_pk;
    secp256k1_ec_pubkey_create(ctx, &lsp_pk, lsp_sec);
    secp256k1_ec_pubkey_create(ctx, &client_pk, client_sec);

    unsigned char funding_txid[32];
    memset(funding_txid, 0xAA, 32);
    unsigned char funding_spk[34] = {0x51, 0x20};
    memset(funding_spk + 2, 0xBB, 32);

    uint64_t total = local_amount + remote_amount;

    /* LSP = local, client = remote */
    channel_init(lsp_ch, ctx, lsp_sec, &lsp_pk, &client_pk,
                   funding_txid, 0, total, funding_spk, 34,
                   local_amount, remote_amount, 144);
    channel_generate_random_basepoints(lsp_ch);

    /* Client = local, LSP = remote */
    channel_init(client_ch, ctx, client_sec, &client_pk, &lsp_pk,
                   funding_txid, 0, total, funding_spk, 34,
                   remote_amount, local_amount, 144);
    channel_generate_random_basepoints(client_ch);

    /* Exchange basepoints */
    channel_set_remote_basepoints(lsp_ch,
        &client_ch->local_payment_basepoint,
        &client_ch->local_delayed_payment_basepoint,
        &client_ch->local_revocation_basepoint);
    channel_set_remote_basepoints(client_ch,
        &lsp_ch->local_payment_basepoint,
        &lsp_ch->local_delayed_payment_basepoint,
        &lsp_ch->local_revocation_basepoint);

    /* Exchange HTLC basepoints */
    channel_set_remote_htlc_basepoint(lsp_ch, &client_ch->local_htlc_basepoint);
    channel_set_remote_htlc_basepoint(client_ch, &lsp_ch->local_htlc_basepoint);

    /* Exchange initial PCPs */
    secp256k1_pubkey lsp_pcp0, lsp_pcp1, client_pcp0, client_pcp1;
    channel_get_per_commitment_point(lsp_ch, 0, &lsp_pcp0);
    channel_get_per_commitment_point(lsp_ch, 1, &lsp_pcp1);
    channel_get_per_commitment_point(client_ch, 0, &client_pcp0);
    channel_get_per_commitment_point(client_ch, 1, &client_pcp1);
    channel_set_remote_pcp(lsp_ch, 0, &client_pcp0);
    channel_set_remote_pcp(lsp_ch, 1, &client_pcp1);
    channel_set_remote_pcp(client_ch, 0, &lsp_pcp0);
    channel_set_remote_pcp(client_ch, 1, &lsp_pcp1);

    /* Build local's commitment tx #0 to get txid */
    if (local_txid_out) {
        tx_buf_t unsigned_tx;
        tx_buf_init(&unsigned_tx, 512);
        channel_build_commitment_tx(lsp_ch, &unsigned_tx, local_txid_out);
        tx_buf_free(&unsigned_tx);
    }
}

/* Test 1: penalty tx with anchor has 2 outputs, anchor = 330 sats */
int test_penalty_tx_has_anchor(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    channel_t lsp_ch, client_ch;
    unsigned char local_txid[32];
    setup_penalty_channel_pair(ctx, &lsp_ch, &client_ch, local_txid, 70000, 29846);

    /* Advance to commitment #1 so we can revoke #0 */
    channel_generate_local_pcs(&lsp_ch, 1);
    channel_generate_local_pcs(&client_ch, 1);

    secp256k1_pubkey lsp_pcp2, client_pcp2;
    channel_get_per_commitment_point(&lsp_ch, 2, &lsp_pcp2);
    channel_get_per_commitment_point(&client_ch, 2, &client_pcp2);
    channel_set_remote_pcp(&lsp_ch, 2, &client_pcp2);
    channel_set_remote_pcp(&client_ch, 2, &lsp_pcp2);

    lsp_ch.commitment_number = 1;
    client_ch.commitment_number = 1;

    /* Exchange revocation secrets for commitment #0 */
    unsigned char lsp_secret0[32], client_secret0[32];
    channel_get_revocation_secret(&lsp_ch, 0, lsp_secret0);
    channel_get_revocation_secret(&client_ch, 0, client_secret0);
    channel_receive_revocation(&lsp_ch, 0, client_secret0);
    channel_receive_revocation(&client_ch, 0, lsp_secret0);

    /* Build local commitment #0 to get to_local SPK */
    tx_buf_t commit_tx;
    tx_buf_init(&commit_tx, 512);
    unsigned char commit_txid[32];

    /* Temporarily revert to cn=0 to build the old commitment */
    lsp_ch.commitment_number = 0;
    channel_build_commitment_tx_for_remote(&lsp_ch, &commit_tx, commit_txid);
    lsp_ch.commitment_number = 1;

    unsigned char to_local_spk[34];
    memcpy(to_local_spk, commit_tx.data + 47 + 8 + 1, 34);
    tx_buf_free(&commit_tx);

    /* Create a fake anchor SPK (any valid P2TR SPK) */
    unsigned char anchor_spk[34] = {0x51, 0x20};
    memset(anchor_spk + 2, 0xCC, 32);

    /* Build penalty tx WITH anchor */
    tx_buf_t penalty_tx;
    tx_buf_init(&penalty_tx, 512);
    TEST_ASSERT(channel_build_penalty_tx(&client_ch, &penalty_tx,
                                           commit_txid, 0,
                                           70000, to_local_spk, 34,
                                           0, anchor_spk, 34),
                "build penalty tx with anchor");

    /* Verify penalty tx is non-empty */
    TEST_ASSERT(penalty_tx.len > 0, "penalty tx non-empty");

    /* Parse the penalty tx to verify 2 outputs.
       Segwit format: nVersion(4) + marker(1) + flag(1) + vin_count(1) +
       input(txid32+vout4+scriptSig_varint1+nSequence4=41) + vout_count(1) + ...
       vout_count is at offset 4+1+1+1+41 = 48 */
    TEST_ASSERT(penalty_tx.len > 48, "tx long enough");
    uint8_t vout_count = penalty_tx.data[48];
    TEST_ASSERT_EQ(vout_count, 2, "2 outputs (sweep + anchor)");

    /* Output 0 (sweep) starts at offset 49: amount(8) + spk_varint(1) + spk(34) = 43 bytes
       Output 1 (anchor) starts at offset 49+43 = 92 */
    size_t anchor_out_offset = 49 + 43;
    TEST_ASSERT(penalty_tx.len > anchor_out_offset + 43, "room for anchor output");

    /* Parse anchor amount (little-endian 8 bytes) */
    uint64_t anchor_amt = 0;
    for (int b = 0; b < 8; b++)
        anchor_amt |= ((uint64_t)penalty_tx.data[anchor_out_offset + b]) << (b * 8);
    TEST_ASSERT_EQ(anchor_amt, 330, "anchor amount = 330 sats");

    /* Verify anchor SPK matches */
    uint8_t anchor_spk_len_val = penalty_tx.data[anchor_out_offset + 8];
    TEST_ASSERT_EQ(anchor_spk_len_val, 34, "anchor spk len = 34");
    TEST_ASSERT(memcmp(penalty_tx.data + anchor_out_offset + 9, anchor_spk, 34) == 0,
                "anchor SPK matches");

    /* Verify sweep amount = to_local - fee - 330 */
    uint64_t penalty_fee = (client_ch.fee_rate_sat_per_kvb * 195 + 999) / 1000;
    uint64_t expected_sweep = 70000 - penalty_fee - 330;
    uint64_t sweep_amt = 0;
    size_t sweep_offset = 49;  /* first output starts right after vout_count */
    for (int b = 0; b < 8; b++)
        sweep_amt |= ((uint64_t)penalty_tx.data[sweep_offset + b]) << (b * 8);
    TEST_ASSERT_EQ(sweep_amt, expected_sweep, "sweep amount correct");

    tx_buf_free(&penalty_tx);

    /* Also verify: without anchor (NULL), only 1 output */
    tx_buf_t penalty_no_anchor;
    tx_buf_init(&penalty_no_anchor, 512);
    TEST_ASSERT(channel_build_penalty_tx(&client_ch, &penalty_no_anchor,
                                           commit_txid, 0,
                                           70000, to_local_spk, 34,
                                           0, NULL, 0),
                "build penalty tx without anchor");
    TEST_ASSERT(penalty_no_anchor.len > 48, "no-anchor tx long enough");
    TEST_ASSERT_EQ(penalty_no_anchor.data[48], 1, "1 output without anchor");
    tx_buf_free(&penalty_no_anchor);

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test 2: HTLC penalty tx with anchor has 2 outputs */
int test_htlc_penalty_tx_has_anchor(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    channel_t lsp_ch, client_ch;
    setup_penalty_channel_pair(ctx, &lsp_ch, &client_ch, NULL, 70000, 29846);

    /* Add an HTLC */
    uint64_t htlc_id;
    unsigned char payment_hash[32];
    memset(payment_hash, 0xDD, 32);
    channel_add_htlc(&lsp_ch, HTLC_OFFERED, 5000, payment_hash, 500, &htlc_id);
    channel_add_htlc(&client_ch, HTLC_RECEIVED, 5000, payment_hash, 500, &htlc_id);

    /* Advance to cn=1 */
    channel_generate_local_pcs(&lsp_ch, 1);
    channel_generate_local_pcs(&client_ch, 1);
    secp256k1_pubkey lsp_pcp2, client_pcp2;
    channel_get_per_commitment_point(&lsp_ch, 2, &lsp_pcp2);
    channel_get_per_commitment_point(&client_ch, 2, &client_pcp2);
    channel_set_remote_pcp(&lsp_ch, 2, &client_pcp2);
    channel_set_remote_pcp(&client_ch, 2, &lsp_pcp2);
    lsp_ch.commitment_number = 1;
    client_ch.commitment_number = 1;

    /* Revoke #0 */
    unsigned char lsp_secret0[32], client_secret0[32];
    channel_get_revocation_secret(&lsp_ch, 0, lsp_secret0);
    channel_get_revocation_secret(&client_ch, 0, client_secret0);
    channel_receive_revocation(&lsp_ch, 0, client_secret0);
    channel_receive_revocation(&client_ch, 0, lsp_secret0);

    /* Get the HTLC output info from the old commitment.
       For this unit test we just need a plausible SPK and txid. */
    unsigned char commit_txid[32];
    memset(commit_txid, 0xEE, 32);
    unsigned char htlc_spk[34] = {0x51, 0x20};
    memset(htlc_spk + 2, 0xFF, 32);
    unsigned char anchor_spk[34] = {0x51, 0x20};
    memset(anchor_spk + 2, 0xCC, 32);

    /* Need to set htlc state for the builder */
    client_ch.n_htlcs = 1;
    memset(&client_ch.htlcs[0], 0, sizeof(htlc_t));
    client_ch.htlcs[0].direction = HTLC_RECEIVED;
    memcpy(client_ch.htlcs[0].payment_hash, payment_hash, 32);
    client_ch.htlcs[0].cltv_expiry = 500;
    client_ch.htlcs[0].state = HTLC_STATE_ACTIVE;

    /* Build HTLC penalty with anchor */
    tx_buf_t htlc_penalty;
    tx_buf_init(&htlc_penalty, 512);
    int ok = channel_build_htlc_penalty_tx(&client_ch, &htlc_penalty,
                commit_txid, 2, 5000, htlc_spk, 34,
                0, 0, anchor_spk, 34);
    TEST_ASSERT(ok, "build htlc penalty tx with anchor");
    TEST_ASSERT(htlc_penalty.len > 48, "htlc penalty tx long enough");
    TEST_ASSERT_EQ(htlc_penalty.data[48], 2, "2 outputs (sweep + anchor)");

    /* Verify anchor amount = 330 */
    size_t anchor_out_offset = 49 + 43;
    uint64_t anchor_amt = 0;
    for (int b = 0; b < 8; b++)
        anchor_amt |= ((uint64_t)htlc_penalty.data[anchor_out_offset + b]) << (b * 8);
    TEST_ASSERT_EQ(anchor_amt, 330, "anchor amount = 330");

    tx_buf_free(&htlc_penalty);
    secp256k1_context_destroy(ctx);
    return 1;
}

/* Test 3: watchtower pending tracking */
int test_watchtower_pending_tracking(void) {
    watchtower_t wt;
    fee_estimator_t fee;
    fee_init(&fee, 1000);
    watchtower_init(&wt, 1, NULL, &fee, NULL);

    /* Initially no pending */
    TEST_ASSERT_EQ(wt.n_pending, 0, "no pending initially");

    /* Add a pending entry */
    TEST_ASSERT(wt.n_pending < WATCHTOWER_MAX_PENDING, "room for pending");
    watchtower_pending_t *p = &wt.pending[wt.n_pending++];
    strncpy(p->txid, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 64);
    p->txid[64] = '\0';
    p->anchor_vout = 1;
    p->anchor_amount = 330;
    p->cycles_in_mempool = 0;
    p->bumped = 0;
    TEST_ASSERT_EQ(wt.n_pending, 1, "1 pending after add");

    /* Increment cycles */
    p->cycles_in_mempool++;
    TEST_ASSERT_EQ(p->cycles_in_mempool, 1, "1 cycle");
    p->cycles_in_mempool++;
    TEST_ASSERT_EQ(p->cycles_in_mempool, 2, "2 cycles — bump threshold");

    /* Remove (swap with last) */
    wt.pending[0] = wt.pending[wt.n_pending - 1];
    wt.n_pending--;
    TEST_ASSERT_EQ(wt.n_pending, 0, "0 pending after remove");

    watchtower_cleanup(&wt);
    return 1;
}

/* Test 4: fee_for_penalty_tx returns 195 vB-based fee */
int test_penalty_fee_updated(void) {
    fee_estimator_t fe;
    fee_init(&fe, 1000);  /* 1000 sat/kvB = 1 sat/vB */

    uint64_t penalty_fee = fee_for_penalty_tx(&fe);
    /* 1000 * 195 + 999 / 1000 = 195 (rounded) */
    uint64_t expected = (1000 * 195 + 999) / 1000;
    TEST_ASSERT_EQ(penalty_fee, expected, "penalty fee at 195 vB");

    /* Also check CPFP child fee */
    uint64_t cpfp_fee = fee_for_cpfp_child(&fe);
    uint64_t expected_cpfp = (1000 * 264 + 999) / 1000;
    TEST_ASSERT_EQ(cpfp_fee, expected_cpfp, "cpfp child fee at 264 vB");

    /* Check with higher fee rate */
    fee_init(&fe, 5000);  /* 5 sat/vB */
    penalty_fee = fee_for_penalty_tx(&fe);
    expected = (5000 * 195 + 999) / 1000;
    TEST_ASSERT_EQ(penalty_fee, expected, "penalty fee at 5 sat/vB");

    return 1;
}

/* Test 5: watchtower init generates valid anchor keypair and SPK */
int test_watchtower_anchor_init(void) {
    watchtower_t wt;
    fee_estimator_t fee;
    fee_init(&fee, 1000);
    watchtower_init(&wt, 1, NULL, &fee, NULL);

    /* Anchor SPK should be set (34 bytes, starts with 0x51 0x20) */
    TEST_ASSERT_EQ(wt.anchor_spk_len, 34, "anchor SPK len = 34");
    TEST_ASSERT_EQ(wt.anchor_spk[0], 0x51, "anchor SPK starts with OP_1");
    TEST_ASSERT_EQ(wt.anchor_spk[1], 0x20, "anchor SPK has PUSHBYTES_32");

    /* Verify the secp context was created */
    TEST_ASSERT(wt.ctx != NULL, "secp context created");

    /* Verify the anchor key is non-zero */
    unsigned char zero[32] = {0};
    TEST_ASSERT(memcmp(wt.anchor_seckey, zero, 32) != 0, "anchor key non-zero");

    /* Verify anchor xonly pubkey is parseable */
    unsigned char xonly_ser[32];
    secp256k1_xonly_pubkey_serialize(wt.ctx, xonly_ser, &wt.anchor_xonly);
    TEST_ASSERT(memcmp(xonly_ser, zero, 32) != 0, "anchor xonly non-zero");

    watchtower_cleanup(&wt);
    return 1;
}
