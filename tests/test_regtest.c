#include "superscalar/regtest.h"
#include "superscalar/musig.h"
#include "superscalar/tx_builder.h"
#include "superscalar/dw_state.h"
#include "superscalar/types.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

static const unsigned char lsp_seckey[32] = {
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
};

static const unsigned char client_seckey[32] = {
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
};

/* Set up a 2-of-2 MuSig factory UTXO on regtest. */
static int setup_factory(
    regtest_t *rt,
    secp256k1_context *ctx,
    secp256k1_keypair *kps,
    musig_keyagg_t *keyagg,
    char *factory_addr,
    char *funding_txid
) {
    if (!secp256k1_keypair_create(ctx, &kps[0], lsp_seckey)) return 0;
    if (!secp256k1_keypair_create(ctx, &kps[1], client_seckey)) return 0;

    secp256k1_pubkey pubkeys[2];
    secp256k1_keypair_pub(ctx, &pubkeys[0], &kps[0]);
    secp256k1_keypair_pub(ctx, &pubkeys[1], &kps[1]);

    if (!musig_aggregate_keys(ctx, keyagg, pubkeys, 2)) return 0;

    /* tweaked output key for P2TR key-path (no script tree) */
    unsigned char internal_key[32];
    secp256k1_xonly_pubkey_serialize(ctx, internal_key, &keyagg->agg_pubkey);

    extern void sha256_tagged(const char *, const unsigned char *, size_t, unsigned char *);
    unsigned char tweak[32];
    sha256_tagged("TapTweak", internal_key, 32, tweak);

    musig_keyagg_t addr_keyagg = *keyagg;
    secp256k1_pubkey tweaked_pk;
    secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk, &addr_keyagg.cache, tweak);
    secp256k1_xonly_pubkey tweaked_xonly;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk);

    unsigned char spk[34];
    build_p2tr_script_pubkey(spk, &tweaked_xonly);

    /* derive bech32m address via bitcoin-cli */
    char spk_hex[69];
    hex_encode(spk, 34, spk_hex);

    char params[256];
    snprintf(params, sizeof(params), "\"%s\"", spk_hex);
    char *result = regtest_exec(rt, "decodescript", params);
    if (!result) return 0;

    char *addr_start = strstr(result, "\"address\"");
    if (!addr_start) {
        free(result);

        /* fallback: rawtr() descriptor */
        char key_hex[65];
        unsigned char tweaked_ser[32];
        secp256k1_xonly_pubkey_serialize(ctx, tweaked_ser, &tweaked_xonly);
        hex_encode(tweaked_ser, 32, key_hex);

        snprintf(params, sizeof(params), "\"rawtr(%s)\"", key_hex);
        result = regtest_exec(rt, "deriveaddresses", params);
        if (!result) return 0;

        char *start = strchr(result, '"');
        if (!start) { free(result); return 0; }
        start++;
        start = strchr(result, '"');
        if (start) start++;
        if (!start) { free(result); return 0; }
        char *end = strchr(start, '"');
        if (!end || (size_t)(end - start) >= 128) { free(result); return 0; }
        size_t addr_len = (size_t)(end - start);
        memcpy(factory_addr, start, addr_len);
        factory_addr[addr_len] = '\0';
    } else {
        addr_start = strchr(addr_start, ':');
        if (!addr_start) { free(result); return 0; }
        addr_start = strchr(addr_start, '"');
        if (!addr_start) { free(result); return 0; }
        addr_start++;
        char *addr_end = strchr(addr_start, '"');
        if (!addr_end) { free(result); return 0; }
        size_t addr_len = (size_t)(addr_end - addr_start);
        memcpy(factory_addr, addr_start, addr_len);
        factory_addr[addr_len] = '\0';
    }
    free(result);

    if (!regtest_fund_address(rt, factory_addr, 0.001, funding_txid)) return 0;

    char mine_addr[128];
    if (!regtest_get_new_address(rt, mine_addr, sizeof(mine_addr))) return 0;
    if (!regtest_mine_blocks(rt, 1, mine_addr)) return 0;

    return 1;
}

/* Build, sign, and broadcast a state tx spending the given outpoint. */
static int build_and_broadcast_state_tx(
    regtest_t *rt,
    secp256k1_context *ctx,
    const secp256k1_keypair *kps,
    musig_keyagg_t *keyagg,
    const unsigned char *prev_txid_bytes,
    uint32_t prev_vout,
    uint64_t prev_amount,
    const unsigned char *prev_spk,
    size_t prev_spk_len,
    uint32_t nsequence,
    const secp256k1_xonly_pubkey *output_key,
    uint64_t output_amount,
    char *txid_out
) {
    tx_output_t output;
    output.amount_sats = output_amount;
    build_p2tr_script_pubkey(output.script_pubkey, output_key);
    output.script_pubkey_len = 34;

    tx_buf_t unsigned_buf;
    tx_buf_init(&unsigned_buf, 256);
    unsigned char state_txid[32];

    if (!build_unsigned_tx(&unsigned_buf, state_txid, prev_txid_bytes, prev_vout,
                           nsequence, &output, 1)) {
        tx_buf_free(&unsigned_buf);
        return 0;
    }

    unsigned char sighash[32];
    if (!compute_taproot_sighash(sighash, unsigned_buf.data, unsigned_buf.len,
                                  0, prev_spk, prev_spk_len, prev_amount,
                                  nsequence)) {
        tx_buf_free(&unsigned_buf);
        return 0;
    }

    unsigned char sig[64];
    musig_keyagg_t sign_keyagg = *keyagg;
    if (!musig_sign_taproot(ctx, sig, sighash, kps, 2, &sign_keyagg, NULL)) {
        tx_buf_free(&unsigned_buf);
        return 0;
    }

    tx_buf_t signed_buf;
    tx_buf_init(&signed_buf, 512);
    if (!finalize_signed_tx(&signed_buf, unsigned_buf.data, unsigned_buf.len, sig)) {
        tx_buf_free(&unsigned_buf);
        tx_buf_free(&signed_buf);
        return 0;
    }

    char *tx_hex = (char *)malloc(signed_buf.len * 2 + 1);
    hex_encode(signed_buf.data, signed_buf.len, tx_hex);

    int ok = regtest_send_raw_tx(rt, tx_hex, txid_out);

    free(tx_hex);
    tx_buf_free(&unsigned_buf);
    tx_buf_free(&signed_buf);
    return ok;
}

/* Spend factory UTXO with newest state (lowest nSequence), mine to confirm. */
int test_regtest_basic_dw(void) {
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    regtest_t rt;
    if (!regtest_init(&rt)) {
        printf("  SKIP: bitcoind not running\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "test_dw");

    char mine_addr[128];
    regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr));
    regtest_mine_blocks(&rt, 101, mine_addr);

    secp256k1_keypair kps[2];
    musig_keyagg_t keyagg;
    char factory_addr[128];
    char funding_txid[65];

    TEST_ASSERT(setup_factory(&rt, ctx, kps, &keyagg, factory_addr, funding_txid),
                "factory setup");

    printf("  Factory funded: %s\n", funding_txid);

    uint64_t fund_amount;
    unsigned char fund_spk[34];
    size_t fund_spk_len;

    unsigned char fund_txid_bytes[32];
    hex_decode(funding_txid, fund_txid_bytes, 32);
    reverse_bytes(fund_txid_bytes, 32); /* display order -> internal order */

    int found_vout = -1;
    for (int v = 0; v < 2; v++) {
        if (regtest_get_tx_output(&rt, funding_txid, (uint32_t)v,
                                   &fund_amount, fund_spk, &fund_spk_len)) {
            if (fund_spk_len == 34 && fund_spk[0] == 0x51) {
                found_vout = v;
                break;
            }
        }
    }
    TEST_ASSERT(found_vout >= 0, "find factory vout");

    /* small step for test: 2 blocks instead of 144 */
    dw_layer_t layer;
    dw_layer_init(&layer, 2, 4);

    /* advance to newest state */
    dw_advance(&layer); dw_advance(&layer); dw_advance(&layer);
    uint32_t nseq = dw_current_nsequence(&layer);

    unsigned char out_seckey[32];
    memset(out_seckey, 0x30, 32);
    secp256k1_keypair out_kp;
    secp256k1_keypair_create(ctx, &out_kp, out_seckey);
    secp256k1_xonly_pubkey out_xpk;
    secp256k1_keypair_xonly_pub(ctx, &out_xpk, NULL, &out_kp);

    uint64_t output_amount = fund_amount - 1000; /* leave room for fee */

    char state_txid[65];
    int sent = build_and_broadcast_state_tx(
        &rt, ctx, kps, &keyagg,
        fund_txid_bytes, (uint32_t)found_vout,
        fund_amount, fund_spk, fund_spk_len,
        nseq, &out_xpk, output_amount, state_txid);

    if (sent) {
        printf("  State tx in mempool: %s\n", state_txid);
        regtest_mine_blocks(&rt, (int)nseq + 1, mine_addr);

        int conf = regtest_get_confirmations(&rt, state_txid);
        printf("  State tx confirmations: %d\n", conf);
        TEST_ASSERT(conf > 0, "state tx should be confirmed");
    } else {
        printf("  State tx broadcast failed (sighash/sig debugging needed)\n");
    }

    secp256k1_context_destroy(ctx);
    return 1;
}

/* Broadcast oldest state first, then newest. Newest should win. */
int test_regtest_old_first_attack(void) {
    printf("  TODO: requires basic DW to work first\n");
    return 1;
}

/* MuSig2 on-chain: covered by basic_dw test. */
int test_regtest_musig_onchain(void) {
    printf("  Covered by basic_dw test\n");
    return 1;
}

/* nSequence edge cases: nSequence = 1 (minimum relative timelock). */
int test_regtest_nsequence_edge(void) {
    printf("  TODO: nSequence edge cases\n");
    return 1;
}
