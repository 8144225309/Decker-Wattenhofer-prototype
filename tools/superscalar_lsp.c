#include "superscalar/lsp.h"
#include "superscalar/lsp_channels.h"
#include "superscalar/tx_builder.h"
#include "superscalar/regtest.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <secp256k1_extrakeys.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);
extern void sha256_tagged(const char *, const unsigned char *, size_t, unsigned char *);

static volatile sig_atomic_t g_shutdown = 0;
static lsp_t *g_lsp = NULL;  /* for signal handler cleanup */

static void sigint_handler(int sig) {
    (void)sig;
    g_shutdown = 1;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s --port PORT --regtest [OPTIONS]\n"
        "\n"
        "  SuperScalar LSP: creates a factory with N clients, then cooperatively closes.\n"
        "\n"
        "Options:\n"
        "  --port PORT         Listen port (default 9735)\n"
        "  --clients N         Number of clients to accept (default 4, max %d)\n"
        "  --amount SATS       Funding amount in satoshis (default 100000)\n"
        "  --step-blocks N     DW step blocks (default 10)\n"
        "  --seckey HEX        LSP secret key (32-byte hex, default: deterministic)\n"
        "  --payments N        Number of HTLC payments to process (default 0)\n"
        "  --regtest           Use regtest (required)\n"
        "  --help              Show this help\n",
        prog, LSP_MAX_CLIENTS);
}

/* Derive bech32m address from tweaked xonly pubkey via bitcoin-cli descriptors */
static int derive_p2tr_address(regtest_t *rt, const unsigned char *tweaked_ser32,
                                char *addr_out, size_t addr_len) {
    char tweaked_hex[65];
    hex_encode(tweaked_ser32, 32, tweaked_hex);

    /* Step 1: getdescriptorinfo "rawtr(HEX)" -> checksummed descriptor */
    char params[512];
    snprintf(params, sizeof(params), "\"rawtr(%s)\"", tweaked_hex);
    char *desc_result = regtest_exec(rt, "getdescriptorinfo", params);
    if (!desc_result) return 0;

    char checksummed_desc[256];
    char *dstart = strstr(desc_result, "\"descriptor\"");
    if (!dstart) { free(desc_result); return 0; }
    dstart = strchr(dstart + 12, '"');
    if (!dstart) { free(desc_result); return 0; }
    dstart++;
    char *dend = strchr(dstart, '"');
    if (!dend) { free(desc_result); return 0; }
    size_t dlen = (size_t)(dend - dstart);
    if (dlen >= sizeof(checksummed_desc)) { free(desc_result); return 0; }
    memcpy(checksummed_desc, dstart, dlen);
    checksummed_desc[dlen] = '\0';
    free(desc_result);

    /* Step 2: deriveaddresses "rawtr(HEX)#checksum" -> bech32m address */
    snprintf(params, sizeof(params), "\"%s\"", checksummed_desc);
    char *addr_result = regtest_exec(rt, "deriveaddresses", params);
    if (!addr_result) return 0;

    char *astart = strchr(addr_result, '"');
    if (!astart) { free(addr_result); return 0; }
    astart++;
    char *aend = strchr(astart, '"');
    if (!aend) { free(addr_result); return 0; }
    size_t alen = (size_t)(aend - astart);
    if (alen == 0 || alen >= addr_len) { free(addr_result); return 0; }
    memcpy(addr_out, astart, alen);
    addr_out[alen] = '\0';
    free(addr_result);

    return 1;
}

/* Ensure wallet has funds (handle exhausted regtest chains) */
static int ensure_funded(regtest_t *rt, const char *mine_addr) {
    char *bal_s = regtest_exec(rt, "getbalance", "");
    double wallet_bal = bal_s ? atof(bal_s) : 0;
    if (bal_s) free(bal_s);

    if (wallet_bal >= 0.01) return 1;

    /* Block subsidy exhausted — fund from an existing wallet */
    static const char *faucet_wallets[] = {
        "test_dw", "test_factory", "test_ladder_life", NULL
    };
    for (int w = 0; faucet_wallets[w]; w++) {
        regtest_t faucet;
        memcpy(&faucet, rt, sizeof(faucet));
        faucet.wallet[0] = '\0';
        char wparams[128];
        snprintf(wparams, sizeof(wparams), "\"%s\"", faucet_wallets[w]);
        char *lr = regtest_exec(&faucet, "loadwallet", wparams);
        if (lr) free(lr);
        strncpy(faucet.wallet, faucet_wallets[w], sizeof(faucet.wallet) - 1);

        char sp[256];
        snprintf(sp, sizeof(sp), "\"%s\" 0.01", mine_addr);
        char *sr = regtest_exec(&faucet, "sendtoaddress", sp);
        if (sr && !strstr(sr, "error")) {
            free(sr);
            regtest_mine_blocks(rt, 1, mine_addr);
            return 1;
        }
        if (sr) free(sr);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    int port = 9735;
    int regtest = 0;
    int n_clients = 4;
    int n_payments = 0;
    uint64_t funding_sats = 100000;
    uint16_t step_blocks = 10;
    const char *seckey_hex = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
            port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--clients") == 0 && i + 1 < argc)
            n_clients = atoi(argv[++i]);
        else if (strcmp(argv[i], "--amount") == 0 && i + 1 < argc)
            funding_sats = (uint64_t)strtoull(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--step-blocks") == 0 && i + 1 < argc)
            step_blocks = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--seckey") == 0 && i + 1 < argc)
            seckey_hex = argv[++i];
        else if (strcmp(argv[i], "--payments") == 0 && i + 1 < argc)
            n_payments = atoi(argv[++i]);
        else if (strcmp(argv[i], "--regtest") == 0)
            regtest = 1;
        else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    if (!regtest) {
        fprintf(stderr, "Error: --regtest is required (only mode supported).\n");
        usage(argv[0]);
        return 1;
    }
    if (n_clients < 1 || n_clients > LSP_MAX_CLIENTS) {
        fprintf(stderr, "Error: --clients must be 1..%d\n", LSP_MAX_CLIENTS);
        return 1;
    }

    /* Create LSP keypair */
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char lsp_seckey[32];
    if (seckey_hex) {
        if (hex_decode(seckey_hex, lsp_seckey, 32) != 32) {
            fprintf(stderr, "Error: invalid --seckey (need 64 hex chars)\n");
            return 1;
        }
    } else {
        /* Deterministic default key for regtest */
        memset(lsp_seckey, 0x10, 32);
    }

    secp256k1_keypair lsp_kp;
    if (!secp256k1_keypair_create(ctx, &lsp_kp, lsp_seckey)) {
        fprintf(stderr, "Error: invalid secret key\n");
        memset(lsp_seckey, 0, 32);
        return 1;
    }
    /* Note: lsp_seckey zeroed at cleanup — needed for lsp_channels_init() */

    /* Initialize regtest */
    regtest_t rt;
    if (!regtest_init(&rt)) {
        fprintf(stderr, "Error: cannot connect to bitcoind (is it running with -regtest?)\n");
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_create_wallet(&rt, "superscalar_lsp");

    /* === Phase 1: Accept clients === */
    printf("LSP: listening on port %d, waiting for %d clients...\n", port, n_clients);

    lsp_t lsp;
    lsp_init(&lsp, ctx, &lsp_kp, port, (size_t)n_clients);
    g_lsp = &lsp;

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    if (!lsp_accept_clients(&lsp)) {
        fprintf(stderr, "LSP: failed to accept clients\n");
        lsp_cleanup(&lsp);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    printf("LSP: all %d clients connected\n", n_clients);

    if (g_shutdown) {
        lsp_abort_ceremony(&lsp, "LSP shutting down");
        lsp_cleanup(&lsp);
        secp256k1_context_destroy(ctx);
        return 1;
    }

    /* === Phase 2: Compute funding address === */
    size_t n_total = 1 + lsp.n_clients;
    secp256k1_pubkey all_pks[FACTORY_MAX_SIGNERS];
    all_pks[0] = lsp.lsp_pubkey;
    for (size_t i = 0; i < lsp.n_clients; i++)
        all_pks[i + 1] = lsp.client_pubkeys[i];

    musig_keyagg_t ka;
    musig_aggregate_keys(ctx, &ka, all_pks, n_total);

    /* Compute tweaked xonly pubkey for P2TR */
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

    /* Derive bech32m address */
    unsigned char tweaked_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, tweaked_ser, &tweaked_xonly);

    char fund_addr[128];
    if (!derive_p2tr_address(&rt, tweaked_ser, fund_addr, sizeof(fund_addr))) {
        fprintf(stderr, "LSP: failed to derive funding address\n");
        lsp_cleanup(&lsp);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    printf("LSP: funding address: %s\n", fund_addr);

    /* === Phase 3: Fund the factory === */
    char mine_addr[128];
    if (!regtest_get_new_address(&rt, mine_addr, sizeof(mine_addr))) {
        fprintf(stderr, "LSP: failed to get mining address\n");
        lsp_cleanup(&lsp);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_mine_blocks(&rt, 101, mine_addr);

    if (!ensure_funded(&rt, mine_addr)) {
        fprintf(stderr, "LSP: failed to fund wallet (exhausted regtest?)\n");
        lsp_cleanup(&lsp);
        secp256k1_context_destroy(ctx);
        return 1;
    }

    double funding_btc = (double)funding_sats / 100000000.0;
    char funding_txid_hex[65];
    if (!regtest_fund_address(&rt, fund_addr, funding_btc, funding_txid_hex)) {
        fprintf(stderr, "LSP: failed to fund factory address\n");
        lsp_cleanup(&lsp);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_mine_blocks(&rt, 1, mine_addr);
    printf("LSP: funded %llu sats, txid: %s\n",
           (unsigned long long)funding_sats, funding_txid_hex);

    /* Get funding output details */
    unsigned char funding_txid[32];
    hex_decode(funding_txid_hex, funding_txid, 32);
    reverse_bytes(funding_txid, 32);  /* display -> internal */

    uint64_t funding_amount = 0;
    unsigned char actual_spk[256];
    size_t actual_spk_len = 0;
    uint32_t funding_vout = 0;

    for (uint32_t v = 0; v < 4; v++) {
        regtest_get_tx_output(&rt, funding_txid_hex, v,
                              &funding_amount, actual_spk, &actual_spk_len);
        if (actual_spk_len == 34 && memcmp(actual_spk, fund_spk, 34) == 0) {
            funding_vout = v;
            break;
        }
    }
    if (funding_amount == 0) {
        fprintf(stderr, "LSP: could not find funding output\n");
        lsp_cleanup(&lsp);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    printf("LSP: funding vout=%u, amount=%llu sats\n",
           funding_vout, (unsigned long long)funding_amount);

    /* === Phase 4: Run factory creation ceremony === */
    if (g_shutdown) {
        lsp_abort_ceremony(&lsp, "LSP shutting down");
        lsp_cleanup(&lsp);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    printf("LSP: starting factory creation ceremony...\n");
    if (!lsp_run_factory_creation(&lsp,
                                   funding_txid, funding_vout,
                                   funding_amount,
                                   fund_spk, 34,
                                   step_blocks, 4)) {
        fprintf(stderr, "LSP: factory creation failed\n");
        lsp_cleanup(&lsp);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    printf("LSP: factory creation complete! (%zu nodes signed)\n", lsp.factory.n_nodes);

    /* === Phase 4b: Channel Operations === */
    lsp_channel_mgr_t mgr;
    int channels_active = 0;
    if (n_payments > 0) {
        if (!lsp_channels_init(&mgr, ctx, &lsp.factory, lsp_seckey, (size_t)n_clients)) {
            fprintf(stderr, "LSP: channel init failed\n");
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        if (!lsp_channels_send_ready(&mgr, &lsp)) {
            fprintf(stderr, "LSP: send CHANNEL_READY failed\n");
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        printf("LSP: channels ready, waiting for %d payments (%d messages)...\n",
               n_payments, n_payments * 2);

        if (!lsp_channels_run_event_loop(&mgr, &lsp, (size_t)(n_payments * 2))) {
            fprintf(stderr, "LSP: event loop failed\n");
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
        channels_active = 1;
        printf("LSP: all %d payments processed\n", n_payments);
    }

    /* === Phase 5: Cooperative close === */
    if (g_shutdown) {
        lsp_abort_ceremony(&lsp, "LSP shutting down");
        lsp_cleanup(&lsp);
        memset(lsp_seckey, 0, 32);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    printf("LSP: starting cooperative close...\n");

    tx_output_t close_outputs[FACTORY_MAX_SIGNERS];
    size_t n_close_outputs;

    if (channels_active) {
        n_close_outputs = lsp_channels_build_close_outputs(&mgr, &lsp.factory,
                                                            close_outputs, 500);
        if (n_close_outputs == 0) {
            fprintf(stderr, "LSP: build close outputs failed\n");
            lsp_cleanup(&lsp);
            memset(lsp_seckey, 0, 32);
            secp256k1_context_destroy(ctx);
            return 1;
        }
    } else {
        /* No payments — equal split (original behavior) */
        uint64_t close_total = funding_amount - 500;  /* fee */
        uint64_t per_party = close_total / n_total;
        for (size_t i = 0; i < n_total; i++) {
            close_outputs[i].amount_sats = per_party;
            memcpy(close_outputs[i].script_pubkey, fund_spk, 34);
            close_outputs[i].script_pubkey_len = 34;
        }
        /* Give remainder to last output */
        close_outputs[n_total - 1].amount_sats = close_total - per_party * (n_total - 1);
        n_close_outputs = n_total;
    }

    /* Print final balances */
    printf("LSP: Close outputs:\n");
    printf("  LSP:      %llu sats\n", (unsigned long long)close_outputs[0].amount_sats);
    for (size_t i = 0; i < (size_t)n_clients; i++)
        printf("  Client %zu: %llu sats\n", i, (unsigned long long)close_outputs[i + 1].amount_sats);

    tx_buf_t close_tx;
    tx_buf_init(&close_tx, 512);

    if (!lsp_run_cooperative_close(&lsp, &close_tx, close_outputs, n_close_outputs)) {
        fprintf(stderr, "LSP: cooperative close failed\n");
        tx_buf_free(&close_tx);
        lsp_cleanup(&lsp);
        secp256k1_context_destroy(ctx);
        return 1;
    }

    /* Broadcast close tx */
    char close_hex[close_tx.len * 2 + 1];
    hex_encode(close_tx.data, close_tx.len, close_hex);
    char close_txid[65];
    if (!regtest_send_raw_tx(&rt, close_hex, close_txid)) {
        fprintf(stderr, "LSP: broadcast close tx failed\n");
        tx_buf_free(&close_tx);
        lsp_cleanup(&lsp);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    regtest_mine_blocks(&rt, 1, mine_addr);
    tx_buf_free(&close_tx);

    int conf = regtest_get_confirmations(&rt, close_txid);
    if (conf < 1) {
        fprintf(stderr, "LSP: close tx not confirmed (conf=%d)\n", conf);
        lsp_cleanup(&lsp);
        secp256k1_context_destroy(ctx);
        return 1;
    }

    printf("LSP: cooperative close confirmed! txid: %s\n", close_txid);
    printf("LSP: SUCCESS — factory created and closed with %d clients\n", n_clients);

    lsp_cleanup(&lsp);
    memset(lsp_seckey, 0, 32);
    secp256k1_context_destroy(ctx);
    return 0;
}
