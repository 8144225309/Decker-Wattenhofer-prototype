#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

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

#define TEST_ASSERT_MEM_EQ(a, b, len, msg) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

#define RUN_TEST(fn) do { \
    tests_run++; \
    printf("  %s...", #fn); \
    fflush(stdout); \
    if (fn()) { \
        tests_passed++; \
        printf(" OK\n"); \
    } else { \
        tests_failed++; \
    } \
} while(0)

extern int test_dw_layer_init(void);
extern int test_dw_delay_for_state(void);
extern int test_dw_nsequence_for_state(void);
extern int test_dw_advance(void);
extern int test_dw_exhaustion(void);
extern int test_dw_counter_init(void);
extern int test_dw_counter_advance(void);
extern int test_dw_counter_full_cycle(void);

extern int test_musig_aggregate_keys(void);
extern int test_musig_sign_verify(void);
extern int test_musig_wrong_message(void);
extern int test_musig_taproot_sign(void);

extern int test_musig_split_round_basic(void);
extern int test_musig_split_round_taproot(void);
extern int test_musig_nonce_pool(void);
extern int test_musig_partial_sig_verify(void);
extern int test_musig_serialization(void);
extern int test_musig_split_round_5of5(void);

extern int test_tx_buf_primitives(void);
extern int test_build_p2tr_script_pubkey(void);
extern int test_build_unsigned_tx(void);
extern int test_finalize_signed_tx(void);
extern int test_varint_encoding(void);

extern int test_regtest_basic_dw(void);
extern int test_regtest_old_first_attack(void);
extern int test_regtest_musig_onchain(void);
extern int test_regtest_nsequence_edge(void);

extern int test_factory_build_tree(void);
extern int test_factory_sign_all(void);
extern int test_factory_advance(void);
extern int test_factory_sign_split_round_step_by_step(void);
extern int test_factory_split_round_with_pool(void);
extern int test_factory_advance_split_round(void);
extern int test_regtest_factory_tree(void);

extern int test_tapscript_leaf_hash(void);
extern int test_tapscript_tweak_with_tree(void);
extern int test_tapscript_control_block(void);
extern int test_tapscript_sighash(void);
extern int test_factory_tree_with_timeout(void);
extern int test_regtest_timeout_spend(void);

extern int test_shachain_generation(void);
extern int test_shachain_derivation_property(void);
extern int test_shachain_insert_derive(void);
extern int test_shachain_compact_storage(void);
extern int test_shachain_reject_bad_insert(void);

extern int test_factory_l_stock_with_burn_path(void);
extern int test_factory_burn_tx_construction(void);
extern int test_factory_advance_with_shachain(void);
extern int test_regtest_burn_tx(void);

extern int test_channel_key_derivation(void);
extern int test_channel_commitment_tx(void);
extern int test_channel_sign_commitment(void);
extern int test_channel_update(void);
extern int test_channel_revocation(void);
extern int test_channel_penalty_tx(void);
extern int test_regtest_channel_unilateral(void);

extern int test_htlc_offered_scripts(void);
extern int test_htlc_received_scripts(void);
extern int test_htlc_control_block_2leaf(void);
extern int test_htlc_add_fulfill(void);
extern int test_htlc_add_fail(void);
extern int test_htlc_commitment_tx(void);
extern int test_htlc_success_spend(void);
extern int test_htlc_timeout_spend(void);
extern int test_htlc_penalty(void);
extern int test_regtest_htlc_success(void);
extern int test_regtest_htlc_timeout(void);

extern int test_factory_cooperative_close(void);
extern int test_factory_cooperative_close_balances(void);
extern int test_channel_cooperative_close(void);
extern int test_regtest_factory_coop_close(void);
extern int test_regtest_channel_coop_close(void);

static void run_unit_tests(void) {
    printf("\n=== DW State Machine ===\n");
    RUN_TEST(test_dw_layer_init);
    RUN_TEST(test_dw_delay_for_state);
    RUN_TEST(test_dw_nsequence_for_state);
    RUN_TEST(test_dw_advance);
    RUN_TEST(test_dw_exhaustion);
    RUN_TEST(test_dw_counter_init);
    RUN_TEST(test_dw_counter_advance);
    RUN_TEST(test_dw_counter_full_cycle);

    printf("\n=== MuSig2 ===\n");
    RUN_TEST(test_musig_aggregate_keys);
    RUN_TEST(test_musig_sign_verify);
    RUN_TEST(test_musig_wrong_message);
    RUN_TEST(test_musig_taproot_sign);

    printf("\n=== MuSig2 Split-Round ===\n");
    RUN_TEST(test_musig_split_round_basic);
    RUN_TEST(test_musig_split_round_taproot);
    RUN_TEST(test_musig_nonce_pool);
    RUN_TEST(test_musig_partial_sig_verify);
    RUN_TEST(test_musig_serialization);
    RUN_TEST(test_musig_split_round_5of5);

    printf("\n=== Transaction Builder ===\n");
    RUN_TEST(test_tx_buf_primitives);
    RUN_TEST(test_build_p2tr_script_pubkey);
    RUN_TEST(test_build_unsigned_tx);
    RUN_TEST(test_finalize_signed_tx);
    RUN_TEST(test_varint_encoding);

    printf("\n=== Factory Tree ===\n");
    RUN_TEST(test_factory_build_tree);
    RUN_TEST(test_factory_sign_all);
    RUN_TEST(test_factory_advance);

    printf("\n=== Factory Split-Round ===\n");
    RUN_TEST(test_factory_sign_split_round_step_by_step);
    RUN_TEST(test_factory_split_round_with_pool);
    RUN_TEST(test_factory_advance_split_round);

    printf("\n=== Tapscript (Timeout-Sig-Trees) ===\n");
    RUN_TEST(test_tapscript_leaf_hash);
    RUN_TEST(test_tapscript_tweak_with_tree);
    RUN_TEST(test_tapscript_control_block);
    RUN_TEST(test_tapscript_sighash);
    RUN_TEST(test_factory_tree_with_timeout);

    printf("\n=== Shachain ===\n");
    RUN_TEST(test_shachain_generation);
    RUN_TEST(test_shachain_derivation_property);
    RUN_TEST(test_shachain_insert_derive);
    RUN_TEST(test_shachain_compact_storage);
    RUN_TEST(test_shachain_reject_bad_insert);

    printf("\n=== Factory Shachain (L-Output Invalidation) ===\n");
    RUN_TEST(test_factory_l_stock_with_burn_path);
    RUN_TEST(test_factory_burn_tx_construction);
    RUN_TEST(test_factory_advance_with_shachain);

    printf("\n=== Channel (Poon-Dryja) ===\n");
    RUN_TEST(test_channel_key_derivation);
    RUN_TEST(test_channel_commitment_tx);
    RUN_TEST(test_channel_sign_commitment);
    RUN_TEST(test_channel_update);
    RUN_TEST(test_channel_revocation);
    RUN_TEST(test_channel_penalty_tx);

    printf("\n=== HTLC (Phase 6) ===\n");
    RUN_TEST(test_htlc_offered_scripts);
    RUN_TEST(test_htlc_received_scripts);
    RUN_TEST(test_htlc_control_block_2leaf);
    RUN_TEST(test_htlc_add_fulfill);
    RUN_TEST(test_htlc_add_fail);
    RUN_TEST(test_htlc_commitment_tx);
    RUN_TEST(test_htlc_success_spend);
    RUN_TEST(test_htlc_timeout_spend);
    RUN_TEST(test_htlc_penalty);

    printf("\n=== Cooperative Close (Phase 7) ===\n");
    RUN_TEST(test_factory_cooperative_close);
    RUN_TEST(test_factory_cooperative_close_balances);
    RUN_TEST(test_channel_cooperative_close);
}

static void run_regtest_tests(void) {
    printf("\n=== Regtest Integration ===\n");
    printf("(requires bitcoind -regtest)\n\n");
    RUN_TEST(test_regtest_basic_dw);
    RUN_TEST(test_regtest_old_first_attack);
    RUN_TEST(test_regtest_musig_onchain);
    RUN_TEST(test_regtest_nsequence_edge);
    RUN_TEST(test_regtest_factory_tree);
    RUN_TEST(test_regtest_timeout_spend);
    RUN_TEST(test_regtest_burn_tx);
    RUN_TEST(test_regtest_channel_unilateral);
    RUN_TEST(test_regtest_htlc_success);
    RUN_TEST(test_regtest_htlc_timeout);
    RUN_TEST(test_regtest_factory_coop_close);
    RUN_TEST(test_regtest_channel_coop_close);
}

int main(int argc, char *argv[]) {
    int run_unit = 0, run_regtest = 0;

    if (argc < 2)
        run_unit = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--unit") == 0) run_unit = 1;
        if (strcmp(argv[i], "--regtest") == 0) run_regtest = 1;
        if (strcmp(argv[i], "--all") == 0) { run_unit = 1; run_regtest = 1; }
    }

    printf("SuperScalar Test Suite (Phase 1-7)\n");
    printf("==================================\n");

    if (run_unit) run_unit_tests();
    if (run_regtest) run_regtest_tests();

    printf("\n==============================\n");
    printf("Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0)
        printf(" (%d FAILED)", tests_failed);
    printf("\n");

    return tests_failed > 0 ? 1 : 0;
}
