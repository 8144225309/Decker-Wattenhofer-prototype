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
extern int test_regtest_factory_tree(void);

extern int test_tapscript_leaf_hash(void);
extern int test_tapscript_tweak_with_tree(void);
extern int test_tapscript_control_block(void);
extern int test_tapscript_sighash(void);
extern int test_factory_tree_with_timeout(void);
extern int test_regtest_timeout_spend(void);

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

    printf("\n=== Tapscript (Timeout-Sig-Trees) ===\n");
    RUN_TEST(test_tapscript_leaf_hash);
    RUN_TEST(test_tapscript_tweak_with_tree);
    RUN_TEST(test_tapscript_control_block);
    RUN_TEST(test_tapscript_sighash);
    RUN_TEST(test_factory_tree_with_timeout);
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

    printf("SuperScalar Test Suite (Phase 1 + Phase 2)\n");
    printf("==========================================\n");

    if (run_unit) run_unit_tests();
    if (run_regtest) run_regtest_tests();

    printf("\n==============================\n");
    printf("Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0)
        printf(" (%d FAILED)", tests_failed);
    printf("\n");

    return tests_failed > 0 ? 1 : 0;
}
