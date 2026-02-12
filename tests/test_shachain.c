#include "superscalar/shachain.h"
#include <stdio.h>
#include <string.h>

extern void sha256(const unsigned char *data, size_t len, unsigned char *out32);

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

static const unsigned char test_seed[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

/* Test: derive elements at various indices, verify determinism and uniqueness */
int test_shachain_generation(void) {
    unsigned char elem0[32], elem1[32], elem_max[32], elem0_again[32];
    uint64_t max_idx = (UINT64_C(1) << SHACHAIN_INDEX_BITS) - 1;

    shachain_from_seed(test_seed, 0, elem0);
    shachain_from_seed(test_seed, 1, elem1);
    shachain_from_seed(test_seed, max_idx, elem_max);
    shachain_from_seed(test_seed, 0, elem0_again);

    /* Same seed+index produces same result */
    TEST_ASSERT_MEM_EQ(elem0, elem0_again, 32, "deterministic generation");

    /* Different indices produce different elements */
    TEST_ASSERT(memcmp(elem0, elem1, 32) != 0, "index 0 != index 1");
    TEST_ASSERT(memcmp(elem0, elem_max, 32) != 0, "index 0 != index max");
    TEST_ASSERT(memcmp(elem1, elem_max, 32) != 0, "index 1 != index max");

    /* Index 0 means no bits set -> no flips -> output = seed */
    TEST_ASSERT_MEM_EQ(elem0, test_seed, 32, "index 0 is seed itself");

    return 1;
}

/* Test: element at index N can derive element at N+1 when they differ in lowest bit */
int test_shachain_derivation_property(void) {
    uint64_t max_idx = (UINT64_C(1) << SHACHAIN_INDEX_BITS) - 1;

    /* Index 0 (binary: ...000) should be able to derive index 1 (binary: ...001)
       because they differ only in bit 0, and bit 0 is 0 in index 0. */
    unsigned char elem0[32], elem1[32], derived1[32];
    shachain_from_seed(test_seed, 0, elem0);
    shachain_from_seed(test_seed, 1, elem1);

    /* Derive index 1 from index 0: flip bit 0, hash */
    unsigned char tmp[32];
    memcpy(tmp, elem0, 32);
    tmp[0] ^= 1;
    sha256(tmp, 32, derived1);
    TEST_ASSERT_MEM_EQ(derived1, elem1, 32, "elem0 derives elem1");

    /* Index with bit pattern ...10 can derive ...11 */
    unsigned char elem2[32], elem3[32];
    shachain_from_seed(test_seed, 2, elem2);
    shachain_from_seed(test_seed, 3, elem3);

    memcpy(tmp, elem2, 32);
    tmp[0] ^= 1;  /* flip bit 0 */
    unsigned char derived3[32];
    sha256(tmp, 32, derived3);
    TEST_ASSERT_MEM_EQ(derived3, elem3, 32, "elem2 derives elem3");

    /* Epoch mapping: epoch 0 -> highest index, epoch 1 -> highest-1, etc. */
    uint64_t idx0 = shachain_epoch_to_index(0);
    uint64_t idx1 = shachain_epoch_to_index(1);
    TEST_ASSERT_EQ(idx0, max_idx, "epoch 0 -> max index");
    TEST_ASSERT_EQ(idx1, max_idx - 1, "epoch 1 -> max-1");
    TEST_ASSERT(idx0 > idx1, "epoch 0 > epoch 1 (descending)");

    return 1;
}

/* Test: insert 16 elements in descending order, derive all 16 */
int test_shachain_insert_derive(void) {
    uint64_t max_idx = (UINT64_C(1) << SHACHAIN_INDEX_BITS) - 1;
    shachain_t sc;
    shachain_init(&sc);

    /* Pre-generate all 16 elements */
    unsigned char expected[16][32];
    for (int i = 0; i < 16; i++) {
        uint64_t idx = max_idx - (uint64_t)i;
        shachain_from_seed(test_seed, idx, expected[i]);
    }

    /* Insert in descending index order (epoch 0, 1, 2, ...) */
    for (int i = 0; i < 16; i++) {
        uint64_t idx = max_idx - (uint64_t)i;
        TEST_ASSERT(shachain_insert(&sc, idx, expected[i]), "insert element");
    }

    /* Derive all 16 and verify they match */
    for (int i = 0; i < 16; i++) {
        uint64_t idx = max_idx - (uint64_t)i;
        unsigned char derived[32];
        TEST_ASSERT(shachain_derive(&sc, idx, derived), "derive element");

        char msg[64];
        snprintf(msg, sizeof(msg), "derived element %d matches", i);
        TEST_ASSERT_MEM_EQ(derived, expected[i], 32, msg);
    }

    return 1;
}

/* Test: insert 1000 elements, verify compact storage stays <= 49 */
int test_shachain_compact_storage(void) {
    uint64_t max_idx = (UINT64_C(1) << SHACHAIN_INDEX_BITS) - 1;
    shachain_t sc;
    shachain_init(&sc);

    for (int i = 0; i < 1000; i++) {
        uint64_t idx = max_idx - (uint64_t)i;
        unsigned char secret[32];
        shachain_from_seed(test_seed, idx, secret);
        TEST_ASSERT(shachain_insert(&sc, idx, secret), "insert element");

        size_t stored = shachain_num_stored(&sc);
        TEST_ASSERT(stored <= SHACHAIN_MAX_STORED, "storage bounded");
    }

    /* Verify we can still derive element 0 (most recently overwritable) */
    unsigned char derived[32], expected[32];
    shachain_from_seed(test_seed, max_idx, expected);
    TEST_ASSERT(shachain_derive(&sc, max_idx, derived), "derive oldest element");
    TEST_ASSERT_MEM_EQ(derived, expected, 32, "oldest element correct");

    /* Verify we can derive element 999 */
    uint64_t idx999 = max_idx - 999;
    shachain_from_seed(test_seed, idx999, expected);
    TEST_ASSERT(shachain_derive(&sc, idx999, derived), "derive newest element");
    TEST_ASSERT_MEM_EQ(derived, expected, 32, "newest element correct");

    return 1;
}

/* Test: reject inconsistent element at a slot that has lower slots to check.
   Slot 0 (ctz=0) elements can't be verified at insertion time (no lower slots).
   We test rejection at slot 1+ where cross-derivation is checked. */
int test_shachain_reject_bad_insert(void) {
    uint64_t max_idx = (UINT64_C(1) << SHACHAIN_INDEX_BITS) - 1;
    shachain_t sc;
    shachain_init(&sc);

    /* Insert epoch 0: index = max (ctz=0, slot 0) */
    unsigned char secret0[32];
    shachain_from_seed(test_seed, max_idx, secret0);
    TEST_ASSERT(shachain_insert(&sc, max_idx, secret0), "insert epoch 0");

    /* Try inserting a bad element at epoch 1: index = max-1 (ctz=1, slot 1).
       Slot 1 checks slot 0 — the bad element must be able to derive the
       element at slot 0 (max). With a wrong seed, derivation won't match. */
    unsigned char bad_seed[32] = {0xff, 0xfe, 0xfd};
    unsigned char bad_secret[32];
    shachain_from_seed(bad_seed, max_idx - 1, bad_secret);

    int result = shachain_insert(&sc, max_idx - 1, bad_secret);
    TEST_ASSERT(result == 0, "reject inconsistent element at slot 1");

    /* The correct element at epoch 1 should succeed */
    unsigned char good_secret[32];
    shachain_from_seed(test_seed, max_idx - 1, good_secret);
    TEST_ASSERT(shachain_insert(&sc, max_idx - 1, good_secret),
                "accept correct element at slot 1");

    /* Also test rejection at a higher slot: insert epochs 2 (slot 0),
       then try bad epoch 3 (slot 2) which checks slots 0 and 1 */
    unsigned char secret2[32];
    shachain_from_seed(test_seed, max_idx - 2, secret2);
    TEST_ASSERT(shachain_insert(&sc, max_idx - 2, secret2), "insert epoch 2");

    unsigned char bad_secret3[32];
    shachain_from_seed(bad_seed, max_idx - 3, bad_secret3);
    result = shachain_insert(&sc, max_idx - 3, bad_secret3);
    TEST_ASSERT(result == 0, "reject inconsistent element at slot 2");

    /* Correct epoch 3 should succeed */
    unsigned char good_secret3[32];
    shachain_from_seed(test_seed, max_idx - 3, good_secret3);
    TEST_ASSERT(shachain_insert(&sc, max_idx - 3, good_secret3),
                "accept correct element at slot 2");

    return 1;
}
