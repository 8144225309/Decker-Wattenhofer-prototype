#include "superscalar/shachain.h"
#include <string.h>

extern void sha256(const unsigned char *data, size_t len, unsigned char *out32);

#define SHACHAIN_MAX_INDEX ((UINT64_C(1) << SHACHAIN_INDEX_BITS) - 1)

/* Derive element at index from seed using BOLT #3 algorithm.
   Iterate bits 47..0: if bit is set in index, flip that bit in value and hash. */
void shachain_from_seed(const unsigned char *seed32, uint64_t index,
                         unsigned char *out32) {
    unsigned char value[32];
    memcpy(value, seed32, 32);

    for (int bit = SHACHAIN_INDEX_BITS - 1; bit >= 0; bit--) {
        if (index & (UINT64_C(1) << bit)) {
            int byte_idx = bit / 8;
            int bit_within_byte = bit % 8;
            value[byte_idx] ^= (1 << bit_within_byte);
            sha256(value, 32, value);
        }
    }

    memcpy(out32, value, 32);
}

/* Map factory epoch N to shachain index (2^48 - 1) - N.
   Epoch 0 maps to highest index (revealed first). */
uint64_t shachain_epoch_to_index(uint32_t epoch) {
    return SHACHAIN_MAX_INDEX - (uint64_t)epoch;
}

/* Count trailing zeros in index. Returns SHACHAIN_INDEX_BITS for index 0. */
static int ctz48(uint64_t index) {
    for (int i = 0; i < SHACHAIN_INDEX_BITS; i++) {
        if (index & (UINT64_C(1) << i))
            return i;
    }
    return SHACHAIN_INDEX_BITS;
}

/* Check if element at from_index can derive element at to_index.
   Possible when to_index differs from from_index only in its trailing
   zero positions (setting some of them to 1). */
static int can_derive(uint64_t from_index, uint64_t to_index) {
    int tz = ctz48(from_index);
    uint64_t mask;
    if (tz >= SHACHAIN_INDEX_BITS)
        mask = 0;  /* index 0 can derive everything */
    else
        mask = ~((UINT64_C(1) << tz) - 1);
    return (to_index & mask) == (from_index & mask);
}

/* Given a known element at known_index, derive element at target_index.
   The derivation applies flip+hash operations for bits that are set in
   target but not in known, processing from high to low bit position. */
static int derive_element(const unsigned char *known32, uint64_t known_index,
                           uint64_t target_index, unsigned char *out32) {
    if (!can_derive(known_index, target_index))
        return 0;

    unsigned char value[32];
    memcpy(value, known32, 32);

    /* Apply operations for bits in the trailing-zero range of known_index
       that are set in target_index. Process high-to-low to match generation order. */
    int tz = ctz48(known_index);
    for (int bit = tz - 1; bit >= 0; bit--) {
        if ((target_index & (UINT64_C(1) << bit)) &&
            !(known_index & (UINT64_C(1) << bit))) {
            int byte_idx = bit / 8;
            int bit_within_byte = bit % 8;
            value[byte_idx] ^= (1 << bit_within_byte);
            sha256(value, 32, value);
        }
    }

    memcpy(out32, value, 32);
    return 1;
}

void shachain_init(shachain_t *sc) {
    memset(sc, 0, sizeof(*sc));
}

/* Insert element at index in descending order (BOLT #3 receiver).
   The storage bucket is determined by count_trailing_zeros(index).
   Elements at higher buckets can derive elements at lower buckets. */
int shachain_insert(shachain_t *sc, uint64_t index,
                     const unsigned char *secret32) {
    int slot = ctz48(index);

    /* Verify: new element must be able to derive all existing elements
       at lower-numbered slots. */
    for (size_t i = 0; i < (size_t)slot && i < sc->num_stored; i++) {
        if (!sc->elements[i].valid)
            continue;

        unsigned char derived[32];
        if (!derive_element(secret32, index, sc->elements[i].index, derived))
            return 0;

        if (memcmp(derived, sc->elements[i].secret, 32) != 0)
            return 0;
    }

    /* Store at slot position */
    memcpy(sc->elements[slot].secret, secret32, 32);
    sc->elements[slot].index = index;
    sc->elements[slot].valid = 1;

    if ((size_t)(slot + 1) > sc->num_stored)
        sc->num_stored = (size_t)(slot + 1);

    return 1;
}

/* Derive a previously-stored element by scanning stored elements. */
int shachain_derive(const shachain_t *sc, uint64_t index,
                     unsigned char *out32) {
    for (size_t i = 0; i < sc->num_stored; i++) {
        if (!sc->elements[i].valid)
            continue;

        if (derive_element(sc->elements[i].secret, sc->elements[i].index,
                            index, out32))
            return 1;
    }
    return 0;
}

size_t shachain_num_stored(const shachain_t *sc) {
    size_t count = 0;
    for (size_t i = 0; i < sc->num_stored; i++) {
        if (sc->elements[i].valid)
            count++;
    }
    return count;
}
