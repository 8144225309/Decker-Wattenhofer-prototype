#ifndef SUPERSCALAR_SHACHAIN_H
#define SUPERSCALAR_SHACHAIN_H

#include <stdint.h>
#include <stddef.h>

#define SHACHAIN_INDEX_BITS 48
#define SHACHAIN_MAX_STORED 49  /* ceil(48) + 1 */

typedef struct {
    unsigned char secret[32];
    uint64_t index;
    int valid;
} shachain_element_t;

typedef struct {
    shachain_element_t elements[SHACHAIN_MAX_STORED];
    size_t num_stored;
} shachain_t;

/* Derive element at index from seed (generator side, BOLT #3 algorithm) */
void shachain_from_seed(const unsigned char *seed32, uint64_t index,
                         unsigned char *out32);

/* Map factory epoch to shachain index (descending order) */
uint64_t shachain_epoch_to_index(uint32_t epoch);

/* Init receiver (empty) */
void shachain_init(shachain_t *sc);

/* Insert element (must be descending index order). Returns 1 on success. */
int shachain_insert(shachain_t *sc, uint64_t index,
                     const unsigned char *secret32);

/* Derive a previously-stored element. Returns 1 on success. */
int shachain_derive(const shachain_t *sc, uint64_t index,
                     unsigned char *out32);

/* Number of elements currently stored */
size_t shachain_num_stored(const shachain_t *sc);

#endif /* SUPERSCALAR_SHACHAIN_H */
