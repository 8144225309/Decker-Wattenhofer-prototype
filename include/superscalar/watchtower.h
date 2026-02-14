#ifndef SUPERSCALAR_WATCHTOWER_H
#define SUPERSCALAR_WATCHTOWER_H

#include "channel.h"
#include "persist.h"
#include "regtest.h"
#include "fee.h"

#define WATCHTOWER_MAX_WATCH 64

typedef struct {
    uint32_t channel_id;
    uint64_t commit_num;
    unsigned char txid[32];       /* commitment txid to watch for (internal byte order) */
    uint32_t to_local_vout;
    uint64_t to_local_amount;
    unsigned char to_local_spk[34];
    size_t to_local_spk_len;
} watchtower_entry_t;

#define WATCHTOWER_MAX_CHANNELS 8

typedef struct {
    watchtower_entry_t entries[WATCHTOWER_MAX_WATCH];
    size_t n_entries;
    channel_t *channels[WATCHTOWER_MAX_CHANNELS];  /* pointers to channels by index */
    size_t n_channels;
    regtest_t *rt;                 /* for chain queries + broadcasting */
    fee_estimator_t *fee;
    persist_t *db;
} watchtower_t;

/* Initialize watchtower. Load old commitments from DB if available. */
int watchtower_init(watchtower_t *wt, size_t n_channels,
                      regtest_t *rt, fee_estimator_t *fee, persist_t *db);

/* Set channel pointer for a given index. */
void watchtower_set_channel(watchtower_t *wt, size_t idx, channel_t *ch);

/* Add an old commitment to watch for. */
int watchtower_watch(watchtower_t *wt, uint32_t channel_id,
                       uint64_t commit_num, const unsigned char *txid32,
                       uint32_t to_local_vout, uint64_t to_local_amount,
                       const unsigned char *to_local_spk, size_t spk_len);

/* Check chain for breaches. For each detected breach:
   1. Build penalty tx via channel_build_penalty_tx()
   2. Broadcast via regtest_send_raw_tx()
   Returns number of penalties broadcast. */
int watchtower_check(watchtower_t *wt);

/* Remove entries for a channel (e.g., after cooperative close). */
void watchtower_remove_channel(watchtower_t *wt, uint32_t channel_id);

#endif /* SUPERSCALAR_WATCHTOWER_H */
