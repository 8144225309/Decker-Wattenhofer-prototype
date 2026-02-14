#include "superscalar/watchtower.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern void reverse_bytes(unsigned char *data, size_t len);

int watchtower_init(watchtower_t *wt, size_t n_channels,
                      regtest_t *rt, fee_estimator_t *fee, persist_t *db) {
    if (!wt) return 0;
    memset(wt, 0, sizeof(*wt));
    wt->n_channels = n_channels < WATCHTOWER_MAX_CHANNELS ? n_channels : WATCHTOWER_MAX_CHANNELS;
    wt->rt = rt;
    wt->fee = fee;
    wt->db = db;

    /* Load old commitments from DB if available */
    if (db && db->db) {
        for (size_t c = 0; c < wt->n_channels; c++) {
            uint64_t commit_nums[WATCHTOWER_MAX_WATCH];
            unsigned char txids[WATCHTOWER_MAX_WATCH][32];
            uint32_t vouts[WATCHTOWER_MAX_WATCH];
            uint64_t amounts[WATCHTOWER_MAX_WATCH];
            unsigned char spks[WATCHTOWER_MAX_WATCH][34];
            size_t spk_lens[WATCHTOWER_MAX_WATCH];

            size_t loaded = persist_load_old_commitments(
                db, (uint32_t)c, commit_nums, txids, vouts, amounts,
                spks, spk_lens, WATCHTOWER_MAX_WATCH - wt->n_entries);

            for (size_t i = 0; i < loaded && wt->n_entries < WATCHTOWER_MAX_WATCH; i++) {
                watchtower_entry_t *e = &wt->entries[wt->n_entries++];
                e->channel_id = (uint32_t)c;
                e->commit_num = commit_nums[i];
                memcpy(e->txid, txids[i], 32);
                e->to_local_vout = vouts[i];
                e->to_local_amount = amounts[i];
                memcpy(e->to_local_spk, spks[i], spk_lens[i]);
                e->to_local_spk_len = spk_lens[i];
            }
        }
    }

    return 1;
}

void watchtower_set_channel(watchtower_t *wt, size_t idx, channel_t *ch) {
    if (!wt || idx >= WATCHTOWER_MAX_CHANNELS) return;
    wt->channels[idx] = ch;
    if (idx >= wt->n_channels)
        wt->n_channels = idx + 1;
}

int watchtower_watch(watchtower_t *wt, uint32_t channel_id,
                       uint64_t commit_num, const unsigned char *txid32,
                       uint32_t to_local_vout, uint64_t to_local_amount,
                       const unsigned char *to_local_spk, size_t spk_len) {
    if (!wt || !txid32 || !to_local_spk) return 0;
    if (wt->n_entries >= WATCHTOWER_MAX_WATCH) return 0;
    if (spk_len > 34) return 0;

    watchtower_entry_t *e = &wt->entries[wt->n_entries++];
    e->channel_id = channel_id;
    e->commit_num = commit_num;
    memcpy(e->txid, txid32, 32);
    e->to_local_vout = to_local_vout;
    e->to_local_amount = to_local_amount;
    memcpy(e->to_local_spk, to_local_spk, spk_len);
    e->to_local_spk_len = spk_len;

    /* Persist if DB available */
    if (wt->db && wt->db->db) {
        persist_save_old_commitment(wt->db, channel_id, commit_num,
                                      txid32, to_local_vout, to_local_amount,
                                      to_local_spk, spk_len);
    }

    return 1;
}

int watchtower_check(watchtower_t *wt) {
    if (!wt || !wt->rt) return 0;

    int penalties_broadcast = 0;

    for (size_t i = 0; i < wt->n_entries; ) {
        watchtower_entry_t *e = &wt->entries[i];

        /* Convert txid to display-order hex */
        unsigned char display_txid[32];
        memcpy(display_txid, e->txid, 32);
        reverse_bytes(display_txid, 32);
        char txid_hex[65];
        hex_encode(display_txid, 32, txid_hex);

        /* Check if old commitment is on chain or in mempool */
        int conf = regtest_get_confirmations(wt->rt, txid_hex);
        int in_mempool = regtest_is_in_mempool(wt->rt, txid_hex);

        if (conf < 0 && !in_mempool) {
            i++;  /* not found, keep watching */
            continue;
        }

        printf("BREACH DETECTED on channel %u, commitment %llu (txid: %s)!\n",
               e->channel_id, (unsigned long long)e->commit_num, txid_hex);

        /* If in mempool but not confirmed, mine a block first */
        if (in_mempool && conf < 0) {
            char mine_addr[128];
            if (regtest_get_new_address(wt->rt, mine_addr, sizeof(mine_addr)))
                regtest_mine_blocks(wt->rt, 1, mine_addr);
        }

        /* Find corresponding channel */
        channel_t *ch = NULL;
        if (e->channel_id < WATCHTOWER_MAX_CHANNELS)
            ch = wt->channels[e->channel_id];

        if (!ch) {
            fprintf(stderr, "Watchtower: no channel %u for penalty\n", e->channel_id);
            i++;
            continue;
        }

        tx_buf_t penalty_tx;
        tx_buf_init(&penalty_tx, 512);

        if (!channel_build_penalty_tx(ch, &penalty_tx,
                                        e->txid, e->to_local_vout,
                                        e->to_local_amount,
                                        e->to_local_spk, e->to_local_spk_len,
                                        e->commit_num)) {
            fprintf(stderr, "Watchtower: build penalty tx failed for channel %u\n",
                    e->channel_id);
            tx_buf_free(&penalty_tx);
            i++;
            continue;
        }

        /* Broadcast penalty tx */
        char *penalty_hex = (char *)malloc(penalty_tx.len * 2 + 1);
        if (penalty_hex) {
            hex_encode(penalty_tx.data, penalty_tx.len, penalty_hex);
            char penalty_txid[65];
            if (regtest_send_raw_tx(wt->rt, penalty_hex, penalty_txid)) {
                printf("  Penalty tx broadcast: %s\n", penalty_txid);
                penalties_broadcast++;
            } else {
                fprintf(stderr, "  Penalty tx broadcast failed\n");
            }
            free(penalty_hex);
        }
        tx_buf_free(&penalty_tx);

        /* Remove this entry (swap with last) */
        wt->entries[i] = wt->entries[wt->n_entries - 1];
        wt->n_entries--;
        /* Don't increment i — check the swapped entry */
    }

    return penalties_broadcast;
}

void watchtower_remove_channel(watchtower_t *wt, uint32_t channel_id) {
    if (!wt) return;

    for (size_t i = 0; i < wt->n_entries; ) {
        if (wt->entries[i].channel_id == channel_id) {
            wt->entries[i] = wt->entries[wt->n_entries - 1];
            wt->n_entries--;
        } else {
            i++;
        }
    }
}
