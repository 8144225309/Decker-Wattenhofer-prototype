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
                e->type = WATCH_COMMITMENT;
                e->channel_id = (uint32_t)c;
                e->commit_num = commit_nums[i];
                memcpy(e->txid, txids[i], 32);
                e->to_local_vout = vouts[i];
                e->to_local_amount = amounts[i];
                memcpy(e->to_local_spk, spks[i], spk_lens[i]);
                e->to_local_spk_len = spk_lens[i];
                e->n_htlc_outputs = 0;
                e->response_tx = NULL;
                e->response_tx_len = 0;

                /* Load persisted HTLC output data for this commitment */
                if (db && db->db) {
                    e->n_htlc_outputs = persist_load_old_commitment_htlcs(
                        db, (uint32_t)c, commit_nums[i],
                        e->htlc_outputs, MAX_HTLCS);
                }
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
    e->type = WATCH_COMMITMENT;
    e->channel_id = channel_id;
    e->commit_num = commit_num;
    memcpy(e->txid, txid32, 32);
    e->to_local_vout = to_local_vout;
    e->to_local_amount = to_local_amount;
    memcpy(e->to_local_spk, to_local_spk, spk_len);
    e->to_local_spk_len = spk_len;
    e->n_htlc_outputs = 0;
    e->response_tx = NULL;
    e->response_tx_len = 0;

    /* Persist if DB available */
    if (wt->db && wt->db->db) {
        persist_save_old_commitment(wt->db, channel_id, commit_num,
                                      txid32, to_local_vout, to_local_amount,
                                      to_local_spk, spk_len);
    }

    return 1;
}

void watchtower_watch_revoked_commitment(watchtower_t *wt, channel_t *ch,
                                           uint32_t channel_id,
                                           uint64_t old_commit_num,
                                           uint64_t old_local, uint64_t old_remote,
                                           const htlc_t *old_htlcs, size_t old_n_htlcs) {
    if (!wt)
        return;

    /* Save current state (including HTLC state — the old commitment may have
     * had different active HTLCs than the current channel state) */
    uint64_t saved_num = ch->commitment_number;
    uint64_t saved_local = ch->local_amount;
    uint64_t saved_remote = ch->remote_amount;
    size_t saved_n_htlcs = ch->n_htlcs;
    htlc_t saved_htlcs[MAX_HTLCS];
    if (saved_n_htlcs > 0)
        memcpy(saved_htlcs, ch->htlcs, saved_n_htlcs * sizeof(htlc_t));

    /* Temporarily set to old state, restoring the HTLC state that was active
     * at the time of the old commitment. This ensures the rebuilt commitment tx
     * includes HTLC outputs and produces the correct txid. */
    ch->commitment_number = old_commit_num;
    ch->local_amount = old_local;
    ch->remote_amount = old_remote;
    if (old_htlcs && old_n_htlcs > 0) {
        ch->n_htlcs = old_n_htlcs;
        memcpy(ch->htlcs, old_htlcs, old_n_htlcs * sizeof(htlc_t));
    } else {
        ch->n_htlcs = 0;
    }

    /* Count active HTLCs for output parsing */
    size_t n_active_htlcs = 0;
    for (size_t i = 0; i < ch->n_htlcs; i++) {
        if (ch->htlcs[i].state == HTLC_STATE_ACTIVE)
            n_active_htlcs++;
    }

    /* Ensure old remote PCP is available: derive from stored revocation secret */
    {
        unsigned char old_rev_secret[32];
        if (channel_get_received_revocation(ch, old_commit_num, old_rev_secret)) {
            secp256k1_pubkey old_pcp;
            if (secp256k1_ec_pubkey_create(ch->ctx, &old_pcp, old_rev_secret)) {
                channel_set_remote_pcp(ch, old_commit_num, &old_pcp);
            }
            memset(old_rev_secret, 0, 32);
        }
    }

    tx_buf_t old_tx;
    tx_buf_init(&old_tx, 512);
    unsigned char old_txid[32];
    int ok = channel_build_commitment_tx_for_remote(ch, &old_tx, old_txid);

    /* Restore state */
    ch->commitment_number = saved_num;
    ch->local_amount = saved_local;
    ch->remote_amount = saved_remote;
    ch->n_htlcs = saved_n_htlcs;
    if (saved_n_htlcs > 0)
        memcpy(ch->htlcs, saved_htlcs, saved_n_htlcs * sizeof(htlc_t));

    if (!ok) {
        tx_buf_free(&old_tx);
        return;
    }

    /* Parse outputs from the unsigned raw tx.
     * Layout (no segwit marker/flag):
     *   4 version + 1 vincount +
     *   (32 prevhash + 4 vout + 1 scriptlen + 0 script + 4 sequence) = 41 vin bytes
     *   + 1 voutcount = 47 bytes offset to first output
     *   Each output: 8 amount (LE) + 1 spk_len + spk_len bytes */
    if (old_tx.len > 60) {
        size_t ofs = 4 + 1 + 41 + 1;  /* 47: offset to first output */

        /* Output 0: to_local */
        if (ofs + 8 + 1 + 34 <= old_tx.len) {
            uint8_t spk_len = old_tx.data[ofs + 8];
            if (spk_len == 34) {
                unsigned char to_local_spk[34];
                memcpy(to_local_spk, &old_tx.data[ofs + 9], 34);
                /* Remote commitment's to_local = peer's balance = old_remote */
                watchtower_watch(wt, channel_id, old_commit_num,
                                   old_txid, 0, old_remote,
                                   to_local_spk, 34);
            }
        }

        /* If we have active HTLCs, parse their outputs (vout 2+) and store
         * in the watchtower entry we just created */
        if (n_active_htlcs > 0 && wt->n_entries > 0) {
            watchtower_entry_t *entry = &wt->entries[wt->n_entries - 1];
            entry->n_htlc_outputs = 0;

            /* Skip output 0 and output 1 to reach HTLC outputs */
            size_t out_ofs = ofs;
            for (uint32_t v = 0; v < 2; v++) {
                if (out_ofs + 9 > old_tx.len) break;
                uint8_t slen = old_tx.data[out_ofs + 8];
                out_ofs += 8 + 1 + slen;
            }

            /* Parse HTLC outputs (vout 2, 3, ...) */
            size_t htlc_active_idx = 0;
            for (size_t i = 0; i < old_n_htlcs && htlc_active_idx < n_active_htlcs; i++) {
                if (old_htlcs[i].state != HTLC_STATE_ACTIVE)
                    continue;

                if (out_ofs + 8 + 1 > old_tx.len) break;
                uint64_t amount = 0;
                for (int b = 0; b < 8; b++)
                    amount |= ((uint64_t)old_tx.data[out_ofs + b]) << (b * 8);
                uint8_t slen = old_tx.data[out_ofs + 8];
                if (slen != 34 || out_ofs + 9 + slen > old_tx.len) {
                    out_ofs += 8 + 1 + slen;
                    htlc_active_idx++;
                    continue;
                }

                watchtower_htlc_t *wh = &entry->htlc_outputs[entry->n_htlc_outputs];
                wh->htlc_vout = (uint32_t)(2 + htlc_active_idx);
                wh->htlc_amount = amount;
                memcpy(wh->htlc_spk, &old_tx.data[out_ofs + 9], 34);
                wh->direction = old_htlcs[i].direction;
                memcpy(wh->payment_hash, old_htlcs[i].payment_hash, 32);
                wh->cltv_expiry = old_htlcs[i].cltv_expiry;
                entry->n_htlc_outputs++;

                out_ofs += 8 + 1 + slen;
                htlc_active_idx++;
            }

            /* Persist HTLC outputs if DB available */
            if (wt->db && wt->db->db) {
                for (size_t h = 0; h < entry->n_htlc_outputs; h++) {
                    persist_save_old_commitment_htlc(wt->db, channel_id,
                        old_commit_num, &entry->htlc_outputs[h]);
                }
            }
        }
    }

    tx_buf_free(&old_tx);
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

        if (e->type == WATCH_FACTORY_NODE) {
            printf("FACTORY BREACH on node %u (txid: %s)!\n",
                   e->channel_id, txid_hex);

            /* Broadcast the pre-built latest state tx as response */
            if (e->response_tx && e->response_tx_len > 0) {
                char *resp_hex = (char *)malloc(e->response_tx_len * 2 + 1);
                if (resp_hex) {
                    hex_encode(e->response_tx, e->response_tx_len, resp_hex);
                    char resp_txid[65];
                    if (regtest_send_raw_tx(wt->rt, resp_hex, resp_txid)) {
                        printf("  Latest state tx broadcast: %s\n", resp_txid);
                        penalties_broadcast++;
                    } else {
                        fprintf(stderr, "  Latest state tx broadcast failed\n");
                    }
                    free(resp_hex);
                }
            }

            /* Free response_tx and remove entry */
            free(e->response_tx);
            e->response_tx = NULL;
            wt->entries[i] = wt->entries[wt->n_entries - 1];
            wt->n_entries--;
            continue;
        }

        /* WATCH_COMMITMENT: build and broadcast penalty tx */
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

        /* Sweep HTLC outputs via penalty txs */
        for (size_t h = 0; h < e->n_htlc_outputs; h++) {
            /* Temporarily set ch->htlcs[0] to stored HTLC metadata */
            size_t saved_n = ch->n_htlcs;
            htlc_t saved_h0;
            if (saved_n > 0)
                saved_h0 = ch->htlcs[0];
            ch->n_htlcs = 1;
            memset(&ch->htlcs[0], 0, sizeof(htlc_t));
            ch->htlcs[0].direction = e->htlc_outputs[h].direction;
            memcpy(ch->htlcs[0].payment_hash, e->htlc_outputs[h].payment_hash, 32);
            ch->htlcs[0].cltv_expiry = e->htlc_outputs[h].cltv_expiry;
            ch->htlcs[0].state = HTLC_STATE_ACTIVE;

            tx_buf_t htlc_penalty;
            tx_buf_init(&htlc_penalty, 512);
            if (channel_build_htlc_penalty_tx(ch, &htlc_penalty,
                    e->txid, e->htlc_outputs[h].htlc_vout,
                    e->htlc_outputs[h].htlc_amount,
                    e->htlc_outputs[h].htlc_spk, 34,
                    e->commit_num, 0)) {
                char *htlc_hex = (char *)malloc(htlc_penalty.len * 2 + 1);
                if (htlc_hex) {
                    hex_encode(htlc_penalty.data, htlc_penalty.len, htlc_hex);
                    char htlc_txid[65];
                    if (regtest_send_raw_tx(wt->rt, htlc_hex, htlc_txid)) {
                        printf("  HTLC penalty tx (vout %u) broadcast: %s\n",
                               e->htlc_outputs[h].htlc_vout, htlc_txid);
                        penalties_broadcast++;
                    } else {
                        fprintf(stderr, "  HTLC penalty tx (vout %u) broadcast failed\n",
                                e->htlc_outputs[h].htlc_vout);
                    }
                    free(htlc_hex);
                }
            }
            tx_buf_free(&htlc_penalty);

            ch->n_htlcs = saved_n;
            if (saved_n > 0)
                ch->htlcs[0] = saved_h0;
        }

        /* Remove this entry (swap with last) */
        wt->entries[i] = wt->entries[wt->n_entries - 1];
        wt->n_entries--;
        /* Don't increment i — check the swapped entry */
    }

    return penalties_broadcast;
}

int watchtower_watch_factory_node(watchtower_t *wt, uint32_t node_idx,
                                    const unsigned char *old_txid32,
                                    const unsigned char *response_tx,
                                    size_t response_tx_len) {
    if (!wt || !old_txid32 || !response_tx || response_tx_len == 0) return 0;
    if (wt->n_entries >= WATCHTOWER_MAX_WATCH) return 0;

    watchtower_entry_t *e = &wt->entries[wt->n_entries++];
    memset(e, 0, sizeof(*e));
    e->type = WATCH_FACTORY_NODE;
    e->channel_id = node_idx;
    e->commit_num = 0;
    memcpy(e->txid, old_txid32, 32);

    e->response_tx = (unsigned char *)malloc(response_tx_len);
    if (!e->response_tx) {
        wt->n_entries--;
        return 0;
    }
    memcpy(e->response_tx, response_tx, response_tx_len);
    e->response_tx_len = response_tx_len;

    return 1;
}

void watchtower_cleanup(watchtower_t *wt) {
    if (!wt) return;
    for (size_t i = 0; i < wt->n_entries; i++) {
        if (wt->entries[i].type == WATCH_FACTORY_NODE && wt->entries[i].response_tx) {
            free(wt->entries[i].response_tx);
            wt->entries[i].response_tx = NULL;
        }
    }
}

void watchtower_remove_channel(watchtower_t *wt, uint32_t channel_id) {
    if (!wt) return;

    for (size_t i = 0; i < wt->n_entries; ) {
        if (wt->entries[i].channel_id == channel_id) {
            if (wt->entries[i].type == WATCH_FACTORY_NODE &&
                wt->entries[i].response_tx) {
                free(wt->entries[i].response_tx);
            }
            wt->entries[i] = wt->entries[wt->n_entries - 1];
            wt->n_entries--;
        } else {
            i++;
        }
    }
}
