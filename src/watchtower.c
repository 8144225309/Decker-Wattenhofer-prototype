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
                e->response_tx = NULL;
                e->response_tx_len = 0;
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
                                           uint64_t old_local, uint64_t old_remote) {
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

    /* Temporarily set to old state.
     * We clear HTLCs because we don't track per-commitment HTLC state.
     * Build the REMOTE commitment (what the peer holds) since that's
     * what would appear on-chain in a breach scenario.
     * The old remote PCP can be derived from the just-received revocation secret
     * (which is stored in received_revocations[old_commit_num]). */
    ch->commitment_number = old_commit_num;
    ch->local_amount = old_local;
    ch->remote_amount = old_remote;
    ch->n_htlcs = 0;

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

    /* to_local is vout 0, its SPK is the first output scriptPubKey */
    /* Extract to_local_spk from the old commitment tx output 0 */
    unsigned char to_local_spk[34];
    /* In our commitment tx, output[0] = to_local with a P2TR SPK (34 bytes) */
    /* Parse the first output's SPK from the unsigned raw tx (no segwit marker/flag) */
    if (old_tx.len > 60) {
        /* Unsigned tx layout (no segwit marker/flag):
           4 version + 1 vincount +
           (32 prevhash + 4 vout + 1 scriptlen + 0 script + 4 sequence) = 41 vin bytes
           + 1 voutcount = 47 bytes offset to first output
           First output: 8 amount + 1 scriptlen + N script */
        size_t ofs = 4 + 1 + 41 + 1;  /* 47 */
        if (ofs + 8 + 1 + 34 <= old_tx.len) {
            uint8_t spk_len = old_tx.data[ofs + 8];
            if (spk_len == 34) {
                memcpy(to_local_spk, &old_tx.data[ofs + 9], 34);
                /* Remote commitment's to_local = peer's balance = old_remote */
                watchtower_watch(wt, channel_id, old_commit_num,
                                   old_txid, 0, old_remote,
                                   to_local_spk, 34);
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
