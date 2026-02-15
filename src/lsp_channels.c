#include "superscalar/lsp_channels.h"
#include "superscalar/persist.h"
#include "superscalar/factory.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

extern void sha256(const unsigned char *, size_t, unsigned char *);

/* After receiving a revocation, register the old commitment with the watchtower.
   We rebuild the old commitment tx to get its txid and to_local output info. */
static void watch_revoked_commitment(watchtower_t *wt, channel_t *ch,
                                       uint32_t channel_id,
                                       uint64_t old_commit_num,
                                       uint64_t old_local, uint64_t old_remote) {
    if (!wt) return;

    /* Save current state */
    uint64_t saved_num = ch->commitment_number;
    uint64_t saved_local = ch->local_amount;
    uint64_t saved_remote = ch->remote_amount;

    /* Temporarily set to old state */
    ch->commitment_number = old_commit_num;
    ch->local_amount = old_local;
    ch->remote_amount = old_remote;

    tx_buf_t old_tx;
    tx_buf_init(&old_tx, 512);
    unsigned char old_txid[32];
    int ok = channel_build_commitment_tx(ch, &old_tx, old_txid);

    /* Restore state */
    ch->commitment_number = saved_num;
    ch->local_amount = saved_local;
    ch->remote_amount = saved_remote;

    if (!ok) {
        tx_buf_free(&old_tx);
        return;
    }

    /* to_local is vout 0, its SPK is the first output scriptPubKey */
    /* Extract to_local_spk from the old commitment tx output 0 */
    unsigned char to_local_spk[34];
    /* In our commitment tx, output[0] = to_local with a P2TR SPK (34 bytes) */
    /* We can get the SPK from the serialized tx: skip past version(4)+marker(1)+flag(1)+
       vin_count(1)+vin(41)+vout_count(1) to first output amount(8)+spk_len(1)+spk(34) */
    /* Simpler: use the to_local amount = old_local (what was local at that commitment) */
    /* For the SPK, rebuild it from the commitment tx structure */
    /* Actually, the simplest approach: parse the first output's SPK from the raw tx */
    if (old_tx.len > 60) {
        /* Standard commitment tx layout (segwit):
           4 version + 1 marker + 1 flag + 1 vincount +
           (32 prevhash + 4 vout + 1 scriptlen + 0 script + 4 sequence) = 41 vin bytes
           + 1 voutcount = 49 bytes offset to first output
           First output: 8 amount + 1 scriptlen + N script */
        size_t ofs = 4 + 1 + 1 + 1 + 41 + 1;  /* 49 */
        if (ofs + 8 + 1 + 34 <= old_tx.len) {
            uint8_t spk_len = old_tx.data[ofs + 8];
            if (spk_len == 34) {
                memcpy(to_local_spk, &old_tx.data[ofs + 9], 34);
                watchtower_watch(wt, channel_id, old_commit_num,
                                   old_txid, 0, old_local,
                                   to_local_spk, 34);
            }
        }
    }

    tx_buf_free(&old_tx);
}

/*
 * Factory tree layout (5 participants: LSP=0, A=1, B=2, C=3, D=4):
 *   node[0] = kickoff_root (5-of-5)
 *   node[1] = state_root   (5-of-5)
 *   node[2] = kickoff_left (3-of-3: LSP,A,B)
 *   node[3] = kickoff_right(3-of-3: LSP,C,D)
 *   node[4] = state_left   (3-of-3) -> outputs: [chan_A, chan_B, L_stock]
 *   node[5] = state_right  (3-of-3) -> outputs: [chan_C, chan_D, L_stock]
 *
 * Channel mapping:
 *   client 0 (A): node[4].txid, vout=0
 *   client 1 (B): node[4].txid, vout=1
 *   client 2 (C): node[5].txid, vout=0
 *   client 3 (D): node[5].txid, vout=1
 */

/* Map client index (0-based) to factory state node and vout */
static void client_to_leaf(size_t client_idx, size_t *node_idx_out,
                            uint32_t *vout_out) {
    if (client_idx < 2) {
        *node_idx_out = 4;  /* state_left */
        *vout_out = (uint32_t)client_idx;
    } else {
        *node_idx_out = 5;  /* state_right */
        *vout_out = (uint32_t)(client_idx - 2);
    }
}

int lsp_channels_init(lsp_channel_mgr_t *mgr,
                       secp256k1_context *ctx,
                       const factory_t *factory,
                       const unsigned char *lsp_seckey32,
                       size_t n_clients) {
    if (!mgr || !ctx || !factory || !lsp_seckey32) return 0;
    if (n_clients > LSP_MAX_CLIENTS || n_clients != 4) return 0;

    memset(mgr, 0, sizeof(*mgr));
    mgr->ctx = ctx;
    mgr->n_channels = n_clients;
    mgr->bridge_fd = -1;
    mgr->n_invoices = 0;
    mgr->n_htlc_origins = 0;
    mgr->next_request_id = 1;

    for (size_t c = 0; c < n_clients; c++) {
        lsp_channel_entry_t *entry = &mgr->entries[c];
        entry->channel_id = (uint32_t)c;
        entry->ready = 0;

        /* Find leaf output for this client */
        size_t node_idx;
        uint32_t vout;
        client_to_leaf(c, &node_idx, &vout);

        const factory_node_t *state_node = &factory->nodes[node_idx];
        if (vout >= state_node->n_outputs) return 0;

        /* Funding info from the leaf output */
        const unsigned char *funding_txid = state_node->txid;  /* internal byte order */
        uint64_t funding_amount = state_node->outputs[vout].amount_sats;
        const unsigned char *funding_spk = state_node->outputs[vout].script_pubkey;
        size_t funding_spk_len = state_node->outputs[vout].script_pubkey_len;

        /* LSP pubkey (participant 0) */
        secp256k1_pubkey lsp_pubkey;
        if (!secp256k1_ec_pubkey_create(ctx, &lsp_pubkey, lsp_seckey32))
            return 0;

        /* Client pubkey (participant c+1) */
        const secp256k1_pubkey *client_pubkey = &factory->pubkeys[c + 1];

        /* Initial balance: split equally */
        uint64_t local_amount = funding_amount / 2;
        uint64_t remote_amount = funding_amount - local_amount;

        /* Initialize channel: LSP = local, client = remote */
        if (!channel_init(&entry->channel, ctx,
                           lsp_seckey32,
                           &lsp_pubkey,
                           client_pubkey,
                           funding_txid, vout,
                           funding_amount,
                           funding_spk, funding_spk_len,
                           local_amount, remote_amount,
                           CHANNEL_DEFAULT_CSV_DELAY))
            return 0;

        /* Set up basepoints using deterministic derivation from LSP seckey.
           Use SHA256(lsp_seckey || "payment" || client_idx) etc. */
        unsigned char payment_secret[32], delayed_secret[32], revocation_secret[32];
        unsigned char htlc_secret[32];
        {
            unsigned char buf[32 + 16];
            memcpy(buf, lsp_seckey32, 32);

            memcpy(buf + 32, "payment\0\0\0\0\0\0\0\0", 8);
            buf[40] = (unsigned char)c;
            sha256(buf, 41, payment_secret);

            memcpy(buf + 32, "delayed\0\0\0\0\0\0\0\0", 8);
            buf[40] = (unsigned char)c;
            sha256(buf, 41, delayed_secret);

            memcpy(buf + 32, "revocatn", 8);
            buf[40] = (unsigned char)c;
            sha256(buf, 41, revocation_secret);

            memcpy(buf + 32, "htlcbase", 8);
            buf[40] = (unsigned char)c;
            sha256(buf, 41, htlc_secret);
        }

        channel_set_local_basepoints(&entry->channel,
                                      payment_secret, delayed_secret,
                                      revocation_secret);
        channel_set_local_htlc_basepoint(&entry->channel, htlc_secret);

        /* Set remote basepoints: use deterministic derivation from client pubkey.
           Since we don't have the client's secrets, we derive "pseudo-basepoints"
           from the client's pubkey serialization.
           In a real protocol, clients would send their basepoints in CHANNEL_READY.
           For the PoC, we use a shared deterministic scheme. */
        unsigned char client_pk_ser[33];
        size_t pk_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, client_pk_ser, &pk_len, client_pubkey,
                                       SECP256K1_EC_COMPRESSED);

        /* Derive remote basepoint pubkeys from client pubkey */
        unsigned char rpay_sec[32], rdelay_sec[32], rrevoc_sec[32], rhtlc_sec[32];
        {
            unsigned char buf[33 + 16];
            memcpy(buf, client_pk_ser, 33);

            memcpy(buf + 33, "payment\0", 8);
            sha256(buf, 41, rpay_sec);

            memcpy(buf + 33, "delayed\0", 8);
            sha256(buf, 41, rdelay_sec);

            memcpy(buf + 33, "revocatn", 8);
            sha256(buf, 41, rrevoc_sec);

            memcpy(buf + 33, "htlcbase", 8);
            sha256(buf, 41, rhtlc_sec);
        }

        secp256k1_pubkey rpay, rdelay, rrevoc, rhtlc;
        secp256k1_ec_pubkey_create(ctx, &rpay, rpay_sec);
        secp256k1_ec_pubkey_create(ctx, &rdelay, rdelay_sec);
        secp256k1_ec_pubkey_create(ctx, &rrevoc, rrevoc_sec);
        secp256k1_ec_pubkey_create(ctx, &rhtlc, rhtlc_sec);

        channel_set_remote_basepoints(&entry->channel, &rpay, &rdelay, &rrevoc);
        channel_set_remote_htlc_basepoint(&entry->channel, &rhtlc);

        /* Shachain seed: deterministic from LSP key + channel_id */
        unsigned char seed[32];
        {
            unsigned char buf[33];
            memcpy(buf, lsp_seckey32, 32);
            buf[32] = (unsigned char)c;
            sha256(buf, 33, seed);
        }
        channel_set_shachain_seed(&entry->channel, seed);

        memset(payment_secret, 0, 32);
        memset(delayed_secret, 0, 32);
        memset(revocation_secret, 0, 32);
        memset(htlc_secret, 0, 32);

        /* Initialize nonce pool for commitment signing (Phase 12) */
        if (!channel_init_nonce_pool(&entry->channel, MUSIG_NONCE_POOL_MAX))
            return 0;
    }

    return 1;
}

int lsp_channels_send_ready(lsp_channel_mgr_t *mgr, lsp_t *lsp) {
    if (!mgr || !lsp) return 0;

    for (size_t c = 0; c < mgr->n_channels; c++) {
        lsp_channel_entry_t *entry = &mgr->entries[c];

        /* Send CHANNEL_READY */
        cJSON *msg = wire_build_channel_ready(
            entry->channel_id,
            entry->channel.local_amount * 1000,   /* sats → msat */
            entry->channel.remote_amount * 1000);
        if (!wire_send(lsp->client_fds[c], MSG_CHANNEL_READY, msg)) {
            fprintf(stderr, "LSP: failed to send CHANNEL_READY to client %zu\n", c);
            cJSON_Delete(msg);
            return 0;
        }
        cJSON_Delete(msg);

        /* Phase 12: Send nonce pool pubnonces to client */
        {
            channel_t *ch = &entry->channel;
            size_t nonce_count = ch->local_nonce_pool.count;
            unsigned char (*pubnonces_ser)[66] =
                (unsigned char (*)[66])calloc(nonce_count, 66);
            if (!pubnonces_ser) return 0;

            for (size_t i = 0; i < nonce_count; i++) {
                musig_pubnonce_serialize(mgr->ctx,
                    pubnonces_ser[i], &ch->local_nonce_pool.nonces[i].pubnonce);
            }

            cJSON *nonce_msg = wire_build_channel_nonces(
                entry->channel_id, (const unsigned char (*)[66])pubnonces_ser,
                nonce_count);
            if (!wire_send(lsp->client_fds[c], MSG_CHANNEL_NONCES, nonce_msg)) {
                fprintf(stderr, "LSP: failed to send CHANNEL_NONCES to client %zu\n", c);
                cJSON_Delete(nonce_msg);
                free(pubnonces_ser);
                return 0;
            }
            cJSON_Delete(nonce_msg);
            free(pubnonces_ser);
        }

        /* Wait for client's nonces */
        {
            wire_msg_t nonce_resp;
            if (!wire_recv(lsp->client_fds[c], &nonce_resp) ||
                nonce_resp.msg_type != MSG_CHANNEL_NONCES) {
                fprintf(stderr, "LSP: expected CHANNEL_NONCES from client %zu\n", c);
                if (nonce_resp.json) cJSON_Delete(nonce_resp.json);
                return 0;
            }

            uint32_t resp_ch_id;
            unsigned char client_nonces[MUSIG_NONCE_POOL_MAX][66];
            size_t client_nonce_count;
            if (!wire_parse_channel_nonces(nonce_resp.json, &resp_ch_id,
                                             client_nonces, MUSIG_NONCE_POOL_MAX,
                                             &client_nonce_count)) {
                fprintf(stderr, "LSP: failed to parse client nonces\n");
                cJSON_Delete(nonce_resp.json);
                return 0;
            }
            cJSON_Delete(nonce_resp.json);

            channel_set_remote_pubnonces(&entry->channel,
                (const unsigned char (*)[66])client_nonces, client_nonce_count);
        }

        entry->ready = 1;
    }
    return 1;
}

/* --- HTLC handling --- */

/* Handle ADD_HTLC from a client: add to sender's channel, forward to recipient. */
static int handle_add_htlc(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                             size_t sender_idx, const cJSON *json) {
    uint64_t htlc_id, amount_msat;
    unsigned char payment_hash[32];
    uint32_t cltv_expiry;

    if (!wire_parse_update_add_htlc(json, &htlc_id, &amount_msat,
                                      payment_hash, &cltv_expiry))
        return 0;

    uint64_t amount_sats = amount_msat / 1000;
    if (amount_sats == 0) return 0;

    channel_t *sender_ch = &mgr->entries[sender_idx].channel;

    /* Add HTLC to sender's channel (offered from client = received by LSP) */
    uint64_t new_htlc_id;
    if (!channel_add_htlc(sender_ch, HTLC_RECEIVED, amount_sats,
                           payment_hash, cltv_expiry, &new_htlc_id)) {
        fprintf(stderr, "LSP: add_htlc failed for client %zu (insufficient funds?)\n",
                sender_idx);
        /* Send fail back */
        cJSON *fail = wire_build_update_fail_htlc(htlc_id, "insufficient funds");
        wire_send(lsp->client_fds[sender_idx], MSG_UPDATE_FAIL_HTLC, fail);
        cJSON_Delete(fail);
        return 1;  /* not a protocol error, just a payment failure */
    }

    /* Send COMMITMENT_SIGNED to sender (real partial sig) */
    {
        unsigned char psig32[32];
        uint32_t nonce_idx;
        if (!channel_create_commitment_partial_sig(sender_ch, psig32, &nonce_idx)) {
            fprintf(stderr, "LSP: create partial sig failed for sender %zu\n", sender_idx);
            return 0;
        }
        cJSON *cs = wire_build_commitment_signed(
            mgr->entries[sender_idx].channel_id,
            sender_ch->commitment_number, psig32, nonce_idx);
        if (!wire_send(lsp->client_fds[sender_idx], MSG_COMMITMENT_SIGNED, cs)) {
            cJSON_Delete(cs);
            return 0;
        }
        cJSON_Delete(cs);
    }

    /* Wait for REVOKE_AND_ACK from sender */
    {
        wire_msg_t ack_msg;
        if (!wire_recv(lsp->client_fds[sender_idx], &ack_msg) ||
            ack_msg.msg_type != MSG_REVOKE_AND_ACK) {
            if (ack_msg.json) cJSON_Delete(ack_msg.json);
            fprintf(stderr, "LSP: expected REVOKE_AND_ACK from sender %zu\n", sender_idx);
            return 0;
        }
        /* Parse and store revocation secret */
        uint32_t ack_chan_id;
        unsigned char rev_secret[32], next_point[33];
        if (wire_parse_revoke_and_ack(ack_msg.json, &ack_chan_id,
                                        rev_secret, next_point)) {
            uint64_t old_cn = sender_ch->commitment_number - 1;
            channel_receive_revocation(sender_ch, old_cn, rev_secret);
            watch_revoked_commitment(mgr->watchtower, sender_ch,
                (uint32_t)sender_idx, old_cn,
                sender_ch->local_amount, sender_ch->remote_amount);
        }
        cJSON_Delete(ack_msg.json);
    }

    /* Find destination: check dest_client field, then bolt11 for bridge routing */
    cJSON *dest_item = cJSON_GetObjectItem(json, "dest_client");
    cJSON *bolt11_item = cJSON_GetObjectItem(json, "bolt11");

    /* If bolt11 present and bridge connected, route outbound via bridge */
    if ((!dest_item || !cJSON_IsNumber(dest_item)) &&
        bolt11_item && cJSON_IsString(bolt11_item) && mgr->bridge_fd >= 0) {
        uint64_t request_id = mgr->next_request_id++;
        cJSON *pay = wire_build_bridge_send_pay(bolt11_item->valuestring,
                                                  payment_hash, request_id);
        int ok = wire_send(mgr->bridge_fd, MSG_BRIDGE_SEND_PAY, pay);
        cJSON_Delete(pay);
        if (!ok) return 0;

        /* Track origin for when PAY_RESULT comes back */
        lsp_channels_track_bridge_origin(mgr, payment_hash, 0);
        /* Store request_id + sender info for back-propagation */
        if (mgr->n_htlc_origins > 0) {
            htlc_origin_t *origin = &mgr->htlc_origins[mgr->n_htlc_origins - 1];
            origin->request_id = request_id;
            origin->sender_idx = sender_idx;
            origin->sender_htlc_id = new_htlc_id;
            /* Persist full origin with all fields */
            if (mgr->persist)
                persist_save_htlc_origin((persist_t *)mgr->persist,
                    payment_hash, 0, request_id, sender_idx, new_htlc_id);
        }
        if (mgr->persist)
            persist_save_counter((persist_t *)mgr->persist,
                                  "next_request_id", mgr->next_request_id);
        printf("LSP: HTLC from client %zu routed to bridge (bolt11)\n", sender_idx);
        return 1;
    }

    if (!dest_item || !cJSON_IsNumber(dest_item)) {
        fprintf(stderr, "LSP: ADD_HTLC missing dest_client\n");
        return 0;
    }
    size_t dest_idx = (size_t)dest_item->valuedouble;
    if (dest_idx >= mgr->n_channels || dest_idx == sender_idx) {
        fprintf(stderr, "LSP: invalid dest_client %zu\n", dest_idx);
        return 0;
    }

    channel_t *dest_ch = &mgr->entries[dest_idx].channel;

    /* Add HTLC to destination's channel (offered from LSP) */
    uint64_t dest_htlc_id;
    if (!channel_add_htlc(dest_ch, HTLC_OFFERED, amount_sats,
                           payment_hash, cltv_expiry, &dest_htlc_id)) {
        fprintf(stderr, "LSP: forward add_htlc failed to client %zu\n", dest_idx);
        return 0;
    }

    /* Forward ADD_HTLC to destination */
    {
        cJSON *fwd = wire_build_update_add_htlc(dest_htlc_id, amount_msat,
                                                   payment_hash, cltv_expiry);
        if (!wire_send(lsp->client_fds[dest_idx], MSG_UPDATE_ADD_HTLC, fwd)) {
            cJSON_Delete(fwd);
            return 0;
        }
        cJSON_Delete(fwd);
    }

    /* Send COMMITMENT_SIGNED to dest (real partial sig) */
    {
        unsigned char psig32[32];
        uint32_t nonce_idx;
        if (!channel_create_commitment_partial_sig(dest_ch, psig32, &nonce_idx)) {
            fprintf(stderr, "LSP: create partial sig failed for dest %zu\n", dest_idx);
            return 0;
        }
        cJSON *cs = wire_build_commitment_signed(
            mgr->entries[dest_idx].channel_id,
            dest_ch->commitment_number, psig32, nonce_idx);
        if (!wire_send(lsp->client_fds[dest_idx], MSG_COMMITMENT_SIGNED, cs)) {
            cJSON_Delete(cs);
            return 0;
        }
        cJSON_Delete(cs);
    }

    /* Wait for REVOKE_AND_ACK from dest */
    {
        wire_msg_t ack_msg;
        if (!wire_recv(lsp->client_fds[dest_idx], &ack_msg) ||
            ack_msg.msg_type != MSG_REVOKE_AND_ACK) {
            if (ack_msg.json) cJSON_Delete(ack_msg.json);
            fprintf(stderr, "LSP: expected REVOKE_AND_ACK from dest %zu\n", dest_idx);
            return 0;
        }
        uint32_t ack_chan_id;
        unsigned char rev_secret[32], next_point[33];
        if (wire_parse_revoke_and_ack(ack_msg.json, &ack_chan_id,
                                        rev_secret, next_point)) {
            uint64_t old_cn = dest_ch->commitment_number - 1;
            channel_receive_revocation(dest_ch, old_cn, rev_secret);
            watch_revoked_commitment(mgr->watchtower, dest_ch,
                (uint32_t)dest_idx, old_cn,
                dest_ch->local_amount, dest_ch->remote_amount);
        }
        cJSON_Delete(ack_msg.json);
    }

    printf("LSP: HTLC %llu forwarded: client %zu -> client %zu (%llu sats)\n",
           (unsigned long long)new_htlc_id, sender_idx, dest_idx,
           (unsigned long long)amount_sats);
    return 1;
}

/* Handle FULFILL_HTLC from a client (the payee reveals the preimage). */
static int handle_fulfill_htlc(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                 size_t client_idx, const cJSON *json) {
    uint64_t htlc_id;
    unsigned char preimage[32];

    if (!wire_parse_update_fulfill_htlc(json, &htlc_id, preimage))
        return 0;

    channel_t *ch = &mgr->entries[client_idx].channel;

    /* Fulfill the HTLC on this channel (LSP offered → client fulfills) */
    if (!channel_fulfill_htlc(ch, htlc_id, preimage)) {
        fprintf(stderr, "LSP: fulfill_htlc failed for client %zu htlc %llu\n",
                client_idx, (unsigned long long)htlc_id);
        return 0;
    }

    /* Send COMMITMENT_SIGNED to this client (real partial sig) */
    {
        unsigned char psig32[32];
        uint32_t nonce_idx;
        if (!channel_create_commitment_partial_sig(ch, psig32, &nonce_idx)) {
            fprintf(stderr, "LSP: create partial sig failed for client %zu\n", client_idx);
            return 0;
        }
        cJSON *cs = wire_build_commitment_signed(
            mgr->entries[client_idx].channel_id,
            ch->commitment_number, psig32, nonce_idx);
        if (!wire_send(lsp->client_fds[client_idx], MSG_COMMITMENT_SIGNED, cs)) {
            cJSON_Delete(cs);
            return 0;
        }
        cJSON_Delete(cs);
    }

    /* Wait for REVOKE_AND_ACK */
    {
        wire_msg_t ack_msg;
        if (!wire_recv(lsp->client_fds[client_idx], &ack_msg) ||
            ack_msg.msg_type != MSG_REVOKE_AND_ACK) {
            if (ack_msg.json) cJSON_Delete(ack_msg.json);
            return 0;
        }
        uint32_t ack_chan_id;
        unsigned char rev_secret[32], next_point[33];
        if (wire_parse_revoke_and_ack(ack_msg.json, &ack_chan_id,
                                        rev_secret, next_point)) {
            uint64_t old_cn = ch->commitment_number - 1;
            channel_receive_revocation(ch, old_cn, rev_secret);
            watch_revoked_commitment(mgr->watchtower, ch,
                (uint32_t)client_idx, old_cn,
                ch->local_amount, ch->remote_amount);
        }
        cJSON_Delete(ack_msg.json);
    }

    /* Now back-propagate: find the sender's channel that has a matching HTLC.
       We search all other channels for a received HTLC with the same payment_hash. */
    unsigned char payment_hash[32];
    /* Compute hash from preimage */
    sha256(preimage, 32, payment_hash);

    /* Deactivate fulfilled invoice in persistence */
    if (mgr->persist)
        persist_deactivate_invoice((persist_t *)mgr->persist, payment_hash);

    /* Check if this HTLC originated from the bridge */
    uint64_t bridge_htlc_id = lsp_channels_get_bridge_origin(mgr, payment_hash);
    if (bridge_htlc_id > 0 && mgr->bridge_fd >= 0) {
        /* Back-propagate to bridge instead of intra-factory */
        cJSON *fulfill = wire_build_bridge_fulfill_htlc(payment_hash, preimage,
                                                          bridge_htlc_id);
        wire_send(mgr->bridge_fd, MSG_BRIDGE_FULFILL_HTLC, fulfill);
        cJSON_Delete(fulfill);
        printf("LSP: HTLC fulfilled via bridge (htlc_id=%llu)\n",
               (unsigned long long)bridge_htlc_id);
        return 1;
    }

    for (size_t s = 0; s < mgr->n_channels; s++) {
        if (s == client_idx) continue;
        channel_t *sender_ch = &mgr->entries[s].channel;

        /* Find matching received HTLC (from sender's perspective, LSP received it) */
        for (size_t h = 0; h < sender_ch->n_htlcs; h++) {
            htlc_t *htlc = &sender_ch->htlcs[h];
            if (htlc->state != HTLC_STATE_ACTIVE) continue;
            if (htlc->direction != HTLC_RECEIVED) continue;
            if (memcmp(htlc->payment_hash, payment_hash, 32) != 0) continue;

            /* Found it — fulfill on sender's channel */
            if (!channel_fulfill_htlc(sender_ch, htlc->id, preimage)) {
                fprintf(stderr, "LSP: back-fulfill failed\n");
                continue;
            }

            /* Send FULFILL_HTLC to sender */
            cJSON *fwd = wire_build_update_fulfill_htlc(htlc->id, preimage);
            wire_send(lsp->client_fds[s], MSG_UPDATE_FULFILL_HTLC, fwd);
            cJSON_Delete(fwd);

            /* Send COMMITMENT_SIGNED (real partial sig) */
            {
                unsigned char psig32[32];
                uint32_t nonce_idx;
                if (!channel_create_commitment_partial_sig(sender_ch, psig32, &nonce_idx)) {
                    fprintf(stderr, "LSP: create partial sig failed for back-propagation to %zu\n", s);
                    continue;
                }
                cJSON *cs = wire_build_commitment_signed(
                    mgr->entries[s].channel_id,
                    sender_ch->commitment_number, psig32, nonce_idx);
                wire_send(lsp->client_fds[s], MSG_COMMITMENT_SIGNED, cs);
                cJSON_Delete(cs);
            }

            /* Wait for REVOKE_AND_ACK */
            wire_msg_t ack_msg;
            if (wire_recv(lsp->client_fds[s], &ack_msg) &&
                ack_msg.msg_type == MSG_REVOKE_AND_ACK) {
                uint32_t ack_chan_id;
                unsigned char rev_secret[32], next_point[33];
                if (wire_parse_revoke_and_ack(ack_msg.json, &ack_chan_id,
                                                rev_secret, next_point)) {
                    uint64_t old_cn = sender_ch->commitment_number - 1;
                    channel_receive_revocation(sender_ch, old_cn, rev_secret);
                    watch_revoked_commitment(mgr->watchtower, sender_ch,
                        (uint32_t)s, old_cn,
                        sender_ch->local_amount, sender_ch->remote_amount);
                }
            }
            if (ack_msg.json) cJSON_Delete(ack_msg.json);

            printf("LSP: HTLC fulfilled: client %zu -> client %zu (%llu sats)\n",
                   s, client_idx, (unsigned long long)htlc->amount_sats);
            break;
        }
    }

    return 1;
}

int lsp_channels_handle_msg(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                              size_t client_idx, const wire_msg_t *msg) {
    if (!mgr || !lsp || !msg || client_idx >= mgr->n_channels) return 0;

    switch (msg->msg_type) {
    case MSG_UPDATE_ADD_HTLC:
        return handle_add_htlc(mgr, lsp, client_idx, msg->json);

    case MSG_UPDATE_FULFILL_HTLC:
        return handle_fulfill_htlc(mgr, lsp, client_idx, msg->json);

    case MSG_UPDATE_FAIL_HTLC: {
        uint64_t htlc_id;
        char reason[256];
        if (!wire_parse_update_fail_htlc(msg->json, &htlc_id, reason, sizeof(reason)))
            return 0;
        channel_t *ch = &mgr->entries[client_idx].channel;
        channel_fail_htlc(ch, htlc_id);
        printf("LSP: HTLC %llu failed by client %zu: %s\n",
               (unsigned long long)htlc_id, client_idx, reason);
        return 1;
    }

    case MSG_REGISTER_INVOICE: {
        unsigned char payment_hash[32];
        uint64_t amount_msat;
        size_t dest_client;
        if (!wire_parse_register_invoice(msg->json, payment_hash,
                                           &amount_msat, &dest_client))
            return 0;
        if (!lsp_channels_register_invoice(mgr, payment_hash,
                                             dest_client, amount_msat)) {
            fprintf(stderr, "LSP: register_invoice failed\n");
            return 0;
        }
        /* Also forward to bridge if connected */
        if (mgr->bridge_fd >= 0) {
            cJSON *reg = wire_build_bridge_register(payment_hash, amount_msat,
                                                      dest_client);
            wire_send(mgr->bridge_fd, MSG_BRIDGE_REGISTER, reg);
            cJSON_Delete(reg);
        }
        printf("LSP: registered invoice for client %zu (%llu msat)\n",
               dest_client, (unsigned long long)amount_msat);
        return 1;
    }

    case MSG_CLOSE_REQUEST:
        printf("LSP: client %zu requested close\n", client_idx);
        return 1;  /* handled by caller */

    default:
        fprintf(stderr, "LSP: unexpected msg 0x%02x from client %zu\n",
                msg->msg_type, client_idx);
        return 0;
    }
}

/* --- Bridge support functions (Phase 14) --- */

void lsp_channels_set_bridge(lsp_channel_mgr_t *mgr, int bridge_fd) {
    mgr->bridge_fd = bridge_fd;
}

int lsp_channels_register_invoice(lsp_channel_mgr_t *mgr,
                                    const unsigned char *payment_hash32,
                                    size_t dest_client, uint64_t amount_msat) {
    if (mgr->n_invoices >= MAX_INVOICE_REGISTRY) return 0;
    if (dest_client >= mgr->n_channels) return 0;

    invoice_entry_t *inv = &mgr->invoices[mgr->n_invoices++];
    memcpy(inv->payment_hash, payment_hash32, 32);
    inv->dest_client = dest_client;
    inv->amount_msat = amount_msat;
    inv->bridge_htlc_id = 0;
    inv->active = 1;

    if (mgr->persist)
        persist_save_invoice((persist_t *)mgr->persist, payment_hash32,
                              dest_client, amount_msat);
    return 1;
}

int lsp_channels_lookup_invoice(lsp_channel_mgr_t *mgr,
                                  const unsigned char *payment_hash32,
                                  size_t *dest_client_out) {
    for (size_t i = 0; i < mgr->n_invoices; i++) {
        if (!mgr->invoices[i].active) continue;
        if (memcmp(mgr->invoices[i].payment_hash, payment_hash32, 32) == 0) {
            *dest_client_out = mgr->invoices[i].dest_client;
            return 1;
        }
    }
    return 0;
}

void lsp_channels_track_bridge_origin(lsp_channel_mgr_t *mgr,
                                        const unsigned char *payment_hash32,
                                        uint64_t bridge_htlc_id) {
    if (mgr->n_htlc_origins >= MAX_HTLC_ORIGINS) return;
    htlc_origin_t *origin = &mgr->htlc_origins[mgr->n_htlc_origins++];
    memcpy(origin->payment_hash, payment_hash32, 32);
    origin->bridge_htlc_id = bridge_htlc_id;
    origin->active = 1;

    if (mgr->persist)
        persist_save_htlc_origin((persist_t *)mgr->persist, payment_hash32,
                                  bridge_htlc_id, 0, 0, 0);
}

uint64_t lsp_channels_get_bridge_origin(lsp_channel_mgr_t *mgr,
                                          const unsigned char *payment_hash32) {
    for (size_t i = 0; i < mgr->n_htlc_origins; i++) {
        if (!mgr->htlc_origins[i].active) continue;
        if (memcmp(mgr->htlc_origins[i].payment_hash, payment_hash32, 32) == 0) {
            mgr->htlc_origins[i].active = 0;
            if (mgr->persist)
                persist_deactivate_htlc_origin((persist_t *)mgr->persist,
                                                payment_hash32);
            return mgr->htlc_origins[i].bridge_htlc_id;
        }
    }
    return 0;
}

int lsp_channels_handle_bridge_msg(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                     const wire_msg_t *msg) {
    if (!mgr || !lsp || !msg) return 0;

    switch (msg->msg_type) {
    case MSG_BRIDGE_ADD_HTLC: {
        /* Inbound payment from LN via bridge */
        unsigned char payment_hash[32];
        uint64_t amount_msat, htlc_id;
        uint32_t cltv_expiry;
        if (!wire_parse_bridge_add_htlc(msg->json, payment_hash,
                                          &amount_msat, &cltv_expiry, &htlc_id))
            return 0;

        /* Look up invoice to find dest_client */
        size_t dest_idx;
        if (!lsp_channels_lookup_invoice(mgr, payment_hash, &dest_idx)) {
            /* Unknown payment hash — fail back to bridge */
            cJSON *fail = wire_build_bridge_fail_htlc(payment_hash,
                "unknown_payment_hash", htlc_id);
            wire_send(mgr->bridge_fd, MSG_BRIDGE_FAIL_HTLC, fail);
            cJSON_Delete(fail);
            printf("LSP: bridge HTLC unknown hash, failing back\n");
            return 1;
        }

        uint64_t amount_sats = amount_msat / 1000;
        if (amount_sats == 0) return 0;

        channel_t *dest_ch = &mgr->entries[dest_idx].channel;

        /* Add HTLC to destination's channel (offered from LSP) */
        uint64_t dest_htlc_id;
        if (!channel_add_htlc(dest_ch, HTLC_OFFERED, amount_sats,
                               payment_hash, cltv_expiry, &dest_htlc_id)) {
            cJSON *fail = wire_build_bridge_fail_htlc(payment_hash,
                "insufficient_funds", htlc_id);
            wire_send(mgr->bridge_fd, MSG_BRIDGE_FAIL_HTLC, fail);
            cJSON_Delete(fail);
            return 1;
        }

        /* Track bridge origin for back-propagation */
        lsp_channels_track_bridge_origin(mgr, payment_hash, htlc_id);

        /* Forward ADD_HTLC to destination client */
        cJSON *fwd = wire_build_update_add_htlc(dest_htlc_id, amount_msat,
                                                   payment_hash, cltv_expiry);
        if (!wire_send(lsp->client_fds[dest_idx], MSG_UPDATE_ADD_HTLC, fwd)) {
            cJSON_Delete(fwd);
            return 0;
        }
        cJSON_Delete(fwd);

        /* Send COMMITMENT_SIGNED to dest */
        {
            unsigned char psig32[32];
            uint32_t nonce_idx;
            if (!channel_create_commitment_partial_sig(dest_ch, psig32, &nonce_idx))
                return 0;
            cJSON *cs = wire_build_commitment_signed(
                mgr->entries[dest_idx].channel_id,
                dest_ch->commitment_number, psig32, nonce_idx);
            if (!wire_send(lsp->client_fds[dest_idx], MSG_COMMITMENT_SIGNED, cs)) {
                cJSON_Delete(cs);
                return 0;
            }
            cJSON_Delete(cs);
        }

        /* Wait for REVOKE_AND_ACK from dest */
        {
            wire_msg_t ack_msg;
            if (!wire_recv(lsp->client_fds[dest_idx], &ack_msg) ||
                ack_msg.msg_type != MSG_REVOKE_AND_ACK) {
                if (ack_msg.json) cJSON_Delete(ack_msg.json);
                return 0;
            }
            uint32_t ack_chan_id;
            unsigned char rev_secret[32], next_point[33];
            if (wire_parse_revoke_and_ack(ack_msg.json, &ack_chan_id,
                                            rev_secret, next_point)) {
                uint64_t old_cn = dest_ch->commitment_number - 1;
                channel_receive_revocation(dest_ch, old_cn, rev_secret);
                watch_revoked_commitment(mgr->watchtower, dest_ch,
                    (uint32_t)dest_idx, old_cn,
                    dest_ch->local_amount, dest_ch->remote_amount);
            }
            cJSON_Delete(ack_msg.json);
        }

        printf("LSP: bridge HTLC forwarded to client %zu (%llu sats)\n",
               dest_idx, (unsigned long long)amount_sats);
        return 1;
    }

    case MSG_BRIDGE_PAY_RESULT: {
        /* Outbound pay result from bridge */
        uint64_t request_id;
        int success;
        unsigned char preimage[32];
        if (!wire_parse_bridge_pay_result(msg->json, &request_id, &success,
                                            preimage))
            return 0;

        printf("LSP: bridge pay result: request_id=%llu success=%d\n",
               (unsigned long long)request_id, success);

        /* Find the originating HTLC by request_id */
        for (size_t i = 0; i < mgr->n_htlc_origins; i++) {
            if (!mgr->htlc_origins[i].active) continue;
            if (mgr->htlc_origins[i].request_id != request_id) continue;

            size_t client_idx = mgr->htlc_origins[i].sender_idx;
            uint64_t htlc_id = mgr->htlc_origins[i].sender_htlc_id;
            mgr->htlc_origins[i].active = 0;

            if (client_idx >= mgr->n_channels) break;
            channel_t *ch = &mgr->entries[client_idx].channel;

            if (success) {
                /* Fulfill the HTLC on the client's channel */
                channel_fulfill_htlc(ch, htlc_id, preimage);

                cJSON *ful = wire_build_update_fulfill_htlc(htlc_id, preimage);
                wire_send(lsp->client_fds[client_idx], MSG_UPDATE_FULFILL_HTLC, ful);
                cJSON_Delete(ful);

                /* Sign commitment */
                unsigned char psig[32];
                uint32_t nonce_idx;
                if (channel_create_commitment_partial_sig(ch, psig, &nonce_idx)) {
                    cJSON *cs = wire_build_commitment_signed(
                        mgr->entries[client_idx].channel_id,
                        ch->commitment_number, psig, nonce_idx);
                    wire_send(lsp->client_fds[client_idx], MSG_COMMITMENT_SIGNED, cs);
                    cJSON_Delete(cs);
                }

                printf("LSP: bridge pay fulfilled for client %zu htlc %llu\n",
                       client_idx, (unsigned long long)htlc_id);
            } else {
                /* Fail the HTLC */
                channel_fail_htlc(ch, htlc_id);
                cJSON *fail = wire_build_update_fail_htlc(htlc_id, "bridge_pay_failed");
                wire_send(lsp->client_fds[client_idx], MSG_UPDATE_FAIL_HTLC, fail);
                cJSON_Delete(fail);

                printf("LSP: bridge pay failed for client %zu htlc %llu\n",
                       client_idx, (unsigned long long)htlc_id);
            }
            break;
        }
        return 1;
    }

    default:
        fprintf(stderr, "LSP: unexpected bridge msg 0x%02x\n", msg->msg_type);
        return 0;
    }
}

/* --- Reconnection (Phase 16) --- */

/* Core reconnect handler that takes an already-read MSG_RECONNECT message. */
static int handle_reconnect_with_msg(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                       int new_fd, const wire_msg_t *msg) {
    if (!mgr || !lsp || new_fd < 0 || !msg) return 0;

    /* 2. Parse pubkey + commitment_number */
    secp256k1_pubkey client_pk;
    uint64_t commitment_number;
    if (!wire_parse_reconnect(msg->json, mgr->ctx, &client_pk, &commitment_number)) {
        fprintf(stderr, "LSP reconnect: failed to parse MSG_RECONNECT\n");
        wire_close(new_fd);
        return 0;
    }

    /* 3. Match pubkey against lsp->client_pubkeys[] to find client index */
    int found = -1;
    unsigned char client_ser[33], cmp_ser[33];
    size_t len1 = 33, len2 = 33;
    secp256k1_ec_pubkey_serialize(mgr->ctx, client_ser, &len1, &client_pk,
                                   SECP256K1_EC_COMPRESSED);
    for (size_t c = 0; c < lsp->n_clients; c++) {
        len2 = 33;
        secp256k1_ec_pubkey_serialize(mgr->ctx, cmp_ser, &len2,
                                       &lsp->client_pubkeys[c],
                                       SECP256K1_EC_COMPRESSED);
        if (memcmp(client_ser, cmp_ser, 33) == 0) {
            found = (int)c;
            break;
        }
    }

    if (found < 0) {
        fprintf(stderr, "LSP reconnect: unknown pubkey\n");
        wire_close(new_fd);
        return 0;
    }
    size_t c = (size_t)found;

    /* 4. Verify commitment_number matches */
    channel_t *ch = &mgr->entries[c].channel;
    if (commitment_number != ch->commitment_number) {
        fprintf(stderr, "LSP reconnect: commitment_number mismatch "
                "(client=%llu, lsp=%llu) for slot %zu\n",
                (unsigned long long)commitment_number,
                (unsigned long long)ch->commitment_number, c);
        /* Proceed anyway for PoC — the ACK will tell client the LSP's state */
    }

    /* 5. Close old client_fds[c] if still open */
    if (lsp->client_fds[c] >= 0) {
        wire_close(lsp->client_fds[c]);
    }

    /* 6. Set new fd */
    lsp->client_fds[c] = new_fd;

    /* 7. Re-init nonce pool */
    if (!channel_init_nonce_pool(ch, MUSIG_NONCE_POOL_MAX)) {
        fprintf(stderr, "LSP reconnect: nonce pool init failed for slot %zu\n", c);
        return 0;
    }

    /* 8. Exchange CHANNEL_NONCES (send LSP's, recv client's) */
    {
        size_t nonce_count = ch->local_nonce_pool.count;
        unsigned char (*pubnonces_ser)[66] =
            (unsigned char (*)[66])calloc(nonce_count, 66);
        if (!pubnonces_ser) return 0;

        for (size_t i = 0; i < nonce_count; i++) {
            musig_pubnonce_serialize(mgr->ctx,
                pubnonces_ser[i], &ch->local_nonce_pool.nonces[i].pubnonce);
        }

        cJSON *nonce_msg = wire_build_channel_nonces(
            mgr->entries[c].channel_id, (const unsigned char (*)[66])pubnonces_ser,
            nonce_count);
        if (!wire_send(new_fd, MSG_CHANNEL_NONCES, nonce_msg)) {
            fprintf(stderr, "LSP reconnect: send CHANNEL_NONCES failed\n");
            cJSON_Delete(nonce_msg);
            free(pubnonces_ser);
            return 0;
        }
        cJSON_Delete(nonce_msg);
        free(pubnonces_ser);
    }

    /* Recv client's nonces */
    {
        wire_msg_t nonce_resp;
        if (!wire_recv(new_fd, &nonce_resp) ||
            nonce_resp.msg_type != MSG_CHANNEL_NONCES) {
            fprintf(stderr, "LSP reconnect: expected CHANNEL_NONCES from client\n");
            if (nonce_resp.json) cJSON_Delete(nonce_resp.json);
            return 0;
        }

        uint32_t resp_ch_id;
        unsigned char client_nonces[MUSIG_NONCE_POOL_MAX][66];
        size_t client_nonce_count;
        if (!wire_parse_channel_nonces(nonce_resp.json, &resp_ch_id,
                                         client_nonces, MUSIG_NONCE_POOL_MAX,
                                         &client_nonce_count)) {
            fprintf(stderr, "LSP reconnect: failed to parse client nonces\n");
            cJSON_Delete(nonce_resp.json);
            return 0;
        }
        cJSON_Delete(nonce_resp.json);

        channel_set_remote_pubnonces(ch,
            (const unsigned char (*)[66])client_nonces, client_nonce_count);
    }

    /* 9. Send MSG_RECONNECT_ACK */
    {
        cJSON *ack = wire_build_reconnect_ack(
            mgr->entries[c].channel_id,
            ch->local_amount * 1000,   /* sats → msat */
            ch->remote_amount * 1000,
            ch->commitment_number);
        if (!wire_send(new_fd, MSG_RECONNECT_ACK, ack)) {
            fprintf(stderr, "LSP reconnect: send RECONNECT_ACK failed\n");
            cJSON_Delete(ack);
            return 0;
        }
        cJSON_Delete(ack);
    }

    printf("LSP: client %zu reconnected (commitment=%llu)\n",
           c, (unsigned long long)ch->commitment_number);
    return 1;
}

int lsp_channels_handle_reconnect(lsp_channel_mgr_t *mgr, lsp_t *lsp, int new_fd) {
    if (!mgr || !lsp || new_fd < 0) return 0;

    /* Read MSG_RECONNECT */
    wire_msg_t msg;
    if (!wire_recv(new_fd, &msg) || msg.msg_type != MSG_RECONNECT) {
        fprintf(stderr, "LSP reconnect: expected MSG_RECONNECT, got 0x%02x\n",
                msg.msg_type);
        if (msg.json) cJSON_Delete(msg.json);
        wire_close(new_fd);
        return 0;
    }

    int ret = handle_reconnect_with_msg(mgr, lsp, new_fd, &msg);
    cJSON_Delete(msg.json);
    return ret;
}

lsp_channel_entry_t *lsp_channels_get(lsp_channel_mgr_t *mgr, size_t client_idx) {
    if (!mgr || client_idx >= mgr->n_channels) return NULL;
    return &mgr->entries[client_idx];
}

size_t lsp_channels_build_close_outputs(const lsp_channel_mgr_t *mgr,
                                         const factory_t *factory,
                                         tx_output_t *outputs,
                                         uint64_t close_fee) {
    if (!mgr || !factory || !outputs) return 0;

    /* Output 0: LSP gets factory_funding - sum(client_remotes) - close_fee.
       In a cooperative close that bypasses the tree, the LSP recovers the
       tree transaction fees (funding_amount - sum_of_leaf_outputs). */
    uint64_t client_total = 0;
    for (size_t c = 0; c < mgr->n_channels; c++)
        client_total += mgr->entries[c].channel.remote_amount;

    if (factory->funding_amount_sats < client_total + close_fee) return 0;
    uint64_t lsp_total = factory->funding_amount_sats - client_total - close_fee;

    outputs[0].amount_sats = lsp_total;
    memcpy(outputs[0].script_pubkey, factory->funding_spk, factory->funding_spk_len);
    outputs[0].script_pubkey_len = factory->funding_spk_len;

    /* Outputs 1..N: each client gets their remote_amount */
    for (size_t c = 0; c < mgr->n_channels; c++) {
        outputs[c + 1].amount_sats = mgr->entries[c].channel.remote_amount;
        memcpy(outputs[c + 1].script_pubkey, factory->funding_spk, factory->funding_spk_len);
        outputs[c + 1].script_pubkey_len = factory->funding_spk_len;
    }

    /* Invariant: sum of outputs + close_fee == funding_amount */
    uint64_t sum = close_fee;
    for (size_t i = 0; i < mgr->n_channels + 1; i++)
        sum += outputs[i].amount_sats;
    if (sum != factory->funding_amount_sats) {
        fprintf(stderr, "lsp_channels_build_close_outputs: balance invariant failed "
                "(%llu vs %llu)\n", (unsigned long long)sum,
                (unsigned long long)factory->funding_amount_sats);
        return 0;
    }

    return mgr->n_channels + 1;
}

int lsp_channels_run_event_loop(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                  size_t expected_msgs) {
    if (!mgr || !lsp) return 0;

    size_t handled = 0;
    while (handled < expected_msgs) {
        fd_set rfds;
        FD_ZERO(&rfds);
        int max_fd = -1;
        for (size_t c = 0; c < mgr->n_channels; c++) {
            int cfd = lsp->client_fds[c];
            FD_SET(cfd, &rfds);
            if (cfd > max_fd) max_fd = cfd;
        }

        /* Include bridge fd in select if connected */
        if (mgr->bridge_fd >= 0) {
            FD_SET(mgr->bridge_fd, &rfds);
            if (mgr->bridge_fd > max_fd) max_fd = mgr->bridge_fd;
        }

        struct timeval tv;
        tv.tv_sec = 30;
        tv.tv_usec = 0;

        int ret = select(max_fd + 1, &rfds, NULL, NULL, &tv);
        if (ret <= 0) {
            fprintf(stderr, "LSP event loop: select timeout/error (handled %zu/%zu)\n",
                    handled, expected_msgs);
            return 0;
        }

        /* Handle bridge messages */
        if (mgr->bridge_fd >= 0 && FD_ISSET(mgr->bridge_fd, &rfds)) {
            wire_msg_t msg;
            if (!wire_recv(mgr->bridge_fd, &msg)) {
                fprintf(stderr, "LSP event loop: bridge recv failed\n");
                mgr->bridge_fd = -1;  /* bridge disconnected */
            } else {
                if (!lsp_channels_handle_bridge_msg(mgr, lsp, &msg)) {
                    fprintf(stderr, "LSP event loop: bridge handle failed 0x%02x\n",
                            msg.msg_type);
                }
                cJSON_Delete(msg.json);
                handled++;
            }
        }

        for (size_t c = 0; c < mgr->n_channels; c++) {
            if (!FD_ISSET(lsp->client_fds[c], &rfds)) continue;

            wire_msg_t msg;
            if (!wire_recv(lsp->client_fds[c], &msg)) {
                fprintf(stderr, "LSP event loop: recv failed from client %zu\n", c);
                return 0;
            }

            if (!lsp_channels_handle_msg(mgr, lsp, c, &msg)) {
                fprintf(stderr, "LSP event loop: handle_msg failed for client %zu "
                        "msg 0x%02x\n", c, msg.msg_type);
                cJSON_Delete(msg.json);
                return 0;
            }
            cJSON_Delete(msg.json);
            handled++;
        }
    }

    return 1;
}

int lsp_channels_run_daemon_loop(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                   volatile sig_atomic_t *shutdown_flag) {
    if (!mgr || !lsp || !shutdown_flag) return 0;

    printf("LSP: daemon loop started (Ctrl+C to stop)\n");

    while (!(*shutdown_flag)) {
        fd_set rfds;
        FD_ZERO(&rfds);
        int max_fd = -1;
        for (size_t c = 0; c < mgr->n_channels; c++) {
            int cfd = lsp->client_fds[c];
            if (cfd < 0) continue;  /* skip disconnected clients */
            FD_SET(cfd, &rfds);
            if (cfd > max_fd) max_fd = cfd;
        }

        /* Include bridge fd in select if connected */
        if (mgr->bridge_fd >= 0) {
            FD_SET(mgr->bridge_fd, &rfds);
            if (mgr->bridge_fd > max_fd) max_fd = mgr->bridge_fd;
        }

        /* Include listen_fd for reconnections (Phase 16) */
        if (lsp->listen_fd >= 0) {
            FD_SET(lsp->listen_fd, &rfds);
            if (lsp->listen_fd > max_fd) max_fd = lsp->listen_fd;
        }

        if (max_fd < 0) {
            /* No fds to watch — all clients disconnected, no listen socket */
            struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
            select(0, NULL, NULL, NULL, &tv);
            continue;
        }

        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;

        int ret = select(max_fd + 1, &rfds, NULL, NULL, &tv);
        if (ret < 0) {
            /* EINTR from signal — check shutdown flag */
            continue;
        }
        if (ret == 0) {
            /* Timeout — run watchtower check if available */
            if (mgr->watchtower)
                watchtower_check(mgr->watchtower);
            /* Check HTLC timeouts if we have a chain connection */
            if (mgr->watchtower && mgr->watchtower->rt) {
                int height = regtest_get_block_height(mgr->watchtower->rt);
                if (height > 0) {
                    for (size_t c = 0; c < mgr->n_channels; c++) {
                        channel_t *ch = &mgr->entries[c].channel;
                        int n_failed = channel_check_htlc_timeouts(ch, (uint32_t)height);
                        if (n_failed > 0) {
                            printf("LSP: auto-failed %d expired HTLCs on channel %zu "
                                   "(height=%d)\n", n_failed, c, height);
                        }
                    }
                    /* Factory lifecycle monitoring */
                    factory_state_t fstate = factory_get_state(
                        &lsp->factory, (uint32_t)height);
                    if (fstate == FACTORY_DYING)
                        printf("LSP: factory DYING (%u blocks to expiry)\n",
                               factory_blocks_until_expired(&lsp->factory,
                                                            (uint32_t)height));
                    else if (fstate == FACTORY_EXPIRED)
                        printf("LSP: factory EXPIRED at height %d\n", height);
                }
            }
            continue;
        }

        /* Handle new connections on listen_fd (bridge or client reconnect) */
        if (lsp->listen_fd >= 0 && FD_ISSET(lsp->listen_fd, &rfds)) {
            int new_fd = wire_accept(lsp->listen_fd);
            if (new_fd >= 0) {
                /* Noise handshake */
                if (!wire_noise_handshake_responder(new_fd, mgr->ctx)) {
                    wire_close(new_fd);
                } else {
                    /* Peek at first message to distinguish bridge vs client */
                    wire_msg_t peek;
                    if (wire_recv(new_fd, &peek)) {
                        if (peek.msg_type == MSG_BRIDGE_HELLO) {
                            /* Bridge connection */
                            cJSON_Delete(peek.json);
                            cJSON *ack = wire_build_bridge_hello_ack();
                            wire_send(new_fd, MSG_BRIDGE_HELLO_ACK, ack);
                            cJSON_Delete(ack);
                            lsp->bridge_fd = new_fd;
                            mgr->bridge_fd = new_fd;
                            printf("LSP: bridge connected in daemon loop (fd=%d)\n", new_fd);
                        } else if (peek.msg_type == MSG_RECONNECT) {
                            /* Client reconnect — use pre-read message */
                            int ret = handle_reconnect_with_msg(mgr, lsp, new_fd, &peek);
                            cJSON_Delete(peek.json);
                            if (!ret) {
                                fprintf(stderr, "LSP daemon: reconnect handshake failed\n");
                            }
                        } else {
                            fprintf(stderr, "LSP daemon: unexpected msg 0x%02x from new connection\n",
                                    peek.msg_type);
                            cJSON_Delete(peek.json);
                            wire_close(new_fd);
                        }
                    } else {
                        wire_close(new_fd);
                    }
                }
            }
        }

        /* Handle bridge messages */
        if (mgr->bridge_fd >= 0 && FD_ISSET(mgr->bridge_fd, &rfds)) {
            wire_msg_t msg;
            if (!wire_recv(mgr->bridge_fd, &msg)) {
                fprintf(stderr, "LSP daemon: bridge disconnected\n");
                mgr->bridge_fd = -1;
            } else {
                if (!lsp_channels_handle_bridge_msg(mgr, lsp, &msg)) {
                    fprintf(stderr, "LSP daemon: bridge handle failed 0x%02x\n",
                            msg.msg_type);
                }
                cJSON_Delete(msg.json);
            }
        }

        for (size_t c = 0; c < mgr->n_channels; c++) {
            if (lsp->client_fds[c] < 0) continue;
            if (!FD_ISSET(lsp->client_fds[c], &rfds)) continue;

            wire_msg_t msg;
            if (!wire_recv(lsp->client_fds[c], &msg)) {
                fprintf(stderr, "LSP daemon: client %zu disconnected\n", c);
                wire_close(lsp->client_fds[c]);
                lsp->client_fds[c] = -1;
                continue;
            }

            if (!lsp_channels_handle_msg(mgr, lsp, c, &msg)) {
                fprintf(stderr, "LSP daemon: handle_msg failed for client %zu "
                        "msg 0x%02x\n", c, msg.msg_type);
            }
            cJSON_Delete(msg.json);
        }
    }

    printf("LSP: daemon loop stopped (shutdown requested)\n");
    return 1;
}

/* --- Demo mode (Phase 17) --- */

void lsp_channels_print_balances(const lsp_channel_mgr_t *mgr) {
    if (!mgr) return;
    printf("\n  Channel | Client | Local (sats) | Remote (sats)\n");
    printf("  --------+--------+--------------+--------------\n");
    for (size_t c = 0; c < mgr->n_channels; c++) {
        const channel_t *ch = &mgr->entries[c].channel;
        printf("    %zu     |   %zu    |  %10llu  |  %10llu\n",
               c, c + 1,
               (unsigned long long)ch->local_amount,
               (unsigned long long)ch->remote_amount);
    }
    printf("\n");
}

/* Wait for a specific message type from a client fd, processing
   MSG_REGISTER_INVOICE messages that may arrive before the expected one.
   Returns 1 on success with msg filled, 0 on error. */
static int wait_for_msg(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                          int fd, uint8_t expected_type, wire_msg_t *msg,
                          int timeout_sec) {
    (void)lsp;
    struct timeval start, now;
    gettimeofday(&start, NULL);

    while (1) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        gettimeofday(&now, NULL);
        int elapsed = (int)(now.tv_sec - start.tv_sec);
        int remaining = timeout_sec - elapsed;
        if (remaining <= 0) return 0;

        struct timeval tv = { .tv_sec = remaining, .tv_usec = 0 };
        int ret = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (ret <= 0) return 0;

        if (!wire_recv(fd, msg)) return 0;

        if (msg->msg_type == expected_type)
            return 1;

        /* Handle MSG_REGISTER_INVOICE that arrives before INVOICE_CREATED */
        if (msg->msg_type == MSG_REGISTER_INVOICE) {
            unsigned char ph[32];
            uint64_t am;
            size_t dc;
            if (wire_parse_register_invoice(msg->json, ph, &am, &dc))
                lsp_channels_register_invoice(mgr, ph, dc, am);
            cJSON_Delete(msg->json);
            msg->json = NULL;
            continue;
        }

        /* Unexpected message — skip */
        fprintf(stderr, "LSP demo: expected 0x%02x, got 0x%02x (skipping)\n",
                expected_type, msg->msg_type);
        cJSON_Delete(msg->json);
        msg->json = NULL;
    }
}

int lsp_channels_initiate_payment(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                    size_t from_client, size_t to_client,
                                    uint64_t amount_sats) {
    if (!mgr || !lsp) return 0;
    if (from_client >= mgr->n_channels || to_client >= mgr->n_channels) return 0;
    if (from_client == to_client) return 0;

    uint64_t amount_msat = amount_sats * 1000;

    /* 1. Send MSG_CREATE_INVOICE to receiving client */
    {
        cJSON *inv_req = wire_build_create_invoice(amount_msat);
        if (!wire_send(lsp->client_fds[to_client], MSG_CREATE_INVOICE, inv_req)) {
            cJSON_Delete(inv_req);
            fprintf(stderr, "LSP demo: send CREATE_INVOICE failed\n");
            return 0;
        }
        cJSON_Delete(inv_req);
    }

    /* 2. Wait for MSG_INVOICE_CREATED from receiver */
    unsigned char payment_hash[32];
    {
        wire_msg_t inv_resp;
        if (!wait_for_msg(mgr, lsp, lsp->client_fds[to_client],
                            MSG_INVOICE_CREATED, &inv_resp, 10)) {
            fprintf(stderr, "LSP demo: timeout waiting for INVOICE_CREATED\n");
            return 0;
        }
        uint64_t resp_amount;
        if (!wire_parse_invoice_created(inv_resp.json, payment_hash, &resp_amount)) {
            cJSON_Delete(inv_resp.json);
            fprintf(stderr, "LSP demo: bad INVOICE_CREATED\n");
            return 0;
        }
        cJSON_Delete(inv_resp.json);
    }

    /* 3. Drain any pending MSG_REGISTER_INVOICE from receiver */
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(lsp->client_fds[to_client], &rfds);
        struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 }; /* 200ms */
        while (select(lsp->client_fds[to_client] + 1, &rfds, NULL, NULL, &tv) > 0) {
            wire_msg_t drain_msg;
            if (!wire_recv(lsp->client_fds[to_client], &drain_msg)) break;
            if (drain_msg.msg_type == MSG_REGISTER_INVOICE) {
                unsigned char ph[32];
                uint64_t am;
                size_t dc;
                if (wire_parse_register_invoice(drain_msg.json, ph, &am, &dc))
                    lsp_channels_register_invoice(mgr, ph, dc, am);
            }
            cJSON_Delete(drain_msg.json);
            FD_ZERO(&rfds);
            FD_SET(lsp->client_fds[to_client], &rfds);
            tv.tv_sec = 0;
            tv.tv_usec = 200000;
        }
    }

    /* 4. Add HTLC on sender's channel (HTLC_RECEIVED from LSP perspective) */
    channel_t *sender_ch = &mgr->entries[from_client].channel;
    uint64_t sender_htlc_id;
    if (!channel_add_htlc(sender_ch, HTLC_RECEIVED, amount_sats,
                           payment_hash, 500, &sender_htlc_id)) {
        fprintf(stderr, "LSP demo: add_htlc on sender failed\n");
        return 0;
    }

    /* 5. Send ADD_HTLC + COMMITMENT_SIGNED to sender */
    {
        cJSON *add = wire_build_update_add_htlc(sender_htlc_id, amount_msat,
                                                   payment_hash, 500);
        /* Add dest_client field so sender knows where it's going */
        cJSON_AddNumberToObject(add, "dest_client", (double)to_client);
        if (!wire_send(lsp->client_fds[from_client], MSG_UPDATE_ADD_HTLC, add)) {
            cJSON_Delete(add);
            return 0;
        }
        cJSON_Delete(add);
    }
    {
        unsigned char psig32[32];
        uint32_t nonce_idx;
        if (!channel_create_commitment_partial_sig(sender_ch, psig32, &nonce_idx))
            return 0;
        cJSON *cs = wire_build_commitment_signed(
            mgr->entries[from_client].channel_id,
            sender_ch->commitment_number, psig32, nonce_idx);
        if (!wire_send(lsp->client_fds[from_client], MSG_COMMITMENT_SIGNED, cs)) {
            cJSON_Delete(cs);
            return 0;
        }
        cJSON_Delete(cs);
    }

    /* 6. Wait for REVOKE_AND_ACK from sender */
    {
        wire_msg_t ack_msg;
        if (!wire_recv(lsp->client_fds[from_client], &ack_msg) ||
            ack_msg.msg_type != MSG_REVOKE_AND_ACK) {
            if (ack_msg.json) cJSON_Delete(ack_msg.json);
            fprintf(stderr, "LSP demo: expected REVOKE_AND_ACK from sender\n");
            return 0;
        }
        uint32_t ack_chan_id;
        unsigned char rev_secret[32], next_point[33];
        if (wire_parse_revoke_and_ack(ack_msg.json, &ack_chan_id,
                                        rev_secret, next_point)) {
            uint64_t old_cn = sender_ch->commitment_number - 1;
            channel_receive_revocation(sender_ch, old_cn, rev_secret);
            watch_revoked_commitment(mgr->watchtower, sender_ch,
                (uint32_t)from_client, old_cn,
                sender_ch->local_amount, sender_ch->remote_amount);
        }
        cJSON_Delete(ack_msg.json);
    }

    /* 7. Forward HTLC to destination client */
    channel_t *dest_ch = &mgr->entries[to_client].channel;
    uint64_t dest_htlc_id;
    if (!channel_add_htlc(dest_ch, HTLC_OFFERED, amount_sats,
                           payment_hash, 500, &dest_htlc_id)) {
        fprintf(stderr, "LSP demo: forward add_htlc failed\n");
        return 0;
    }

    {
        cJSON *fwd = wire_build_update_add_htlc(dest_htlc_id, amount_msat,
                                                   payment_hash, 500);
        if (!wire_send(lsp->client_fds[to_client], MSG_UPDATE_ADD_HTLC, fwd)) {
            cJSON_Delete(fwd);
            return 0;
        }
        cJSON_Delete(fwd);
    }
    {
        unsigned char psig32[32];
        uint32_t nonce_idx;
        if (!channel_create_commitment_partial_sig(dest_ch, psig32, &nonce_idx))
            return 0;
        cJSON *cs = wire_build_commitment_signed(
            mgr->entries[to_client].channel_id,
            dest_ch->commitment_number, psig32, nonce_idx);
        if (!wire_send(lsp->client_fds[to_client], MSG_COMMITMENT_SIGNED, cs)) {
            cJSON_Delete(cs);
            return 0;
        }
        cJSON_Delete(cs);
    }

    /* 8. Wait for REVOKE_AND_ACK from dest */
    {
        wire_msg_t ack_msg;
        if (!wire_recv(lsp->client_fds[to_client], &ack_msg) ||
            ack_msg.msg_type != MSG_REVOKE_AND_ACK) {
            if (ack_msg.json) cJSON_Delete(ack_msg.json);
            fprintf(stderr, "LSP demo: expected REVOKE_AND_ACK from dest\n");
            return 0;
        }
        uint32_t ack_chan_id;
        unsigned char rev_secret[32], next_point[33];
        if (wire_parse_revoke_and_ack(ack_msg.json, &ack_chan_id,
                                        rev_secret, next_point)) {
            uint64_t old_cn = dest_ch->commitment_number - 1;
            channel_receive_revocation(dest_ch, old_cn, rev_secret);
            watch_revoked_commitment(mgr->watchtower, dest_ch,
                (uint32_t)to_client, old_cn,
                dest_ch->local_amount, dest_ch->remote_amount);
        }
        cJSON_Delete(ack_msg.json);
    }

    /* 9. Wait for FULFILL_HTLC from dest (client fulfills with real preimage) */
    {
        wire_msg_t ful_msg;
        if (!wire_recv(lsp->client_fds[to_client], &ful_msg) ||
            ful_msg.msg_type != MSG_UPDATE_FULFILL_HTLC) {
            if (ful_msg.json) cJSON_Delete(ful_msg.json);
            fprintf(stderr, "LSP demo: expected FULFILL from dest\n");
            return 0;
        }
        uint64_t ful_htlc_id;
        unsigned char preimage[32];
        if (!wire_parse_update_fulfill_htlc(ful_msg.json, &ful_htlc_id, preimage)) {
            cJSON_Delete(ful_msg.json);
            return 0;
        }
        cJSON_Delete(ful_msg.json);

        /* Fulfill on dest channel */
        channel_fulfill_htlc(dest_ch, ful_htlc_id, preimage);

        /* Send COMMITMENT_SIGNED to dest */
        {
            unsigned char psig32[32];
            uint32_t nonce_idx;
            if (!channel_create_commitment_partial_sig(dest_ch, psig32, &nonce_idx))
                return 0;
            cJSON *cs = wire_build_commitment_signed(
                mgr->entries[to_client].channel_id,
                dest_ch->commitment_number, psig32, nonce_idx);
            wire_send(lsp->client_fds[to_client], MSG_COMMITMENT_SIGNED, cs);
            cJSON_Delete(cs);
        }

        /* Wait for REVOKE_AND_ACK from dest */
        {
            wire_msg_t ack;
            if (wire_recv(lsp->client_fds[to_client], &ack) &&
                ack.msg_type == MSG_REVOKE_AND_ACK) {
                uint32_t ack_chan_id;
                unsigned char rev_secret[32], next_point[33];
                if (wire_parse_revoke_and_ack(ack.json, &ack_chan_id,
                                                rev_secret, next_point)) {
                    uint64_t old_cn = dest_ch->commitment_number - 1;
                    channel_receive_revocation(dest_ch, old_cn, rev_secret);
                    watch_revoked_commitment(mgr->watchtower, dest_ch,
                        (uint32_t)to_client, old_cn,
                        dest_ch->local_amount, dest_ch->remote_amount);
                }
            }
            if (ack.json) cJSON_Delete(ack.json);
        }

        /* 10. Back-propagate fulfill to sender */
        channel_fulfill_htlc(sender_ch, sender_htlc_id, preimage);

        cJSON *ful_fwd = wire_build_update_fulfill_htlc(sender_htlc_id, preimage);
        wire_send(lsp->client_fds[from_client], MSG_UPDATE_FULFILL_HTLC, ful_fwd);
        cJSON_Delete(ful_fwd);

        /* Send COMMITMENT_SIGNED to sender */
        {
            unsigned char psig32[32];
            uint32_t nonce_idx;
            if (!channel_create_commitment_partial_sig(sender_ch, psig32, &nonce_idx))
                return 0;
            cJSON *cs = wire_build_commitment_signed(
                mgr->entries[from_client].channel_id,
                sender_ch->commitment_number, psig32, nonce_idx);
            wire_send(lsp->client_fds[from_client], MSG_COMMITMENT_SIGNED, cs);
            cJSON_Delete(cs);
        }

        /* Wait for REVOKE_AND_ACK from sender */
        {
            wire_msg_t ack;
            if (wire_recv(lsp->client_fds[from_client], &ack) &&
                ack.msg_type == MSG_REVOKE_AND_ACK) {
                uint32_t ack_chan_id;
                unsigned char rev_secret[32], next_point[33];
                if (wire_parse_revoke_and_ack(ack.json, &ack_chan_id,
                                                rev_secret, next_point)) {
                    uint64_t old_cn = sender_ch->commitment_number - 1;
                    channel_receive_revocation(sender_ch, old_cn, rev_secret);
                    watch_revoked_commitment(mgr->watchtower, sender_ch,
                        (uint32_t)from_client, old_cn,
                        sender_ch->local_amount, sender_ch->remote_amount);
                }
            }
            if (ack.json) cJSON_Delete(ack.json);
        }
    }

    printf("  Payment complete: client %zu -> client %zu (%llu sats)\n",
           from_client + 1, to_client + 1, (unsigned long long)amount_sats);
    return 1;
}

int lsp_channels_run_demo_sequence(lsp_channel_mgr_t *mgr, lsp_t *lsp) {
    if (!mgr || !lsp) return 0;

    printf("\n");
    printf("======================================================\n");
    printf("  SuperScalar Factory Demo - Payment Sequence\n");
    printf("======================================================\n");
    printf("\n");

    printf("Factory created with %zu channels (1 LSP + %zu clients)\n",
           mgr->n_channels, mgr->n_channels);
    printf("Initial balances:\n");
    lsp_channels_print_balances(mgr);

    /* Payment 1: Client 1 pays Client 2 */
    printf("--- Payment 1: Client 1 -> Client 2 (10,000 sats) ---\n");
    if (!lsp_channels_initiate_payment(mgr, lsp, 0, 1, 10000)) {
        fprintf(stderr, "LSP demo: payment 1 failed\n");
        return 0;
    }
    lsp_channels_print_balances(mgr);

    /* Payment 2: Client 3 pays Client 1 */
    printf("--- Payment 2: Client 3 -> Client 1 (5,000 sats) ---\n");
    if (!lsp_channels_initiate_payment(mgr, lsp, 2, 0, 5000)) {
        fprintf(stderr, "LSP demo: payment 2 failed\n");
        return 0;
    }
    lsp_channels_print_balances(mgr);

    /* Payment 3: Client 4 pays Client 3 */
    printf("--- Payment 3: Client 4 -> Client 3 (7,500 sats) ---\n");
    if (!lsp_channels_initiate_payment(mgr, lsp, 3, 2, 7500)) {
        fprintf(stderr, "LSP demo: payment 3 failed\n");
        return 0;
    }
    lsp_channels_print_balances(mgr);

    /* Payment 4: Client 2 pays Client 4 */
    printf("--- Payment 4: Client 2 -> Client 4 (3,000 sats) ---\n");
    if (!lsp_channels_initiate_payment(mgr, lsp, 1, 3, 3000)) {
        fprintf(stderr, "LSP demo: payment 4 failed\n");
        return 0;
    }

    printf("\n");
    printf("======================================================\n");
    printf("  Demo Complete - Final Balances\n");
    printf("======================================================\n");
    lsp_channels_print_balances(mgr);

    return 1;
}
