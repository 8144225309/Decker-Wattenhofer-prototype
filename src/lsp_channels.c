#include "superscalar/lsp_channels.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/select.h>

extern void sha256(const unsigned char *, size_t, unsigned char *);

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
            channel_receive_revocation(sender_ch,
                                        sender_ch->commitment_number - 1,
                                        rev_secret);
        }
        cJSON_Delete(ack_msg.json);
    }

    /* Find destination client from payment_hash.
       For intra-factory routing, we check all other clients' pending invoices.
       Simplified: the ADD_HTLC includes a "dest_client" field (extension). */
    cJSON *dest_item = cJSON_GetObjectItem(json, "dest_client");
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
            channel_receive_revocation(dest_ch,
                                        dest_ch->commitment_number - 1,
                                        rev_secret);
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
            channel_receive_revocation(ch, ch->commitment_number - 1, rev_secret);
        }
        cJSON_Delete(ack_msg.json);
    }

    /* Now back-propagate: find the sender's channel that has a matching HTLC.
       We search all other channels for a received HTLC with the same payment_hash. */
    unsigned char payment_hash[32];
    /* Compute hash from preimage */
    sha256(preimage, 32, payment_hash);

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
                    channel_receive_revocation(sender_ch,
                                                sender_ch->commitment_number - 1,
                                                rev_secret);
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

    case MSG_CLOSE_REQUEST:
        printf("LSP: client %zu requested close\n", client_idx);
        return 1;  /* handled by caller */

    default:
        fprintf(stderr, "LSP: unexpected msg 0x%02x from client %zu\n",
                msg->msg_type, client_idx);
        return 0;
    }
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

        struct timeval tv;
        tv.tv_sec = 30;
        tv.tv_usec = 0;

        int ret = select(max_fd + 1, &rfds, NULL, NULL, &tv);
        if (ret <= 0) {
            fprintf(stderr, "LSP event loop: select timeout/error (handled %zu/%zu)\n",
                    handled, expected_msgs);
            return 0;
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
