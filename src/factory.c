#include "superscalar/factory.h"
#include <string.h>
#include <stdlib.h>

extern void sha256_tagged(const char *, const unsigned char *, size_t,
                           unsigned char *);
extern void reverse_bytes(unsigned char *, size_t);

/* ---- Internal helpers ---- */

/* Compute taproot-tweaked xonly pubkey.
   merkle_root = NULL for key-path only, non-NULL to include script tree. */
static int taproot_tweak_pubkey(
    const secp256k1_context *ctx,
    secp256k1_xonly_pubkey *tweaked_out,
    int *parity_out,
    const secp256k1_xonly_pubkey *internal_key,
    const unsigned char *merkle_root
) {
    unsigned char internal_ser[32];
    if (!secp256k1_xonly_pubkey_serialize(ctx, internal_ser, internal_key))
        return 0;

    unsigned char tweak[32];
    if (merkle_root) {
        /* TapTweak = tagged_hash("TapTweak", internal_key || merkle_root) */
        unsigned char tweak_data[64];
        memcpy(tweak_data, internal_ser, 32);
        memcpy(tweak_data + 32, merkle_root, 32);
        sha256_tagged("TapTweak", tweak_data, 64, tweak);
    } else {
        sha256_tagged("TapTweak", internal_ser, 32, tweak);
    }

    secp256k1_pubkey tweaked_full;
    if (!secp256k1_xonly_pubkey_tweak_add(ctx, &tweaked_full, internal_key, tweak))
        return 0;

    int parity = 0;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, tweaked_out, &parity, &tweaked_full))
        return 0;

    if (parity_out)
        *parity_out = parity;

    return 1;
}

/* Build P2TR spk from a set of pubkeys via MuSig aggregate + taproot tweak.
   merkle_root = NULL for key-path only, non-NULL to include script tree. */
static int build_musig_p2tr_spk(
    const secp256k1_context *ctx,
    unsigned char *spk_out34,
    secp256k1_xonly_pubkey *tweaked_out,
    int *parity_out,
    musig_keyagg_t *keyagg_out,
    const secp256k1_pubkey *pubkeys,
    size_t n_pubkeys,
    const unsigned char *merkle_root
) {
    if (!musig_aggregate_keys(ctx, keyagg_out, pubkeys, n_pubkeys))
        return 0;

    if (!taproot_tweak_pubkey(ctx, tweaked_out, parity_out,
                               &keyagg_out->agg_pubkey, merkle_root))
        return 0;

    build_p2tr_script_pubkey(spk_out34, tweaked_out);
    return 1;
}

/* Build P2TR spk for a single pubkey (no MuSig). */
static int build_single_p2tr_spk(
    const secp256k1_context *ctx,
    unsigned char *spk_out34,
    secp256k1_xonly_pubkey *tweaked_out,
    const secp256k1_pubkey *pubkey
) {
    secp256k1_xonly_pubkey internal;
    if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &internal, NULL, pubkey))
        return 0;

    if (!taproot_tweak_pubkey(ctx, tweaked_out, NULL, &internal, NULL))
        return 0;

    build_p2tr_script_pubkey(spk_out34, tweaked_out);
    return 1;
}

/* Get nSequence for a node based on its type and DW layer. */
static uint32_t node_nsequence(const factory_t *f, const factory_node_t *node) {
    if (node->type == NODE_KICKOFF)
        return NSEQUENCE_DISABLE_BIP68;
    return dw_current_nsequence(&f->counter.layers[node->dw_layer_index]);
}

/* Add a node to the factory. Returns node index or -1 on error.
   has_timeout_path: if true, build CLTV timeout taptree for this node's spending_spk. */
static int add_node(
    factory_t *f,
    factory_node_type_t type,
    const uint32_t *signer_indices,
    size_t n_signers,
    int parent_index,
    uint32_t parent_vout,
    int dw_layer_index,
    int has_timeout_path
) {
    if (f->n_nodes >= FACTORY_MAX_NODES) return -1;

    int idx = (int)f->n_nodes++;
    factory_node_t *node = &f->nodes[idx];
    memset(node, 0, sizeof(*node));

    node->type = type;
    node->n_signers = n_signers;
    memcpy(node->signer_indices, signer_indices, n_signers * sizeof(uint32_t));
    node->parent_index = parent_index;
    node->parent_vout = parent_vout;
    node->dw_layer_index = dw_layer_index;
    node->has_taptree = (has_timeout_path && f->cltv_timeout > 0) ? 1 : 0;

    tx_buf_init(&node->unsigned_tx, 256);
    tx_buf_init(&node->signed_tx, 512);

    /* Aggregate keys and compute tweaked pubkey + spending SPK */
    secp256k1_pubkey pks[FACTORY_MAX_SIGNERS];
    for (size_t i = 0; i < n_signers; i++)
        pks[i] = f->pubkeys[signer_indices[i]];

    if (node->has_taptree) {
        /* Build CLTV timeout script leaf using LSP pubkey (index 0) */
        secp256k1_xonly_pubkey lsp_xonly;
        if (!secp256k1_xonly_pubkey_from_pubkey(f->ctx, &lsp_xonly, NULL, &f->pubkeys[0]))
            return -1;

        tapscript_build_cltv_timeout(&node->timeout_leaf, f->cltv_timeout,
                                      &lsp_xonly, f->ctx);
        tapscript_merkle_root(node->merkle_root, &node->timeout_leaf, 1);

        /* Tweak internal key with merkle root */
        if (!build_musig_p2tr_spk(f->ctx, node->spending_spk, &node->tweaked_pubkey,
                                   &node->output_parity, &node->keyagg, pks, n_signers,
                                   node->merkle_root))
            return -1;
    } else {
        if (!build_musig_p2tr_spk(f->ctx, node->spending_spk, &node->tweaked_pubkey,
                                   NULL, &node->keyagg, pks, n_signers, NULL))
            return -1;
    }

    node->spending_spk_len = 34;

    /* Link to parent */
    if (parent_index >= 0) {
        factory_node_t *parent = &f->nodes[parent_index];
        parent->child_indices[parent->n_children++] = idx;
    }

    return idx;
}

/* Set up leaf outputs for a leaf state node. */
static int setup_leaf_outputs(
    factory_t *f,
    factory_node_t *node,
    uint32_t client_a_idx,
    uint32_t client_b_idx,
    uint64_t input_amount
) {
    uint64_t output_total = input_amount - f->fee_per_tx;
    uint64_t per_output = output_total / 3;
    uint64_t remainder = output_total - per_output * 3;

    node->n_outputs = 3;

    /* Channel A: MuSig(client_a, LSP) */
    {
        secp256k1_pubkey pks[2] = { f->pubkeys[client_a_idx], f->pubkeys[0] };
        musig_keyagg_t ka;
        secp256k1_xonly_pubkey tw;
        if (!build_musig_p2tr_spk(f->ctx, node->outputs[0].script_pubkey,
                                   &tw, NULL, &ka, pks, 2, NULL))
            return 0;
        node->outputs[0].script_pubkey_len = 34;
        node->outputs[0].amount_sats = per_output;
    }

    /* Channel B: MuSig(client_b, LSP) */
    {
        secp256k1_pubkey pks[2] = { f->pubkeys[client_b_idx], f->pubkeys[0] };
        musig_keyagg_t ka;
        secp256k1_xonly_pubkey tw;
        if (!build_musig_p2tr_spk(f->ctx, node->outputs[1].script_pubkey,
                                   &tw, NULL, &ka, pks, 2, NULL))
            return 0;
        node->outputs[1].script_pubkey_len = 34;
        node->outputs[1].amount_sats = per_output;
    }

    /* L stock: LSP only */
    {
        secp256k1_xonly_pubkey tw;
        if (!build_single_p2tr_spk(f->ctx, node->outputs[2].script_pubkey,
                                    &tw, &f->pubkeys[0]))
            return 0;
        node->outputs[2].script_pubkey_len = 34;
        node->outputs[2].amount_sats = per_output + remainder;
    }

    return 1;
}

/* Build all unsigned transactions top-down. Nodes must be in top-down order. */
static int build_all_unsigned_txs(factory_t *f) {
    for (size_t i = 0; i < f->n_nodes; i++) {
        factory_node_t *node = &f->nodes[i];
        unsigned char display_txid[32];

        /* Determine input */
        const unsigned char *input_txid;
        uint32_t input_vout;

        if (node->parent_index < 0) {
            input_txid = f->funding_txid;
            input_vout = f->funding_vout;
        } else {
            factory_node_t *parent = &f->nodes[node->parent_index];
            input_txid = parent->txid;  /* internal byte order */
            input_vout = node->parent_vout;
        }

        node->nsequence = node_nsequence(f, node);

        if (!build_unsigned_tx(&node->unsigned_tx, display_txid,
                               input_txid, input_vout,
                               node->nsequence,
                               node->outputs, node->n_outputs))
            return 0;

        /* Convert display-order txid to internal byte order */
        memcpy(node->txid, display_txid, 32);
        reverse_bytes(node->txid, 32);

        node->is_built = 1;
        node->is_signed = 0;
    }
    return 1;
}

/* ---- Public API ---- */

void factory_init(factory_t *f, secp256k1_context *ctx,
                  const secp256k1_keypair *keypairs, size_t n_participants,
                  uint16_t step_blocks, uint32_t states_per_layer) {
    memset(f, 0, sizeof(*f));
    f->ctx = ctx;
    f->n_participants = n_participants;
    f->step_blocks = step_blocks;
    f->states_per_layer = states_per_layer;
    f->fee_per_tx = 500;

    for (size_t i = 0; i < n_participants; i++) {
        int ok;
        f->keypairs[i] = keypairs[i];
        ok = secp256k1_keypair_pub(ctx, &f->pubkeys[i], &keypairs[i]);
        (void)ok;
    }

    /* 2 DW layers: root state = layer 0, leaf states = layer 1 */
    dw_counter_init(&f->counter, 2, step_blocks, states_per_layer);
}

void factory_set_funding(factory_t *f,
                         const unsigned char *txid, uint32_t vout,
                         uint64_t amount_sats,
                         const unsigned char *spk, size_t spk_len) {
    memcpy(f->funding_txid, txid, 32);
    f->funding_vout = vout;
    f->funding_amount_sats = amount_sats;
    memcpy(f->funding_spk, spk, spk_len);
    f->funding_spk_len = spk_len;
}

int factory_build_tree(factory_t *f) {
    if (f->n_participants != 5) return 0;  /* 4 clients + 1 LSP */

    /* Participant indices: LSP=0, A=1, B=2, C=3, D=4 */
    uint32_t all[] = {0, 1, 2, 3, 4};
    uint32_t left_set[] = {0, 1, 2};       /* L, A, B */
    uint32_t right_set[] = {0, 3, 4};      /* L, C, D */

    /* ---- Phase 1: Setup nodes (top-down order) ---- */
    /* has_timeout_path: kickoff_left/kickoff_right get taptree
       (their spending_spk appears in state_root outputs with CLTV timeout) */
    int kr  = add_node(f, NODE_KICKOFF, all, 5,        -1, 0, -1, 0);
    int sr  = add_node(f, NODE_STATE,   all, 5,        kr, 0,  0, 0);
    int kl  = add_node(f, NODE_KICKOFF, left_set, 3,   sr, 0, -1, 1);
    int kri = add_node(f, NODE_KICKOFF, right_set, 3,  sr, 1, -1, 1);
    int sl  = add_node(f, NODE_STATE,   left_set, 3,   kl, 0,  1, 0);
    int sri = add_node(f, NODE_STATE,   right_set, 3, kri, 0,  1, 0);

    if (kr < 0 || sr < 0 || kl < 0 || kri < 0 || sl < 0 || sri < 0)
        return 0;

    /* ---- Phase 2: Setup outputs and amounts ---- */
    uint64_t fee = f->fee_per_tx;
    uint64_t kr_out = f->funding_amount_sats - fee;
    uint64_t sr_per_child = (kr_out - fee) / 2;
    uint64_t kl_out = sr_per_child - fee;
    uint64_t kri_out = sr_per_child - fee;

    /* kickoff_root -> 1 output: state_root */
    f->nodes[kr].n_outputs = 1;
    f->nodes[kr].outputs[0].amount_sats = kr_out;
    memcpy(f->nodes[kr].outputs[0].script_pubkey, f->nodes[sr].spending_spk, 34);
    f->nodes[kr].outputs[0].script_pubkey_len = 34;
    f->nodes[kr].input_amount = f->funding_amount_sats;

    /* state_root -> 2 outputs: kickoff_left, kickoff_right */
    f->nodes[sr].n_outputs = 2;
    f->nodes[sr].outputs[0].amount_sats = sr_per_child;
    memcpy(f->nodes[sr].outputs[0].script_pubkey, f->nodes[kl].spending_spk, 34);
    f->nodes[sr].outputs[0].script_pubkey_len = 34;
    f->nodes[sr].outputs[1].amount_sats = sr_per_child;
    memcpy(f->nodes[sr].outputs[1].script_pubkey, f->nodes[kri].spending_spk, 34);
    f->nodes[sr].outputs[1].script_pubkey_len = 34;
    f->nodes[sr].input_amount = kr_out;

    /* kickoff_left -> 1 output: state_left */
    f->nodes[kl].n_outputs = 1;
    f->nodes[kl].outputs[0].amount_sats = kl_out;
    memcpy(f->nodes[kl].outputs[0].script_pubkey, f->nodes[sl].spending_spk, 34);
    f->nodes[kl].outputs[0].script_pubkey_len = 34;
    f->nodes[kl].input_amount = sr_per_child;

    /* kickoff_right -> 1 output: state_right */
    f->nodes[kri].n_outputs = 1;
    f->nodes[kri].outputs[0].amount_sats = kri_out;
    memcpy(f->nodes[kri].outputs[0].script_pubkey, f->nodes[sri].spending_spk, 34);
    f->nodes[kri].outputs[0].script_pubkey_len = 34;
    f->nodes[kri].input_amount = sr_per_child;

    /* state_left -> 3 leaf outputs: chan_A, chan_B, L_stock */
    f->nodes[sl].input_amount = kl_out;
    if (!setup_leaf_outputs(f, &f->nodes[sl], 1, 2, kl_out))
        return 0;

    /* state_right -> 3 leaf outputs: chan_C, chan_D, L_stock */
    f->nodes[sri].input_amount = kri_out;
    if (!setup_leaf_outputs(f, &f->nodes[sri], 3, 4, kri_out))
        return 0;

    /* ---- Phase 3: Build unsigned txs top-down ---- */
    return build_all_unsigned_txs(f);
}

int factory_sign_all(factory_t *f) {
    for (size_t i = 0; i < f->n_nodes; i++) {
        factory_node_t *node = &f->nodes[i];
        if (!node->is_built) return 0;

        /* Previous output info for sighash */
        const unsigned char *prev_spk;
        size_t prev_spk_len;
        uint64_t prev_amount;

        if (node->parent_index < 0) {
            prev_spk = f->funding_spk;
            prev_spk_len = f->funding_spk_len;
            prev_amount = f->funding_amount_sats;
        } else {
            factory_node_t *parent = &f->nodes[node->parent_index];
            prev_spk = parent->outputs[node->parent_vout].script_pubkey;
            prev_spk_len = parent->outputs[node->parent_vout].script_pubkey_len;
            prev_amount = parent->outputs[node->parent_vout].amount_sats;
        }

        unsigned char sighash[32];
        if (!compute_taproot_sighash(sighash,
                                      node->unsigned_tx.data, node->unsigned_tx.len,
                                      0, prev_spk, prev_spk_len,
                                      prev_amount, node->nsequence))
            return 0;

        /* Gather keypairs for this node's signers */
        secp256k1_keypair kps[FACTORY_MAX_SIGNERS];
        for (size_t j = 0; j < node->n_signers; j++)
            kps[j] = f->keypairs[node->signer_indices[j]];

        /* Sign (copy keyagg since musig_sign_taproot modifies it).
           Pass merkle_root if this node has a taptree (key-path spend of
           an output that also has a script path). */
        unsigned char sig[64];
        musig_keyagg_t sign_ka = node->keyagg;
        const unsigned char *mr = node->has_taptree ? node->merkle_root : NULL;
        if (!musig_sign_taproot(f->ctx, sig, sighash, kps, node->n_signers,
                                 &sign_ka, mr))
            return 0;

        if (!finalize_signed_tx(&node->signed_tx,
                                 node->unsigned_tx.data, node->unsigned_tx.len,
                                 sig))
            return 0;

        node->is_signed = 1;
    }
    return 1;
}

int factory_advance(factory_t *f) {
    if (!dw_counter_advance(&f->counter))
        return 0;

    if (!build_all_unsigned_txs(f))
        return 0;

    return factory_sign_all(f);
}

void factory_free(factory_t *f) {
    for (size_t i = 0; i < f->n_nodes; i++) {
        tx_buf_free(&f->nodes[i].unsigned_tx);
        tx_buf_free(&f->nodes[i].signed_tx);
    }
}
