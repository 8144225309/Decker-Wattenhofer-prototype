#ifndef SUPERSCALAR_FACTORY_H
#define SUPERSCALAR_FACTORY_H

#include "types.h"
#include "dw_state.h"
#include "musig.h"
#include "tx_builder.h"
#include "tapscript.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#define FACTORY_MAX_NODES   32
#define FACTORY_MAX_OUTPUTS  8
#define FACTORY_MAX_SIGNERS 16

#define NSEQUENCE_DISABLE_BIP68 0xFFFFFFFFu

typedef enum { NODE_KICKOFF, NODE_STATE } factory_node_type_t;

typedef struct {
    factory_node_type_t type;

    /* Signers for this node's N-of-N */
    uint32_t signer_indices[FACTORY_MAX_SIGNERS];
    size_t n_signers;
    musig_keyagg_t keyagg;

    /* Tweaked output key and P2TR scriptPubKey */
    secp256k1_xonly_pubkey tweaked_pubkey;
    unsigned char spending_spk[34];
    size_t spending_spk_len;

    /* Transaction */
    tx_buf_t unsigned_tx;
    tx_buf_t signed_tx;
    unsigned char txid[32];   /* internal byte order */
    uint32_t nsequence;
    int is_built;
    int is_signed;

    /* Outputs */
    tx_output_t outputs[FACTORY_MAX_OUTPUTS];
    size_t n_outputs;

    /* DW layer index into factory counter (-1 for kickoff nodes) */
    int dw_layer_index;

    /* Tree links */
    int parent_index;         /* -1 for root */
    uint32_t parent_vout;
    int child_indices[FACTORY_MAX_OUTPUTS];
    size_t n_children;

    /* Input amount from parent output */
    uint64_t input_amount;

    /* Timeout script path (state outputs feeding kickoff nodes) */
    int has_taptree;
    tapscript_leaf_t timeout_leaf;
    unsigned char merkle_root[32];
    int output_parity;        /* parity of tweaked output key */
} factory_node_t;

typedef struct {
    secp256k1_context *ctx;

    /* Participants: 0 = LSP, 1..N = clients */
    secp256k1_keypair keypairs[FACTORY_MAX_SIGNERS];
    secp256k1_pubkey pubkeys[FACTORY_MAX_SIGNERS];
    size_t n_participants;

    /* Flat node array */
    factory_node_t nodes[FACTORY_MAX_NODES];
    size_t n_nodes;

    /* Funding UTXO */
    unsigned char funding_txid[32];  /* internal byte order */
    uint32_t funding_vout;
    uint64_t funding_amount_sats;
    unsigned char funding_spk[34];
    size_t funding_spk_len;

    /* DW counter */
    dw_counter_t counter;
    uint16_t step_blocks;
    uint32_t states_per_layer;

    /* Fee per transaction */
    uint64_t fee_per_tx;

    /* CLTV timeout (absolute block height) */
    uint32_t cltv_timeout;
} factory_t;

void factory_init(factory_t *f, secp256k1_context *ctx,
                  const secp256k1_keypair *keypairs, size_t n_participants,
                  uint16_t step_blocks, uint32_t states_per_layer);

void factory_set_funding(factory_t *f,
                         const unsigned char *txid, uint32_t vout,
                         uint64_t amount_sats,
                         const unsigned char *spk, size_t spk_len);

int factory_build_tree(factory_t *f);
int factory_sign_all(factory_t *f);
int factory_advance(factory_t *f);
void factory_free(factory_t *f);

#endif /* SUPERSCALAR_FACTORY_H */
