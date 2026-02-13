#ifndef SUPERSCALAR_LSP_CHANNELS_H
#define SUPERSCALAR_LSP_CHANNELS_H

#include "channel.h"
#include "lsp.h"
#include "wire.h"

/* Per-client channel entry managed by the LSP */
typedef struct {
    channel_t channel;          /* Poon-Dryja channel (LSP=local, client=remote) */
    uint32_t channel_id;        /* channel_id sent over wire (= client index) */
    int ready;                  /* 1 after CHANNEL_READY sent */
} lsp_channel_entry_t;

typedef struct {
    lsp_channel_entry_t entries[LSP_MAX_CLIENTS];
    size_t n_channels;
    secp256k1_context *ctx;
} lsp_channel_mgr_t;

/* Initialize channels from factory leaf outputs.
   Must be called after factory creation succeeds.
   lsp_seckey32: LSP's secret key (used to derive channel basepoints).
   Returns 1 on success. */
int lsp_channels_init(lsp_channel_mgr_t *mgr,
                       secp256k1_context *ctx,
                       const factory_t *factory,
                       const unsigned char *lsp_seckey32,
                       size_t n_clients);

/* Send CHANNEL_READY to all clients. Returns 1 on success. */
int lsp_channels_send_ready(lsp_channel_mgr_t *mgr, lsp_t *lsp);

/* Handle an incoming channel message from a client.
   Dispatches based on msg_type. Returns 1 on success, 0 on error. */
int lsp_channels_handle_msg(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                              size_t client_idx, const wire_msg_t *msg);

/* Get a channel entry by client index. */
lsp_channel_entry_t *lsp_channels_get(lsp_channel_mgr_t *mgr, size_t client_idx);

/* Build close outputs reflecting current channel balances.
   outputs: caller-allocated array of at least (n_channels + 1) entries.
   Returns number of outputs written. Output 0 = LSP (sum of local_amounts - close_fee),
   Outputs 1..N = clients (each remote_amount). */
size_t lsp_channels_build_close_outputs(const lsp_channel_mgr_t *mgr,
                                         const factory_t *factory,
                                         tx_output_t *outputs,
                                         uint64_t close_fee);

/* Run a select()-based event loop handling channel messages.
   Processes messages until expected_msgs messages have been handled.
   Returns 1 on success, 0 on error. */
int lsp_channels_run_event_loop(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                  size_t expected_msgs);

#endif /* SUPERSCALAR_LSP_CHANNELS_H */
