#ifndef SUPERSCALAR_LSP_CHANNELS_H
#define SUPERSCALAR_LSP_CHANNELS_H

#include "channel.h"
#include "lsp.h"
#include "wire.h"
#include "watchtower.h"
#include <signal.h>

/* Per-client channel entry managed by the LSP */
typedef struct {
    channel_t channel;          /* Poon-Dryja channel (LSP=local, client=remote) */
    uint32_t channel_id;        /* channel_id sent over wire (= client index) */
    int ready;                  /* 1 after CHANNEL_READY sent */
} lsp_channel_entry_t;

/* Invoice registry entry for bridge inbound payments (Phase 14) */
#define MAX_INVOICE_REGISTRY 64

typedef struct {
    unsigned char payment_hash[32];
    size_t dest_client;
    uint64_t amount_msat;
    uint64_t bridge_htlc_id;     /* correlation ID for bridge response */
    int active;
} invoice_entry_t;

/* HTLC origin tracking for bridge back-propagation (Phase 14) */
#define MAX_HTLC_ORIGINS 64

typedef struct {
    unsigned char payment_hash[32];
    uint64_t bridge_htlc_id;     /* 0 = intra-factory, >0 = from bridge */
    uint64_t request_id;         /* outbound pay correlation (Phase 17) */
    size_t sender_idx;           /* originating client index (Phase 17) */
    uint64_t sender_htlc_id;    /* HTLC id on sender's channel (Phase 17) */
    int active;
} htlc_origin_t;

typedef struct {
    lsp_channel_entry_t entries[LSP_MAX_CLIENTS];
    size_t n_channels;
    secp256k1_context *ctx;

    /* Bridge support (Phase 14) */
    int bridge_fd;               /* -1 if no bridge connected */
    invoice_entry_t invoices[MAX_INVOICE_REGISTRY];
    size_t n_invoices;
    htlc_origin_t htlc_origins[MAX_HTLC_ORIGINS];
    size_t n_htlc_origins;
    uint64_t next_request_id;    /* for outbound pay correlation */

    /* Watchtower (Phase 18) */
    watchtower_t *watchtower;

    /* Persistence (Phase 23) */
    void *persist;  /* persist_t* or NULL — avoids header dependency */

    /* Ladder manager (Tier 2) */
    void *ladder;   /* ladder_t* or NULL — avoids header dependency */
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

/* Exchange MSG_CHANNEL_BASEPOINTS with all clients.
   Must be called after lsp_channels_init() and before lsp_channels_send_ready().
   Sends LSP's basepoint pubkeys and receives client's basepoint pubkeys.
   Returns 1 on success. */
int lsp_channels_exchange_basepoints(lsp_channel_mgr_t *mgr, lsp_t *lsp);

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

/* Run a daemon event loop handling channel messages until shutdown.
   Loops on select() with 5-second timeout checking *shutdown_flag.
   Returns 1 on clean shutdown. */
int lsp_channels_run_daemon_loop(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                   volatile sig_atomic_t *shutdown_flag);

/* --- Reconnection (Phase 16) --- */

/* Handle a reconnecting client on a new fd.
   Reads MSG_RECONNECT, matches pubkey to client slot, re-exchanges nonces,
   sends MSG_RECONNECT_ACK. Returns 1 on success. */
int lsp_channels_handle_reconnect(lsp_channel_mgr_t *mgr, lsp_t *lsp, int new_fd);

/* --- Bridge support (Phase 14) --- */

/* Set bridge fd in channel manager. */
void lsp_channels_set_bridge(lsp_channel_mgr_t *mgr, int bridge_fd);

/* Register an invoice (payment_hash → dest_client) for bridge inbound routing. */
int lsp_channels_register_invoice(lsp_channel_mgr_t *mgr,
                                    const unsigned char *payment_hash32,
                                    size_t dest_client, uint64_t amount_msat);

/* Look up invoice by payment_hash. Returns dest_client index, or -1. */
int lsp_channels_lookup_invoice(lsp_channel_mgr_t *mgr,
                                  const unsigned char *payment_hash32,
                                  size_t *dest_client_out);

/* Handle a MSG_BRIDGE_* message from the bridge daemon.
   Dispatches based on msg_type. Returns 1 on success. */
int lsp_channels_handle_bridge_msg(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                     const wire_msg_t *msg);

/* Track that an HTLC came from the bridge (for back-propagation). */
void lsp_channels_track_bridge_origin(lsp_channel_mgr_t *mgr,
                                        const unsigned char *payment_hash32,
                                        uint64_t bridge_htlc_id);

/* Check if an HTLC originated from the bridge. Returns bridge_htlc_id, 0 if not. */
uint64_t lsp_channels_get_bridge_origin(lsp_channel_mgr_t *mgr,
                                          const unsigned char *payment_hash32);

/* --- Demo mode (Phase 17) --- */

/* Print a formatted balance table for all channels. */
void lsp_channels_print_balances(const lsp_channel_mgr_t *mgr);

/* Initiate a payment from one client to another via the LSP.
   Sends MSG_CREATE_INVOICE to receiver, waits for invoice, adds HTLC on
   sender's channel, forwards to receiver, waits for fulfill, back-propagates.
   Returns 1 on success. */
int lsp_channels_initiate_payment(lsp_channel_mgr_t *mgr, lsp_t *lsp,
                                    size_t from_client, size_t to_client,
                                    uint64_t amount_sats);

/* Run a scripted demo sequence of payments after channels are ready.
   Returns 1 on success. */
int lsp_channels_run_demo_sequence(lsp_channel_mgr_t *mgr, lsp_t *lsp);

#endif /* SUPERSCALAR_LSP_CHANNELS_H */
