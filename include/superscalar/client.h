#ifndef SUPERSCALAR_CLIENT_H
#define SUPERSCALAR_CLIENT_H

#include "channel.h"
#include "wire.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

/* Run the client-side factory creation + cooperative close ceremony.
   Connects to LSP at host:port, performs HELLO handshake, builds factory,
   generates nonces/psigs, and does cooperative close.
   Returns 1 on success, 0 on failure. */
int client_run_ceremony(secp256k1_context *ctx,
                        const secp256k1_keypair *keypair,
                        const char *host, int port);

/* Callback for automated (non-interactive) channel operations.
   fd: wire connection to LSP.
   channel: the client's channel with the LSP.
   my_index: participant index (1..N).
   ctx: secp256k1 context.
   user_data: opaque pointer for test harness.
   Return 1 to continue, 0 to close. */
typedef int (*client_channel_cb_t)(int fd, channel_t *channel,
                                    uint32_t my_index,
                                    secp256k1_context *ctx,
                                    void *user_data);

/* Run the full ceremony with optional channel operations.
   If channel_cb is NULL, behaves identically to client_run_ceremony
   (creates factory then immediately closes).
   If channel_cb is non-NULL, calls it after CHANNEL_READY and before close. */
int client_run_with_channels(secp256k1_context *ctx,
                              const secp256k1_keypair *keypair,
                              const char *host, int port,
                              client_channel_cb_t channel_cb,
                              void *user_data);

/* --- Client-side channel message handlers --- */

/* Send ADD_HTLC to LSP for payment to dest_client.
   payment_hash: 32-byte hash (caller generates).
   Returns 1 on success. */
int client_send_payment(int fd, uint64_t amount_sats,
                         const unsigned char *payment_hash32,
                         uint32_t cltv_expiry, uint32_t dest_client);

/* Handle incoming COMMITMENT_SIGNED from LSP.
   Verifies and sends REVOKE_AND_ACK back. Returns 1 on success. */
int client_handle_commitment_signed(int fd, channel_t *ch,
                                      secp256k1_context *ctx,
                                      const wire_msg_t *msg);

/* Handle incoming ADD_HTLC from LSP (we are the payee).
   Returns 1 on success. */
int client_handle_add_htlc(channel_t *ch, const wire_msg_t *msg);

/* Send FULFILL_HTLC to LSP (reveal preimage for received HTLC).
   Returns 1 on success. */
int client_fulfill_payment(int fd, channel_t *ch,
                             uint64_t htlc_id,
                             const unsigned char *preimage32);

#endif /* SUPERSCALAR_CLIENT_H */
