#ifndef SUPERSCALAR_WIRE_H
#define SUPERSCALAR_WIRE_H

#include "types.h"
#include "factory.h"
#include <stdint.h>
#include <stddef.h>
#include <cJSON.h>

/* --- Message types --- */
#define MSG_HELLO              0x01
#define MSG_HELLO_ACK          0x02
#define MSG_FACTORY_PROPOSE    0x10
#define MSG_NONCE_BUNDLE       0x11
#define MSG_ALL_NONCES         0x12
#define MSG_PSIG_BUNDLE        0x13
#define MSG_FACTORY_READY      0x14
#define MSG_CLOSE_PROPOSE      0x20
#define MSG_CLOSE_NONCE        0x21
#define MSG_CLOSE_ALL_NONCES   0x22
#define MSG_CLOSE_PSIG         0x23
#define MSG_CLOSE_DONE         0x24
/* Channel operation messages (Phase 10) */
#define MSG_CHANNEL_READY      0x30
#define MSG_UPDATE_ADD_HTLC    0x31
#define MSG_COMMITMENT_SIGNED  0x32
#define MSG_REVOKE_AND_ACK     0x33
#define MSG_UPDATE_FULFILL_HTLC 0x34
#define MSG_UPDATE_FAIL_HTLC   0x35
#define MSG_CLOSE_REQUEST      0x36

#define MSG_ERROR              0xFF

/* --- Protocol limits --- */
#define WIRE_MAX_FRAME_SIZE     (1024 * 1024)   /* 1 MB */
#define WIRE_DEFAULT_TIMEOUT_SEC 120

/* --- Wire frame: [uint32 len][uint8 type][JSON payload] --- */

typedef struct {
    uint8_t  msg_type;
    cJSON   *json;      /* caller must cJSON_Delete after use */
} wire_msg_t;

/* --- TCP transport --- */

int wire_listen(const char *host, int port);
int wire_accept(int listen_fd);
int wire_connect(const char *host, int port);
void wire_close(int fd);
int wire_set_timeout(int fd, int timeout_sec);

/* --- Framing --- */

/* Send: writes [4-byte big-endian length][1-byte type][JSON bytes]. Returns 1 on success. */
int wire_send(int fd, uint8_t msg_type, cJSON *json);

/* Recv: reads one frame. Caller must cJSON_Delete(msg->json). Returns 1 on success, 0 on EOF/error. */
int wire_recv(int fd, wire_msg_t *msg);

/* --- Crypto JSON helpers --- */

/* Encode binary as hex string and add to JSON object */
void wire_json_add_hex(cJSON *obj, const char *key, const unsigned char *data, size_t len);

/* Decode hex string from JSON object into binary. Returns decoded length or 0 on error. */
int wire_json_get_hex(const cJSON *obj, const char *key, unsigned char *out, size_t max_len);

/* --- Nonce/Psig bundle entry --- */
typedef struct {
    uint32_t node_idx;
    uint32_t signer_slot;
    unsigned char data[66];  /* 66 for pubnonce, 32 for psig */
    size_t data_len;
} wire_bundle_entry_t;

/* --- Message builders --- */

/* Client → LSP: HELLO {pubkey} */
cJSON *wire_build_hello(const secp256k1_context *ctx, const secp256k1_pubkey *pubkey);

/* LSP → Client: HELLO_ACK {lsp_pubkey, participant_index, all_pubkeys[]} */
cJSON *wire_build_hello_ack(const secp256k1_context *ctx,
                            const secp256k1_pubkey *lsp_pubkey,
                            uint32_t participant_index,
                            const secp256k1_pubkey *all_pubkeys, size_t n);

/* LSP → Client: FACTORY_PROPOSE {funding_txid, funding_vout, funding_amount,
                                   step_blocks, states_per_layer, cltv_timeout, fee_per_tx} */
cJSON *wire_build_factory_propose(const factory_t *f);

/* Client → LSP: NONCE_BUNDLE {entries: [{node_idx, slot, pubnonce_hex}...]} */
cJSON *wire_build_nonce_bundle(const wire_bundle_entry_t *entries, size_t n);

/* LSP → Client: ALL_NONCES {nonces: [{node_idx, slot, pubnonce_hex}...]} */
cJSON *wire_build_all_nonces(const wire_bundle_entry_t *entries, size_t n);

/* Client → LSP: PSIG_BUNDLE {entries: [{node_idx, slot, psig_hex}...]} */
cJSON *wire_build_psig_bundle(const wire_bundle_entry_t *entries, size_t n);

/* LSP → Client: FACTORY_READY {signed_txs: [{node_idx, tx_hex}...]} */
cJSON *wire_build_factory_ready(const factory_t *f);

/* LSP → Client: CLOSE_PROPOSE {outputs: [{amount, spk_hex}...]} */
cJSON *wire_build_close_propose(const tx_output_t *outputs, size_t n);

/* Client → LSP: CLOSE_NONCE {pubnonce_hex} */
cJSON *wire_build_close_nonce(const unsigned char *pubnonce66);

/* LSP → Client: CLOSE_ALL_NONCES {nonces: [pubnonce_hex...]} */
cJSON *wire_build_close_all_nonces(const unsigned char pubnonces[][66], size_t n);

/* Client → LSP: CLOSE_PSIG {psig_hex} */
cJSON *wire_build_close_psig(const unsigned char *psig32);

/* LSP → Client: CLOSE_DONE {tx_hex} */
cJSON *wire_build_close_done(const unsigned char *tx_data, size_t tx_len);

/* MSG_ERROR {message} */
cJSON *wire_build_error(const char *message);

/* --- Channel operation message builders (Phase 10) --- */

/* LSP → Client: CHANNEL_READY {channel_id, balance_local_msat, balance_remote_msat} */
cJSON *wire_build_channel_ready(uint32_t channel_id,
                                 uint64_t balance_local_msat,
                                 uint64_t balance_remote_msat);

/* Either → LSP: UPDATE_ADD_HTLC {htlc_id, amount_msat, payment_hash, cltv_expiry} */
cJSON *wire_build_update_add_htlc(uint64_t htlc_id, uint64_t amount_msat,
                                    const unsigned char *payment_hash32,
                                    uint32_t cltv_expiry);

/* Both: COMMITMENT_SIGNED {channel_id, commitment_number, sig} */
cJSON *wire_build_commitment_signed(uint32_t channel_id,
                                      uint64_t commitment_number,
                                      const unsigned char *sig64);

/* Both: REVOKE_AND_ACK {channel_id, revocation_secret, next_per_commitment_point} */
cJSON *wire_build_revoke_and_ack(uint32_t channel_id,
                                   const unsigned char *revocation_secret32,
                                   const secp256k1_context *ctx,
                                   const secp256k1_pubkey *next_per_commitment_point);

/* Either → LSP: UPDATE_FULFILL_HTLC {htlc_id, preimage} */
cJSON *wire_build_update_fulfill_htlc(uint64_t htlc_id,
                                        const unsigned char *preimage32);

/* Either → LSP: UPDATE_FAIL_HTLC {htlc_id, reason} */
cJSON *wire_build_update_fail_htlc(uint64_t htlc_id, const char *reason);

/* Client → LSP: CLOSE_REQUEST {} */
cJSON *wire_build_close_request(void);

/* --- Channel operation message parsers (Phase 10) --- */

int wire_parse_channel_ready(const cJSON *json, uint32_t *channel_id,
                              uint64_t *balance_local_msat,
                              uint64_t *balance_remote_msat);

int wire_parse_update_add_htlc(const cJSON *json, uint64_t *htlc_id,
                                 uint64_t *amount_msat,
                                 unsigned char *payment_hash32,
                                 uint32_t *cltv_expiry);

int wire_parse_commitment_signed(const cJSON *json, uint32_t *channel_id,
                                   uint64_t *commitment_number,
                                   unsigned char *sig64);

int wire_parse_revoke_and_ack(const cJSON *json, uint32_t *channel_id,
                                unsigned char *revocation_secret32,
                                unsigned char *next_point33);

int wire_parse_update_fulfill_htlc(const cJSON *json, uint64_t *htlc_id,
                                     unsigned char *preimage32);

int wire_parse_update_fail_htlc(const cJSON *json, uint64_t *htlc_id,
                                  char *reason, size_t reason_len);

/* --- Bundle parsing --- */

/* Parse a nonce or psig bundle array from JSON. Returns count, fills entries[]. */
size_t wire_parse_bundle(const cJSON *array, wire_bundle_entry_t *entries,
                         size_t max_entries, size_t expected_data_len);

#endif /* SUPERSCALAR_WIRE_H */
