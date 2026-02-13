#include "superscalar/wire.h"
#include "superscalar/factory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

/* --- TCP transport --- */

int wire_listen(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (host && host[0])
        inet_pton(AF_INET, host, &addr.sin_addr);
    else
        addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 16) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int wire_accept(int listen_fd) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    int fd = accept(listen_fd, (struct sockaddr *)&addr, &len);
    if (fd >= 0)
        wire_set_timeout(fd, WIRE_DEFAULT_TIMEOUT_SEC);
    return fd;
}

int wire_connect(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, host ? host : "127.0.0.1", &addr.sin_addr);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    wire_set_timeout(fd, WIRE_DEFAULT_TIMEOUT_SEC);
    return fd;
}

void wire_close(int fd) {
    if (fd >= 0) close(fd);
}

int wire_set_timeout(int fd, int timeout_sec) {
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return 1;
}

/* --- Low-level I/O --- */

static int write_all(int fd, const unsigned char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, buf + sent, len - sent);
        if (n <= 0) return 0;
        sent += (size_t)n;
    }
    return 1;
}

static int read_all(int fd, unsigned char *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0) return 0;
        got += (size_t)n;
    }
    return 1;
}

/* --- Framing --- */

int wire_send(int fd, uint8_t msg_type, cJSON *json) {
    char *payload = cJSON_PrintUnformatted(json);
    if (!payload) return 0;

    uint32_t payload_len = (uint32_t)strlen(payload);
    uint32_t frame_len = 1 + payload_len;  /* type byte + JSON */

    unsigned char header[5];
    header[0] = (unsigned char)(frame_len >> 24);
    header[1] = (unsigned char)(frame_len >> 16);
    header[2] = (unsigned char)(frame_len >> 8);
    header[3] = (unsigned char)(frame_len);
    header[4] = msg_type;

    int ok = write_all(fd, header, 5) &&
             write_all(fd, (unsigned char *)payload, payload_len);
    free(payload);
    return ok;
}

int wire_recv(int fd, wire_msg_t *msg) {
    unsigned char header[5];
    if (!read_all(fd, header, 4)) return 0;

    uint32_t frame_len = ((uint32_t)header[0] << 24) |
                          ((uint32_t)header[1] << 16) |
                          ((uint32_t)header[2] << 8) |
                          ((uint32_t)header[3]);
    if (frame_len < 1 || frame_len > WIRE_MAX_FRAME_SIZE) return 0;

    if (!read_all(fd, &header[4], 1)) return 0;
    msg->msg_type = header[4];

    uint32_t json_len = frame_len - 1;
    char *buf = (char *)malloc(json_len + 1);
    if (!buf) return 0;

    if (!read_all(fd, (unsigned char *)buf, json_len)) {
        free(buf);
        return 0;
    }
    buf[json_len] = '\0';

    msg->json = cJSON_Parse(buf);
    free(buf);
    return msg->json ? 1 : 0;
}

/* --- Crypto JSON helpers --- */

void wire_json_add_hex(cJSON *obj, const char *key,
                       const unsigned char *data, size_t len) {
    char *hex = (char *)malloc(len * 2 + 1);
    hex_encode(data, len, hex);
    cJSON_AddStringToObject(obj, key, hex);
    free(hex);
}

int wire_json_get_hex(const cJSON *obj, const char *key,
                      unsigned char *out, size_t max_len) {
    cJSON *item = cJSON_GetObjectItem(obj, key);
    if (!item || !cJSON_IsString(item)) return 0;
    return hex_decode(item->valuestring, out, max_len);
}

/* --- Pubkey serialization helpers --- */

static void pubkey_to_hex(const secp256k1_context *ctx,
                          const secp256k1_pubkey *pk, char *hex_out) {
    unsigned char buf[33];
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, buf, &len, pk, SECP256K1_EC_COMPRESSED);
    hex_encode(buf, 33, hex_out);
}

static int hex_to_pubkey(const secp256k1_context *ctx,
                         secp256k1_pubkey *pk, const char *hex) {
    unsigned char buf[33];
    if (hex_decode(hex, buf, 33) != 33) return 0;
    return secp256k1_ec_pubkey_parse(ctx, pk, buf, 33);
}

/* --- Bundle helper: build JSON array from entries --- */

static cJSON *build_bundle_array(const wire_bundle_entry_t *entries, size_t n) {
    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < n; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddNumberToObject(item, "node_idx", entries[i].node_idx);
        cJSON_AddNumberToObject(item, "slot", entries[i].signer_slot);
        wire_json_add_hex(item, "data", entries[i].data, entries[i].data_len);
        cJSON_AddItemToArray(arr, item);
    }
    return arr;
}

/* --- Message builders --- */

cJSON *wire_build_hello(const secp256k1_context *ctx,
                        const secp256k1_pubkey *pubkey) {
    cJSON *j = cJSON_CreateObject();
    char hex[67];
    pubkey_to_hex(ctx, pubkey, hex);
    cJSON_AddStringToObject(j, "pubkey", hex);
    return j;
}

cJSON *wire_build_hello_ack(const secp256k1_context *ctx,
                            const secp256k1_pubkey *lsp_pubkey,
                            uint32_t participant_index,
                            const secp256k1_pubkey *all_pubkeys, size_t n) {
    cJSON *j = cJSON_CreateObject();
    char hex[67];
    pubkey_to_hex(ctx, lsp_pubkey, hex);
    cJSON_AddStringToObject(j, "lsp_pubkey", hex);
    cJSON_AddNumberToObject(j, "participant_index", participant_index);

    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < n; i++) {
        pubkey_to_hex(ctx, &all_pubkeys[i], hex);
        cJSON_AddItemToArray(arr, cJSON_CreateString(hex));
    }
    cJSON_AddItemToObject(j, "all_pubkeys", arr);
    return j;
}

cJSON *wire_build_factory_propose(const factory_t *f) {
    cJSON *j = cJSON_CreateObject();

    /* Funding txid in display order */
    unsigned char display_txid[32];
    memcpy(display_txid, f->funding_txid, 32);
    reverse_bytes(display_txid, 32);
    wire_json_add_hex(j, "funding_txid", display_txid, 32);

    cJSON_AddNumberToObject(j, "funding_vout", f->funding_vout);
    cJSON_AddNumberToObject(j, "funding_amount", (double)f->funding_amount_sats);
    wire_json_add_hex(j, "funding_spk", f->funding_spk, f->funding_spk_len);
    cJSON_AddNumberToObject(j, "step_blocks", f->step_blocks);
    cJSON_AddNumberToObject(j, "states_per_layer", f->states_per_layer);
    cJSON_AddNumberToObject(j, "cltv_timeout", f->cltv_timeout);
    cJSON_AddNumberToObject(j, "fee_per_tx", (double)f->fee_per_tx);
    return j;
}

cJSON *wire_build_nonce_bundle(const wire_bundle_entry_t *entries, size_t n) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddItemToObject(j, "entries", build_bundle_array(entries, n));
    return j;
}

cJSON *wire_build_all_nonces(const wire_bundle_entry_t *entries, size_t n) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddItemToObject(j, "nonces", build_bundle_array(entries, n));
    return j;
}

cJSON *wire_build_psig_bundle(const wire_bundle_entry_t *entries, size_t n) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddItemToObject(j, "entries", build_bundle_array(entries, n));
    return j;
}

cJSON *wire_build_factory_ready(const factory_t *f) {
    cJSON *j = cJSON_CreateObject();
    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < f->n_nodes; i++) {
        if (!f->nodes[i].is_signed) continue;
        cJSON *item = cJSON_CreateObject();
        cJSON_AddNumberToObject(item, "node_idx", (double)i);
        wire_json_add_hex(item, "tx_hex",
                          f->nodes[i].signed_tx.data,
                          f->nodes[i].signed_tx.len);
        cJSON_AddItemToArray(arr, item);
    }
    cJSON_AddItemToObject(j, "signed_txs", arr);
    return j;
}

cJSON *wire_build_close_propose(const tx_output_t *outputs, size_t n) {
    cJSON *j = cJSON_CreateObject();
    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < n; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddNumberToObject(item, "amount", (double)outputs[i].amount_sats);
        wire_json_add_hex(item, "spk", outputs[i].script_pubkey,
                          outputs[i].script_pubkey_len);
        cJSON_AddItemToArray(arr, item);
    }
    cJSON_AddItemToObject(j, "outputs", arr);
    return j;
}

cJSON *wire_build_close_nonce(const unsigned char *pubnonce66) {
    cJSON *j = cJSON_CreateObject();
    wire_json_add_hex(j, "pubnonce", pubnonce66, 66);
    return j;
}

cJSON *wire_build_close_all_nonces(const unsigned char pubnonces[][66], size_t n) {
    cJSON *j = cJSON_CreateObject();
    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < n; i++) {
        char hex[133];
        hex_encode(pubnonces[i], 66, hex);
        cJSON_AddItemToArray(arr, cJSON_CreateString(hex));
    }
    cJSON_AddItemToObject(j, "nonces", arr);
    return j;
}

cJSON *wire_build_close_psig(const unsigned char *psig32) {
    cJSON *j = cJSON_CreateObject();
    wire_json_add_hex(j, "psig", psig32, 32);
    return j;
}

cJSON *wire_build_close_done(const unsigned char *tx_data, size_t tx_len) {
    cJSON *j = cJSON_CreateObject();
    wire_json_add_hex(j, "tx_hex", tx_data, tx_len);
    return j;
}

cJSON *wire_build_error(const char *message) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddStringToObject(j, "message", message);
    return j;
}

/* --- Channel operation message builders (Phase 10) --- */

cJSON *wire_build_channel_ready(uint32_t channel_id,
                                 uint64_t balance_local_msat,
                                 uint64_t balance_remote_msat) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "channel_id", channel_id);
    cJSON_AddNumberToObject(j, "balance_local_msat", (double)balance_local_msat);
    cJSON_AddNumberToObject(j, "balance_remote_msat", (double)balance_remote_msat);
    return j;
}

cJSON *wire_build_update_add_htlc(uint64_t htlc_id, uint64_t amount_msat,
                                    const unsigned char *payment_hash32,
                                    uint32_t cltv_expiry) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "htlc_id", (double)htlc_id);
    cJSON_AddNumberToObject(j, "amount_msat", (double)amount_msat);
    wire_json_add_hex(j, "payment_hash", payment_hash32, 32);
    cJSON_AddNumberToObject(j, "cltv_expiry", cltv_expiry);
    return j;
}

cJSON *wire_build_commitment_signed(uint32_t channel_id,
                                      uint64_t commitment_number,
                                      const unsigned char *partial_sig32,
                                      uint32_t nonce_index) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "channel_id", channel_id);
    cJSON_AddNumberToObject(j, "commitment_number", (double)commitment_number);
    wire_json_add_hex(j, "partial_sig", partial_sig32, 32);
    cJSON_AddNumberToObject(j, "nonce_index", nonce_index);
    return j;
}

cJSON *wire_build_revoke_and_ack(uint32_t channel_id,
                                   const unsigned char *revocation_secret32,
                                   const secp256k1_context *ctx,
                                   const secp256k1_pubkey *next_per_commitment_point) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "channel_id", channel_id);
    wire_json_add_hex(j, "revocation_secret", revocation_secret32, 32);
    if (ctx && next_per_commitment_point) {
        char hex[67];
        pubkey_to_hex(ctx, next_per_commitment_point, hex);
        cJSON_AddStringToObject(j, "next_per_commitment_point", hex);
    }
    return j;
}

cJSON *wire_build_update_fulfill_htlc(uint64_t htlc_id,
                                        const unsigned char *preimage32) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "htlc_id", (double)htlc_id);
    wire_json_add_hex(j, "preimage", preimage32, 32);
    return j;
}

cJSON *wire_build_update_fail_htlc(uint64_t htlc_id, const char *reason) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "htlc_id", (double)htlc_id);
    cJSON_AddStringToObject(j, "reason", reason ? reason : "unknown");
    return j;
}

cJSON *wire_build_close_request(void) {
    return cJSON_CreateObject();
}

cJSON *wire_build_channel_nonces(uint32_t channel_id,
                                   const unsigned char pubnonces[][66],
                                   size_t count) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddNumberToObject(j, "channel_id", channel_id);
    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < count; i++) {
        char hex[133];
        hex_encode(pubnonces[i], 66, hex);
        cJSON_AddItemToArray(arr, cJSON_CreateString(hex));
    }
    cJSON_AddItemToObject(j, "pubnonces", arr);
    return j;
}

/* --- Channel operation message parsers (Phase 10) --- */

int wire_parse_channel_ready(const cJSON *json, uint32_t *channel_id,
                              uint64_t *balance_local_msat,
                              uint64_t *balance_remote_msat) {
    cJSON *ci = cJSON_GetObjectItem(json, "channel_id");
    cJSON *bl = cJSON_GetObjectItem(json, "balance_local_msat");
    cJSON *br = cJSON_GetObjectItem(json, "balance_remote_msat");
    if (!ci || !cJSON_IsNumber(ci) || !bl || !cJSON_IsNumber(bl) ||
        !br || !cJSON_IsNumber(br))
        return 0;
    *channel_id = (uint32_t)ci->valuedouble;
    *balance_local_msat = (uint64_t)bl->valuedouble;
    *balance_remote_msat = (uint64_t)br->valuedouble;
    return 1;
}

int wire_parse_update_add_htlc(const cJSON *json, uint64_t *htlc_id,
                                 uint64_t *amount_msat,
                                 unsigned char *payment_hash32,
                                 uint32_t *cltv_expiry) {
    cJSON *hi = cJSON_GetObjectItem(json, "htlc_id");
    cJSON *am = cJSON_GetObjectItem(json, "amount_msat");
    cJSON *ce = cJSON_GetObjectItem(json, "cltv_expiry");
    if (!hi || !cJSON_IsNumber(hi) || !am || !cJSON_IsNumber(am) ||
        !ce || !cJSON_IsNumber(ce))
        return 0;
    if (wire_json_get_hex(json, "payment_hash", payment_hash32, 32) != 32)
        return 0;
    *htlc_id = (uint64_t)hi->valuedouble;
    *amount_msat = (uint64_t)am->valuedouble;
    *cltv_expiry = (uint32_t)ce->valuedouble;
    return 1;
}

int wire_parse_commitment_signed(const cJSON *json, uint32_t *channel_id,
                                   uint64_t *commitment_number,
                                   unsigned char *partial_sig32,
                                   uint32_t *nonce_index) {
    cJSON *ci = cJSON_GetObjectItem(json, "channel_id");
    cJSON *cn = cJSON_GetObjectItem(json, "commitment_number");
    cJSON *ni = cJSON_GetObjectItem(json, "nonce_index");
    if (!ci || !cJSON_IsNumber(ci) || !cn || !cJSON_IsNumber(cn) ||
        !ni || !cJSON_IsNumber(ni))
        return 0;
    if (wire_json_get_hex(json, "partial_sig", partial_sig32, 32) != 32)
        return 0;
    *channel_id = (uint32_t)ci->valuedouble;
    *commitment_number = (uint64_t)cn->valuedouble;
    *nonce_index = (uint32_t)ni->valuedouble;
    return 1;
}

int wire_parse_revoke_and_ack(const cJSON *json, uint32_t *channel_id,
                                unsigned char *revocation_secret32,
                                unsigned char *next_point33) {
    cJSON *ci = cJSON_GetObjectItem(json, "channel_id");
    if (!ci || !cJSON_IsNumber(ci)) return 0;
    if (wire_json_get_hex(json, "revocation_secret", revocation_secret32, 32) != 32)
        return 0;
    if (next_point33) {
        cJSON *np = cJSON_GetObjectItem(json, "next_per_commitment_point");
        if (!np || !cJSON_IsString(np)) return 0;
        if (hex_decode(np->valuestring, next_point33, 33) != 33) return 0;
    }
    *channel_id = (uint32_t)ci->valuedouble;
    return 1;
}

int wire_parse_update_fulfill_htlc(const cJSON *json, uint64_t *htlc_id,
                                     unsigned char *preimage32) {
    cJSON *hi = cJSON_GetObjectItem(json, "htlc_id");
    if (!hi || !cJSON_IsNumber(hi)) return 0;
    if (wire_json_get_hex(json, "preimage", preimage32, 32) != 32)
        return 0;
    *htlc_id = (uint64_t)hi->valuedouble;
    return 1;
}

int wire_parse_update_fail_htlc(const cJSON *json, uint64_t *htlc_id,
                                  char *reason, size_t reason_len) {
    cJSON *hi = cJSON_GetObjectItem(json, "htlc_id");
    cJSON *re = cJSON_GetObjectItem(json, "reason");
    if (!hi || !cJSON_IsNumber(hi)) return 0;
    *htlc_id = (uint64_t)hi->valuedouble;
    if (reason && reason_len > 0) {
        if (re && cJSON_IsString(re)) {
            strncpy(reason, re->valuestring, reason_len - 1);
            reason[reason_len - 1] = '\0';
        } else {
            reason[0] = '\0';
        }
    }
    return 1;
}

int wire_parse_channel_nonces(const cJSON *json, uint32_t *channel_id,
                                unsigned char pubnonces_out[][66],
                                size_t max_nonces, size_t *count_out) {
    cJSON *ci = cJSON_GetObjectItem(json, "channel_id");
    cJSON *arr = cJSON_GetObjectItem(json, "pubnonces");
    if (!ci || !cJSON_IsNumber(ci) || !arr || !cJSON_IsArray(arr))
        return 0;
    *channel_id = (uint32_t)ci->valuedouble;
    size_t count = 0;
    cJSON *item;
    cJSON_ArrayForEach(item, arr) {
        if (count >= max_nonces) break;
        if (!cJSON_IsString(item)) continue;
        if (hex_decode(item->valuestring, pubnonces_out[count], 66) != 66)
            continue;
        count++;
    }
    *count_out = count;
    return 1;
}

/* --- Bundle parsing --- */

size_t wire_parse_bundle(const cJSON *array, wire_bundle_entry_t *entries,
                         size_t max_entries, size_t expected_data_len) {
    if (!cJSON_IsArray(array)) return 0;
    size_t count = 0;
    cJSON *item;
    cJSON_ArrayForEach(item, array) {
        if (count >= max_entries) break;

        cJSON *ni = cJSON_GetObjectItem(item, "node_idx");
        cJSON *sl = cJSON_GetObjectItem(item, "slot");
        cJSON *d  = cJSON_GetObjectItem(item, "data");
        if (!ni || !cJSON_IsNumber(ni) ||
            !sl || !cJSON_IsNumber(sl) ||
            !d || !cJSON_IsString(d)) continue;
        if (ni->valuedouble < 0 || ni->valuedouble >= FACTORY_MAX_NODES) continue;
        if (sl->valuedouble < 0 || sl->valuedouble >= FACTORY_MAX_SIGNERS) continue;

        entries[count].node_idx = (uint32_t)ni->valuedouble;
        entries[count].signer_slot = (uint32_t)sl->valuedouble;
        int decoded = hex_decode(d->valuestring, entries[count].data, sizeof(entries[count].data));
        if (decoded != (int)expected_data_len) continue;
        entries[count].data_len = (size_t)decoded;
        count++;
    }
    return count;
}
