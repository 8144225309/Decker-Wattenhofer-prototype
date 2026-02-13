#include "superscalar/client.h"
#include "superscalar/wire.h"
#include "superscalar/channel.h"
#include "superscalar/report.h"
#include "superscalar/persist.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include "cJSON.h"

extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern void sha256(const unsigned char *, size_t, unsigned char *);

#define MAX_ACTIONS 16

typedef enum { ACTION_SEND, ACTION_RECV } action_type_t;

typedef struct {
    action_type_t type;
    uint32_t dest_client;
    uint64_t amount_sats;
    unsigned char preimage[32];
    unsigned char payment_hash[32];
} scripted_action_t;

typedef struct {
    scripted_action_t *actions;
    size_t n_actions;
    size_t current;
} multi_payment_data_t;

/* Channel callback replicating multi_payment_client_cb from test harness */
static int standalone_channel_cb(int fd, channel_t *ch, uint32_t my_index,
                                   secp256k1_context *ctx, void *user_data) {
    multi_payment_data_t *data = (multi_payment_data_t *)user_data;

    for (size_t i = 0; i < data->n_actions; i++) {
        scripted_action_t *act = &data->actions[i];

        if (act->type == ACTION_SEND) {
            printf("Client %u: SEND %llu sats to client %u\n",
                   my_index, (unsigned long long)act->amount_sats, act->dest_client);

            if (!client_send_payment(fd, act->amount_sats, act->payment_hash,
                                       500, act->dest_client)) {
                fprintf(stderr, "Client %u: send_payment failed\n", my_index);
                return 0;
            }

            /* Wait for COMMITMENT_SIGNED (acknowledging HTLC) */
            wire_msg_t msg;
            if (!wire_recv(fd, &msg)) {
                fprintf(stderr, "Client %u: recv failed after send\n", my_index);
                return 0;
            }
            if (msg.msg_type == MSG_COMMITMENT_SIGNED) {
                client_handle_commitment_signed(fd, ch, ctx, &msg);
                cJSON_Delete(msg.json);
            } else {
                fprintf(stderr, "Client %u: expected COMMIT_SIGNED, got 0x%02x\n",
                        my_index, msg.msg_type);
                cJSON_Delete(msg.json);
                return 0;
            }

            /* Wait for FULFILL_HTLC */
            if (!wire_recv(fd, &msg)) {
                fprintf(stderr, "Client %u: recv fulfill failed\n", my_index);
                return 0;
            }
            if (msg.msg_type == MSG_UPDATE_FULFILL_HTLC) {
                printf("Client %u: payment fulfilled!\n", my_index);
                cJSON_Delete(msg.json);
            } else {
                fprintf(stderr, "Client %u: expected FULFILL, got 0x%02x\n",
                        my_index, msg.msg_type);
                cJSON_Delete(msg.json);
                return 0;
            }

            /* Handle COMMITMENT_SIGNED for the fulfill */
            if (!wire_recv(fd, &msg)) {
                fprintf(stderr, "Client %u: recv commit after fulfill failed\n", my_index);
                return 0;
            }
            if (msg.msg_type == MSG_COMMITMENT_SIGNED) {
                client_handle_commitment_signed(fd, ch, ctx, &msg);
                cJSON_Delete(msg.json);
            } else {
                cJSON_Delete(msg.json);
            }

            printf("Client %u: payment sent: %llu sats to client %u\n",
                   my_index, (unsigned long long)act->amount_sats, act->dest_client);

        } else { /* ACTION_RECV */
            printf("Client %u: RECV (waiting for ADD_HTLC)\n", my_index);

            /* Wait for ADD_HTLC from LSP */
            wire_msg_t msg;
            if (!wire_recv(fd, &msg)) {
                fprintf(stderr, "Client %u: recv ADD_HTLC failed\n", my_index);
                return 0;
            }
            if (msg.msg_type == MSG_UPDATE_ADD_HTLC) {
                client_handle_add_htlc(ch, &msg);
                cJSON_Delete(msg.json);
            } else {
                fprintf(stderr, "Client %u: expected ADD_HTLC, got 0x%02x\n",
                        my_index, msg.msg_type);
                cJSON_Delete(msg.json);
                return 0;
            }

            /* Handle COMMITMENT_SIGNED */
            if (!wire_recv(fd, &msg)) {
                fprintf(stderr, "Client %u: recv commit failed\n", my_index);
                return 0;
            }
            if (msg.msg_type == MSG_COMMITMENT_SIGNED) {
                client_handle_commitment_signed(fd, ch, ctx, &msg);
                cJSON_Delete(msg.json);
            } else {
                cJSON_Delete(msg.json);
            }

            /* Find active received HTLC and fulfill it */
            uint64_t htlc_id = 0;
            int found = 0;
            for (size_t h = 0; h < ch->n_htlcs; h++) {
                if (ch->htlcs[h].state == HTLC_STATE_ACTIVE &&
                    ch->htlcs[h].direction == HTLC_RECEIVED) {
                    htlc_id = ch->htlcs[h].id;
                    found = 1;
                    break;
                }
            }
            if (!found) {
                fprintf(stderr, "Client %u: no active received HTLC to fulfill\n", my_index);
                return 0;
            }

            printf("Client %u: fulfilling HTLC %llu\n", my_index,
                   (unsigned long long)htlc_id);
            client_fulfill_payment(fd, ch, htlc_id, act->preimage);

            /* Handle COMMITMENT_SIGNED for the fulfill */
            if (!wire_recv(fd, &msg)) {
                fprintf(stderr, "Client %u: recv commit after fulfill failed\n", my_index);
                return 0;
            }
            if (msg.msg_type == MSG_COMMITMENT_SIGNED) {
                client_handle_commitment_signed(fd, ch, ctx, &msg);
                cJSON_Delete(msg.json);
            } else {
                cJSON_Delete(msg.json);
            }

            printf("Client %u: payment received\n", my_index);
        }
    }

    return 1;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s --seckey HEX --port PORT [--host HOST] [OPTIONS]\n"
        "\n"
        "Options:\n"
        "  --seckey HEX                      Client secret key (32-byte hex, required)\n"
        "  --port PORT                       LSP port (default 9735)\n"
        "  --host HOST                       LSP host (default 127.0.0.1)\n"
        "  --send DEST:AMOUNT:PREIMAGE_HEX   Send payment (can repeat)\n"
        "  --recv PREIMAGE_HEX               Receive payment (can repeat)\n"
        "  --channels                        Expect channel phase (for when LSP uses --payments)\n"
        "  --report PATH                     Write diagnostic JSON report to PATH\n"
        "  --db PATH                         SQLite database for persistence (default: none)\n"
        "  --help                            Show this help\n",
        prog);
}

int main(int argc, char *argv[]) {
    const char *seckey_hex = NULL;
    int port = 9735;
    const char *host = "127.0.0.1";
    int expect_channels = 0;
    const char *report_path = NULL;
    const char *db_path = NULL;

    scripted_action_t actions[MAX_ACTIONS];
    size_t n_actions = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--seckey") == 0 && i + 1 < argc)
            seckey_hex = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
            port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--host") == 0 && i + 1 < argc)
            host = argv[++i];
        else if (strcmp(argv[i], "--channels") == 0)
            expect_channels = 1;
        else if (strcmp(argv[i], "--report") == 0 && i + 1 < argc)
            report_path = argv[++i];
        else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc)
            db_path = argv[++i];
        else if (strcmp(argv[i], "--send") == 0 && i + 1 < argc) {
            if (n_actions >= MAX_ACTIONS) {
                fprintf(stderr, "Too many actions (max %d)\n", MAX_ACTIONS);
                return 1;
            }
            /* Parse DEST:AMOUNT:PREIMAGE_HEX */
            const char *arg = argv[++i];
            char *copy = strdup(arg);
            char *p1 = strchr(copy, ':');
            if (!p1) { fprintf(stderr, "Bad --send format: %s\n", arg); free(copy); return 1; }
            *p1++ = '\0';
            char *p2 = strchr(p1, ':');
            if (!p2) { fprintf(stderr, "Bad --send format: %s\n", arg); free(copy); return 1; }
            *p2++ = '\0';

            scripted_action_t *act = &actions[n_actions++];
            act->type = ACTION_SEND;
            act->dest_client = (uint32_t)atoi(copy);
            act->amount_sats = (uint64_t)strtoull(p1, NULL, 10);
            if (hex_decode(p2, act->preimage, 32) != 32) {
                fprintf(stderr, "Bad preimage hex in --send: %s\n", p2);
                free(copy);
                return 1;
            }
            sha256(act->preimage, 32, act->payment_hash);
            free(copy);

        } else if (strcmp(argv[i], "--recv") == 0 && i + 1 < argc) {
            if (n_actions >= MAX_ACTIONS) {
                fprintf(stderr, "Too many actions (max %d)\n", MAX_ACTIONS);
                return 1;
            }
            const char *arg = argv[++i];
            scripted_action_t *act = &actions[n_actions++];
            act->type = ACTION_RECV;
            act->dest_client = 0;
            act->amount_sats = 0;
            if (hex_decode(arg, act->preimage, 32) != 32) {
                fprintf(stderr, "Bad preimage hex in --recv: %s\n", arg);
                return 1;
            }
            sha256(act->preimage, 32, act->payment_hash);

        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
    }

    if (!seckey_hex) {
        usage(argv[0]);
        return 1;
    }

    unsigned char seckey[32];
    if (hex_decode(seckey_hex, seckey, 32) != 32) {
        fprintf(stderr, "Invalid seckey hex\n");
        return 1;
    }

    /* Initialize diagnostic report */
    report_t rpt;
    if (!report_init(&rpt, report_path)) {
        fprintf(stderr, "Error: cannot open report file: %s\n", report_path);
        return 1;
    }
    report_add_string(&rpt, "role", "client");
    report_add_string(&rpt, "host", host);
    report_add_uint(&rpt, "port", (uint64_t)port);
    report_add_uint(&rpt, "n_actions", n_actions);
    report_add_bool(&rpt, "expect_channels", expect_channels);

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, seckey)) {
        fprintf(stderr, "Invalid secret key\n");
        memset(seckey, 0, 32);
        report_close(&rpt);
        return 1;
    }

    /* Report: client pubkey */
    {
        secp256k1_pubkey pk;
        int ok_pk = secp256k1_keypair_pub(ctx, &pk, &kp);
        if (ok_pk)
            report_add_pubkey(&rpt, "pubkey", ctx, &pk);
    }
    memset(seckey, 0, 32);

    /* Report: scripted actions */
    if (n_actions > 0) {
        report_begin_array(&rpt, "actions");
        for (size_t i = 0; i < n_actions; i++) {
            report_begin_section(&rpt, NULL);
            report_add_string(&rpt, "type",
                              actions[i].type == ACTION_SEND ? "send" : "recv");
            if (actions[i].type == ACTION_SEND) {
                report_add_uint(&rpt, "dest_client", actions[i].dest_client);
                report_add_uint(&rpt, "amount_sats", actions[i].amount_sats);
            }
            report_add_hex(&rpt, "payment_hash", actions[i].payment_hash, 32);
            report_end_section(&rpt);
        }
        report_end_array(&rpt);
    }
    report_flush(&rpt);

    /* Initialize persistence (optional) */
    persist_t db;
    int use_db = 0;
    if (db_path) {
        if (!persist_open(&db, db_path)) {
            fprintf(stderr, "Error: cannot open database: %s\n", db_path);
            secp256k1_context_destroy(ctx);
            report_close(&rpt);
            return 1;
        }
        use_db = 1;
        printf("Client: persistence enabled (%s)\n", db_path);
    }

    int ok;
    if (n_actions > 0 || expect_channels) {
        multi_payment_data_t data = { actions, n_actions, 0 };
        ok = client_run_with_channels(ctx, &kp, host, port, standalone_channel_cb, &data);
    } else {
        ok = client_run_ceremony(ctx, &kp, host, port);
    }

    report_add_string(&rpt, "result", ok ? "success" : "failure");
    report_close(&rpt);

    if (use_db)
        persist_close(&db);
    secp256k1_context_destroy(ctx);
    return ok ? 0 : 1;
}
