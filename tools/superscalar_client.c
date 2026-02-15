#include "superscalar/client.h"
#include "superscalar/wire.h"
#include "superscalar/channel.h"
#include "superscalar/factory.h"
#include "superscalar/report.h"
#include "superscalar/persist.h"
#include "superscalar/keyfile.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/select.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include "cJSON.h"

static volatile sig_atomic_t g_shutdown = 0;

static void sigint_handler(int sig) {
    (void)sig;
    g_shutdown = 1;
}

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
                                   secp256k1_context *ctx,
                                   const secp256k1_keypair *keypair,
                                   factory_t *factory,
                                   size_t n_participants,
                                   void *user_data) {
    (void)keypair; (void)factory; (void)n_participants;
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

/* Client-side invoice store for real preimage validation (Phase 17) */
#define MAX_CLIENT_INVOICES 32

typedef struct {
    unsigned char payment_hash[32];
    unsigned char preimage[32];
    uint64_t amount_msat;
    int active;
} client_invoice_t;

/* Data passed through daemon callback's user_data */
typedef struct {
    persist_t *db;
    int saved_initial;  /* 1 after first save of factory+channel */
    client_invoice_t invoices[MAX_CLIENT_INVOICES];
    size_t n_invoices;
} daemon_cb_data_t;

/* Daemon mode callback: select() loop handling incoming HTLCs and close */
static int daemon_channel_cb(int fd, channel_t *ch, uint32_t my_index,
                               secp256k1_context *ctx,
                               const secp256k1_keypair *keypair,
                               factory_t *factory,
                               size_t n_participants,
                               void *user_data) {
    daemon_cb_data_t *cbd = (daemon_cb_data_t *)user_data;

    /* Save factory + channel state on first entry (Phase 16 persistence) */
    if (cbd && cbd->db && !cbd->saved_initial) {
        persist_save_factory(cbd->db, factory, ctx, 0);
        uint32_t client_idx = my_index - 1;
        persist_save_channel(cbd->db, ch, 0, client_idx);
        cbd->saved_initial = 1;
        printf("Client %u: persisted factory + channel to DB\n", my_index);
    }

    secp256k1_pubkey my_pubkey;
    secp256k1_keypair_pub(ctx, &my_pubkey, keypair);

    printf("Client %u: daemon mode active (Ctrl+C to stop)\n", my_index);

    /* Log factory lifecycle once (Tier 2) */
    if (factory && factory->active_blocks > 0) {
        printf("Client %u: factory lifecycle: active %u blocks, dying %u blocks\n",
               my_index, factory->active_blocks, factory->dying_blocks);
    }

    while (!g_shutdown) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
        int ret = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (ret < 0) continue;  /* EINTR */
        if (ret == 0) continue;  /* timeout */

        wire_msg_t msg;
        if (!wire_recv(fd, &msg)) {
            fprintf(stderr, "Client %u: daemon recv failed (disconnected)\n", my_index);
            break;
        }

        switch (msg.msg_type) {
        case MSG_UPDATE_ADD_HTLC:
            client_handle_add_htlc(ch, &msg);
            cJSON_Delete(msg.json);

            /* Wait for COMMITMENT_SIGNED */
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

            /* Persist balance after commitment update */
            if (cbd && cbd->db) {
                persist_update_channel_balance(cbd->db, my_index - 1,
                    ch->local_amount, ch->remote_amount, ch->commitment_number);
            }

            /* Fulfill: find the most recent active received HTLC and look up preimage */
            {
                uint64_t htlc_id = 0;
                unsigned char htlc_hash[32];
                int found = 0;
                for (size_t h = 0; h < ch->n_htlcs; h++) {
                    if (ch->htlcs[h].state == HTLC_STATE_ACTIVE &&
                        ch->htlcs[h].direction == HTLC_RECEIVED) {
                        htlc_id = ch->htlcs[h].id;
                        memcpy(htlc_hash, ch->htlcs[h].payment_hash, 32);
                        found = 1;
                    }
                }
                if (found) {
                    /* Look up preimage from local invoice store */
                    unsigned char preimage[32];
                    int have_preimage = 0;
                    if (cbd) {
                        for (size_t inv = 0; inv < cbd->n_invoices; inv++) {
                            if (cbd->invoices[inv].active &&
                                memcmp(cbd->invoices[inv].payment_hash, htlc_hash, 32) == 0) {
                                memcpy(preimage, cbd->invoices[inv].preimage, 32);
                                cbd->invoices[inv].active = 0;
                                /* Deactivate in persistence (Phase 23) */
                                if (cbd->db)
                                    persist_deactivate_client_invoice(cbd->db, htlc_hash);
                                have_preimage = 1;
                                break;
                            }
                        }
                    }
                    if (!have_preimage) {
                        fprintf(stderr, "Client %u: no preimage for HTLC %llu, failing\n",
                                my_index, (unsigned long long)htlc_id);
                        break;
                    }
                    printf("Client %u: fulfilling HTLC %llu with real preimage\n",
                           my_index, (unsigned long long)htlc_id);
                    client_fulfill_payment(fd, ch, htlc_id, preimage);

                    /* Handle COMMITMENT_SIGNED for the fulfill */
                    if (wire_recv(fd, &msg) && msg.msg_type == MSG_COMMITMENT_SIGNED) {
                        client_handle_commitment_signed(fd, ch, ctx, &msg);
                    }
                    if (msg.json) cJSON_Delete(msg.json);

                    /* Persist balance after fulfill */
                    if (cbd && cbd->db) {
                        persist_update_channel_balance(cbd->db, my_index - 1,
                            ch->local_amount, ch->remote_amount, ch->commitment_number);
                    }
                }
            }
            break;

        case MSG_COMMITMENT_SIGNED:
            client_handle_commitment_signed(fd, ch, ctx, &msg);
            cJSON_Delete(msg.json);
            /* Persist balance after commitment update */
            if (cbd && cbd->db) {
                persist_update_channel_balance(cbd->db, my_index - 1,
                    ch->local_amount, ch->remote_amount, ch->commitment_number);
            }
            break;

        case MSG_UPDATE_FULFILL_HTLC:
            printf("Client %u: payment fulfilled!\n", my_index);
            cJSON_Delete(msg.json);
            /* Handle follow-up COMMITMENT_SIGNED */
            if (wire_recv(fd, &msg) && msg.msg_type == MSG_COMMITMENT_SIGNED) {
                client_handle_commitment_signed(fd, ch, ctx, &msg);
            }
            if (msg.json) cJSON_Delete(msg.json);
            /* Persist balance after fulfill */
            if (cbd && cbd->db) {
                persist_update_channel_balance(cbd->db, my_index - 1,
                    ch->local_amount, ch->remote_amount, ch->commitment_number);
            }
            break;

        case MSG_CLOSE_PROPOSE:
            printf("Client %u: received CLOSE_PROPOSE in daemon mode\n", my_index);
            client_do_close_ceremony(fd, ctx, keypair, &my_pubkey,
                                      factory, n_participants, &msg);
            cJSON_Delete(msg.json);
            return 2;  /* close already handled */

        case MSG_CREATE_INVOICE: {
            /* LSP asks us to create an invoice (Phase 17) */
            uint64_t inv_amount_msat;
            if (!wire_parse_create_invoice(msg.json, &inv_amount_msat)) {
                fprintf(stderr, "Client %u: bad CREATE_INVOICE\n", my_index);
                cJSON_Delete(msg.json);
                break;
            }
            cJSON_Delete(msg.json);

            if (cbd && cbd->n_invoices < MAX_CLIENT_INVOICES) {
                client_invoice_t *inv = &cbd->invoices[cbd->n_invoices];

                /* Generate random preimage from /dev/urandom */
                FILE *urand = fopen("/dev/urandom", "rb");
                if (urand) {
                    if (fread(inv->preimage, 1, 32, urand) != 32)
                        memset(inv->preimage, 0x42, 32); /* fallback */
                    fclose(urand);
                } else {
                    /* Deterministic fallback: derive from index */
                    memset(inv->preimage, 0x42, 32);
                    inv->preimage[0] = (unsigned char)cbd->n_invoices;
                    inv->preimage[1] = (unsigned char)my_index;
                }

                /* Compute payment_hash = SHA256(preimage) */
                sha256(inv->preimage, 32, inv->payment_hash);
                inv->amount_msat = inv_amount_msat;
                inv->active = 1;
                cbd->n_invoices++;

                /* Persist client invoice (Phase 23) */
                if (cbd->db)
                    persist_save_client_invoice(cbd->db, inv->payment_hash,
                                                inv->preimage, inv_amount_msat);

                printf("Client %u: created invoice for %llu msat\n",
                       my_index, (unsigned long long)inv_amount_msat);

                /* Send MSG_INVOICE_CREATED back to LSP */
                cJSON *reply = wire_build_invoice_created(inv->payment_hash,
                                                            inv_amount_msat);
                wire_send(fd, MSG_INVOICE_CREATED, reply);
                cJSON_Delete(reply);

                /* Also register with LSP so it knows to route to us */
                uint32_t client_idx = my_index - 1;
                cJSON *reg = wire_build_register_invoice(inv->payment_hash,
                                                           inv_amount_msat,
                                                           (size_t)client_idx);
                wire_send(fd, MSG_REGISTER_INVOICE, reg);
                cJSON_Delete(reg);
            }
            break;
        }

        default:
            fprintf(stderr, "Client %u: daemon got unexpected msg 0x%02x\n",
                    my_index, msg.msg_type);
            cJSON_Delete(msg.json);
            break;
        }
    }

    return 1;  /* normal return — caller handles close */
}

/* Wire message log callback (Phase 22) */
static void client_wire_log_cb(int dir, uint8_t type, const cJSON *json,
                                 const char *peer_label, void *ud) {
    persist_log_wire_message((persist_t *)ud, dir, type, peer_label, json);
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
        "  --daemon                          Run as long-lived daemon (auto-fulfill HTLCs)\n"
        "  --fee-rate N                      Fee rate in sat/kvB (default 1000 = 1 sat/vB)\n"
        "  --report PATH                     Write diagnostic JSON report to PATH\n"
        "  --db PATH                         SQLite database for persistence (default: none)\n"
        "  --network MODE                    Network: regtest, signet, testnet, mainnet (default: regtest)\n"
        "  --regtest                         Shorthand for --network regtest\n"
        "  --keyfile PATH                    Load/save secret key from encrypted file\n"
        "  --passphrase PASS                 Passphrase for keyfile (default: empty)\n"
        "  --cli-path PATH                   Path to bitcoin-cli binary (default: bitcoin-cli)\n"
        "  --rpcuser USER                    Bitcoin RPC username (default: rpcuser)\n"
        "  --rpcpassword PASS                Bitcoin RPC password (default: rpcpass)\n"
        "  --help                            Show this help\n",
        prog);
}

int main(int argc, char *argv[]) {
    const char *seckey_hex = NULL;
    int port = 9735;
    const char *host = "127.0.0.1";
    int expect_channels = 0;
    int daemon_mode = 0;
    const char *report_path = NULL;
    const char *db_path = NULL;
    const char *keyfile_path = NULL;
    const char *passphrase = "";

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
        else if (strcmp(argv[i], "--daemon") == 0)
            daemon_mode = 1;
        else if (strcmp(argv[i], "--report") == 0 && i + 1 < argc)
            report_path = argv[++i];
        else if (strcmp(argv[i], "--fee-rate") == 0 && i + 1 < argc)
            ++i; /* parsed but not used by client (fee rate is LSP-managed) */
        else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc)
            db_path = argv[++i];
        else if (strcmp(argv[i], "--network") == 0 && i + 1 < argc)
            ++i; /* parsed but not used by client (network is LSP-managed) */
        else if (strcmp(argv[i], "--regtest") == 0)
            ; /* accepted for backward compat */
        else if (strcmp(argv[i], "--cli-path") == 0 && i + 1 < argc)
            ++i; /* parsed but not used by client (LSP manages chain) */
        else if (strcmp(argv[i], "--rpcuser") == 0 && i + 1 < argc)
            ++i; /* parsed but not used by client (LSP manages chain) */
        else if (strcmp(argv[i], "--rpcpassword") == 0 && i + 1 < argc)
            ++i; /* parsed but not used by client (LSP manages chain) */
        else if (strcmp(argv[i], "--keyfile") == 0 && i + 1 < argc)
            keyfile_path = argv[++i];
        else if (strcmp(argv[i], "--passphrase") == 0 && i + 1 < argc)
            passphrase = argv[++i];
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

    unsigned char seckey[32];
    int key_loaded = 0;

    if (seckey_hex) {
        if (hex_decode(seckey_hex, seckey, 32) != 32) {
            fprintf(stderr, "Invalid seckey hex\n");
            return 1;
        }
        key_loaded = 1;
    } else if (keyfile_path) {
        secp256k1_context *tmp_ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        if (keyfile_load(keyfile_path, seckey, passphrase)) {
            printf("Client: loaded key from %s\n", keyfile_path);
            key_loaded = 1;
        } else {
            printf("Client: generating new key and saving to %s\n", keyfile_path);
            if (keyfile_generate(keyfile_path, seckey, passphrase, tmp_ctx)) {
                key_loaded = 1;
            } else {
                fprintf(stderr, "Error: failed to generate keyfile\n");
                secp256k1_context_destroy(tmp_ctx);
                return 1;
            }
        }
        secp256k1_context_destroy(tmp_ctx);
    }

    if (!key_loaded) {
        usage(argv[0]);
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

        /* Wire message logging (Phase 22) */
        wire_set_log_callback(client_wire_log_cb, &db);
    }

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    int ok;
    if (daemon_mode) {
        daemon_cb_data_t cbd = { use_db ? &db : NULL, 0 };

        /* Load persisted client invoices (Phase 23) */
        if (use_db) {
            unsigned char ci_hashes[MAX_CLIENT_INVOICES][32];
            unsigned char ci_preimages[MAX_CLIENT_INVOICES][32];
            uint64_t ci_amounts[MAX_CLIENT_INVOICES];
            size_t n_ci = persist_load_client_invoices(&db,
                ci_hashes, ci_preimages, ci_amounts, MAX_CLIENT_INVOICES);
            for (size_t i = 0; i < n_ci && cbd.n_invoices < MAX_CLIENT_INVOICES; i++) {
                client_invoice_t *inv = &cbd.invoices[cbd.n_invoices++];
                memcpy(inv->payment_hash, ci_hashes[i], 32);
                memcpy(inv->preimage, ci_preimages[i], 32);
                inv->amount_msat = ci_amounts[i];
                inv->active = 1;
            }
            if (n_ci > 0)
                printf("Client: loaded %zu invoices from DB\n", n_ci);
        }

        int first_run = 1;

        while (!g_shutdown) {
            if (first_run || !use_db) {
                ok = client_run_with_channels(ctx, &kp, host, port,
                                                daemon_channel_cb, &cbd);
                first_run = 0;
            } else {
                printf("Client: reconnecting from persisted state...\n");
                cbd.saved_initial = 1;  /* already saved on first run */
                ok = client_run_reconnect(ctx, &kp, host, port, &db,
                                            daemon_channel_cb, &cbd);
            }
            if (g_shutdown) break;
            if (!ok) {
                fprintf(stderr, "Client: disconnected, retrying in 5s...\n");
                sleep(5);
            } else {
                break;  /* clean exit */
            }
        }
    } else if (n_actions > 0 || expect_channels) {
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
