#include "superscalar/persist.h"
#include "superscalar/wire.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);
extern void reverse_bytes(unsigned char *data, size_t len);

static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS factories ("
    "  id INTEGER PRIMARY KEY,"
    "  n_participants INTEGER NOT NULL,"
    "  funding_txid TEXT,"
    "  funding_vout INTEGER,"
    "  funding_amount INTEGER,"
    "  step_blocks INTEGER,"
    "  states_per_layer INTEGER,"
    "  cltv_timeout INTEGER,"
    "  fee_per_tx INTEGER,"
    "  state TEXT DEFAULT 'active',"
    "  created_at INTEGER DEFAULT (strftime('%%s','now'))"
    ");"
    "CREATE TABLE IF NOT EXISTS factory_participants ("
    "  factory_id INTEGER NOT NULL,"
    "  slot INTEGER NOT NULL,"
    "  pubkey TEXT NOT NULL,"
    "  PRIMARY KEY (factory_id, slot)"
    ");"
    "CREATE TABLE IF NOT EXISTS channels ("
    "  id INTEGER PRIMARY KEY,"
    "  factory_id INTEGER NOT NULL,"
    "  slot INTEGER NOT NULL,"
    "  local_amount INTEGER NOT NULL,"
    "  remote_amount INTEGER NOT NULL,"
    "  funding_amount INTEGER NOT NULL,"
    "  commitment_number INTEGER DEFAULT 0,"
    "  funding_txid TEXT,"
    "  funding_vout INTEGER,"
    "  state TEXT DEFAULT 'open'"
    ");"
    "CREATE TABLE IF NOT EXISTS revocation_secrets ("
    "  channel_id INTEGER NOT NULL,"
    "  commit_num INTEGER NOT NULL,"
    "  secret TEXT NOT NULL,"
    "  PRIMARY KEY (channel_id, commit_num)"
    ");"
    "CREATE TABLE IF NOT EXISTS htlcs ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  channel_id INTEGER NOT NULL,"
    "  htlc_id INTEGER NOT NULL,"
    "  direction TEXT NOT NULL,"
    "  amount INTEGER NOT NULL,"
    "  payment_hash TEXT NOT NULL,"
    "  payment_preimage TEXT,"
    "  cltv_expiry INTEGER,"
    "  state TEXT NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS nonce_pools ("
    "  channel_id INTEGER NOT NULL,"
    "  side TEXT NOT NULL,"
    "  pool_data BLOB,"
    "  next_index INTEGER DEFAULT 0,"
    "  PRIMARY KEY (channel_id, side)"
    ");"
    "CREATE TABLE IF NOT EXISTS old_commitments ("
    "  channel_id INTEGER NOT NULL,"
    "  commit_num INTEGER NOT NULL,"
    "  txid TEXT NOT NULL,"
    "  to_local_vout INTEGER NOT NULL,"
    "  to_local_amount INTEGER NOT NULL,"
    "  to_local_spk TEXT NOT NULL,"
    "  PRIMARY KEY (channel_id, commit_num)"
    ");"
    "CREATE TABLE IF NOT EXISTS wire_messages ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  timestamp INTEGER NOT NULL,"
    "  direction TEXT NOT NULL,"
    "  msg_type INTEGER NOT NULL,"
    "  msg_name TEXT NOT NULL,"
    "  peer TEXT,"
    "  payload_summary TEXT"
    ");"
    "CREATE TABLE IF NOT EXISTS tree_nodes ("
    "  factory_id INTEGER NOT NULL,"
    "  node_index INTEGER NOT NULL,"
    "  type TEXT NOT NULL,"
    "  parent_index INTEGER,"
    "  parent_vout INTEGER,"
    "  dw_layer_index INTEGER,"
    "  n_signers INTEGER,"
    "  signer_indices TEXT,"
    "  n_outputs INTEGER,"
    "  output_amounts TEXT,"
    "  nsequence INTEGER,"
    "  input_amount INTEGER,"
    "  txid TEXT,"
    "  is_built INTEGER,"
    "  is_signed INTEGER,"
    "  spending_spk TEXT,"
    "  PRIMARY KEY (factory_id, node_index)"
    ");"
    "CREATE TABLE IF NOT EXISTS ladder_factories ("
    "  factory_id INTEGER PRIMARY KEY,"
    "  state TEXT NOT NULL,"
    "  is_funded INTEGER,"
    "  is_initialized INTEGER,"
    "  n_departed INTEGER DEFAULT 0,"
    "  created_block INTEGER,"
    "  active_blocks INTEGER,"
    "  dying_blocks INTEGER,"
    "  updated_at INTEGER"
    ");";

int persist_open(persist_t *p, const char *path) {
    if (!p) return 0;
    memset(p, 0, sizeof(*p));

    const char *db_path = (path && path[0]) ? path : ":memory:";
    strncpy(p->path, db_path, sizeof(p->path) - 1);

    int rc = sqlite3_open(db_path, &p->db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "persist_open: %s\n", sqlite3_errmsg(p->db));
        sqlite3_close(p->db);
        p->db = NULL;
        return 0;
    }

    /* Enable WAL mode for better concurrent performance */
    sqlite3_exec(p->db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);

    /* Create schema */
    char *errmsg = NULL;
    rc = sqlite3_exec(p->db, SCHEMA_SQL, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "persist_open: schema error: %s\n", errmsg);
        sqlite3_free(errmsg);
        sqlite3_close(p->db);
        p->db = NULL;
        return 0;
    }

    return 1;
}

void persist_close(persist_t *p) {
    if (p && p->db) {
        sqlite3_close(p->db);
        p->db = NULL;
    }
}

/* --- Factory --- */

int persist_save_factory(persist_t *p, const factory_t *f,
                          secp256k1_context *ctx, uint32_t factory_id) {
    if (!p || !p->db || !f || !ctx) return 0;

    /* Encode funding_txid as hex (display order = reversed internal) */
    unsigned char txid_display[32];
    memcpy(txid_display, f->funding_txid, 32);
    /* reverse to display order */
    for (size_t i = 0; i < 16; i++) {
        unsigned char tmp = txid_display[i];
        txid_display[i] = txid_display[31 - i];
        txid_display[31 - i] = tmp;
    }
    char txid_hex[65];
    hex_encode(txid_display, 32, txid_hex);

    const char *sql =
        "INSERT OR REPLACE INTO factories "
        "(id, n_participants, funding_txid, funding_vout, funding_amount, "
        " step_blocks, states_per_layer, cltv_timeout, fee_per_tx) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)factory_id);
    sqlite3_bind_int(stmt, 2, (int)f->n_participants);
    sqlite3_bind_text(stmt, 3, txid_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, (int)f->funding_vout);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)f->funding_amount_sats);
    sqlite3_bind_int(stmt, 6, (int)f->step_blocks);
    sqlite3_bind_int(stmt, 7, (int)f->states_per_layer);
    sqlite3_bind_int(stmt, 8, (int)f->cltv_timeout);
    sqlite3_bind_int64(stmt, 9, (sqlite3_int64)f->fee_per_tx);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    if (!ok) return 0;

    /* Save participants */
    const char *pk_sql =
        "INSERT OR REPLACE INTO factory_participants (factory_id, slot, pubkey) "
        "VALUES (?, ?, ?);";

    for (size_t i = 0; i < f->n_participants; i++) {
        sqlite3_stmt *pk_stmt;
        if (sqlite3_prepare_v2(p->db, pk_sql, -1, &pk_stmt, NULL) != SQLITE_OK)
            return 0;

        unsigned char pk_ser[33];
        size_t pk_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, pk_ser, &pk_len, &f->pubkeys[i],
                                       SECP256K1_EC_COMPRESSED);
        char pk_hex[67];
        hex_encode(pk_ser, 33, pk_hex);

        sqlite3_bind_int(pk_stmt, 1, (int)factory_id);
        sqlite3_bind_int(pk_stmt, 2, (int)i);
        sqlite3_bind_text(pk_stmt, 3, pk_hex, -1, SQLITE_TRANSIENT);

        ok = (sqlite3_step(pk_stmt) == SQLITE_DONE);
        sqlite3_finalize(pk_stmt);
        if (!ok) return 0;
    }

    return 1;
}

int persist_load_factory(persist_t *p, uint32_t factory_id,
                          factory_t *f, secp256k1_context *ctx) {
    if (!p || !p->db || !f || !ctx) return 0;

    const char *sql =
        "SELECT n_participants, funding_txid, funding_vout, funding_amount, "
        "step_blocks, states_per_layer, cltv_timeout, fee_per_tx "
        "FROM factories WHERE id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)factory_id);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return 0;
    }

    size_t n_participants = (size_t)sqlite3_column_int(stmt, 0);
    const char *txid_hex = (const char *)sqlite3_column_text(stmt, 1);
    uint32_t funding_vout = (uint32_t)sqlite3_column_int(stmt, 2);
    uint64_t funding_amount = (uint64_t)sqlite3_column_int64(stmt, 3);
    uint16_t step_blocks = (uint16_t)sqlite3_column_int(stmt, 4);
    uint32_t states_per_layer = (uint32_t)sqlite3_column_int(stmt, 5);
    uint32_t cltv_timeout = (uint32_t)sqlite3_column_int(stmt, 6);
    uint64_t fee_per_tx = (uint64_t)sqlite3_column_int64(stmt, 7);

    unsigned char funding_txid[32];
    if (txid_hex)
        hex_decode(txid_hex, funding_txid, 32);
    else
        memset(funding_txid, 0, 32);

    /* Reverse from display to internal order */
    for (size_t i = 0; i < 16; i++) {
        unsigned char tmp = funding_txid[i];
        funding_txid[i] = funding_txid[31 - i];
        funding_txid[31 - i] = tmp;
    }

    sqlite3_finalize(stmt);

    /* Load participants */
    const char *pk_sql =
        "SELECT slot, pubkey FROM factory_participants "
        "WHERE factory_id = ? ORDER BY slot;";

    sqlite3_stmt *pk_stmt;
    if (sqlite3_prepare_v2(p->db, pk_sql, -1, &pk_stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(pk_stmt, 1, (int)factory_id);

    secp256k1_pubkey pubkeys[FACTORY_MAX_SIGNERS];
    size_t pk_count = 0;
    while (sqlite3_step(pk_stmt) == SQLITE_ROW && pk_count < FACTORY_MAX_SIGNERS) {
        const char *pk_hex = (const char *)sqlite3_column_text(pk_stmt, 1);
        if (!pk_hex) continue;
        unsigned char pk_ser[33];
        if (hex_decode(pk_hex, pk_ser, 33) != 33) continue;
        if (!secp256k1_ec_pubkey_parse(ctx, &pubkeys[pk_count], pk_ser, 33))
            continue;
        pk_count++;
    }
    sqlite3_finalize(pk_stmt);

    if (pk_count != n_participants) return 0;

    /* Compute funding SPK from aggregate key of all participants */
    extern void sha256_tagged(const char *, const unsigned char *, size_t,
                               unsigned char *);
    musig_keyagg_t ka;
    if (!musig_aggregate_keys(ctx, &ka, pubkeys, n_participants))
        return 0;

    unsigned char internal_ser[32];
    secp256k1_xonly_pubkey_serialize(ctx, internal_ser, &ka.agg_pubkey);
    unsigned char twk[32];
    sha256_tagged("TapTweak", internal_ser, 32, twk);

    musig_keyagg_t ka_copy = ka;
    secp256k1_pubkey tweaked_pk;
    if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked_pk,
                                                   &ka_copy.cache, twk))
        return 0;
    secp256k1_xonly_pubkey tweaked_xonly;
    secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly, NULL, &tweaked_pk);

    unsigned char fund_spk[34];
    build_p2tr_script_pubkey(fund_spk, &tweaked_xonly);

    /* Reconstruct factory */
    factory_init_from_pubkeys(f, ctx, pubkeys, n_participants,
                               step_blocks, states_per_layer);
    f->cltv_timeout = cltv_timeout;
    f->fee_per_tx = fee_per_tx;

    factory_set_funding(f, funding_txid, funding_vout, funding_amount,
                         fund_spk, 34);

    if (!factory_build_tree(f))
        return 0;

    return 1;
}

/* --- Channel --- */

int persist_save_channel(persist_t *p, const channel_t *ch,
                          uint32_t factory_id, uint32_t slot) {
    if (!p || !p->db || !ch) return 0;

    /* Encode funding txid as display hex */
    unsigned char txid_display[32];
    memcpy(txid_display, ch->funding_txid, 32);
    for (size_t i = 0; i < 16; i++) {
        unsigned char tmp = txid_display[i];
        txid_display[i] = txid_display[31 - i];
        txid_display[31 - i] = tmp;
    }
    char txid_hex[65];
    hex_encode(txid_display, 32, txid_hex);

    const char *sql =
        "INSERT OR REPLACE INTO channels "
        "(id, factory_id, slot, local_amount, remote_amount, funding_amount, "
        " commitment_number, funding_txid, funding_vout, state) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open');";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)slot);  /* channel_id = slot */
    sqlite3_bind_int(stmt, 2, (int)factory_id);
    sqlite3_bind_int(stmt, 3, (int)slot);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)ch->local_amount);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)ch->remote_amount);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)ch->funding_amount);
    sqlite3_bind_int64(stmt, 7, (sqlite3_int64)ch->commitment_number);
    sqlite3_bind_text(stmt, 8, txid_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 9, (int)ch->funding_vout);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

int persist_load_channel_state(persist_t *p, uint32_t channel_id,
                                 uint64_t *local_amount,
                                 uint64_t *remote_amount,
                                 uint64_t *commitment_number) {
    if (!p || !p->db) return 0;

    const char *sql =
        "SELECT local_amount, remote_amount, commitment_number "
        "FROM channels WHERE id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return 0;
    }

    if (local_amount)
        *local_amount = (uint64_t)sqlite3_column_int64(stmt, 0);
    if (remote_amount)
        *remote_amount = (uint64_t)sqlite3_column_int64(stmt, 1);
    if (commitment_number)
        *commitment_number = (uint64_t)sqlite3_column_int64(stmt, 2);

    sqlite3_finalize(stmt);
    return 1;
}

int persist_update_channel_balance(persist_t *p, uint32_t channel_id,
                                     uint64_t local_amount,
                                     uint64_t remote_amount,
                                     uint64_t commitment_number) {
    if (!p || !p->db) return 0;

    const char *sql =
        "UPDATE channels SET local_amount = ?, remote_amount = ?, "
        "commitment_number = ? WHERE id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)local_amount);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)remote_amount);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)commitment_number);
    sqlite3_bind_int(stmt, 4, (int)channel_id);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

/* --- Revocation secrets --- */

int persist_save_revocation(persist_t *p, uint32_t channel_id,
                              uint64_t commitment_number,
                              const unsigned char *secret32) {
    if (!p || !p->db || !secret32) return 0;

    char secret_hex[65];
    hex_encode(secret32, 32, secret_hex);

    const char *sql =
        "INSERT OR REPLACE INTO revocation_secrets "
        "(channel_id, commit_num, secret) VALUES (?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)commitment_number);
    sqlite3_bind_text(stmt, 3, secret_hex, -1, SQLITE_TRANSIENT);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

int persist_load_revocations(persist_t *p, uint32_t channel_id,
                               shachain_t *chain) {
    if (!p || !p->db || !chain) return 0;

    shachain_init(chain);

    const char *sql =
        "SELECT commit_num, secret FROM revocation_secrets "
        "WHERE channel_id = ? ORDER BY commit_num ASC;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        uint64_t commit_num = (uint64_t)sqlite3_column_int64(stmt, 0);
        const char *hex = (const char *)sqlite3_column_text(stmt, 1);
        if (!hex) continue;

        unsigned char secret[32];
        if (hex_decode(hex, secret, 32) != 32) continue;

        uint64_t index = ((UINT64_C(1) << 48) - 1) - commit_num;
        shachain_insert(chain, index, secret);
        count++;
    }

    sqlite3_finalize(stmt);
    return 1;
}

/* --- HTLC --- */

int persist_save_htlc(persist_t *p, uint32_t channel_id,
                        const htlc_t *htlc) {
    if (!p || !p->db || !htlc) return 0;

    char hash_hex[65], preimage_hex[65];
    hex_encode(htlc->payment_hash, 32, hash_hex);
    hex_encode(htlc->payment_preimage, 32, preimage_hex);

    const char *direction_str = (htlc->direction == HTLC_OFFERED) ? "offered" : "received";
    const char *state_str;
    switch (htlc->state) {
        case HTLC_STATE_ACTIVE:    state_str = "active"; break;
        case HTLC_STATE_FULFILLED: state_str = "fulfilled"; break;
        case HTLC_STATE_FAILED:    state_str = "failed"; break;
        default:                   state_str = "unknown"; break;
    }

    const char *sql =
        "INSERT OR REPLACE INTO htlcs "
        "(channel_id, htlc_id, direction, amount, payment_hash, "
        " payment_preimage, cltv_expiry, state) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)htlc->id);
    sqlite3_bind_text(stmt, 3, direction_str, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)htlc->amount_sats);
    sqlite3_bind_text(stmt, 5, hash_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, preimage_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 7, (int)htlc->cltv_expiry);
    sqlite3_bind_text(stmt, 8, state_str, -1, SQLITE_STATIC);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

size_t persist_load_htlcs(persist_t *p, uint32_t channel_id,
                            htlc_t *htlcs_out, size_t max_htlcs) {
    if (!p || !p->db || !htlcs_out) return 0;

    const char *sql =
        "SELECT htlc_id, direction, amount, payment_hash, "
        "payment_preimage, cltv_expiry, state "
        "FROM htlcs WHERE channel_id = ? ORDER BY htlc_id;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);

    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_htlcs) {
        htlc_t *h = &htlcs_out[count];
        memset(h, 0, sizeof(*h));

        h->id = (uint64_t)sqlite3_column_int64(stmt, 0);

        const char *dir = (const char *)sqlite3_column_text(stmt, 1);
        h->direction = (dir && strcmp(dir, "offered") == 0)
                       ? HTLC_OFFERED : HTLC_RECEIVED;

        h->amount_sats = (uint64_t)sqlite3_column_int64(stmt, 2);

        const char *hash_hex = (const char *)sqlite3_column_text(stmt, 3);
        if (hash_hex)
            hex_decode(hash_hex, h->payment_hash, 32);

        const char *preimage_hex = (const char *)sqlite3_column_text(stmt, 4);
        if (preimage_hex)
            hex_decode(preimage_hex, h->payment_preimage, 32);

        h->cltv_expiry = (uint32_t)sqlite3_column_int(stmt, 5);

        const char *state = (const char *)sqlite3_column_text(stmt, 6);
        if (state && strcmp(state, "fulfilled") == 0)
            h->state = HTLC_STATE_FULFILLED;
        else if (state && strcmp(state, "failed") == 0)
            h->state = HTLC_STATE_FAILED;
        else
            h->state = HTLC_STATE_ACTIVE;

        count++;
    }

    sqlite3_finalize(stmt);
    return count;
}

/* --- Nonce pool --- */

int persist_save_nonce_pool(persist_t *p, uint32_t channel_id,
                              const char *side,
                              const unsigned char *pool_data,
                              size_t pool_data_len,
                              size_t next_index) {
    if (!p || !p->db || !side) return 0;

    const char *sql =
        "INSERT OR REPLACE INTO nonce_pools "
        "(channel_id, side, pool_data, next_index) VALUES (?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);
    sqlite3_bind_text(stmt, 2, side, -1, SQLITE_STATIC);
    if (pool_data && pool_data_len > 0)
        sqlite3_bind_blob(stmt, 3, pool_data, (int)pool_data_len, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(stmt, 3);
    sqlite3_bind_int(stmt, 4, (int)next_index);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

int persist_load_nonce_pool(persist_t *p, uint32_t channel_id,
                              const char *side,
                              unsigned char *pool_data_out,
                              size_t max_len,
                              size_t *data_len_out,
                              size_t *next_index_out) {
    if (!p || !p->db || !side) return 0;

    const char *sql =
        "SELECT pool_data, next_index FROM nonce_pools "
        "WHERE channel_id = ? AND side = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);
    sqlite3_bind_text(stmt, 2, side, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return 0;
    }

    const void *blob = sqlite3_column_blob(stmt, 0);
    int blob_len = sqlite3_column_bytes(stmt, 0);
    size_t copy_len = (size_t)blob_len < max_len ? (size_t)blob_len : max_len;

    if (pool_data_out && blob && copy_len > 0)
        memcpy(pool_data_out, blob, copy_len);
    if (data_len_out)
        *data_len_out = copy_len;
    if (next_index_out)
        *next_index_out = (size_t)sqlite3_column_int(stmt, 1);

    sqlite3_finalize(stmt);
    return 1;
}

/* --- Old commitments (watchtower) --- */

int persist_save_old_commitment(persist_t *p, uint32_t channel_id,
                                  uint64_t commit_num,
                                  const unsigned char *txid32,
                                  uint32_t to_local_vout,
                                  uint64_t to_local_amount,
                                  const unsigned char *to_local_spk,
                                  size_t spk_len) {
    if (!p || !p->db || !txid32 || !to_local_spk) return 0;

    char txid_hex[65], spk_hex[69];
    hex_encode(txid32, 32, txid_hex);
    hex_encode(to_local_spk, spk_len, spk_hex);

    const char *sql =
        "INSERT OR REPLACE INTO old_commitments "
        "(channel_id, commit_num, txid, to_local_vout, to_local_amount, to_local_spk) "
        "VALUES (?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)commit_num);
    sqlite3_bind_text(stmt, 3, txid_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, (int)to_local_vout);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)to_local_amount);
    sqlite3_bind_text(stmt, 6, spk_hex, -1, SQLITE_TRANSIENT);

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}

size_t persist_load_old_commitments(persist_t *p, uint32_t channel_id,
                                      uint64_t *commit_nums,
                                      unsigned char (*txids)[32],
                                      uint32_t *vouts,
                                      uint64_t *amounts,
                                      unsigned char (*spks)[34],
                                      size_t *spk_lens,
                                      size_t max_entries) {
    if (!p || !p->db) return 0;

    const char *sql =
        "SELECT commit_num, txid, to_local_vout, to_local_amount, to_local_spk "
        "FROM old_commitments WHERE channel_id = ? ORDER BY commit_num ASC;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)channel_id);

    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_entries) {
        if (commit_nums)
            commit_nums[count] = (uint64_t)sqlite3_column_int64(stmt, 0);

        const char *txid_hex = (const char *)sqlite3_column_text(stmt, 1);
        if (txid_hex && txids)
            hex_decode(txid_hex, txids[count], 32);

        if (vouts)
            vouts[count] = (uint32_t)sqlite3_column_int(stmt, 2);

        if (amounts)
            amounts[count] = (uint64_t)sqlite3_column_int64(stmt, 3);

        const char *spk_hex_str = (const char *)sqlite3_column_text(stmt, 4);
        if (spk_hex_str && spks && spk_lens) {
            int decoded = hex_decode(spk_hex_str, spks[count], 34);
            spk_lens[count] = decoded > 0 ? (size_t)decoded : 0;
        }

        count++;
    }

    sqlite3_finalize(stmt);
    return count;
}

/* --- Wire message logging (Phase 22) --- */

void persist_log_wire_message(persist_t *p, int direction, uint8_t msg_type,
                               const char *peer_label, const void *json) {
    if (!p || !p->db) return;

    const char *dir_str = direction ? "recv" : "sent";
    const char *msg_name = wire_msg_type_name(msg_type);

    /* Truncated payload summary */
    char summary[501];
    summary[0] = '\0';
    if (json) {
        char *printed = cJSON_PrintUnformatted((cJSON *)json);
        if (printed) {
            size_t len = strlen(printed);
            if (len > 500) len = 500;
            memcpy(summary, printed, len);
            summary[len] = '\0';
            free(printed);
        }
    }

    const char *sql =
        "INSERT INTO wire_messages "
        "(timestamp, direction, msg_type, msg_name, peer, payload_summary) "
        "VALUES (?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return;

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)time(NULL));
    sqlite3_bind_text(stmt, 2, dir_str, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, (int)msg_type);
    sqlite3_bind_text(stmt, 4, msg_name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, peer_label ? peer_label : "unknown", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, summary, -1, SQLITE_TRANSIENT);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

/* --- Factory tree nodes (Phase 22) --- */

int persist_save_tree_nodes(persist_t *p, const factory_t *f, uint32_t factory_id) {
    if (!p || !p->db || !f) return 0;

    const char *sql =
        "INSERT OR REPLACE INTO tree_nodes "
        "(factory_id, node_index, type, parent_index, parent_vout, "
        " dw_layer_index, n_signers, signer_indices, n_outputs, output_amounts, "
        " nsequence, input_amount, txid, is_built, is_signed, spending_spk) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    for (size_t i = 0; i < f->n_nodes; i++) {
        const factory_node_t *node = &f->nodes[i];

        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
            return 0;

        sqlite3_bind_int(stmt, 1, (int)factory_id);
        sqlite3_bind_int(stmt, 2, (int)i);
        sqlite3_bind_text(stmt, 3, node->type == NODE_KICKOFF ? "kickoff" : "state",
                          -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 4, node->parent_index);
        sqlite3_bind_int(stmt, 5, (int)node->parent_vout);
        sqlite3_bind_int(stmt, 6, node->dw_layer_index);
        sqlite3_bind_int(stmt, 7, (int)node->n_signers);

        /* signer_indices as comma-separated */
        char signers_buf[128];
        signers_buf[0] = '\0';
        for (size_t s = 0; s < node->n_signers; s++) {
            char tmp[16];
            snprintf(tmp, sizeof(tmp), "%s%u", s > 0 ? "," : "",
                     node->signer_indices[s]);
            strncat(signers_buf, tmp, sizeof(signers_buf) - strlen(signers_buf) - 1);
        }
        sqlite3_bind_text(stmt, 8, signers_buf, -1, SQLITE_TRANSIENT);

        sqlite3_bind_int(stmt, 9, (int)node->n_outputs);

        /* output_amounts as comma-separated sats */
        char amounts_buf[256];
        amounts_buf[0] = '\0';
        for (size_t o = 0; o < node->n_outputs; o++) {
            char tmp[32];
            snprintf(tmp, sizeof(tmp), "%s%llu", o > 0 ? "," : "",
                     (unsigned long long)node->outputs[o].amount_sats);
            strncat(amounts_buf, tmp, sizeof(amounts_buf) - strlen(amounts_buf) - 1);
        }
        sqlite3_bind_text(stmt, 10, amounts_buf, -1, SQLITE_TRANSIENT);

        sqlite3_bind_int64(stmt, 11, (sqlite3_int64)node->nsequence);
        sqlite3_bind_int64(stmt, 12, (sqlite3_int64)node->input_amount);

        /* txid in display order */
        if (node->is_built) {
            unsigned char display_txid[32];
            memcpy(display_txid, node->txid, 32);
            reverse_bytes(display_txid, 32);
            char txid_hex[65];
            hex_encode(display_txid, 32, txid_hex);
            sqlite3_bind_text(stmt, 13, txid_hex, -1, SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_null(stmt, 13);
        }

        sqlite3_bind_int(stmt, 14, node->is_built);
        sqlite3_bind_int(stmt, 15, node->is_signed);

        /* spending_spk as hex */
        if (node->spending_spk_len > 0) {
            char spk_hex[69];
            hex_encode(node->spending_spk, node->spending_spk_len, spk_hex);
            sqlite3_bind_text(stmt, 16, spk_hex, -1, SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_null(stmt, 16);
        }

        int ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
        if (!ok) return 0;
    }

    return 1;
}

/* --- Ladder factory state (Phase 22) --- */

int persist_save_ladder_factory(persist_t *p, uint32_t factory_id,
                                 const char *state_str,
                                 int is_funded, int is_initialized,
                                 size_t n_departed,
                                 uint32_t created_block,
                                 uint32_t active_blocks,
                                 uint32_t dying_blocks) {
    if (!p || !p->db) return 0;

    const char *sql =
        "INSERT OR REPLACE INTO ladder_factories "
        "(factory_id, state, is_funded, is_initialized, n_departed, "
        " created_block, active_blocks, dying_blocks, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(p->db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 0;

    sqlite3_bind_int(stmt, 1, (int)factory_id);
    sqlite3_bind_text(stmt, 2, state_str ? state_str : "active", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, is_funded);
    sqlite3_bind_int(stmt, 4, is_initialized);
    sqlite3_bind_int(stmt, 5, (int)n_departed);
    sqlite3_bind_int(stmt, 6, (int)created_block);
    sqlite3_bind_int(stmt, 7, (int)active_blocks);
    sqlite3_bind_int(stmt, 8, (int)dying_blocks);
    sqlite3_bind_int64(stmt, 9, (sqlite3_int64)time(NULL));

    int ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}
