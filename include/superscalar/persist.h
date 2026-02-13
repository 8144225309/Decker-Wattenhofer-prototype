#ifndef SUPERSCALAR_PERSIST_H
#define SUPERSCALAR_PERSIST_H

#include "channel.h"
#include "factory.h"
#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>

typedef struct {
    sqlite3 *db;
    char path[256];
} persist_t;

/* Open or create database at path. Creates schema if needed.
   Pass NULL or ":memory:" for in-memory database.
   Returns 1 on success, 0 on error. */
int persist_open(persist_t *p, const char *path);

/* Close database. */
void persist_close(persist_t *p);

/* --- Factory persistence --- */

/* Save factory metadata (funding info, participants, step_blocks, etc.).
   factory_id is caller-assigned (typically 0 for single-factory PoC). */
int persist_save_factory(persist_t *p, const factory_t *f,
                          secp256k1_context *ctx, uint32_t factory_id);

/* Load factory metadata. Caller must have initialized f->pubkeys with
   correct keys before calling (used to rebuild the tree).
   Returns 1 on success. */
int persist_load_factory(persist_t *p, uint32_t factory_id,
                          factory_t *f, secp256k1_context *ctx);

/* --- Channel persistence --- */

/* Save channel state (balances, commitment_number, funding info). */
int persist_save_channel(persist_t *p, const channel_t *ch,
                          uint32_t factory_id, uint32_t slot);

/* Load channel core state (balances, commitment_number).
   Channel must already be initialized via channel_init() with the correct
   keys. This overwrites balances and commitment_number. */
int persist_load_channel_state(persist_t *p, uint32_t channel_id,
                                 uint64_t *local_amount,
                                 uint64_t *remote_amount,
                                 uint64_t *commitment_number);

/* Update channel balances after a payment. */
int persist_update_channel_balance(persist_t *p, uint32_t channel_id,
                                     uint64_t local_amount,
                                     uint64_t remote_amount,
                                     uint64_t commitment_number);

/* --- Revocation secrets --- */

/* Save a revocation secret for a given channel and commitment number. */
int persist_save_revocation(persist_t *p, uint32_t channel_id,
                              uint64_t commitment_number,
                              const unsigned char *secret32);

/* Load all revocation secrets for a channel into a shachain. */
int persist_load_revocations(persist_t *p, uint32_t channel_id,
                               shachain_t *chain);

/* --- HTLC persistence --- */

/* Save an HTLC entry. */
int persist_save_htlc(persist_t *p, uint32_t channel_id,
                        const htlc_t *htlc);

/* Load all HTLCs for a channel. Returns count loaded. */
size_t persist_load_htlcs(persist_t *p, uint32_t channel_id,
                            htlc_t *htlcs_out, size_t max_htlcs);

/* --- Nonce pool persistence --- */

/* Save serialized nonce pool state. */
int persist_save_nonce_pool(persist_t *p, uint32_t channel_id,
                              const char *side,
                              const unsigned char *pool_data,
                              size_t pool_data_len,
                              size_t next_index);

/* Load nonce pool state. Returns data in caller-allocated buffer. */
int persist_load_nonce_pool(persist_t *p, uint32_t channel_id,
                              const char *side,
                              unsigned char *pool_data_out,
                              size_t max_len,
                              size_t *data_len_out,
                              size_t *next_index_out);

#endif /* SUPERSCALAR_PERSIST_H */
