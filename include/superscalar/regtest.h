#ifndef SUPERSCALAR_REGTEST_H
#define SUPERSCALAR_REGTEST_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* bitcoin-cli subprocess harness for regtest. */

typedef struct {
    char cli_path[256];
    char datadir[256];
    char rpcuser[64];
    char rpcpassword[64];
    char wallet[64];
} regtest_t;

int   regtest_init(regtest_t *rt);
char *regtest_exec(const regtest_t *rt, const char *method, const char *params);
int   regtest_create_wallet(regtest_t *rt, const char *name);
int   regtest_get_new_address(regtest_t *rt, char *addr_out, size_t len);
int   regtest_mine_blocks(regtest_t *rt, int n, const char *address);
int   regtest_fund_address(regtest_t *rt, const char *address, double btc_amount, char *txid_out);
int   regtest_send_raw_tx(regtest_t *rt, const char *tx_hex, char *txid_out);
int   regtest_get_confirmations(regtest_t *rt, const char *txid);
bool  regtest_is_in_mempool(regtest_t *rt, const char *txid);
int   regtest_get_tx_output(regtest_t *rt, const char *txid, uint32_t vout,
                             uint64_t *amount_sats_out,
                             unsigned char *scriptpubkey_out, size_t *spk_len_out);

/* Get raw tx hex by txid. Returns 1 on success. */
int regtest_get_raw_tx(regtest_t *rt, const char *txid,
                         char *tx_hex_out, size_t max_len);

#endif /* SUPERSCALAR_REGTEST_H */
