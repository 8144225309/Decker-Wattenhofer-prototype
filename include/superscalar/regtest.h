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
    char network[16];  /* "regtest", "signet", "testnet", "mainnet" */
} regtest_t;

int   regtest_init(regtest_t *rt);
int   regtest_init_network(regtest_t *rt, const char *network);
int   regtest_init_full(regtest_t *rt, const char *network,
                        const char *cli_path, const char *rpcuser,
                        const char *rpcpassword);
char *regtest_exec(const regtest_t *rt, const char *method, const char *params);
int   regtest_get_block_height(regtest_t *rt);
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

/* Get wallet balance in BTC. Returns -1.0 on error. */
double regtest_get_balance(regtest_t *rt);

/* Poll for tx confirmation. Returns confirmations count, -1 on timeout. */
int regtest_wait_for_confirmation(regtest_t *rt, const char *txid,
                                    int timeout_secs);

#endif /* SUPERSCALAR_REGTEST_H */
