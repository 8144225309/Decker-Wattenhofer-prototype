#include "superscalar/regtest.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void hex_encode(const unsigned char *data, size_t len, char *out);
extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);

static char *run_command(const char *cmd) {
    FILE *fp = popen(cmd, "r");
    if (!fp) return NULL;

    size_t cap = 4096;
    size_t len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) { pclose(fp); return NULL; }

    while (1) {
        size_t n = fread(buf + len, 1, cap - len - 1, fp);
        if (n == 0) break;
        len += n;
        if (len >= cap - 1) {
            cap *= 2;
            buf = (char *)realloc(buf, cap);
            if (!buf) { pclose(fp); return NULL; }
        }
    }
    buf[len] = '\0';

    pclose(fp);
    return buf;
}

static void build_cli_prefix(const regtest_t *rt, char *buf, size_t buf_len) {
    snprintf(buf, buf_len,
        "%s -regtest -rpcuser=%s -rpcpassword=%s",
        rt->cli_path, rt->rpcuser, rt->rpcpassword);

    if (rt->wallet[0] != '\0') {
        size_t cur = strlen(buf);
        snprintf(buf + cur, buf_len - cur, " -rpcwallet=%s", rt->wallet);
    }
}

int regtest_init(regtest_t *rt) {
    memset(rt, 0, sizeof(*rt));
    strncpy(rt->cli_path, "bitcoin-cli", sizeof(rt->cli_path) - 1);
    strncpy(rt->rpcuser, "rpcuser", sizeof(rt->rpcuser) - 1);
    strncpy(rt->rpcpassword, "rpcpass", sizeof(rt->rpcpassword) - 1);

    char *result = run_command("bitcoin-cli -regtest -rpcuser=rpcuser -rpcpassword=rpcpass getblockchaininfo 2>&1");
    if (!result) return 0;

    int ok = (strstr(result, "\"chain\"") != NULL);
    free(result);
    return ok ? 1 : 0;
}

char *regtest_exec(const regtest_t *rt, const char *method, const char *params) {
    char prefix[512];
    build_cli_prefix(rt, prefix, sizeof(prefix));

    char cmd[2048];
    if (params && params[0] != '\0') {
        snprintf(cmd, sizeof(cmd), "%s %s %s 2>&1", prefix, method, params);
    } else {
        snprintf(cmd, sizeof(cmd), "%s %s 2>&1", prefix, method);
    }

    return run_command(cmd);
}

int regtest_create_wallet(regtest_t *rt, const char *name) {
    char params[256];
    snprintf(params, sizeof(params), "\"%s\"", name);
    char *result = regtest_exec(rt, "createwallet", params);
    if (!result) return 0;

    if (strstr(result, "error") != NULL && strstr(result, "already exists") == NULL) {
        free(result);
        result = regtest_exec(rt, "loadwallet", params);
        if (!result) return 0;
    }

    free(result);
    strncpy(rt->wallet, name, sizeof(rt->wallet) - 1);
    return 1;
}

int regtest_get_new_address(regtest_t *rt, char *addr_out, size_t len) {
    char *result = regtest_exec(rt, "getnewaddress", "\"\" bech32m");
    if (!result) return 0;

    char *start = result;
    while (*start == '"' || *start == ' ' || *start == '\n') start++;
    char *end = start + strlen(start) - 1;
    while (end > start && (*end == '"' || *end == '\n' || *end == '\r' || *end == ' ')) {
        *end = '\0';
        end--;
    }

    if (strlen(start) == 0 || strlen(start) >= len) {
        free(result);
        return 0;
    }

    strncpy(addr_out, start, len - 1);
    addr_out[len - 1] = '\0';
    free(result);
    return 1;
}

int regtest_mine_blocks(regtest_t *rt, int n, const char *address) {
    char params[512];
    snprintf(params, sizeof(params), "%d \"%s\"", n, address);
    char *result = regtest_exec(rt, "generatetoaddress", params);
    if (!result) return 0;

    int ok = (result[0] == '[');
    free(result);
    return ok;
}

int regtest_fund_address(regtest_t *rt, const char *address,
                         double btc_amount, char *txid_out) {
    char params[512];
    snprintf(params, sizeof(params), "\"%s\" %.8f", address, btc_amount);
    char *result = regtest_exec(rt, "sendtoaddress", params);
    if (!result) return 0;

    char *start = result;
    while (*start == '"' || *start == ' ' || *start == '\n') start++;
    char *end = start + strlen(start) - 1;
    while (end > start && (*end == '"' || *end == '\n' || *end == '\r' || *end == ' ')) {
        *end = '\0';
        end--;
    }

    if (strlen(start) != 64) {
        free(result);
        return 0;
    }

    if (txid_out)
        strncpy(txid_out, start, 65);
    free(result);
    return 1;
}

int regtest_send_raw_tx(regtest_t *rt, const char *tx_hex, char *txid_out) {
    char *params = (char *)malloc(strlen(tx_hex) + 4);
    if (!params) return 0;
    snprintf(params, strlen(tx_hex) + 4, "\"%s\"", tx_hex);

    char *result = regtest_exec(rt, "sendrawtransaction", params);
    free(params);
    if (!result) return 0;

    if (strstr(result, "error") != NULL) {
        fprintf(stderr, "sendrawtransaction error: %s\n", result);
        free(result);
        return 0;
    }

    char *start = result;
    while (*start == '"' || *start == ' ' || *start == '\n') start++;
    char *end = start + strlen(start) - 1;
    while (end > start && (*end == '"' || *end == '\n' || *end == '\r' || *end == ' ')) {
        *end = '\0';
        end--;
    }

    if (strlen(start) != 64) {
        free(result);
        return 0;
    }

    if (txid_out)
        strncpy(txid_out, start, 65);
    free(result);
    return 1;
}

int regtest_get_confirmations(regtest_t *rt, const char *txid) {
    char params[256];

    /* Try gettransaction (wallet txs) */
    snprintf(params, sizeof(params), "\"%s\" true", txid);
    char *result = regtest_exec(rt, "gettransaction", params);
    if (result) {
        cJSON *json = cJSON_Parse(result);
        free(result);
        if (json) {
            cJSON *conf = cJSON_GetObjectItem(json, "confirmations");
            if (conf && cJSON_IsNumber(conf)) {
                int val = conf->valueint;
                cJSON_Delete(json);
                return val;
            }
            cJSON_Delete(json);
        }
    }

    /* Fallback: scan recent blocks with getrawtransaction + blockhash */
    result = regtest_exec(rt, "getblockcount", "");
    if (!result) return -1;
    int height = atoi(result);
    free(result);

    for (int i = 0; i < 20 && i <= height; i++) {
        snprintf(params, sizeof(params), "%d", height - i);
        char *hash_result = regtest_exec(rt, "getblockhash", params);
        if (!hash_result) continue;

        /* Trim whitespace */
        char blockhash[65];
        char *s = hash_result;
        while (*s == ' ' || *s == '\n' || *s == '"') s++;
        char *e = s + strlen(s) - 1;
        while (e > s && (*e == ' ' || *e == '\n' || *e == '"' || *e == '\r'))
            *e-- = '\0';
        strncpy(blockhash, s, 64);
        blockhash[64] = '\0';
        free(hash_result);

        snprintf(params, sizeof(params), "\"%s\" true \"%s\"", txid, blockhash);
        char *tx_result = regtest_exec(rt, "getrawtransaction", params);
        if (!tx_result) continue;

        cJSON *json = cJSON_Parse(tx_result);
        free(tx_result);
        if (!json) continue;

        cJSON *conf = cJSON_GetObjectItem(json, "confirmations");
        if (conf && cJSON_IsNumber(conf)) {
            int val = conf->valueint;
            cJSON_Delete(json);
            return val;
        }
        cJSON_Delete(json);
    }

    return -1;
}

bool regtest_is_in_mempool(regtest_t *rt, const char *txid) {
    char params[256];
    snprintf(params, sizeof(params), "\"%s\"", txid);
    char *result = regtest_exec(rt, "getmempoolentry", params);
    if (!result) return false;

    bool in_mempool = (strstr(result, "error") == NULL);
    free(result);
    return in_mempool;
}

/* Parse a vout object from getrawtransaction or gettransaction decoded output. */
static int parse_vout_obj(cJSON *vout_obj,
                           uint64_t *amount_sats_out,
                           unsigned char *scriptpubkey_out, size_t *spk_len_out) {
    cJSON *value = cJSON_GetObjectItem(vout_obj, "value");
    if (value && cJSON_IsNumber(value))
        *amount_sats_out = (uint64_t)(value->valuedouble * 100000000.0 + 0.5);

    cJSON *spk = cJSON_GetObjectItem(vout_obj, "scriptPubKey");
    if (spk) {
        cJSON *hex = cJSON_GetObjectItem(spk, "hex");
        if (hex && cJSON_IsString(hex)) {
            int decoded = hex_decode(hex->valuestring, scriptpubkey_out, 256);
            if (decoded > 0)
                *spk_len_out = (size_t)decoded;
        }
    }
    return 1;
}

int regtest_get_tx_output(regtest_t *rt, const char *txid, uint32_t vout,
                          uint64_t *amount_sats_out,
                          unsigned char *scriptpubkey_out, size_t *spk_len_out) {
    char params[256];
    cJSON *json = NULL;
    cJSON *vouts = NULL;

    /* Try getrawtransaction first (works with -txindex or for mempool txs) */
    snprintf(params, sizeof(params), "\"%s\" true", txid);
    char *result = regtest_exec(rt, "getrawtransaction", params);
    if (result) {
        json = cJSON_Parse(result);
        free(result);
        if (json) {
            vouts = cJSON_GetObjectItem(json, "vout");
            if (vouts && cJSON_IsArray(vouts)) {
                cJSON *vout_obj = cJSON_GetArrayItem(vouts, (int)vout);
                if (vout_obj) {
                    int ok = parse_vout_obj(vout_obj, amount_sats_out,
                                             scriptpubkey_out, spk_len_out);
                    cJSON_Delete(json);
                    return ok;
                }
            }
            cJSON_Delete(json);
            json = NULL;
        }
    }

    /* Fallback: gettransaction with decode (wallet txs, no -txindex needed) */
    snprintf(params, sizeof(params), "\"%s\" true true", txid);
    result = regtest_exec(rt, "gettransaction", params);
    if (result) {
        json = cJSON_Parse(result);
        free(result);
        if (json) {
            cJSON *decoded = cJSON_GetObjectItem(json, "decoded");
            if (decoded) {
                vouts = cJSON_GetObjectItem(decoded, "vout");
                if (vouts && cJSON_IsArray(vouts)) {
                    cJSON *vout_obj = cJSON_GetArrayItem(vouts, (int)vout);
                    if (vout_obj) {
                        int ok = parse_vout_obj(vout_obj, amount_sats_out,
                                                 scriptpubkey_out, spk_len_out);
                        cJSON_Delete(json);
                        return ok;
                    }
                }
            }
            cJSON_Delete(json);
            json = NULL;
        }
    }

    /* Fallback: scan recent blocks with getrawtransaction + blockhash
       (works for non-wallet txs without -txindex) */
    result = regtest_exec(rt, "getblockcount", "");
    if (!result) return 0;
    int height = atoi(result);
    free(result);

    for (int i = 0; i < 20 && i <= height; i++) {
        snprintf(params, sizeof(params), "%d", height - i);
        char *hash_result = regtest_exec(rt, "getblockhash", params);
        if (!hash_result) continue;

        char blockhash[65];
        char *s = hash_result;
        while (*s == ' ' || *s == '\n' || *s == '"') s++;
        char *e = s + strlen(s) - 1;
        while (e > s && (*e == ' ' || *e == '\n' || *e == '"' || *e == '\r'))
            *e-- = '\0';
        strncpy(blockhash, s, 64);
        blockhash[64] = '\0';
        free(hash_result);

        snprintf(params, sizeof(params), "\"%s\" true \"%s\"", txid, blockhash);
        result = regtest_exec(rt, "getrawtransaction", params);
        if (!result) continue;

        json = cJSON_Parse(result);
        free(result);
        if (!json) continue;

        vouts = cJSON_GetObjectItem(json, "vout");
        if (vouts && cJSON_IsArray(vouts)) {
            cJSON *vout_obj = cJSON_GetArrayItem(vouts, (int)vout);
            if (vout_obj) {
                int ok = parse_vout_obj(vout_obj, amount_sats_out,
                                         scriptpubkey_out, spk_len_out);
                cJSON_Delete(json);
                return ok;
            }
        }
        cJSON_Delete(json);
    }

    return 0;
}
