#include "superscalar/client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

extern int hex_decode(const char *hex, unsigned char *out, size_t out_len);

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s --seckey HEX --port PORT [--host HOST]\n", prog);
}

int main(int argc, char *argv[]) {
    const char *seckey_hex = NULL;
    int port = 9735;
    const char *host = "127.0.0.1";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--seckey") == 0 && i + 1 < argc)
            seckey_hex = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
            port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--host") == 0 && i + 1 < argc)
            host = argv[++i];
        else if (strcmp(argv[i], "--help") == 0) {
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

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(ctx, &kp, seckey)) {
        fprintf(stderr, "Invalid secret key\n");
        memset(seckey, 0, 32);
        return 1;
    }
    memset(seckey, 0, 32);

    int ok = client_run_ceremony(ctx, &kp, host, port);

    secp256k1_context_destroy(ctx);
    return ok ? 0 : 1;
}
