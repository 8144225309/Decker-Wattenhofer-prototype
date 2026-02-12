#ifndef SUPERSCALAR_MUSIG_H
#define SUPERSCALAR_MUSIG_H

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_musig.h>

#include <stddef.h>

typedef struct {
    secp256k1_xonly_pubkey agg_pubkey;
    secp256k1_musig_keyagg_cache cache;
} musig_keyagg_t;

/* Aggregate N pubkeys into a single x-only key. */
int musig_aggregate_keys(
    const secp256k1_context *ctx,
    musig_keyagg_t *out,
    const secp256k1_pubkey *pubkeys,
    size_t n_pubkeys
);

/* All-local MuSig2 signing. Produces a 64-byte BIP-340 Schnorr sig. */
int musig_sign_all_local(
    const secp256k1_context *ctx,
    unsigned char *sig64_out,
    const unsigned char *msg32,
    const secp256k1_keypair *keypairs,
    size_t n_signers,
    const musig_keyagg_t *keyagg
);

/* MuSig2 signing with taproot key-path tweak. Modifies keyagg. */
int musig_sign_taproot(
    const secp256k1_context *ctx,
    unsigned char *sig64_out,
    const unsigned char *msg32,
    const secp256k1_keypair *keypairs,
    size_t n_signers,
    musig_keyagg_t *keyagg,
    const unsigned char *merkle_root  /* NULL for keypath-only */
);

#endif /* SUPERSCALAR_MUSIG_H */
