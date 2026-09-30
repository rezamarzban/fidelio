/* Host-test stub for wolfssl/wolfcrypt/ecc.h */
#ifndef STUB_WOLFSSL_ECC_H
#define STUB_WOLFSSL_ECC_H
#include "settings.h"

#define ECC_SECP256R1 1

typedef struct ecc_key { int dummy[4]; } ecc_key;
int wc_ecc_init(ecc_key *key);
int wc_ecc_free(ecc_key *key);
int wc_ecc_check_key(ecc_key *key);
int wc_ecc_import_private_key_ex(const byte *priv, word32 privSz,
                                 const byte *pq, word32 pqSz,
                                 ecc_key *key, int curve);
int wc_ecc_make_pub_ex(ecc_key *key, byte *x, byte *y);
int wc_ecc_export_public_raw(ecc_key *key, byte *x, word32 *xLen,
                             byte *y, word32 *yLen);
word32 wc_ecc_sig_size(ecc_key *key);
int wc_ecc_sign_hash(const byte *in, word32 inLen, byte *out,
                     word32 *outLen, WC_RNG *rng, ecc_key *key);

#endif
