/* Host-test stub for wolfssl/wolfcrypt/asn.h */
#ifndef STUB_WOLFSSL_ASN_H
#define STUB_WOLFSSL_ASN_H
#include "ecc.h"
int wc_EccPrivateKeyDecode(const byte *in, word32 *inIdx,
                           ecc_key *key, word32 inSz);
#endif
