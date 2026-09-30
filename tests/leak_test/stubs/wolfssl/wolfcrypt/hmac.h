/* Host-test stub for wolfssl/wolfcrypt/hmac.h */
#ifndef STUB_WOLFSSL_HMAC_H
#define STUB_WOLFSSL_HMAC_H
#include "settings.h"

#define SHA256 5

typedef struct Hmac { int dummy; } Hmac;
int wc_HmacInit(Hmac *hmac, void *heap, int id);
int wc_HmacSetKey(Hmac *hmac, int type, const byte *key, word32 keySz);
int wc_HmacUpdate(Hmac *hmac, const byte *in, word32 sz);
int wc_HmacFinal(Hmac *hmac, byte *out);
int wc_HmacFree(Hmac *hmac);

#endif
