/* Host-test stub for wolfssl/wolfcrypt/settings.h.
 * Carries every wolfCrypt type/function u2f.c references so the real
 * src/u2f.c compiles on the host without the wolfSSL tree.
 */
#ifndef STUB_WOLFSSL_SETTINGS_H
#define STUB_WOLFSSL_SETTINGS_H
#include <stdint.h>

typedef unsigned int word32;
typedef uint8_t byte;

typedef struct WC_RNG { int dummy; } WC_RNG;
int wc_InitRng(WC_RNG *rng);
int wc_FreeRng(WC_RNG *rng);
int wc_RNG_GenerateBlock(WC_RNG *rng, byte *out, word32 sz);

typedef struct Sha256 { int dummy; } Sha256;
typedef Sha256 wc_Sha256;
int wc_InitSha256(Sha256 *s);
int wc_Sha256Update(Sha256 *s, const byte *in, word32 sz);
int wc_Sha256Final(Sha256 *s, byte *out);
int wc_Sha256Free(Sha256 *s);

#endif
