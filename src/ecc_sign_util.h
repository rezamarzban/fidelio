#ifndef ECC_SIGN_UTIL_H
#define ECC_SIGN_UTIL_H
/*
 * RFC 6979 deterministic ECDSA in the pinned wolfSSL allocates the per-key
 * nonce (key->sign_k) on the heap for every signature.  On the SP-math path
 * that is used here wolfSSL never frees it, so every signature leaked one
 * mp_int until the heap ran dry and signing started failing (a self-inflicted
 * denial of service; found by running the firmware under AddressSanitizer).
 *
 * Call this after EVERY wc_ecc_sign_hash() on a key that was switched to
 * deterministic mode, success or failure.  It wipes and releases the nonce and
 * is a no-op when wolfSSL has already released it.
 */
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/ecc.h"

static inline void ecc_release_sign_k(ecc_key *key)
{
#ifdef WOLFSSL_ECDSA_DETERMINISTIC_K
    if (key != NULL && key->sign_k != NULL) {
        mp_forcezero(key->sign_k);
        mp_free(key->sign_k);
        XFREE(key->sign_k, key->heap, DYNAMIC_TYPE_ECC);
        key->sign_k = NULL;
    }
#else
    (void)key;
#endif
}
#endif /* ECC_SIGN_UTIL_H */
