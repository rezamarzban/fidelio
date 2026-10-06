#include <string.h>
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "se.h"
#include "att_der.h"
#include "hw_sign.h"

/* Verification only (public data): the only software ECDSA in the firmware. */
int hw_verify_raw(const uint8_t pub[64], const uint8_t digest[32], const uint8_t sig_raw[64])
{
    uint8_t der[80];
    ecc_key k;
    int dl, res = 0, ok = -1;

    if ((dl = att_der_sig(sig_raw, der, sizeof(der))) < 0)
        return -1;
    if (wc_ecc_init(&k) != 0)
        return -1;
    if (wc_ecc_import_unsigned(&k, pub, pub + 32, NULL, ECC_SECP256R1) == 0 &&
        wc_ecc_check_key(&k) == 0 &&
        wc_ecc_verify_hash(der, (word32)dl, digest, 32, &res, &k) == 0 && res == 1)
        ok = 0;
    wc_ecc_free(&k);
    return ok;
}

int hw_sign_der(uint8_t slot, const uint8_t pub[64], const uint8_t digest[32],
                uint8_t *sig_der, uint16_t *sig_der_len)
{
    uint8_t raw[64];
    int l;
    if (se_sign(slot, digest, raw) != 0)
        return -1;
    if (hw_verify_raw(pub, digest, raw) != 0)
        return -2;                                   /* chip returned a signature that does not verify */
    if ((l = att_der_sig(raw, sig_der, 80)) < 0)
        return -1;
    *sig_der_len = (uint16_t)l;
    return 0;
}
