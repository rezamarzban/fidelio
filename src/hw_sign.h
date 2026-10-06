#ifndef HW_SIGN_H
#define HW_SIGN_H
#include <stdint.h>
/* Sign a 32-byte digest INSIDE the secure element and hand back a DER ECDSA signature.
 * The signature is verified with the public key before it is released, so a faulty
 * or glitched signature never leaves the device.  Returns 0 on success. */
int hw_sign_der(uint8_t slot, const uint8_t pub[64], const uint8_t digest[32],
                uint8_t *sig_der, uint16_t *sig_der_len);
/* Verify a raw r||s signature against a public key (public data only; no signing code exists in software). */
int hw_verify_raw(const uint8_t pub[64], const uint8_t digest[32], const uint8_t sig_raw[64]);
#endif
