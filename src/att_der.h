#ifndef ATT_DER_H
#define ATT_DER_H
#include <stdint.h>
#include <stddef.h>

/* raw ECDSA r||s (64 bytes) -> DER ECDSA-Sig-Value; returns the length or -1 */
int att_der_sig(const uint8_t raw[64], uint8_t *out, size_t cap);

/* TBSCertificate of the self-signed attestation certificate (subject = issuer);
 * `serial8` is an 8-byte random serial (top bit/first byte are fixed up here).  Returns length or -1. */
int att_der_tbs(const uint8_t x[32], const uint8_t y[32], const uint8_t serial8[8], uint8_t *out, size_t cap);

/* Certificate = SEQ { tbs, ecdsa-with-SHA256, BIT STRING(sig DER) }.  Returns length or -1. */
int att_der_cert(const uint8_t *tbs, size_t tbs_len, const uint8_t sig_raw[64], uint8_t *out, size_t cap);

#endif
