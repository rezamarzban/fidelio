#ifndef ATT_CERT_H
#define ATT_CERT_H
/*
 * Attestation identity, created on the device.  The attestation PRIVATE key is
 * generated inside the secure element (slot SE_ATT_SLOT) and never leaves it.
 * The self-signed X.509 certificate (public data) is built here and signed by
 * the chip, then kept in flash.  No key material is ever compiled into the
 * firmware image, and there is no host-side certificate script.
 */
#include <stdint.h>
#include "se.h"

#define ATT_E_FLASH   -1
#define ATT_E_SE      -2
#define ATT_E_CHIP    -3    /* record belongs to another chip */
#define ATT_NEW        1    /* a new identity was created */

/* Load the record; create key + certificate when none exists.  0, ATT_NEW or ATT_E_*. */
int att_cert_init(const uint8_t serial[SE_SERIAL_LEN]);

const uint8_t *att_cert_der(uint16_t *len);   /* certificate */
const uint8_t *att_cert_pub(void);            /* 64 bytes X||Y of the attestation key */

/* Throw the identity away and make a new one (used by nothing at runtime; for factory re-provisioning). */
int att_cert_renew(const uint8_t serial[SE_SERIAL_LEN]);

#endif
