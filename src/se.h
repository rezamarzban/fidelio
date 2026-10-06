#ifndef SE_H
#define SE_H
/*
 * ATECC608 driver - hardware-only crypto model ("C").
 *
 * Every private key of this firmware lives in the secure element and never
 * leaves it: the attestation key (one slot) and one P-256 key per credential
 * (one slot each).  The RP2040 only ever sees public keys and signatures.
 * There is no software signing code and no fallback to it.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifndef SE_I2C_ADDR
#define SE_I2C_ADDR          0x60   /* 7-bit; ATECC608 factory default (0xC0 8-bit) */
#endif
#ifndef SE_SDA_PIN
#define SE_SDA_PIN           4      /* i2c0 SDA */
#endif
#ifndef SE_SCL_PIN
#define SE_SCL_PIN           5      /* i2c0 SCL */
#endif

/* Slot map.  Must match how the chip was provisioned (see SE.md). */
#ifndef SE_ATT_SLOT
#define SE_ATT_SLOT          0      /* attestation key (U2F + CTAP2 batch attestation) */
#endif
#ifndef SE_CRED_SLOT_FIRST
#define SE_CRED_SLOT_FIRST   1      /* first credential key slot */
#endif
#ifndef SE_CRED_SLOTS
#define SE_CRED_SLOTS        7      /* number of credential key slots = max credentials (<= 14) */
#endif
#if SE_CRED_SLOTS < 1 || SE_CRED_SLOTS > 14 || (SE_CRED_SLOT_FIRST + SE_CRED_SLOTS) > 16
#error "SE_CRED_SLOTS / SE_CRED_SLOT_FIRST out of range"
#endif

#define SE_OK                0
#define SE_E_NO_DEVICE       1   /* no ACK / bad wake response                                   */
#define SE_E_NOT_608         2   /* answers, but is not an ATECC608                               */
#define SE_E_NOT_LOCKED      3   /* config or data zone still unlocked                            */
#define SE_E_SLOT_CONFIG     4   /* a key slot is not configured as required (see SE.md)          */
#define SE_E_NO_ATT_KEY      5   /* attestation slot holds no usable key                          */
#define SE_E_COMM            6   /* CRC / status / timeout during checks                          */
#define SE_E_CHIP_CHANGED    7   /* a different chip than the one enrolled                        */
#define SE_SERIAL_LEN        9

int  se_init(void);                          /* SE_OK or SE_E_*; SE_OK activates the driver */
bool se_active(void);
int  se_serial(uint8_t out[SE_SERIAL_LEN]);  /* chip serial number; 0 ok */
int  se_random32(uint8_t out[32]);           /* chip TRNG; 0 ok */
/* Public key of the private key stored in `slot` (GenKey "public" mode); 0 ok. */
int  se_pubkey(uint8_t slot, uint8_t x[32], uint8_t y[32]);
/* Create a NEW private key inside `slot` (the old one is destroyed) and return its public key; 0 ok. */
int  se_genkey(uint8_t slot, uint8_t x[32], uint8_t y[32]);
/* ECDSA P-256 signature of a 32-byte digest by the key in `slot`: raw r||s, 64 bytes; 0 ok. */
int  se_sign(uint8_t slot, const uint8_t digest[32], uint8_t sig[64]);

#endif /* SE_H */
