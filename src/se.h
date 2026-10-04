/*
 * Optional secure element (Microchip ATECC608A/B) on I2C.
 *
 * Default: software crypto, exactly as before.
 * Secure-element mode: selected at power-up by connecting two pins
 * (SE_JUMPER_DRIVE_PIN and SE_JUMPER_SENSE_PIN, GP7 and GP6 by default) with a
 * jumper wire.  In that mode
 *   - the root secret is a key stored inside the chip; every key derivation is
 *     an HMAC-SHA256 computed BY the chip, so the root secret never enters the
 *     RP2040 (not in flash, not in RAM);
 *   - the chip's hardware RNG is mixed into the DRBG seed.
 * Per-credential ECDSA signing still runs on the RP2040 with a key that the
 * chip derived for that one credential (see SE.md for why).
 *
 * If the jumper is present but the chip is missing or not provisioned as
 * required, the firmware never falls back to software crypto: it blinks an
 * error code and stays off the USB bus.
 */
#ifndef SE_H
#define SE_H

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
#ifndef SE_JUMPER_DRIVE_PIN
#define SE_JUMPER_DRIVE_PIN  7
#endif
#ifndef SE_JUMPER_SENSE_PIN
#define SE_JUMPER_SENSE_PIN  6
#endif
#ifndef SE_HMAC_SLOT
#define SE_HMAC_SLOT         0      /* slot that holds the 32-byte root secret */
#endif

/* se_init() results (also the number of LED blinks shown on failure) */
#define SE_OK                0
#define SE_E_NO_DEVICE       1   /* no ACK / bad wake response            */
#define SE_E_NOT_608         2   /* answers, but is not an ATECC608        */
#define SE_E_NOT_LOCKED      3   /* config or data zone still unlocked     */
#define SE_E_SECRET_READABLE 4   /* root-secret slot can be read in clear  */
#define SE_E_BLANK_KEY       5   /* root-secret slot is all-0x00 / all-0xFF */
#define SE_E_COMM            6   /* CRC / status / timeout during checks   */
#define SE_E_CHIP_CHANGED    7   /* a different chip than the one enrolled */
#define SE_SERIAL_LEN        9

bool se_jumper_present(void);
int  se_init(void);                       /* SE_OK or SE_E_* ; SE_OK activates SE mode */
bool se_active(void);
int  se_serial(uint8_t out[SE_SERIAL_LEN]);   /* chip serial number; 0 ok */
int  se_random32(uint8_t out[32]);        /* 0 ok */
int  se_hmac(const uint8_t *msg, size_t len, uint8_t out[32]);   /* HMAC-SHA256 with the slot key; 0 ok */

#endif /* SE_H */
