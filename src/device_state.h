#ifndef DEVICE_STATE_H
#define DEVICE_STATE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "hardware/flash.h"

/* SE mode, after u2f_init(): SE_OK, or SE_E_CHIP_CHANGED / SE_E_COMM (see se.h). */
int device_se_check(void);

/* out = HMAC-SHA256(root secret, a || b); 0 on success.  Root secret: flash
 * master key, or the secure element when it is active (see se.h). */
int device_kdf(const uint8_t *a, size_t al, const uint8_t *b, size_t bl, uint8_t *out);
uint32_t device_get_counter(void);
void device_counter_inc(void);

/* Wait (bounded) for a *fresh* press of the presence button.
 * A button that is already held when the request arrives does not count: it
 * must be released first, so a stuck/held button or a press meant for another
 * operation cannot silently approve a request.  Returns false on timeout. */
bool device_user_presence(void);

/* Replace the master key with a fresh random one.  Every U2F key handle and
 * CTAP2 credential is derived from it, so all of them stop working: this is
 * what authenticatorReset must do (CTAP2: reset invalidates all credentials).
 * Returns 0 on success; on failure the old key is left untouched. */
int device_rotate_secret(void);
uint32_t device_uptime_ms(void);

/* flash_range_program() programs whole 256-byte pages. The PIN record (40 B)
 * was handed to it with its natural size, which is not a multiple of the page
 * size, so the tail of the page is taken from whatever follows the structure in
 * RAM (other statics such as the PIN token). Always go through a 0xFF-padded
 * page. */
static inline void flash_program_padded(uint32_t off, const void *data, size_t len)
{
    uint8_t page[FLASH_PAGE_SIZE];
    volatile uint8_t *w = page;
    size_t done, n, i;

    for (done = 0; done < len; done += FLASH_PAGE_SIZE) {
        n = len - done;
        if (n > FLASH_PAGE_SIZE)
            n = FLASH_PAGE_SIZE;
        memset(page, 0xFF, sizeof(page));
        memcpy(page, (const uint8_t *)data + done, n);
        flash_range_program(off + (uint32_t)done, page, FLASH_PAGE_SIZE);
    }
    for (i = 0; i < FLASH_PAGE_SIZE; i++)   /* may have held the PIN hash */
        w[i] = 0;
}

#endif /* DEVICE_STATE_H */
