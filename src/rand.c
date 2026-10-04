/* Fidelio
 *
 * (c) 2023 Daniele Lacamera <root@danielinux.net>
 *
 *
 * Fidelio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Fidelio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 *
 */
#include "pico/stdlib.h"
#include "hardware/gpio.h"
#include "hardware/adc.h"
#include "hardware/structs/rosc.h"
#include <string.h>
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "se.h"

/* Entropy for the wolfCrypt DRBG seed (and therefore for the device master
 * key, every credential nonce and every ECDSA nonce).
 *
 * The only source used to be the 3 least-significant bits of ADC samples taken
 * on pins that are left floating, which is an uncharacterised, board-dependent
 * noise source.  It is kept, but is now mixed with the RP2040 ring-oscillator
 * jitter and the microsecond timer through SHA-256, so a weak or biased source
 * cannot make the seed worse than the best of the sources. */

#define IN3_PIN 29
#define IN0_PIN 28
#define IN1_PIN 27
#define IN2_PIN 26

const uint32_t IN[4] = {IN0_PIN, IN1_PIN, IN2_PIN, IN3_PIN};
static int adc_initialized = 0;
static uint32_t seed_calls = 0;

const int in_a[8] = { 0, 1, 2, 3, 1, 3, 0, 2 };

/* ADC noise: 8 samples x 3 LSBs -> 3 bytes (original algorithm) */
static void adc_noise(uint8_t *output, uint32_t sz)
{
    uint32_t i;
    uint32_t result = 0;
    uint32_t rd = 0, wsz;

    if (!adc_initialized) {
        adc_init();
        for (i = 0; i < 4; i++) {
            adc_gpio_init(IN[i]);
        }
        adc_initialized = 1;
        sleep_ms(10);
    }

    for (i = 0; rd < sz; i = (i + 1) % 8) {
        adc_select_input(in_a[i]);
        result = (result << 3) | (adc_read() & 0x00000007);
        /* Introduce a delay to capture environmental noise */
        sleep_ms(1);
        if (i == 7) {
            wsz = 3;
            if (wsz > (sz - rd)) {
                wsz = sz - rd;
            }
            memcpy(output + rd, &result, wsz);
            rd += wsz;
            result = 0;
        }
    }
}

/* Ring-oscillator jitter: one bit per read, spaced out so that consecutive
 * bits sample different phases of the oscillator. */
static void rosc_noise(uint8_t *out, uint32_t sz)
{
    for (uint32_t i = 0; i < sz; i++) {
        uint8_t v = 0;
        for (int b = 0; b < 8; b++) {
            v = (uint8_t)((v << 1) | (rosc_hw->randombit & 1u));
            busy_wait_us_32(1 + (v & 1u));
        }
        out[i] = v;
    }
}

int custom_random_seed(unsigned char *output, unsigned int sz)
{
    uint8_t adc[32], ros[32], prev[32], hw[32];
    uint8_t blk[WC_SHA256_DIGEST_SIZE];
    wc_Sha256 sha;
    uint32_t rd = 0;

    memset(prev, 0, sizeof(prev));
    memset(hw, 0, sizeof(hw));
    /* Secure-element mode: add the chip's hardware RNG. If it fails, so does
     * the seed (and with it every operation that needs randomness). */
    if (se_active() && se_random32(hw) != 0)
        return -1;
    while (rd < sz) {
        uint64_t t;
        uint32_t n;

        adc_noise(adc, sizeof(adc));
        rosc_noise(ros, sizeof(ros));
        t = time_us_64();
        n = ++seed_calls;

        if (wc_InitSha256(&sha) != 0)
            return -1;
        wc_Sha256Update(&sha, adc, sizeof(adc));
        wc_Sha256Update(&sha, ros, sizeof(ros));
        wc_Sha256Update(&sha, hw, sizeof(hw));
        wc_Sha256Update(&sha, (const byte *)&t, sizeof(t));
        wc_Sha256Update(&sha, (const byte *)&n, sizeof(n));
        wc_Sha256Update(&sha, prev, sizeof(prev));
        if (wc_Sha256Final(&sha, blk) != 0) {
            wc_Sha256Free(&sha);
            return -1;
        }
        wc_Sha256Free(&sha);
        memcpy(prev, blk, sizeof(prev));

        n = sizeof(blk);
        if (n > sz - rd)
            n = sz - rd;
        memcpy(output + rd, blk, n);
        rd += n;
    }
    memset(adc, 0, sizeof(adc));
    memset(ros, 0, sizeof(ros));
    memset(hw, 0, sizeof(hw));
    memset(blk, 0, sizeof(blk));
    return 0;
}
