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
#include <stdio.h>
#include <stdint.h>
#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "hardware/gpio.h"
#include "hardware/adc.h"
#include "bsp/board.h"
#include "pins.h"
#include "se.h"
#include "device_state.h"
#include "tusb.h"
#include "usb_descriptors.h"
#include "user_settings.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "hardware/clocks.h"
    
extern void u2f_init(void);

/* Secure element requested but unusable: blink the reason (1..7 flashes) forever.
 * Never fall back to software crypto, never enumerate on USB. */
static void se_fail(int code)
{
    for (;;) {
        for (int i = 0; i < code; i++) {
            gpio_put(U2F_LED, 1); sleep_ms(150);
            gpio_put(U2F_LED, 0); sleep_ms(250);
        }
        sleep_ms(1500);
    }
}

void system_boot(void)
{
    /* Setting system clock */
    set_sys_clock_48mhz();
    
    /* Setting GPIOs for Led + Button */
    gpio_init(U2F_LED);
    gpio_set_dir(U2F_LED, GPIO_OUT);

    gpio_init(PRESENCE_BUTTON);
    gpio_set_dir(PRESENCE_BUTTON, GPIO_IN);
    gpio_pull_up(PRESENCE_BUTTON);

    /* Two pins joined by a jumper at power-up = use the secure element */
    if (se_jumper_present()) {
        int e = se_init();
        if (e != SE_OK)
            se_fail(e);
    }

    /* Initializing U2F parser */
    u2f_init();
    if (se_active()) {
        int e = device_se_check();
        if (e != SE_OK)
            se_fail(e);
    }

    /* Initializing TinyUSB device */
    tusb_init();

}

int main(void) {
    system_boot();

    /* Main loop: transfer control to USB */
    while (1) {
        tud_task();
    }
}
