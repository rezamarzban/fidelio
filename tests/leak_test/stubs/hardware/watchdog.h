/* Host-test stub for hardware/watchdog.h */
#ifndef STUB_HARDWARE_WATCHDOG_H
#define STUB_HARDWARE_WATCHDOG_H
#include <stdint.h>
void watchdog_reboot(uint32_t magic, uint32_t magic2, uint32_t delay_ms);
#endif
