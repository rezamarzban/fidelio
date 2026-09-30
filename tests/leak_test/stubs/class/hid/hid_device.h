/* Host-test stub for class/hid/hid_device.h */
#ifndef STUB_CLASS_HID_DEVICE_H
#define STUB_CLASS_HID_DEVICE_H
#include <stdint.h>
#include "hid.h"
int tud_hid_report(uint8_t instance, void *report, uint16_t len);
void tud_hid_set_report_cb(uint8_t itf, uint8_t report_id,
                           hid_report_type_t report_type,
                           const uint8_t *buffer, uint16_t bufsize);
uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id,
                               hid_report_type_t report_type,
                               uint8_t *buffer, uint16_t reqlen);
void tud_hid_report_complete_cb(uint8_t instance, uint8_t const *report,
                                uint8_t len);
#endif
