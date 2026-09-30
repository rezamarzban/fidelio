/* Link-time stubs so the real src/u2f.c runs on the host.
 * tud_hid_report() captures frames for the test driver; everything else
 * is a no-op or a failure so no crypto path is ever exercised.
 */
#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "class/hid/hid_device.h"
#include "indicator.h"
#include "puf_sram.h"
#include "flash_rt.h"
#include "ctap2.h"
#include "fdo.h"
#include "att.h"

#define MAX_FRAMES 16

int frame_count = 0;
uint8_t frames[MAX_FRAMES][64];

int tud_hid_report(uint8_t instance, void *report, uint16_t len)
{
    (void)instance;
    if (len != 64)
        return -1;
    if (frame_count < MAX_FRAMES)
        memcpy(frames[frame_count], report, 64);
    frame_count++;
    return 0;
}

/* indicator: button never pressed, so register/auth stop at ECOND. */
bool indicator_wait_for_button(uint16_t r, uint16_t g, uint16_t b)
{
    (void)r; (void)g; (void)b;
    return false;
}
void indicator_set(uint16_t r, uint16_t g, uint16_t b)
{
    (void)r; (void)g; (void)b;
}
void indicator_set_idle(void) {}
void indicator_init(void) {}

/* PUF / flash / watchdog: inert. */
static const uint8_t fake_secret[32] = { 0x42 };
const uint8_t *puf_master_secret(void) { return fake_secret; }
void puf_factory_erase(void) {}
int puf_provision(void) { return 0; }
void puf_sram_snapshot(void) {}
int puf_rotate_salt(void) { return 0; }
const uint8_t *puf_raw_response(uint32_t *len)
{
    (void)len;
    return fake_secret;
}
void fidelio_flash_erase(uint32_t off, uint32_t len)
{
    (void)off; (void)len;
}
void fidelio_flash_program(uint32_t off, const void *data, uint32_t len)
{
    (void)off; (void)data; (void)len;
}
void watchdog_reboot(uint32_t m, uint32_t m2, uint32_t d)
{
    (void)m; (void)m2; (void)d;
}

/* CTAP2: always fail, to exercise the CBOR error path. */
/* CTAP2: fails by default (exercises the CBOR error path); the leak test
 * can switch it to a successful multi-frame reply to probe the continuation
 * state. */
int stub_ctap2_fail = 1;
int stub_ctap2_reply_len = 0;

int ctap2_handle_cbor(const uint8_t *payload, uint16_t payload_len,
                      uint8_t *reply, uint16_t reply_max,
                      uint16_t *reply_len)
{
    (void)payload; (void)payload_len;
    if (stub_ctap2_fail)
        return -1;
    if (stub_ctap2_reply_len > reply_max)
        return -1;
    memset(reply, 0xC0, stub_ctap2_reply_len);
    *reply_len = (uint16_t)stub_ctap2_reply_len;
    return 0;
}
void ctap2_reset_state(void) {}
void fdo_reset(void) {}
void fdo_init(void) {}

/* wolfCrypt: every call fails; the leak tests never reach real crypto. */
int wc_InitRng(WC_RNG *r) { (void)r; return -1; }
int wc_FreeRng(WC_RNG *r) { (void)r; return 0; }
int wc_RNG_GenerateBlock(WC_RNG *r, byte *o, word32 s)
{ (void)r; (void)o; (void)s; return -1; }
int wc_InitSha256(Sha256 *s) { (void)s; return -1; }
int wc_Sha256Update(Sha256 *s, const byte *i, word32 z)
{ (void)s; (void)i; (void)z; return -1; }
int wc_Sha256Final(Sha256 *s, byte *o) { (void)s; (void)o; return -1; }
int wc_Sha256Free(Sha256 *s) { (void)s; return 0; }
int wc_ecc_init(ecc_key *k) { (void)k; return -1; }
int wc_ecc_free(ecc_key *k) { (void)k; return 0; }
int wc_ecc_check_key(ecc_key *k) { (void)k; return -1; }
int wc_ecc_import_private_key_ex(const byte *p, word32 ps,
                                 const byte *q, word32 qs,
                                 ecc_key *k, int c)
{
    (void)p; (void)ps; (void)q; (void)qs; (void)k; (void)c;
    return -1;
}
int wc_ecc_make_pub_ex(ecc_key *k, byte *x, byte *y)
{ (void)k; (void)x; (void)y; return -1; }
int wc_ecc_export_public_raw(ecc_key *k, byte *x, word32 *xl,
                             byte *y, word32 *yl)
{
    (void)k; (void)x; (void)xl; (void)y; (void)yl;
    return -1;
}
word32 wc_ecc_sig_size(ecc_key *k) { (void)k; return 0; }
int wc_ecc_sign_hash(const byte *in, word32 il, byte *out,
                     word32 *ol, WC_RNG *rng, ecc_key *k)
{
    (void)in; (void)il; (void)out; (void)ol; (void)rng; (void)k;
    return -1;
}
int wc_EccPrivateKeyDecode(const byte *in, word32 *idx,
                           ecc_key *k, word32 sz)
{
    (void)in; (void)idx; (void)k; (void)sz;
    return -1;
}
int wc_HmacInit(Hmac *h, void *heap, int id)
{ (void)h; (void)heap; (void)id; return -1; }
int wc_HmacSetKey(Hmac *h, int t, const byte *k, word32 ks)
{ (void)h; (void)t; (void)k; (void)ks; return -1; }
int wc_HmacUpdate(Hmac *h, const byte *in, word32 sz)
{ (void)h; (void)in; (void)sz; return -1; }
int wc_HmacFinal(Hmac *h, byte *o) { (void)h; (void)o; return -1; }
int wc_HmacFree(Hmac *h) { (void)h; return 0; }

void ForceZero(void *mem, word32 len)
{
    if (mem)
        memset(mem, 0, len);
}

/* Attestation: fails, matching the wolfCrypt stubs; the leak paths under
 * test never reach it. */
int att_key_init(ecc_key *key) { (void)key; return -1; }
int att_cert_get(WC_RNG *rng, const uint8_t **der, uint32_t *der_len)
{
    (void)rng; (void)der; (void)der_len;
    return -1;
}
