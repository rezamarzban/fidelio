#include <string.h>
#include "pico/stdlib.h"
#include "hardware/flash.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "att_cert.h"
#include "att_der.h"
#include "hw_sign.h"

#define FLASH_ATT_OFF   0x76000
#define ATT_MAGIC       0x31545441u     /* "ATT1" */
#define ATT_CERT_MAX    480

struct __attribute__((packed)) att_record {
    uint32_t magic;
    uint8_t  serial[SE_SERIAL_LEN];
    uint8_t  pad[3];
    uint8_t  pub[64];
    uint16_t cert_len;
    uint8_t  cert[ATT_CERT_MAX];
    uint32_t crc;
};
_Static_assert(sizeof(struct att_record) <= FLASH_SECTOR_SIZE, "att record must fit a sector");
#define REC_PROG_LEN (((sizeof(struct att_record) + FLASH_PAGE_SIZE - 1) / FLASH_PAGE_SIZE) * FLASH_PAGE_SIZE)

static struct att_record g_rec;
static bool g_have;

static uint32_t crc32(const uint8_t *d, size_t n)
{
    uint32_t c = 0xFFFFFFFFu;
    while (n--) {
        c ^= *d++;
        for (int k = 0; k < 8; k++)
            c = (c >> 1) ^ (0xEDB88320u & (uint32_t)-(int32_t)(c & 1u));
    }
    return ~c;
}

static int __not_in_flash_func(rec_write)(void)
{
    static uint8_t buf[REC_PROG_LEN];
    memset(buf, 0xFF, sizeof(buf));
    g_rec.crc = crc32((const uint8_t *)&g_rec, offsetof(struct att_record, crc));
    memcpy(buf, &g_rec, sizeof(g_rec));
    flash_range_erase(FLASH_ATT_OFF, FLASH_SECTOR_SIZE);
    flash_range_program(FLASH_ATT_OFF, buf, REC_PROG_LEN);
    return memcmp((const void *)(XIP_BASE + FLASH_ATT_OFF), buf, sizeof(g_rec)) == 0 ? 0 : ATT_E_FLASH;
}

/* New key in the chip -> certificate -> signed by that same key (self-signed) -> flash. */
static int create_identity(const uint8_t serial[SE_SERIAL_LEN])
{
    uint8_t x[32], y[32], rnd[32], tbs[400], sig[64], dig[32];
    int tl, cl;
    wc_Sha256 sha;

    if (se_genkey(SE_ATT_SLOT, x, y) != 0)
        return ATT_E_SE;
    if (se_random32(rnd) != 0)
        return ATT_E_SE;
    if ((tl = att_der_tbs(x, y, rnd, tbs, sizeof(tbs))) < 0)
        return ATT_E_SE;
    if (wc_InitSha256(&sha) != 0) return ATT_E_SE;
    wc_Sha256Update(&sha, tbs, (word32)tl);
    wc_Sha256Final(&sha, dig);
    wc_Sha256Free(&sha);

    memcpy(g_rec.pub, x, 32); memcpy(g_rec.pub + 32, y, 32);
    if (se_sign(SE_ATT_SLOT, dig, sig) != 0 || hw_verify_raw(g_rec.pub, dig, sig) != 0)
        return ATT_E_SE;
    if ((cl = att_der_cert(tbs, (size_t)tl, sig, g_rec.cert, sizeof(g_rec.cert))) < 0)
        return ATT_E_SE;

    g_rec.magic = ATT_MAGIC;
    memcpy(g_rec.serial, serial, SE_SERIAL_LEN);
    memset(g_rec.pad, 0, sizeof(g_rec.pad));
    g_rec.cert_len = (uint16_t)cl;
    if (rec_write() != 0)
        return ATT_E_FLASH;
    g_have = true;
    return ATT_NEW;
}

int att_cert_init(const uint8_t serial[SE_SERIAL_LEN])
{
    const struct att_record *f = (const struct att_record *)(XIP_BASE + FLASH_ATT_OFF);
    g_have = false;
    if (f->magic == ATT_MAGIC &&
        f->crc == crc32((const uint8_t *)f, offsetof(struct att_record, crc)) &&
        f->cert_len > 0 && f->cert_len <= ATT_CERT_MAX) {
        if (memcmp(f->serial, serial, SE_SERIAL_LEN) != 0)
            return ATT_E_CHIP;
        memcpy(&g_rec, f, sizeof(g_rec));
        /* the chip must still hold the key this certificate belongs to */
        uint8_t x[32], y[32];
        if (se_pubkey(SE_ATT_SLOT, x, y) != 0 || memcmp(x, g_rec.pub, 32) || memcmp(y, g_rec.pub + 32, 32))
            return ATT_E_SE;
        g_have = true;
        return 0;
    }
    return create_identity(serial);
}

int att_cert_renew(const uint8_t serial[SE_SERIAL_LEN]) { return create_identity(serial); }

const uint8_t *att_cert_der(uint16_t *len) { *len = g_have ? g_rec.cert_len : 0; return g_rec.cert; }
const uint8_t *att_cert_pub(void) { return g_rec.pub; }
