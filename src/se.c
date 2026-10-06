/*
 * Minimal ATECC608 driver: wake, one framed command, sleep.  Only what the
 * firmware needs: Info, Read (config / refusal test), Random, GenKey, Nonce
 * (pass-through) and Sign (external).  See se.h for the security model.
 */
#include <string.h>
#include "pico/stdlib.h"
#include "hardware/gpio.h"
#include "hardware/i2c.h"
#include "se.h"

#define SE_I2C            i2c0
#define I2C_TIMEOUT_US    20000   /* never hang on a stuck bus */
#define I2C_W(a, b, n)    i2c_write_timeout_us(SE_I2C, (a), (b), (n), false, I2C_TIMEOUT_US)
#define I2C_R(a, b, n)    i2c_read_timeout_us(SE_I2C, (a), (b), (n), false, I2C_TIMEOUT_US)
#define OP_READ           0x02
#define OP_RANDOM         0x1B
#define OP_INFO           0x30
#define OP_NONCE          0x16
#define OP_GENKEY         0x40
#define OP_SIGN           0x41
#define NONCE_PASSTHROUGH 0x03   /* TempKey := the 32 bytes we send */
#define GENKEY_PUBLIC     0x00   /* public key from the existing private key */
#define GENKEY_PRIVATE    0x04   /* create a new private key */
#define SIGN_EXTERNAL     0x80   /* sign the digest held in TempKey */
#define ST_EXEC_ERROR     0x0F
#define E_STATUS(s)       (-100 - (int)(s))   /* device returned status byte s */
#define E_BUS             (-1)
#define E_CRC             (-2)
#define E_FRAME           (-3)

static bool g_active;

static uint16_t crc16(const uint8_t *d, size_t n)
{
    uint16_t crc = 0;
    size_t i;
    for (i = 0; i < n; i++) {
        uint8_t m;
        for (m = 0x01; m; m <<= 1) {
            uint8_t bit = (d[i] & m) ? 1 : 0;
            uint8_t top = (uint8_t)(crc >> 15);
            crc = (uint16_t)(crc << 1);
            if (bit != top)
                crc ^= 0x8005;
        }
    }
    return crc;
}

static bool crc_ok(const uint8_t *p, size_t n)   /* n includes the 2 CRC bytes */
{
    uint16_t c = crc16(p, n - 2);
    return p[n - 2] == (uint8_t)c && p[n - 1] == (uint8_t)(c >> 8);
}

bool se_active(void) { return g_active; }

/* Wake = hold SDA low for >= 60 us, then wait tWHI. Done on the pin directly:
 * a zero byte sent to I2C address 0 is a reserved address for the SDK. */
static int se_wake(void)
{
    uint8_t r[4];
    int tries;

    gpio_put(SE_SDA_PIN, 0);
    gpio_set_dir(SE_SDA_PIN, GPIO_OUT);
    gpio_set_function(SE_SDA_PIN, GPIO_FUNC_SIO);
    sleep_us(100);
    gpio_set_function(SE_SDA_PIN, GPIO_FUNC_I2C);           /* release; pull-up raises SDA */
    sleep_us(1500);                                         /* tWHI */
    /* The reference HAL retries the wake answer a few times; the chip may need
     * a little longer than tWHI after a cold power-up.  Bounded. */
    for (tries = 0; tries < 5; tries++) {
        if (I2C_R(SE_I2C_ADDR, r, 4) == 4)
            break;
        sleep_us(500);
    }
    if (tries == 5)
        return E_BUS;
    if (r[0] != 4 || !crc_ok(r, 4))
        return E_CRC;
    return (r[1] == 0x11) ? 0 : E_STATUS(r[1]);              /* 0x11 = "awake" */
}

static void se_sleep(void)
{
    uint8_t w = 0x01;
    (void)I2C_W(SE_I2C_ADDR, &w, 1);
}

/* Send one command, wait, read the answer.  rsp gets rsp_len data bytes.
 * rsp_len == 0 means "status-only answer, status must be 0". */
static int se_cmd(uint8_t op, uint8_t p1, uint16_t p2, const uint8_t *data, size_t dlen,
                  uint8_t *rsp, size_t rsp_len)
{
    uint8_t pkt[1 + 7 + 64], r[3 + 64];
    size_t n = 1 + 7 + dlen, cnt, tries;
    uint16_t c;

    if (dlen > 64 || rsp_len > 64)
        return E_FRAME;
    pkt[0] = 0x03;                          /* word address: command */
    pkt[1] = (uint8_t)(7 + dlen);           /* count: itself + op + p1 + p2 + data + crc */
    pkt[2] = op; pkt[3] = p1; pkt[4] = (uint8_t)p2; pkt[5] = (uint8_t)(p2 >> 8);
    if (dlen)
        memcpy(pkt + 6, data, dlen);
    c = crc16(pkt + 1, 5 + dlen);
    pkt[6 + dlen] = (uint8_t)c; pkt[7 + dlen] = (uint8_t)(c >> 8);
    if (I2C_W(SE_I2C_ADDR, pkt, n) != (int)n)
        return E_BUS;

    sleep_ms(2);
    /* Read the answer the way Microchip's hal_i2c_receive does for ATECC parts:
     * a 2-byte head (count + first byte; the chip NACKs while it is still
     * executing), then exactly the remaining count-2 bytes.  An answer is never
     * shorter than 4 bytes, so the head can never over-read. */
    for (tries = 0; tries < 300; tries++) {
        if (I2C_R(SE_I2C_ADDR, r, 2) == 2)
            break;
        sleep_ms(2);
    }
    if (tries == 300)
        return E_BUS;

    cnt = r[0];
    if (cnt != 4 && cnt != (rsp_len ? rsp_len + 3 : 4))
        return E_FRAME;                            /* neither a status nor the expected answer */
    if (cnt > sizeof(r))
        return E_FRAME;
    if (I2C_R(SE_I2C_ADDR, r + 2, cnt - 2) != (int)(cnt - 2))
        return E_BUS;
    if (!crc_ok(r, cnt))
        return E_CRC;

    if (cnt == 4) {                                /* status-only answer */
        if (r[1] != 0)
            return E_STATUS(r[1]);
        return rsp_len ? E_FRAME : 0;
    }
    memcpy(rsp, r + 1, rsp_len);
    return 0;
}

int se_random32(uint8_t out[32])
{
    int r;
    if (!g_active) return -1;
    if ((r = se_wake()) == 0) { r = se_cmd(OP_RANDOM, 0x00, 0, NULL, 0, out, 32); se_sleep(); }
    return r;
}

int se_serial(uint8_t out[SE_SERIAL_LEN])
{
    uint8_t c[32];
    int r;
    if (!g_active) return -1;
    if ((r = se_wake()) == 0) { r = se_cmd(OP_READ, 0x80, 0x0000, NULL, 0, c, 32); se_sleep(); }
    if (r != 0) return r;
    memcpy(out, c, 4);          /* SN[0..3]  */
    memcpy(out + 4, c + 8, 5);  /* SN[4..8]  */
    return 0;
}

static bool slot_is_att(uint8_t slot)  { return slot == SE_ATT_SLOT; }
static bool slot_is_cred(uint8_t slot) { return slot >= SE_CRED_SLOT_FIRST && slot < SE_CRED_SLOT_FIRST + SE_CRED_SLOTS; }
static bool slot_ok(uint8_t slot)      { return slot_is_att(slot) || slot_is_cred(slot); }

/* GenKey; the chip is awake. */
static int genkey_locked(uint8_t mode, uint8_t slot, uint8_t x[32], uint8_t y[32])
{
    uint8_t pub[64];
    int r = se_cmd(OP_GENKEY, mode, slot, NULL, 0, pub, 64);
    if (r == 0) { memcpy(x, pub, 32); memcpy(y, pub + 32, 32); }
    return r;
}

int se_pubkey(uint8_t slot, uint8_t x[32], uint8_t y[32])
{
    int r;
    if (!g_active || !slot_ok(slot)) return -1;
    if ((r = se_wake()) == 0) { r = genkey_locked(GENKEY_PUBLIC, slot, x, y); se_sleep(); }
    return r;
}

int se_genkey(uint8_t slot, uint8_t x[32], uint8_t y[32])
{
    int r;
    if (!g_active || !slot_ok(slot)) return -1;
    if ((r = se_wake()) == 0) { r = genkey_locked(GENKEY_PRIVATE, slot, x, y); se_sleep(); }
    return r;
}

int se_sign(uint8_t slot, const uint8_t digest[32], uint8_t sig[64])
{
    int r;
    if (!g_active || !slot_ok(slot)) return -1;
    if ((r = se_wake()) != 0) return r;
    /* One wake session: the digest in TempKey must survive until Sign. */
    r = se_cmd(OP_NONCE, NONCE_PASSTHROUGH, 0, digest, 32, NULL, 0);
    if (r == 0) r = se_cmd(OP_SIGN, SIGN_EXTERNAL, slot, NULL, 0, sig, 64);
    se_sleep();
    return r;
}

/* Does `slot` look the way this firmware needs it?  Config bits as defined by
 * Microchip (cryptoauthlib calib_device.h): SlotConfig @cfg[20+2n], KeyConfig @cfg[96+2n]. */
static bool slot_config_ok(const uint8_t cfg[128], uint8_t slot, bool is_cred)
{
    uint16_t sc = (uint16_t)(cfg[20 + 2 * slot] | (cfg[21 + 2 * slot] << 8));
    uint16_t kc = (uint16_t)(cfg[96 + 2 * slot] | (cfg[97 + 2 * slot] << 8));
    if (!(kc & 0x0001)) return false;              /* KeyConfig.Private                   */
    if (((kc >> 2) & 0x07) != 4) return false;     /* KeyConfig.KeyType == P256            */
    if (!(sc & 0x0080)) return false;              /* SlotConfig.IsSecret                  */
    if (!(sc & 0x0001)) return false;              /* ReadKey[0]: external signatures      */
    if (sc & 0x0200) return false;                 /* WriteKey[1]: PrivWrite - a host could inject a known key */
    if (is_cred && !(sc & 0x0100)) return false;   /* WriteKey[0]: GenKey (new key per credential) */
    return true;
}

/* Everything that can be verified about the chip from the outside.  Fail
 * closed: anything unexpected refuses to start. */
int se_init(void)
{
    uint8_t b[32], cfg[128];
    int r, s;

    g_active = false;
    i2c_init(SE_I2C, 100000);
    gpio_set_function(SE_SDA_PIN, GPIO_FUNC_I2C);
    gpio_set_function(SE_SCL_PIN, GPIO_FUNC_I2C);
    gpio_pull_up(SE_SDA_PIN);                       /* weak; fit 4.7k external pull-ups */
    gpio_pull_up(SE_SCL_PIN);

    if (se_wake() != 0) return SE_E_NO_DEVICE;
    r = se_cmd(OP_INFO, 0x00, 0, NULL, 0, b, 4);    /* revision: 00 00 60 xx for ATECC608 */
    if (r != 0) { se_sleep(); return SE_E_COMM; }
    if (b[2] != 0x60) { se_sleep(); return SE_E_NOT_608; }

    r = se_cmd(OP_READ, 0x00, 0x0015, NULL, 0, b, 4);   /* config bytes 84..87: ..., LockValue, LockConfig */
    if (r != 0) { se_sleep(); return SE_E_COMM; }
    if (b[2] != 0x00 || b[3] != 0x00) { se_sleep(); return SE_E_NOT_LOCKED; }   /* 0x55 = unlocked */

    /* Config blocks 0, 1 and 3 hold SlotConfig[0..15] and KeyConfig[0..15]. */
    memset(cfg, 0, sizeof(cfg));
    if (se_cmd(OP_READ, 0x80, 0x0000, NULL, 0, cfg + 0, 32) != 0 ||
        se_cmd(OP_READ, 0x80, 0x0008, NULL, 0, cfg + 32, 32) != 0 ||
        se_cmd(OP_READ, 0x80, 0x0018, NULL, 0, cfg + 96, 32) != 0) { se_sleep(); return SE_E_COMM; }

    for (s = 0; s < 16; s++) {
        bool att = slot_is_att((uint8_t)s), cred = slot_is_cred((uint8_t)s);
        if (!att && !cred) continue;
        if (!slot_config_ok(cfg, (uint8_t)s, cred)) { se_sleep(); return SE_E_SLOT_CONFIG; }
        /* A private-key slot must refuse a clear-text read (status 0x0F).  Anything else
         * - a successful read, or any other error - means we cannot vouch for it. */
        r = se_cmd(OP_READ, 0x82, (uint16_t)(s << 3), NULL, 0, b, 32);
        if (r == 0) { se_sleep(); return SE_E_SLOT_CONFIG; }
        if (r != E_STATUS(ST_EXEC_ERROR)) { se_sleep(); return SE_E_COMM; }
    }
    se_sleep();
    g_active = true;
    return SE_OK;
}
