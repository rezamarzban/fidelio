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

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "pico/stdlib.h"
#include "hardware/gpio.h"
#include "hardware/flash.h"
#include "hardware/watchdog.h"
#include "bsp/board.h"
#include "class/hid/hid.h"
#include "class/hid/hid_device.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "ecc_sign_util.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "cert.h"
#include "ctap2.h"
#include "device_state.h"
#include "pins.h"
#include "se.h"


#define PUBKEY_SZ 65
#define PARAM_SZ  32
#define ECC_SZ    32
#define SIGMAX_SZ 75
#define HASH_SZ   32
#define NONCE_SZ  32


#define U2FHID_PACKET_SIZE 64
#define U2FHID_MAX_PAYLOAD (U2FHID_PACKET_SIZE - 7 + 128 * (U2FHID_PACKET_SIZE - 5)) /* = 7609 bytes */

extern void ForceZero(void* mem, word32 len);

#define FLASH_CTR_ADDR0_OFF 0x70000
#define FLASH_CTR_ADDR1_OFF 0x71000
#define FLASH_MKEY_OFF      0x72000
#define FLASH_MKEY ((uint32_t *)(XIP_BASE + FLASH_MKEY_OFF))
#define FLASH_CTR0 *((uint32_t *)(XIP_BASE + FLASH_CTR_ADDR0_OFF))
#define FLASH_CTR1 *((uint32_t *)(XIP_BASE + FLASH_CTR_ADDR1_OFF))

/* Secure-element mode keeps only a PUBLIC salt in flash (its own sector, so a
 * software master key and an SE salt can never be mixed up when the jumper is
 * moved).  The record layout is identical, so provisioning and reset reuse the
 * same code. */
#define FLASH_SALT_OFF      0x75000

static uint32_t master_magic = 0xF1D091C0;

static uint32_t secret_off = FLASH_MKEY_OFF;
static uint8_t *device_secret = (uint8_t *)(FLASH_MKEY + 4);
static uint32_t *magic_check = (uint32_t *)FLASH_MKEY;

static uint32_t U2F_Counter = 0;

/* out = HMAC-SHA256(root secret, a || b).  Every credential key and every
 * key-handle MAC is derived through this one function.
 * Software mode: the root secret is the master key in flash (unchanged, so
 * existing registrations keep working).
 * SE mode: the chip computes HMAC(slot key, salt || a || b); the salt (flash)
 * is rotated by a reset, which therefore still invalidates every credential. */
int device_kdf(const uint8_t *a, size_t al, const uint8_t *b, size_t bl, uint8_t *out)
{
    int r;

    if (se_active()) {
        uint8_t msg[32 + 64];
        if (al + bl > 64)
            return -1;
        memcpy(msg, device_secret, 32);
        memcpy(msg + 32, a, al);
        memcpy(msg + 32 + al, b, bl);
        r = se_hmac(msg, 32 + al + bl, out);
        ForceZero(msg, sizeof(msg));
        return r;
    } else {
        Hmac hmac;
        r = wc_HmacInit(&hmac, NULL, 0);
        if (r != 0)
            return r;
        r = wc_HmacSetKey(&hmac, SHA256, device_secret, ECC_SZ);
        if (r == 0) r = wc_HmacUpdate(&hmac, a, (word32)al);
        if (r == 0) r = wc_HmacUpdate(&hmac, b, (word32)bl);
        if (r == 0) r = wc_HmacFinal(&hmac, out);
        wc_HmacFree(&hmac);
        return r;
    }
}

static void write_counter_page(uint32_t flash_off, uint32_t value)
{
    uint8_t page_buf[FLASH_PAGE_SIZE];
    memcpy(page_buf, (const void *)(XIP_BASE + flash_off), FLASH_PAGE_SIZE);
    memcpy(page_buf, &value, 4);
    flash_range_program(flash_off, page_buf, FLASH_PAGE_SIZE);
}

/* SE mode only: serial number of the enrolled chip, stored after the record so
 * that swapping the chip afterwards is detected instead of silently producing a
 * different identity. */
#define SE_SERIAL_OFF_IN_PAGE 36

static void write_master_page(uint32_t flash_off, const uint8_t *key, uint32_t magic,
                              const uint8_t *serial)
{
    uint8_t page_buf[FLASH_PAGE_SIZE];
    memcpy(page_buf, (const void *)(XIP_BASE + flash_off), FLASH_PAGE_SIZE);
    memcpy(page_buf, &magic, 4);
    memcpy(page_buf + 4, key, 32);
    if (serial)
        memcpy(page_buf + SE_SERIAL_OFF_IN_PAGE, serial, SE_SERIAL_LEN);
    flash_range_program(flash_off, page_buf, FLASH_PAGE_SIZE);
}

static uint32_t U2F_Counter_load(void);

/* Run flash ops from RAM to avoid XIP stalls */
static void __not_in_flash_func(flash_master_keygen)(void)
{
    WC_RNG rng;
    uint8_t mkey_buffer[4 + 32];
    uint8_t serial[SE_SERIAL_LEN];
    /* The U2F counter is global and must never go backwards: servers compare
     * it per registration.  Keep whatever the flash holds (0 on virgin flash)
     * instead of restarting at 0 when the identity (software <-> SE) changes. */
    uint32_t keep_counter = U2F_Counter_load();
    /* Keep LED off during keygen; turn it on once ready for acknowledgment */
    gpio_put(U2F_LED, 0);
    memset(mkey_buffer, 0, sizeof(mkey_buffer));
    memset(serial, 0xFF, sizeof(serial));
    if (wc_InitRng(&rng) != 0 || wc_RNG_GenerateBlock(&rng, mkey_buffer, 32) != 0 ||
        (se_active() && se_serial(serial) != 0)) {
        /* Never provision a master key from a failed/unseeded RNG (the buffer
         * would hold predictable data).  Stay locked and blink instead. */
        for (;;) {
            gpio_put(U2F_LED, 1);
            sleep_ms(100);
            gpio_put(U2F_LED, 0);
            sleep_ms(100);
        }
    }
    wc_FreeRng(&rng);
    flash_range_erase(secret_off, FLASH_SECTOR_SIZE);
    flash_range_erase(FLASH_CTR_ADDR0_OFF, FLASH_SECTOR_SIZE);
    flash_range_erase(FLASH_CTR_ADDR1_OFF, FLASH_SECTOR_SIZE);
    write_counter_page(FLASH_CTR_ADDR0_OFF, keep_counter);
    write_master_page(secret_off, mkey_buffer, master_magic, se_active() ? serial : NULL);
    ForceZero(mkey_buffer, sizeof(mkey_buffer));
    if (se_active()) {
        /* SE enrolment is complete (salt + chip serial are stored): destroy the
         * software master key.  Otherwise it would stay readable in flash and
         * removing the jumper would silently bring the old identity back. */
        flash_range_erase(FLASH_MKEY_OFF, FLASH_SECTOR_SIZE);
    }
    /* Signal ready and wait for presence press to confirm first-boot provisioning */
    gpio_put(U2F_LED, 1);
    while (gpio_get(PRESENCE_BUTTON) != 0) {
        sleep_ms(2);
    }
    sleep_ms(50);
    watchdog_reboot(0, 0, 0);
    while (1) { tight_loop_contents(); }
}

int __not_in_flash_func(device_rotate_secret)(void)
{
    WC_RNG rng;
    uint8_t newkey[32];

    /* Generate first: if the RNG fails the old key stays in place. */
    if (wc_InitRng(&rng) != 0)
        return -1;
    if (wc_RNG_GenerateBlock(&rng, newkey, sizeof(newkey)) != 0) {
        wc_FreeRng(&rng);
        ForceZero(newkey, sizeof(newkey));
        return -1;
    }
    wc_FreeRng(&rng);
    /* Power loss between these two calls leaves no valid magic: the next boot
     * provisions a new key (button press), which is the same end state. */
    {
        uint8_t serial[SE_SERIAL_LEN];       /* same chip: keep its serial */
        memcpy(serial, (const void *)(XIP_BASE + secret_off + SE_SERIAL_OFF_IN_PAGE), sizeof(serial));
        flash_range_erase(secret_off, FLASH_SECTOR_SIZE);
        write_master_page(secret_off, newkey, master_magic, se_active() ? serial : NULL);
    }
    ForceZero(newkey, sizeof(newkey));
    return 0;
}

/* SE mode, after u2f_init(): is the chip on the board the one that was enrolled? */
int device_se_check(void)
{
    uint8_t now[SE_SERIAL_LEN];
    if (se_serial(now) != 0)
        return SE_E_COMM;
    return memcmp(now, (const void *)(XIP_BASE + secret_off + SE_SERIAL_OFF_IN_PAGE), sizeof(now))
               ? SE_E_CHIP_CHANGED : SE_OK;
}

static void __not_in_flash_func(U2F_Counter_up)(void)
{
    U2F_Counter++;
    if ((U2F_Counter & 0x01) == 0x01) {
        write_counter_page(FLASH_CTR_ADDR1_OFF, U2F_Counter);
        flash_range_erase(FLASH_CTR_ADDR0_OFF, FLASH_SECTOR_SIZE);
    } else {
        write_counter_page(FLASH_CTR_ADDR0_OFF, U2F_Counter);
        flash_range_erase(FLASH_CTR_ADDR1_OFF, FLASH_SECTOR_SIZE);
    }
}

static uint32_t U2F_Counter_load(void)
{
    uint32_t a, b;
    a = FLASH_CTR0;
    b = FLASH_CTR1;
    if ((a == 0xFFFFFFFF) && b == (0xFFFFFFFF))
        return 0;
    else if (a == 0xFFFFFFFF)
        return b;
    else if (b == 0xFFFFFFFF)
        return a;
    else if (b > a)
        return b;
    else
        return a;
}

void u2f_init(void)
{
    if (se_active()) {                      /* chosen by the jumper in system_boot() */
        secret_off = FLASH_SALT_OFF;
        device_secret = (uint8_t *)(XIP_BASE + secret_off + 4);
        magic_check = (uint32_t *)(XIP_BASE + secret_off);
    }
    if (*magic_check != master_magic) {
        flash_master_keygen();
        U2F_Counter = 0;
    } else {
        U2F_Counter = U2F_Counter_load();
    }
}



struct __attribute__((packed)) u2fhid_init_packet {
    uint32_t cid;
    uint8_t hid_cmd;
    uint8_t payload_len[2];
    uint8_t data[U2FHID_PACKET_SIZE - 7];
};

struct __attribute__((packed)) u2fhid_cont_packet {
    uint32_t cid;
    uint8_t seq; /* sequence number, 0-127 */
    uint8_t data[U2FHID_PACKET_SIZE - 5];
};

struct __attribute__((packed)) u2fhid_generic_packet {
    uint32_t cid;
    uint8_t select;
};


struct u2f_message {
    uint32_t cid;
    uint8_t cmd;
    uint16_t len;
    uint16_t rx_len;
    uint8_t exp_seq;
    uint8_t data[U2FHID_MAX_PAYLOAD];
};


struct __attribute__((packed)) u2f_raw_hdr {
    uint8_t cla;
    uint8_t ins;
    uint8_t p1, p2;
    uint8_t len[3];
};

#define U2F_REGISTER_INS 0x01
#define U2F_AUTHENTICATE_INS 0x02
#define U2F_VERSION_INS 0x03

/* Authentication data flags. */
#define CTAP_AUTHDATA_USER_PRESENT	0x01
#define CTAP_AUTHDATA_USER_VERIFIED	0x04
#define CTAP_AUTHDATA_ATT_CRED		0x40
#define CTAP_AUTHDATA_EXT_DATA		0x80

/* CTAPHID command opcodes. */
#define CTAP_CMD_PING			0x01
#define CTAP_CMD_MSG			0x03
#define CTAP_CMD_LOCK			0x04
#define CTAP_CMD_INIT			0x06
#define CTAP_CMD_WINK			0x08
#define CTAP_CMD_CBOR			0x10
#define CTAP_CMD_CANCEL			0x11
#define CTAP_KEEPALIVE			0x3b
#define CTAP_FRAME_INIT			0x80

#define RESPONSE_MAX_SIZE 2048

/* CTAPHID_ERROR (0x3f) and error codes */
#define CTAPHID_ERROR        0x3f
#define CTAPHID_ERR_INVALID_CMD 0x01
#define CTAPHID_ERR_INVALID_LEN 0x03
#define CTAPHID_ERR_INVALID_SEQ 0x04
#define CTAPHID_ERR_MSG_TIMEOUT 0x05
#define CTAPHID_ERR_CHANNEL_BUSY 0x06
#define CTAPHID_BROADCAST_CID   0xffffffffu
#define CTAPHID_MSG_TIMEOUT_MS  3000u
#define CTAPHID_ERR_OTHER       0x7f

#define VALID_CID 0x00000000


#define ENOERR 0x9000
#define ECOND  0x6985
#define EWRONGDATA 0x6A80
#define EWRONGLEN  0x6700
#define ECLAUNSUPP 0x6E00
#define EINSUNSUPP 0x6D00

static struct u2f_message U2F_Message;
static uint8_t U2F_cmd_reply[RESPONSE_MAX_SIZE];
static uint32_t U2F_cmd_reply_sent = 0;
static uint32_t U2F_cmd_reply_size = 0;
static uint32_t U2F_cmd_reply_seq = 0;
static uint32_t U2F_cmd_reply_cid = 0;
static uint32_t U2F_next_cid = 1;
static uint32_t U2F_last_rx_ms = 0;

static int ctaphid_send(uint8_t cmd, uint16_t sz, bool append_status_word)
{
    uint8_t u2h_msg[U2FHID_PACKET_SIZE];
    struct u2fhid_init_packet *ip;
    uint32_t len;

    memset(u2h_msg, 0, U2FHID_PACKET_SIZE);
    U2F_cmd_reply_sent = 0;
    U2F_cmd_reply_seq = 0;
    U2F_cmd_reply_cid = U2F_Message.cid;
    if (append_status_word) {
        U2F_cmd_reply_size = sz + 2;
        U2F_cmd_reply[sz] = 0x90;
        U2F_cmd_reply[sz + 1] = 0x00;
    } else {
        U2F_cmd_reply_size = sz;
    }

    ip = (struct u2fhid_init_packet *)u2h_msg;
    ip->cid = U2F_Message.cid;
    ip->hid_cmd = 0x80 | cmd;
    ip->payload_len[0] = ((U2F_cmd_reply_size) & 0xFF00) >> 8;
    ip->payload_len[1] = (U2F_cmd_reply_size) & 0xFF;
    len = U2FHID_PACKET_SIZE - 7;
    if (U2F_cmd_reply_size < len)
        len = U2F_cmd_reply_size;
    memcpy(u2h_msg + 7, U2F_cmd_reply, len);
    tud_hid_report(0, u2h_msg, U2FHID_PACKET_SIZE);
    U2F_cmd_reply_sent = len;
    return 0;
}

#define PRESENCE_TIMEOUT_MS 30000u
#define PRESENCE_DEBOUNCE_MS 20u

static int u2f_ct_memeq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

uint32_t device_uptime_ms(void)
{
    return (uint32_t)(time_us_64() / 1000u);
}

bool device_user_presence(void)
{
    uint32_t waited = 0;
    bool ok = false;

    gpio_put(U2F_LED, 1);
    /* 1. a press already in progress does not count: wait for release */
    while (gpio_get(PRESENCE_BUTTON) == 0) {
        if (waited >= PRESENCE_TIMEOUT_MS)
            goto out;
        sleep_ms(2);
        waited += 2;
    }
    /* 2. wait for a new, debounced press */
    while (waited < PRESENCE_TIMEOUT_MS) {
        if (gpio_get(PRESENCE_BUTTON) == 0) {
            sleep_ms(PRESENCE_DEBOUNCE_MS);
            waited += PRESENCE_DEBOUNCE_MS;
            if (gpio_get(PRESENCE_BUTTON) == 0) {
                ok = true;
                break;
            }
        }
        sleep_ms(2);
        waited += 2;
    }
out:
    gpio_put(U2F_LED, 0);
    return ok;
}

/* Send a CTAPHID_ERROR frame.  The whole 64-byte frame is zeroed first: the
 * callers used to send a partly-initialised stack buffer, which disclosed
 * stale stack memory (key material left by earlier crypto calls) to the host.
 */
static void ctaphid_send_error(uint32_t cid, uint8_t err)
{
    uint8_t frame[U2FHID_PACKET_SIZE];
    memset(frame, 0, sizeof(frame));
    memcpy(frame, &cid, sizeof(cid));
    frame[4] = 0x80 | CTAPHID_ERROR;
    frame[5] = 0x00;
    frame[6] = 0x01; /* payload length = 1 */
    frame[7] = err;
    tud_hid_report(0, frame, sizeof(frame));
}

static uint16_t fido_register(struct u2f_raw_hdr *hdr, uint16_t len)
{
    uint8_t sig_hash[HASH_SZ];
    uint8_t handle_nonce[HASH_SZ];
    uint8_t handle_hash[HASH_SZ];
    word32 ecc_key_size = ECC_SZ;
    word32 qxlen = ECC_SZ;
    word32 qylen = ECC_SZ;
    word32 siglen = SIGMAX_SZ;
    wc_Sha256 sha;
    int ret;
    uint8_t signature[SIGMAX_SZ]; /* Large enough to contain ecc256 signature */
    uint8_t rfu_res = 0;
    uint8_t pubkey[PUBKEY_SZ];
    uint8_t user_private[ECC_SZ];
    word32 inOutIdx = 0;
    uint32_t idx = 0;
    uint8_t *challenge, *application;
    ecc_key user_ecc;
    ecc_key cert_ecc;
    WC_RNG rng;
    uint16_t status = ENOERR;
    bool rng_ok = false, user_ok = false, cert_ok = false;

    /* The request must really contain challenge + application parameters;
     * otherwise stale/zero buffer contents would be used silently. */
    if (len < 2 * PARAM_SZ)
        return EWRONGLEN;

    challenge = U2F_Message.data + sizeof(struct u2f_raw_hdr);
    application = U2F_Message.data + sizeof(struct u2f_raw_hdr) + PARAM_SZ;
    (void)hdr;

    memset(user_private, 0, sizeof(user_private));

    if (!device_user_presence())
        return ECOND;

    /* Initialize wolfCrypt objects */
    if (wc_InitRng(&rng) != 0)
        return 0x6110;
    rng_ok = true;
    if (wc_ecc_init(&user_ecc) != 0) { status = 0x6111; goto out; }
    user_ok = true;
    if (wc_ecc_init(&cert_ecc) != 0) { status = 0x6111; goto out; }
    cert_ok = true;

    /* Import certificate private key */
    if (wc_EccPrivateKeyDecode(cert_master_key_der, &inOutIdx, &cert_ecc, cert_master_key_der_len) != 0) {
        status = 0x6113; goto out;
    }
    /* Check imported key */
    if (wc_ecc_check_key(&cert_ecc) != 0) {
        status = 0x6118; goto out;
    }

    /* Private key = KDF(application, nonce); handle MAC = KDF(application, private) */
    ret = wc_RNG_GenerateBlock(&rng, handle_nonce, NONCE_SZ);
    if (ret != 0) { status = 0x6114; goto out; }
    if (device_kdf(application, PARAM_SZ, handle_nonce, NONCE_SZ, user_private) != 0 ||
        device_kdf(application, PARAM_SZ, user_private, ECC_SZ, handle_hash) != 0) {
        status = 0x6116; goto out;
    }
    if (wc_ecc_import_private_key_ex(user_private, ecc_key_size, NULL, 0,
                &user_ecc, ECC_SECP256R1) != 0) { status = 0x6111; goto out; }
    ret = wc_ecc_make_pub_ex(&user_ecc, NULL, NULL);
    if (ret != 0) { status = 0x6111; goto out; }
    /* At this point the user key should be complete. */
    if (wc_ecc_check_key(&user_ecc) != 0) {
        status = 0x6118; goto out;
    }
    /* Export public key */
    pubkey[0] = 0x04; /* First byte 0x04 indicating uncompressed
                       *  public key (qx, qy)
                       */
    ret = wc_ecc_export_public_raw(&user_ecc, &pubkey[1], &qxlen,
            &pubkey[1 + ecc_key_size], &qylen);
    if (ret != 0) { status = 0x6113; goto out; }

    /* Prepare the digest to sign */
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, &rfu_res, 1); /* RFU = 0 */
    wc_Sha256Update(&sha, application, PARAM_SZ); /* Application parameter */
    wc_Sha256Update(&sha, challenge, PARAM_SZ); /* Challenge parameter */
    wc_Sha256Update(&sha, handle_nonce, NONCE_SZ); /* handle: nonce part */
    wc_Sha256Update(&sha, handle_hash, HASH_SZ); /* handle: hash part */
    wc_Sha256Update(&sha, pubkey, PUBKEY_SZ); /* Public key */
    wc_Sha256Final(&sha, sig_hash);
    wc_Sha256Free(&sha);

    /* Sign the digest */
    memset(signature, 0, sizeof(signature));
    siglen = (word32)wc_ecc_sig_size(&cert_ecc);
#ifdef WOLFSSL_ECDSA_DETERMINISTIC_K
    (void)wc_ecc_set_deterministic(&cert_ecc, 1);
#endif
    ret = wc_ecc_sign_hash(sig_hash, HASH_SZ, signature, &siglen, &rng,
            &cert_ecc);
    ecc_release_sign_k(&cert_ecc);
    if (ret != 0) { status = 0x6119; goto out; }

    U2F_Counter_up();

    /* Populate reply message
     */
    U2F_cmd_reply[idx++] = 0x05; /* Legacy fixed first byte for the response */
    memcpy(&U2F_cmd_reply[idx], pubkey, PUBKEY_SZ);
    idx += PUBKEY_SZ;
    /* Copy key handle (nonce + hash) into reply */
    U2F_cmd_reply[idx++] = NONCE_SZ + HASH_SZ; /* Size of the handle */
    memcpy(&U2F_cmd_reply[idx], handle_nonce, NONCE_SZ);
    idx += NONCE_SZ;
    memcpy(&U2F_cmd_reply[idx], handle_hash, HASH_SZ);
    idx += HASH_SZ;
    /* Copy attestation certificate into reply */
    memcpy(&U2F_cmd_reply[idx], cert_att_der, cert_att_der_len);
    idx += cert_att_der_len;
    /* Copy signature */
    memcpy(&U2F_cmd_reply[idx], signature, siglen);
    idx += siglen;
    /* Send the reply */
    ctaphid_send(CTAP_CMD_MSG, (uint16_t)idx, true);

out:
    /* Single exit: scrub every secret, whichever path got us here. */
    if (rng_ok)  wc_FreeRng(&rng);
    if (user_ok) wc_ecc_free(&user_ecc);
    if (cert_ok) wc_ecc_free(&cert_ecc);
    ForceZero(&user_ecc, sizeof(ecc_key));
    ForceZero(&cert_ecc, sizeof(ecc_key));
    ForceZero(user_private, ECC_SZ);
    return status;
}



static uint16_t fido_auth(struct u2f_raw_hdr *hdr, uint16_t len)
{
    uint8_t *challenge, *application, *handle_nonce, *handle_hash;
    uint8_t private[ECC_SZ], handle_calculated_hash[HASH_SZ];
    uint8_t control = 0, handle_sz = 0, user_presence = 0;
    uint8_t sig_hash[HASH_SZ], signature[SIGMAX_SZ];
    uint32_t be_u2f_counter;
    word32 siglen = SIGMAX_SZ;
    uint8_t *msg_data;
    ecc_key user_ecc;
    WC_RNG rng;
    Sha256 sha;
    int ret;
    uint16_t status = ENOERR;
    bool rng_ok = false, user_ok = false;

    memset(private, 0, sizeof(private));

    /* Need challenge + application + handle length byte, then the handle */
    if (len < 2 * PARAM_SZ + 1)
        return EWRONGLEN;
    msg_data = U2F_Message.data + sizeof(struct u2f_raw_hdr);
    control = hdr->p1;
    challenge = msg_data;
    application = msg_data + PARAM_SZ;
    handle_sz = msg_data[PARAM_SZ + PARAM_SZ];
    handle_nonce = msg_data + PARAM_SZ + PARAM_SZ + 1;
    handle_hash = msg_data + PARAM_SZ + PARAM_SZ + 1 + NONCE_SZ;

    /* Only "check-only" (0x07) and "enforce user presence" (0x03) exist here.
     * "Sign with no presence" (0x08) is deliberately NOT supported: it would
     * let any host process produce a valid signature without a button press,
     * bypassing the second factor. */
    if (control != 0x07 && control != 0x03)
        return EWRONGDATA;
    if (handle_sz != (NONCE_SZ + HASH_SZ))
        return EWRONGDATA;
    if (len < 2 * PARAM_SZ + 1 + handle_sz)
        return EWRONGLEN;

    /* Prove the handle belongs to this device BEFORE asking for a button
     * press, so a foreign/forged handle cannot make the user press for it. */
    if (device_kdf(application, PARAM_SZ, handle_nonce, NONCE_SZ, private) != 0 ||
        device_kdf(application, PARAM_SZ, private, ECC_SZ, handle_calculated_hash) != 0) {
        status = 0x6126; goto out;
    }
    if (!u2f_ct_memeq(handle_calculated_hash, handle_hash, HASH_SZ)) {
        status = EWRONGDATA; goto out;
    }

    if (control == 0x07) {
        status = ECOND; /* "check-only": handle is ours */
        goto out;
    }

    if (!device_user_presence()) {
        status = ECOND; goto out;
    }
    user_presence = 0x01;

    if (wc_InitRng(&rng) != 0) { status = 0x6110; goto out; }
    rng_ok = true;
    if (wc_ecc_init(&user_ecc) < 0) { status = 0x6122; goto out; }
    user_ok = true;
    if (wc_ecc_import_private_key_ex(private, ECC_SZ, NULL, 0,
                &user_ecc, ECC_SECP256R1) != 0) { status = 0x6121; goto out; }
    ret = wc_ecc_make_pub_ex(&user_ecc, NULL, NULL);
    if (ret != 0) { status = 0x6121; goto out; }
    /* At this point the user key should be complete. */
    if (wc_ecc_check_key(&user_ecc) != 0) { status = 0x6128; goto out; }

    be_u2f_counter = __builtin_bswap32(U2F_Counter);
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, application, PARAM_SZ);       /* Application parameter */
    wc_Sha256Update(&sha, &user_presence, 1);           /* User presence byte */
    wc_Sha256Update(&sha, (void*)&be_u2f_counter, 4);   /* Usage counter */
    wc_Sha256Update(&sha, challenge, PARAM_SZ);         /* Challenge parameter */
    wc_Sha256Final(&sha, sig_hash);
    wc_Sha256Free(&sha);

    /* Sign the digest */
    memset(signature, 0, sizeof(signature));
    siglen = (uint16_t)wc_ecc_sig_size(&user_ecc);
#ifdef WOLFSSL_ECDSA_DETERMINISTIC_K
    (void)wc_ecc_set_deterministic(&user_ecc, 1);
#endif
    ret = wc_ecc_sign_hash(sig_hash, HASH_SZ, signature, &siglen, &rng,
            &user_ecc);
    ecc_release_sign_k(&user_ecc);
    if (ret != 0) { status = 0x6129; goto out; }

    memset(U2F_cmd_reply, 0, sizeof(U2F_cmd_reply));
    U2F_cmd_reply[0] = user_presence;
    memcpy(&U2F_cmd_reply[1], &be_u2f_counter, 4);
    memcpy(&U2F_cmd_reply[1 + 4], signature, siglen);

    U2F_Counter_up();

    /* Send the reply */
    ctaphid_send(CTAP_CMD_MSG, (uint16_t)(siglen + 5), true);

out:
    if (rng_ok)  wc_FreeRng(&rng);
    if (user_ok) wc_ecc_free(&user_ecc);
    ForceZero(&user_ecc, sizeof(ecc_key));
    ForceZero(private, ECC_SZ);
    return status;
}

static uint16_t fido_getversion(struct u2f_raw_hdr *hdr, uint16_t len)
{
    static const char proto_name[6] = { 'U', '2', 'F', '_', 'V', '2' };
    (void)hdr;
    (void)len;
    memcpy(U2F_cmd_reply, proto_name, sizeof(proto_name));
    ctaphid_send(CTAP_CMD_MSG, sizeof(proto_name), true);
    return ENOERR;
}

static uint16_t parse_u2f_raw_msg(void)
{
    struct u2f_raw_hdr *hdr = (struct u2f_raw_hdr *)(U2F_Message.data);
    uint32_t len = U2F_Message.len - sizeof(struct u2f_raw_hdr);


    if (U2F_Message.len < sizeof(struct u2f_raw_hdr))
        return EWRONGLEN;
    if (U2F_Message.len > U2FHID_MAX_PAYLOAD)
        return EWRONGLEN;
    if (hdr->cla != 0x00)
        return ECLAUNSUPP;
    switch(hdr->ins) {
        case U2F_REGISTER_INS:
            return fido_register(hdr, (uint16_t)len);
        case U2F_AUTHENTICATE_INS:
            return fido_auth(hdr, (uint16_t)len);
        case U2F_VERSION_INS:
            return fido_getversion(hdr, (uint16_t)len);
        case CTAP_CMD_CBOR:
            /* Should not reach here: CBOR handled at HID layer */
            return EINSUNSUPP;
        default:
            return EINSUNSUPP;
    }
    U2F_Message.len = 0;
    return 0x9000;
}

uint32_t device_get_counter(void)
{
    return U2F_Counter;
}

void device_counter_inc(void)
{
    U2F_Counter_up();
}

static void ctap_init_reply(uint32_t req_cid, const uint8_t *nonce)
{
    uint8_t reply[U2FHID_PACKET_SIZE];
    memset(reply, 0, sizeof(reply));
    uint32_t new_cid = req_cid;
    memcpy(reply, &req_cid, sizeof(uint32_t));
    reply[4] = CTAP_CMD_INIT | 0x80; 
    reply[5] = 0x00; /* Len MSB */
    reply[6] = 17;   /* Len LSB */
    memcpy(reply + 7, nonce, 8);
    if (req_cid == CTAPHID_BROADCAST_CID) {
        /* Hand out a fresh channel; never 0 or the broadcast id. */
        new_cid = U2F_next_cid++;
        if (new_cid == 0 || new_cid == CTAPHID_BROADCAST_CID)
            new_cid = U2F_next_cid++;
    }
    memcpy(reply + 15, &new_cid, 4);
    reply[19] = 2; /* CTAPHID protocol version */
    reply[20] = 2; /* Maj V*/
    reply[21] = 0; /* Min V*/
    reply[22] = 0; /* Build V */
    reply[23] = 0x05; /* cap flags: wink + CBOR */
    tud_hid_report(0, reply, U2FHID_PACKET_SIZE);
}

static uint16_t parse_u2f_raw(void)
{
    uint16_t ret;
    switch (U2F_Message.cmd) {
        case CTAP_CMD_INIT:
            ctap_init_reply(U2F_Message.cid, U2F_Message.data);
            return ENOERR;
        case CTAP_CMD_PING:
            /* Echo; the reply buffer bounds the size */
            if (U2F_Message.len > sizeof(U2F_cmd_reply)) {
                ctaphid_send_error(U2F_Message.cid, CTAPHID_ERR_INVALID_LEN);
                return ENOERR;
            }
            memcpy(U2F_cmd_reply, U2F_Message.data, U2F_Message.len);
            ctaphid_send(CTAP_CMD_PING, U2F_Message.len, false);
            return ENOERR;
        case CTAP_CMD_WINK:
            gpio_put(U2F_LED, 1);
            sleep_ms(100);
            gpio_put(U2F_LED, 0);
            ctaphid_send(CTAP_CMD_WINK, 0, false);
            return ENOERR;
        case CTAP_CMD_CANCEL:
            return ENOERR; /* presence waits are synchronous: nothing to cancel, no reply */
        case CTAP_CMD_MSG:
            ret =  parse_u2f_raw_msg();
            if (ret != ENOERR) {
                uint8_t err[2];
                memcpy(err, &ret, 2);
                U2F_cmd_reply[0] = err[1];
                U2F_cmd_reply[1] = err[0];
                ctaphid_send(CTAP_CMD_MSG, 2, false);
                ret = ENOERR;
            }
            break;
        case CTAP_CMD_CBOR: {
            uint16_t reply_len = 0;
            int ctap2_ret = ctap2_handle_cbor(U2F_Message.data, U2F_Message.len, U2F_cmd_reply, sizeof(U2F_cmd_reply), &reply_len);
            if (ctap2_ret == 0 && reply_len > 0) {
                ctaphid_send(CTAP_CMD_CBOR, reply_len, false);
                ret = ENOERR;
            } else {
                ctaphid_send_error(U2F_Message.cid, CTAPHID_ERR_OTHER);
                ret = ENOERR;
            }
            break;
        }
        default:
            ctaphid_send_error(U2F_Message.cid, CTAPHID_ERR_INVALID_CMD);
            return ENOERR;
    }
    return ret;
}

static bool u2f_msg_in_progress(void)
{
    return U2F_Message.len != 0 && U2F_Message.rx_len < U2F_Message.len;
}

int parse_u2fhid_packet(const uint8_t *data)
{
    const struct u2fhid_generic_packet *gp =
        (const struct u2fhid_generic_packet *)data;
    uint32_t now = device_uptime_ms();
    uint32_t pkt_cid;

    memcpy(&pkt_cid, data, sizeof(pkt_cid));
    if (pkt_cid == 0)
        return 0; /* channel 0 is reserved */

    /* A half-received message that has stalled is dropped (and reported). */
    if (u2f_msg_in_progress() && (uint32_t)(now - U2F_last_rx_ms) > CTAPHID_MSG_TIMEOUT_MS) {
        uint32_t old = U2F_Message.cid;
        memset(&U2F_Message, 0, sizeof(struct u2f_message));
        ctaphid_send_error(old, CTAPHID_ERR_MSG_TIMEOUT);
    }

    if ((gp->select & 0x80) == 0x80) {
        const struct u2fhid_init_packet *ip;
        uint16_t len;
        /* Init packet. */
        ip = (const struct u2fhid_init_packet *)gp;
        len = (uint16_t)((uint16_t)(ip->payload_len[0]) << 8U) + ip->payload_len[1];

        /* Another channel is mid-transfer: do not let this one disturb it.
         * A broadcast INIT is still answered (it only allocates a channel). */
        if (u2f_msg_in_progress() && pkt_cid != U2F_Message.cid) {
            if (pkt_cid == CTAPHID_BROADCAST_CID && (ip->hid_cmd & 0x7F) == CTAP_CMD_INIT && len == 8)
                ctap_init_reply(pkt_cid, ip->data);
            else
                ctaphid_send_error(pkt_cid, CTAPHID_ERR_CHANNEL_BUSY);
            return 0;
        }
        if (len > U2FHID_MAX_PAYLOAD) {
            ctaphid_send_error(pkt_cid, CTAPHID_ERR_INVALID_LEN);
            return EWRONGLEN;
        }
        if ((ip->hid_cmd & 0x7F) == CTAP_CMD_INIT && len != 8) {
            ctaphid_send_error(pkt_cid, CTAPHID_ERR_INVALID_LEN);
            return EWRONGLEN;
        }

        memset(&U2F_Message, 0, sizeof(struct u2f_message));
        U2F_Message.len = len;
        memcpy(&U2F_Message.cid, &ip->cid, sizeof(uint32_t));
        U2F_Message.cmd = ip->hid_cmd & 0x7F;
        memcpy(U2F_Message.data, ip->data, U2FHID_PACKET_SIZE - 7);
        U2F_Message.rx_len = U2FHID_PACKET_SIZE - 7;
        U2F_Message.exp_seq = 0;
        U2F_last_rx_ms = now;
    } else {
        /* Continuation packet */
        const struct u2fhid_cont_packet *cp;
        uint16_t sz_rx;
        cp = (const struct u2fhid_cont_packet *)gp;

        /* No message being assembled: discard. */
        if (!u2f_msg_in_progress())
            return 0;

        /* Only the channel that started the message may continue it; a frame
         * from any other channel must not be spliced into it. */
        if (cp->cid != U2F_Message.cid) {
            ctaphid_send_error(cp->cid, CTAPHID_ERR_CHANNEL_BUSY);
            return 0;
        }

        /* Wrong sequence number: abort the message and say so. */
        if (cp->seq != U2F_Message.exp_seq) {
            uint32_t old = U2F_Message.cid;
            memset(&U2F_Message, 0, sizeof(struct u2f_message));
            ctaphid_send_error(old, CTAPHID_ERR_INVALID_SEQ);
            return 0;
        }
        U2F_Message.exp_seq++;
        U2F_last_rx_ms = now;

        sz_rx = U2FHID_PACKET_SIZE - 5;
        if (sz_rx > (U2F_Message.len - U2F_Message.rx_len))
            sz_rx = U2F_Message.len - U2F_Message.rx_len;
        memcpy(U2F_Message.data + U2F_Message.rx_len, cp->data, sz_rx);
        U2F_Message.rx_len += sz_rx;
    }
    if (U2F_Message.rx_len > U2F_Message.len)
        U2F_Message.rx_len = U2F_Message.len;
    if (U2F_Message.rx_len == U2F_Message.len) {
        /* Finally parse the raw packet */
        uint16_t ret = parse_u2f_raw();
        if (ret != ENOERR) {
            uint32_t cid = U2F_Message.cid;
            memset(&U2F_Message, 0, sizeof(struct u2f_message));
            ctaphid_send_error(cid, CTAPHID_ERR_OTHER);
        } else {
            /* The message has been executed: retire it.  Without this, a
             * stray continuation packet carrying the next expected sequence
             * number re-ran the very same request (replay). */
            U2F_Message.len = 0;
            U2F_Message.rx_len = 0;
        }
    }
    return 0;
}

/* SET_REPORT is called with ID=0 and Type=0 when receiving data
 * on the 'OUT' endpoint
 */
void tud_hid_set_report_cb(uint8_t itf, uint8_t report_id, hid_report_type_t report_type, const uint8_t * buffer, uint16_t bufsize)
{
    (void) itf;
    (void) report_id;
    (void) report_type;

    if (bufsize != U2FHID_PACKET_SIZE)
        return;
    parse_u2fhid_packet(buffer);
    
}


uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type, uint8_t* buffer, uint16_t reqlen)
{
  (void) instance;
  (void) report_id;
  (void) report_type;
  (void) buffer;
  (void) reqlen;

  return 0;
}

void tud_hid_report_complete_cb(uint8_t instance, uint8_t const* report, uint8_t len)
{
    (void) instance;
    (void) len;
    (void) report;


    if (U2F_cmd_reply_size == 0)
        return;
    /* Continue sending if there are
     * any pending u2f reply, spanning over multiple frames 
     */
    if (U2F_cmd_reply_sent < U2F_cmd_reply_size) {
        uint16_t remain_size;
        uint8_t u2h_msg[U2FHID_PACKET_SIZE];
        memset(u2h_msg, 0, U2FHID_PACKET_SIZE);
        memcpy(u2h_msg, &U2F_cmd_reply_cid, sizeof(uint32_t));
        u2h_msg[4] = (uint8_t)(U2F_cmd_reply_seq & 0xFFU);
        U2F_cmd_reply_seq++;
        remain_size = U2FHID_PACKET_SIZE - 5;
        if (remain_size > U2F_cmd_reply_size - U2F_cmd_reply_sent)
            remain_size = (uint16_t)(U2F_cmd_reply_size - U2F_cmd_reply_sent);
        memcpy(u2h_msg + 5, U2F_cmd_reply + U2F_cmd_reply_sent, remain_size); 
        U2F_cmd_reply_sent += remain_size;
        tud_hid_report(0, u2h_msg, U2FHID_PACKET_SIZE);
    } else {
        U2F_cmd_reply_sent = 0;
        U2F_cmd_reply_size = 0;
        U2F_cmd_reply_seq = 0;
    }
}
