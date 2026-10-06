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
#include "wolfssl/wolfcrypt/sha256.h"
#include "ctap2.h"
#include "device_state.h"
#include "pins.h"
#include "se.h"
#include "cred_store.h"
#include "att_cert.h"
#include "hw_sign.h"


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
#define FLASH_LEGACY_MKEY   0x72000     /* old firmware kept a software master key here */
#define FLASH_CTR0 *((uint32_t *)(XIP_BASE + FLASH_CTR_ADDR0_OFF))
#define FLASH_CTR1 *((uint32_t *)(XIP_BASE + FLASH_CTR_ADDR1_OFF))

static uint32_t U2F_Counter = 0;
static uint8_t g_serial[SE_SERIAL_LEN];

static void write_counter_page(uint32_t flash_off, uint32_t value)
{
    uint8_t page_buf[FLASH_PAGE_SIZE];
    memcpy(page_buf, (const void *)(XIP_BASE + flash_off), FLASH_PAGE_SIZE);
    memcpy(page_buf, &value, 4);
    flash_range_program(flash_off, page_buf, FLASH_PAGE_SIZE);
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

/* Older firmware stored a software master key here.  This firmware has no
 * software key at all, so make sure no copy survives an upgrade. */
static void __not_in_flash_func(wipe_legacy_key)(void)
{
    const uint8_t *p = (const uint8_t *)(XIP_BASE + FLASH_LEGACY_MKEY);
    for (int i = 0; i < 64; i++) {
        if (p[i] != 0xFF) {
            flash_range_erase(FLASH_LEGACY_MKEY, FLASH_SECTOR_SIZE);
            return;
        }
    }
}

/* Called once after se_init().  Returns 0 or an SE_E_* code (the caller blinks it and stays off USB). */
int u2f_init(void)
{
    int r;

    if (!se_active())
        return SE_E_NO_DEVICE;                  /* hardware-only: there is no software mode */
    if (se_serial(g_serial) != 0)
        return SE_E_COMM;

    wipe_legacy_key();
    U2F_Counter = U2F_Counter_load();

    r = cred_store_open(g_serial);
    if (r == CRED_E_CHIP)
        return SE_E_CHIP_CHANGED;
    if (r < 0)
        return SE_E_COMM;
    r = att_cert_init(g_serial);
    if (r == ATT_E_CHIP)
        return SE_E_CHIP_CHANGED;
    if (r < 0)
        return SE_E_NO_ATT_KEY;
    return SE_OK;
}

/* authenticatorReset: forget every credential AND destroy its private key in
 * the chip (a fresh random key replaces it), so nothing of the old credentials
 * survives.  The attestation key is kept. */
int device_reset_credentials(void)
{
    uint8_t x[32], y[32];
    int r = cred_wipe();
    for (unsigned i = 0; i < SE_CRED_SLOTS; i++) {
        if (se_genkey((uint8_t)(SE_CRED_SLOT_FIRST + i), x, y) != 0)
            r = -1;
    }
    return r;
}

/* Credential id: 64 random bytes from the chip's TRNG. */
static int new_credential_id(uint8_t id[CRED_ID_LEN])
{
    return (se_random32(id) == 0 && se_random32(id + 32) == 0) ? 0 : -1;
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
    uint8_t digest[HASH_SZ];
    uint8_t handle[CRED_ID_LEN];
    uint8_t pub[64];
    uint8_t sig[80];
    uint16_t siglen = 0;
    uint8_t rfu_res = 0;
    uint8_t *challenge, *application;
    uint8_t slot;
    uint16_t certlen;
    const uint8_t *cert;
    wc_Sha256 sha;
    uint32_t idx = 0;
    uint16_t status = ENOERR;
    int r;

    /* The request must really contain challenge + application parameters. */
    if (len < 2 * PARAM_SZ)
        return EWRONGLEN;

    challenge = U2F_Message.data + sizeof(struct u2f_raw_hdr);
    application = U2F_Message.data + sizeof(struct u2f_raw_hdr) + PARAM_SZ;
    (void)hdr;

    if (!device_user_presence())
        return ECOND;

    if (cred_pick_free(&slot) != CRED_OK)
        return 0x6A84;                                  /* no free key slot in the chip */
    if (new_credential_id(handle) != 0)
        return 0x6110;
    /* The private key is created INSIDE the chip; only the public key comes out. */
    if (se_genkey(slot, pub + 0, pub + 32) != 0)
        return 0x6111;

    /* Signature input: 0x00 || application || challenge || key handle || public key (04 || X || Y) */
    if (wc_InitSha256(&sha) != 0)
        return 0x6114;
    wc_Sha256Update(&sha, &rfu_res, 1);
    wc_Sha256Update(&sha, application, PARAM_SZ);
    wc_Sha256Update(&sha, challenge, PARAM_SZ);
    wc_Sha256Update(&sha, handle, CRED_ID_LEN);
    {
        uint8_t uncompressed = 0x04;
        wc_Sha256Update(&sha, &uncompressed, 1);
        wc_Sha256Update(&sha, pub, 64);
    }
    wc_Sha256Final(&sha, digest);
    wc_Sha256Free(&sha);

    /* Attestation signature: made by the attestation key inside the chip. */
    r = hw_sign_der(SE_ATT_SLOT, att_cert_pub(), digest, sig, &siglen);
    if (r != 0)
        return 0x6119;

    if (cred_commit(slot, application, handle, pub) != CRED_OK)
        return 0x6A84;

    U2F_Counter_up();

    cert = att_cert_der(&certlen);
    U2F_cmd_reply[idx++] = 0x05;                        /* legacy fixed first byte */
    U2F_cmd_reply[idx++] = 0x04;
    memcpy(&U2F_cmd_reply[idx], pub, 64);
    idx += 64;
    U2F_cmd_reply[idx++] = CRED_ID_LEN;
    memcpy(&U2F_cmd_reply[idx], handle, CRED_ID_LEN);
    idx += CRED_ID_LEN;
    memcpy(&U2F_cmd_reply[idx], cert, certlen);
    idx += certlen;
    memcpy(&U2F_cmd_reply[idx], sig, siglen);
    idx += siglen;
    ctaphid_send(CTAP_CMD_MSG, (uint16_t)idx, true);
    return status;
}

static uint16_t fido_auth(struct u2f_raw_hdr *hdr, uint16_t len)
{
    uint8_t *challenge, *application, *handle;
    uint8_t control, handle_sz, user_presence = 0, slot;
    uint8_t digest[HASH_SZ], sig[80], pub[64];
    uint16_t siglen = 0;
    uint32_t be_u2f_counter;
    uint8_t *msg_data;
    wc_Sha256 sha;

    /* Need challenge + application + handle length byte, then the handle */
    if (len < 2 * PARAM_SZ + 1)
        return EWRONGLEN;
    msg_data = U2F_Message.data + sizeof(struct u2f_raw_hdr);
    control = hdr->p1;
    challenge = msg_data;
    application = msg_data + PARAM_SZ;
    handle_sz = msg_data[PARAM_SZ + PARAM_SZ];
    handle = msg_data + PARAM_SZ + PARAM_SZ + 1;

    /* Only "check-only" (0x07) and "enforce user presence" (0x03).  "Sign without
     * presence" (0x08) is deliberately not supported. */
    if (control != 0x07 && control != 0x03)
        return EWRONGDATA;
    if (handle_sz != CRED_ID_LEN)
        return EWRONGDATA;
    if (len < 2 * PARAM_SZ + 1 + handle_sz)
        return EWRONGLEN;

    /* The handle must name a key that exists in THIS chip for THIS relying party,
     * checked BEFORE asking for a button press. */
    if (cred_find(application, handle, &slot, pub) != CRED_OK)
        return EWRONGDATA;
    if (control == 0x07)
        return ECOND;                                   /* "check-only": handle is ours */

    if (!device_user_presence())
        return ECOND;
    user_presence = 0x01;

    be_u2f_counter = __builtin_bswap32(U2F_Counter);
    if (wc_InitSha256(&sha) != 0)
        return 0x6124;
    wc_Sha256Update(&sha, application, PARAM_SZ);
    wc_Sha256Update(&sha, &user_presence, 1);
    wc_Sha256Update(&sha, (void *)&be_u2f_counter, 4);
    wc_Sha256Update(&sha, challenge, PARAM_SZ);
    wc_Sha256Final(&sha, digest);
    wc_Sha256Free(&sha);

    if (hw_sign_der(slot, pub, digest, sig, &siglen) != 0)
        return 0x6129;

    memset(U2F_cmd_reply, 0, sizeof(U2F_cmd_reply));
    U2F_cmd_reply[0] = user_presence;
    memcpy(&U2F_cmd_reply[1], &be_u2f_counter, 4);
    memcpy(&U2F_cmd_reply[1 + 4], sig, siglen);

    U2F_Counter_up();
    ctaphid_send(CTAP_CMD_MSG, (uint16_t)(siglen + 5), true);
    return ENOERR;
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
