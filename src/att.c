/* Fidelio
 *
 * (c) 2026 Daniele Lacamera <root@danielinux.net>
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

/* Per-device attestation key and certificate. See att.h for the why. */

#include <string.h>
#include "att.h"
#include "device_state.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/kdf.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/misc.h"

#define ECC_SZ   32
#define HASH_SZ  32

/* Domain separation for the attestation key. Distinct from the credential
 * label ("fidelio-cred-v2", cred_alg.c) so the two derivations can never
 * collide, and versioned so a future key-format change is a label change.
 */
#define ATT_LABEL     "fidelio-attest-v1"
#define ATT_LABEL_LEN (sizeof(ATT_LABEL) - 1)

/* The generated certificate: same distinguished name, validity window and
 * extensions as the development certificate it replaces, so only the public
 * key, the serial and the signature differ per unit. 546 bytes there; the
 * slack absorbs a shorter or longer ECDSA signature.
 */
#define ATT_CERT_MAX 768

/* The cached certificate is only good for the master secret it was built
 * from. CTAP2_CMD_RESET rotates the PUF salt and re-derives that secret in
 * place, with no reboot (puf_rotate_salt()), so a cache keyed on "have we
 * built one yet" would keep serving a certificate whose public key no longer
 * matches the signing key: packed attestation would stop verifying and
 * registration would stay broken until a power cycle. Keying it on a tag of
 * the secret covers any future in-place rotation too, with no reset hook for
 * a later caller to forget.
 */
#define ATT_TAG_LABEL "fidelio-attest-tag-v1"
#define ATT_TAG_SZ    8

/* id-fido-u2f-ce-transports. wolfSSL has no token for it, hence
 * WOLFSSL_EKU_OID in user_settings.h.
 */
#define ATT_EKU_OID "1.3.6.1.4.1.45724.2.1.1"

static uint8_t att_cert[ATT_CERT_MAX];
static uint32_t att_cert_len = 0;
static uint8_t att_cert_tag[ATT_TAG_SZ];

/* One-way and truncated, so it identifies the secret without standing in for
 * it. A separate label from the key derivation keeps the two independent.
 */
static int att_secret_tag(const uint8_t *secret, uint8_t *tag)
{
    return wc_HKDF_Expand(WC_SHA256, secret, HASH_SZ,
                          (const byte *)ATT_TAG_LABEL,
                          (word32)(sizeof(ATT_TAG_LABEL) - 1), tag,
                          ATT_TAG_SZ);
}

static int att_derive_priv(const uint8_t *secret, uint8_t counter,
                           uint8_t *priv)
{
    uint8_t info[ATT_LABEL_LEN + 1];
    int ret;

    memcpy(info, ATT_LABEL, ATT_LABEL_LEN);
    info[ATT_LABEL_LEN] = counter;
    ret = wc_HKDF_Expand(WC_SHA256, secret, HASH_SZ, info, sizeof(info),
                         priv, ECC_SZ);
    ForceZero(info, sizeof(info));
    return ret;
}

int att_key_init(ecc_key *key)
{
    const uint8_t *secret;
    uint8_t priv[ECC_SZ];
    uint8_t attempt;
    int ret = -1;

    if (key == NULL)
        return -1;
    secret = device_get_secret();
    if (secret == NULL)
        return -1;

    /* A raw 32-byte value is only a valid P-256 scalar when it lands below
     * the group order; the counter walks to the next candidate when it does
     * not. Same construction as derive_ecc() in cred_alg.c.
     */
    for (attempt = 0; attempt < 16; attempt++) {
        if (att_derive_priv(secret, attempt, priv) != 0)
            break;
        if (wc_ecc_init(key) != 0)
            break;
        if (wc_ecc_import_private_key_ex(priv, sizeof(priv), NULL, 0, key,
                                         ECC_SECP256R1) == 0 &&
            wc_ecc_make_pub(key, NULL) == 0) {
            ret = 0;
            break;
        }
        wc_ecc_free(key);
    }

    ForceZero(priv, sizeof(priv));
    /* Callers free cert_ecc from a shared cleanup path, so a failure here has
     * to leave something safe to free rather than the struct wc_ecc_free()
     * already ran over. All-zero is the state wc_ecc_init() produces.
     */
    if (ret != 0)
        memset(key, 0, sizeof(*key));
    return ret;
}

/* UTCTime, tag and length included: wolfSSL reads these fields as encoded
 * DER. Setting them explicitly keeps cert generation off XTIME, which this
 * board has no clock to answer.
 */
static void att_set_validity(Cert *cert)
{
    cert->beforeDate[0] = ASN_UTC_TIME;
    cert->beforeDate[1] = ASN_UTC_TIME_SIZE - 1;
    memcpy(cert->beforeDate + 2, "260930000000Z", ASN_UTC_TIME_SIZE - 1);
    cert->beforeDateSz = ASN_UTC_TIME_SIZE + 1;

    cert->afterDate[0] = ASN_UTC_TIME;
    cert->afterDate[1] = ASN_UTC_TIME_SIZE - 1;
    memcpy(cert->afterDate + 2, "360930000000Z", ASN_UTC_TIME_SIZE - 1);
    cert->afterDateSz = ASN_UTC_TIME_SIZE + 1;
}

/* Serial from the public key, so it is stable for the unit and distinct
 * between units without needing stored state. The top bit is cleared to keep
 * the DER INTEGER positive without a leading pad byte.
 */
static int att_set_serial(Cert *cert, ecc_key *key)
{
    uint8_t qx[ECC_SZ], qy[ECC_SZ];
    word32 qxlen = sizeof(qx), qylen = sizeof(qy);
    uint8_t digest[HASH_SZ];
    wc_Sha256 sha;
    int ret = -1;

    if (wc_ecc_export_public_raw(key, qx, &qxlen, qy, &qylen) != 0)
        return -1;
    if (wc_InitSha256(&sha) != 0)
        return -1;
    if (wc_Sha256Update(&sha, qx, qxlen) == 0 &&
        wc_Sha256Update(&sha, qy, qylen) == 0 &&
        wc_Sha256Final(&sha, digest) == 0) {
        memcpy(cert->serial, digest, CTC_SERIAL_SIZE);
        cert->serial[0] &= 0x7f;
        if (cert->serial[0] == 0)
            cert->serial[0] = 1;
        cert->serialSz = CTC_SERIAL_SIZE;
        ret = 0;
    }
    wc_Sha256Free(&sha);
    ForceZero(digest, sizeof(digest));
    return ret;
}

static void att_set_name(Cert *cert)
{
    /* The development certificate's distinguished name, with the
     * organizational unit set to the value WebAuthn packed attestation
     * requires. wc_MakeCert copies the subject into the issuer for a
     * self-signed certificate, so only the subject is filled here.
     */
    strcpy(cert->subject.country, "ZZ");
    strcpy(cert->subject.state, "StateName");
    strcpy(cert->subject.locality, "CityName");
    strcpy(cert->subject.unit, "Authenticator Attestation");
    strcpy(cert->subject.org, "Fidelio-U2F");
    strcpy(cert->subject.commonName, "U2F-HID");
}

static int att_cert_build(WC_RNG *rng)
{
    /* Static: an ecc_key local would put an 800+ byte frame on a 4 KB
     * stack that already carries the fido_register chain above us.
     * Single-threaded firmware; zeroed on every exit path. */
    static ecc_key key;
    Cert *cert;
    int body, ret = -1;

    if (att_key_init(&key) != 0)
        return -1;

    /* ~6 KB with the certificate-extension fields; the main stack is 4 KB
     * (PICO_STACK_SIZE), so this cannot be a local.
     */
    cert = (Cert *)XMALLOC(sizeof(Cert), NULL, DYNAMIC_TYPE_CERT);
    if (cert == NULL)
        goto out_key;

    if (wc_InitCert(cert) != 0)
        goto out_cert;
    cert->sigType = CTC_SHA256wECDSA;
    cert->selfSigned = 1;
    cert->isCA = 0;
    cert->daysValid = 0;    /* superseded by the explicit dates below */
    att_set_validity(cert);
    att_set_name(cert);
    if (att_set_serial(cert, &key) != 0)
        goto out_cert;
    if (wc_SetSubjectKeyIdFromPublicKey_ex(cert, ECC_TYPE, &key) != 0)
        goto out_cert;
    /* id-fido-u2f-ce-transports, as the development certificate carried it.
     */
    if (wc_SetExtKeyUsageOID(cert, ATT_EKU_OID, sizeof(ATT_EKU_OID) - 1, 0,
                             NULL) != 0)
        goto out_cert;

    body = wc_MakeCert_ex(cert, att_cert, sizeof(att_cert), ECC_TYPE, &key,
                          rng);
    if (body < 0)
        goto out_cert;
    body = wc_SignCert_ex(cert->bodySz, cert->sigType, att_cert,
                          sizeof(att_cert), ECC_TYPE, &key, rng);
    if (body < 0)
        goto out_cert;

    att_cert_len = (uint32_t)body;
    ret = 0;

out_cert:
    ForceZero(cert, sizeof(Cert));
    XFREE(cert, NULL, DYNAMIC_TYPE_CERT);
out_key:
    wc_ecc_free(&key);
    ForceZero(&key, sizeof(key));
    if (ret != 0)
        att_cert_len = 0;
    return ret;
}

int att_cert_get(WC_RNG *rng, const uint8_t **der, uint32_t *der_len)
{
    const uint8_t *secret;
    uint8_t tag[ATT_TAG_SZ];
    int ret = -1;

    if (rng == NULL || der == NULL || der_len == NULL)
        return -1;
    secret = device_get_secret();
    if (secret == NULL)
        return -1;
    if (att_secret_tag(secret, tag) != 0)
        return -1;

    if (att_cert_len == 0 || memcmp(tag, att_cert_tag, ATT_TAG_SZ) != 0) {
        if (att_cert_build(rng) == 0) {
            memcpy(att_cert_tag, tag, ATT_TAG_SZ);
            ret = 0;
        }
    } else {
        ret = 0;
    }

    ForceZero(tag, sizeof(tag));
    if (ret != 0)
        return -1;
    *der = att_cert;
    *der_len = att_cert_len;
    return 0;
}
