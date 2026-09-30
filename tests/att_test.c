/* Host test for src/att.c: the per-device attestation key and the self-signed
 * certificate built around it.
 *
 * Needs a host wolfSSL with certificate generation:
 *   ./configure --enable-cryptonly --enable-ecc --enable-certgen \
 *               --enable-certext --enable-keygen --enable-hkdf \
 *               CFLAGS="-DWOLFSSL_EKU_OID -DHAVE_OID_ENCODING"
 * run_host_tests.sh skips this test when no such build is present.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include "att.h"

/* Stands in for the PUF-reconstructed master secret. */
static unsigned char secret[32];

const unsigned char *device_get_secret(void)
{
    return secret;
}

static void set_secret(unsigned char fill)
{
    memset(secret, fill, sizeof(secret));
}

static void pub_of(ecc_key *k, unsigned char *qx, unsigned char *qy)
{
    word32 qxlen = 32, qylen = 32;
    assert(wc_ecc_export_public_raw(k, qx, &qxlen, qy, &qylen) == 0);
    assert(qxlen == 32 && qylen == 32);
}

static void dump(const char *path, const unsigned char *buf, unsigned int len)
{
    FILE *f = fopen(path, "wb");
    assert(f != NULL);
    assert(fwrite(buf, 1, len, f) == len);
    fclose(f);
}

/* The uncompressed point, for openssl to compare against the certificate. */
static void dump_pub(const char *path, const unsigned char *qx,
                     const unsigned char *qy)
{
    FILE *f = fopen(path, "wb");
    assert(f != NULL);
    fputc(0x04, f);
    assert(fwrite(qx, 1, 32, f) == 32);
    assert(fwrite(qy, 1, 32, f) == 32);
    fclose(f);
}

int main(void)
{
    ecc_key a, b;
    unsigned char ax[32], ay[32], bx[32], by[32];
    const unsigned char *der;
    unsigned int der_len;
    WC_RNG rng;

    assert(wc_InitRng(&rng) == 0);

    /* Deterministic: the same master secret always yields the same key. */
    set_secret(0x11);
    assert(att_key_init(&a) == 0);
    pub_of(&a, ax, ay);
    assert(att_key_init(&b) == 0);
    pub_of(&b, bx, by);
    assert(memcmp(ax, bx, 32) == 0 && memcmp(ay, by, 32) == 0);
    /* The derived key is a usable P-256 key pair, private half included. */
    assert(wc_ecc_check_key(&a) == 0);
    wc_ecc_free(&b);

    /* Per device: a different master secret yields a different key. This is
     * the whole point of the change - one extraction must not cover the
     * fleet the way the shared built-in key did.
     */
    set_secret(0x22);
    assert(att_key_init(&b) == 0);
    pub_of(&b, bx, by);
    assert(memcmp(ax, bx, 32) != 0);
    wc_ecc_free(&b);
    wc_ecc_free(&a);

    /* The certificate is built around that same key. */
    set_secret(0x11);
    assert(att_cert_get(&rng, &der, &der_len) == 0);
    assert(der_len > 0 && der_len < 768);

    /* Cached: the second call must not re-sign or move. */
    {
        const unsigned char *der2;
        unsigned int len2;
        assert(att_cert_get(&rng, &der2, &len2) == 0);
        assert(der2 == der && len2 == der_len);
    }

    dump("att_test_cert.der", der, der_len);
    dump_pub("att_test_pub.bin", ax, ay);

    /* Regression: CTAP2_CMD_RESET rotates the PUF salt and re-derives the
     * master secret in place, without a reboot. A cache keyed on "have we
     * built one yet" kept serving the old certificate, so makeCredential
     * signed with the new key while x5c carried the old public key and
     * packed attestation stopped verifying until a power cycle.
     */
    {
        const unsigned char *der_b;
        unsigned int len_b;
        unsigned char old_der[768];
        unsigned int old_len = der_len;

        assert(der_len <= sizeof(old_der));
        memcpy(old_der, der, der_len);

        set_secret(0x33);
        assert(att_cert_get(&rng, &der_b, &len_b) == 0);
        assert(len_b != old_len || memcmp(der_b, old_der, old_len) != 0);

        /* And the fresh certificate must carry the key the new secret
         * derives, which is what the shell side goes on to verify.
         */
        assert(att_key_init(&a) == 0);
        pub_of(&a, ax, ay);
        wc_ecc_free(&a);
        dump("att_test_cert_rotated.der", der_b, len_b);
        dump_pub("att_test_pub_rotated.bin", ax, ay);
    }

    wc_FreeRng(&rng);
    printf("att_test: passed (cert %u bytes, rebuilt after secret rotation)\n",
           der_len);
    return 0;
}
