/* Minimal DER writer for the attestation certificate and ECDSA signatures.
 * No dependency on wolfSSL: it only formats public data. */
#include <string.h>
#include "att_der.h"

#ifndef ATT_SUBJ_O
#define ATT_SUBJ_O  "Fidelio-U2F"
#endif
#ifndef ATT_SUBJ_OU
#define ATT_SUBJ_OU "Fidelio"
#endif
#ifndef ATT_SUBJ_CN
#define ATT_SUBJ_CN "U2F-HID"
#endif

static int put_len(uint8_t *o, size_t cap, size_t n)
{
    if (n < 0x80) { if (cap < 1) return -1; o[0] = (uint8_t)n; return 1; }
    if (n < 0x100) { if (cap < 2) return -1; o[0] = 0x81; o[1] = (uint8_t)n; return 2; }
    if (cap < 3) return -1;
    o[0] = 0x82; o[1] = (uint8_t)(n >> 8); o[2] = (uint8_t)n; return 3;
}

/* tag || len || content ; returns total length or -1.  `c` may be the same buffer as `o`
 * (in-place wrapping): the content is moved first, the header written afterwards. */
static int tlv(uint8_t *o, size_t cap, uint8_t tag, const uint8_t *c, size_t n)
{
    uint8_t hdr[3];
    int l = put_len(hdr, sizeof(hdr), n);
    if (l < 0 || cap < 1 + (size_t)l + n) return -1;
    memmove(o + 1 + l, c, n);
    o[0] = tag;
    memcpy(o + 1, hdr, (size_t)l);
    return 1 + l + (int)n;
}

int att_der_sig(const uint8_t raw[64], uint8_t *out, size_t cap)
{
    uint8_t tmp[2 + 33 + 2 + 33];
    size_t p = 0;
    for (int part = 0; part < 2; part++) {
        const uint8_t *v = raw + 32 * part;
        size_t skip = 0, n;
        while (skip < 31 && v[skip] == 0) skip++;
        n = 32 - skip;
        tmp[p++] = 0x02;
        tmp[p++] = (uint8_t)(n + ((v[skip] & 0x80) ? 1 : 0));
        if (v[skip] & 0x80) tmp[p++] = 0x00;
        memcpy(tmp + p, v + skip, n);
        p += n;
    }
    return tlv(out, cap, 0x30, tmp, p);
}

static const uint8_t OID_ECDSA_SHA256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
static const uint8_t OID_EC_PUBKEY[]    = { 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
static const uint8_t OID_P256[]         = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static const uint8_t OID_EKU[]          = { 0x06, 0x03, 0x55, 0x1D, 0x25 };
static const uint8_t OID_FIDO_USB[]     = { 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xE5, 0x1C, 0x02, 0x01, 0x01 };

/* RDN: SET { SEQ { OID(2.5.4.x), UTF8String } } */
static int rdn(uint8_t *o, size_t cap, uint8_t attr, const char *s)
{
    uint8_t seq[64]; int n = 0, l;
    seq[n++] = 0x06; seq[n++] = 0x03; seq[n++] = 0x55; seq[n++] = 0x04; seq[n++] = attr;
    l = tlv(seq + n, sizeof(seq) - n, 0x0C, (const uint8_t *)s, strlen(s));
    if (l < 0) return -1;
    n += l;
    l = tlv(seq, sizeof(seq), 0x30, seq, n);          /* SEQ over the OID + string */
    if (l < 0) return -1;
    return tlv(o, cap, 0x31, seq, l);
}

static int name(uint8_t *o, size_t cap)
{
    uint8_t b[96]; int n = 0, l;
    if ((l = rdn(b + n, sizeof(b) - n, 0x0A, ATT_SUBJ_O)) < 0)  return -1; n += l;
    if ((l = rdn(b + n, sizeof(b) - n, 0x0B, ATT_SUBJ_OU)) < 0) return -1; n += l;
    if ((l = rdn(b + n, sizeof(b) - n, 0x03, ATT_SUBJ_CN)) < 0) return -1; n += l;
    return tlv(o, cap, 0x30, b, n);
}

int att_der_tbs(const uint8_t x[32], const uint8_t y[32], const uint8_t serial8[8], uint8_t *out, size_t cap)
{
    uint8_t b[400]; int n = 0, l;
    uint8_t inner[160];

    /* version [0] EXPLICIT INTEGER 2 (v3) */
    static const uint8_t ver[] = { 0xA0, 0x03, 0x02, 0x01, 0x02 };
    memcpy(b + n, ver, sizeof(ver)); n += sizeof(ver);
    /* serial: positive, 8 bytes, first byte non-zero */
    b[n++] = 0x02; b[n++] = 0x08;
    memcpy(b + n, serial8, 8);
    b[n] = (uint8_t)((b[n] & 0x7F) | 0x40);
    n += 8;
    /* signature algorithm */
    l = tlv(b + n, sizeof(b) - n, 0x30, OID_ECDSA_SHA256, sizeof(OID_ECDSA_SHA256));
    if (l < 0) return -1; n += l;
    /* issuer */
    if ((l = name(b + n, sizeof(b) - n)) < 0) return -1; n += l;
    /* validity: 2020-01-01 .. 2049-12-31 (UTCTime) */
    {
        static const uint8_t nb[] = { 0x17, 0x0D, '2','0','0','1','0','1','0','0','0','0','0','0','Z' };
        static const uint8_t na[] = { 0x17, 0x0D, '4','9','1','2','3','1','2','3','5','9','5','9','Z' };
        memcpy(inner, nb, sizeof(nb)); memcpy(inner + sizeof(nb), na, sizeof(na));
        if ((l = tlv(b + n, sizeof(b) - n, 0x30, inner, sizeof(nb) + sizeof(na))) < 0) return -1; n += l;
    }
    /* subject */
    if ((l = name(b + n, sizeof(b) - n)) < 0) return -1; n += l;
    /* SubjectPublicKeyInfo */
    {
        uint8_t alg[32], bs[66]; int an = 0;
        memcpy(alg, OID_EC_PUBKEY, sizeof(OID_EC_PUBKEY)); an += sizeof(OID_EC_PUBKEY);
        memcpy(alg + an, OID_P256, sizeof(OID_P256)); an += sizeof(OID_P256);
        l = tlv(inner, sizeof(inner), 0x30, alg, an); if (l < 0) return -1;     /* AlgorithmIdentifier */
        bs[0] = 0x00; bs[1] = 0x04; memcpy(bs + 2, x, 32); memcpy(bs + 34, y, 32);
        {
            uint8_t bsd[80];
            int bl = tlv(bsd, sizeof(bsd), 0x03, bs, 66); if (bl < 0) return -1;
            memcpy(inner + l, bsd, bl);
            l += bl;
        }
        if ((l = tlv(b + n, sizeof(b) - n, 0x30, inner, l)) < 0) return -1; n += l;
    }
    /* extensions [3] { SEQ { SEQ { EKU oid, OCTET STRING { SEQ { FIDO-USB oid } } } } } */
    {
        uint8_t e1[40], e2[40]; int p, q;
        q = tlv(e1, sizeof(e1), 0x30, OID_FIDO_USB, sizeof(OID_FIDO_USB)); if (q < 0) return -1;
        q = tlv(e2, sizeof(e2), 0x04, e1, q);                               if (q < 0) return -1;
        p = sizeof(OID_EKU); memcpy(e1, OID_EKU, p); memcpy(e1 + p, e2, q); p += q;
        p = tlv(e2, sizeof(e2), 0x30, e1, p);                               if (p < 0) return -1;   /* Extension */
        p = tlv(e1, sizeof(e1), 0x30, e2, p);                               if (p < 0) return -1;   /* Extensions */
        p = tlv(b + n, sizeof(b) - n, 0xA3, e1, p);                         if (p < 0) return -1;
        n += p;
    }
    return tlv(out, cap, 0x30, b, n);
}

int att_der_cert(const uint8_t *tbs, size_t tbs_len, const uint8_t sig_raw[64], uint8_t *out, size_t cap)
{
    uint8_t sd[80], bs[82], alg[16], body[520]; int n = 0, l, sl;
    if (tbs_len > 400) return -1;
    sl = att_der_sig(sig_raw, sd, sizeof(sd)); if (sl < 0) return -1;
    bs[0] = 0x00; memcpy(bs + 1, sd, sl);
    memcpy(body, tbs, tbs_len); n = (int)tbs_len;
    l = tlv(alg, sizeof(alg), 0x30, OID_ECDSA_SHA256, sizeof(OID_ECDSA_SHA256)); if (l < 0) return -1;
    memcpy(body + n, alg, l); n += l;
    l = tlv(body + n, sizeof(body) - n, 0x03, bs, 1 + sl); if (l < 0) return -1; n += l;
    return tlv(out, cap, 0x30, body, n);
}
