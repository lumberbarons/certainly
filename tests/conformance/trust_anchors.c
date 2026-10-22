/*
 * trust_anchors.c — PEM to br_x509_trust_anchor, host-only (uses malloc).
 */

#include "trust_anchors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    unsigned char *data;
    size_t         len;
    size_t         cap;
    int            oom;
} bytes;

static void bytes_append(void *ctx, const void *src, size_t n)
{
    bytes *b = (bytes *)ctx;

    if (b->oom) return;
    if (b->len + n > b->cap) {
        size_t cap = b->cap ? b->cap : 1024;
        unsigned char *p;

        while (cap < b->len + n) cap *= 2;
        p = (unsigned char *)realloc(b->data, cap);
        if (p == NULL) {
            b->oom = 1;
            return;
        }
        b->data = p;
        b->cap = cap;
    }
    memcpy(b->data + b->len, src, n);
    b->len += n;
}

static int read_file(const char *path, bytes *out)
{
    FILE *f = fopen(path, "rb");
    unsigned char chunk[4096];
    size_t n;

    if (f == NULL) return -1;
    while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0) {
        bytes_append(out, chunk, n);
    }
    fclose(f);
    return out->oom ? -1 : 0;
}

static void free_ta(br_x509_trust_anchor *ta)
{
    free(ta->dn.data);
    if (ta->pkey.key_type == BR_KEYTYPE_RSA) {
        free(ta->pkey.key.rsa.n);
        free(ta->pkey.key.rsa.e);
    } else if (ta->pkey.key_type == BR_KEYTYPE_EC) {
        free(ta->pkey.key.ec.q);
    }
    memset(ta, 0, sizeof(*ta));
}

static unsigned char *dup_bytes(const unsigned char *src, size_t len)
{
    unsigned char *p = (unsigned char *)malloc(len ? len : 1);

    if (p != NULL) memcpy(p, src, len);
    return p;
}

/* Fill `ta` from one DER certificate; 0 on success. */
static int make_anchor(const unsigned char *der, size_t der_len,
                       br_x509_trust_anchor *ta, char *err, size_t errlen)
{
    br_x509_decoder_context dc;
    bytes dn = { NULL, 0, 0, 0 };
    const br_x509_pkey *pk;

    br_x509_decoder_init(&dc, bytes_append, &dn);
    br_x509_decoder_push(&dc, der, der_len);
    pk = br_x509_decoder_get_pkey(&dc);
    if (pk == NULL || dn.oom) {
        snprintf(err, errlen, "certificate does not decode (error %d)",
                 br_x509_decoder_last_error(&dc));
        free(dn.data);
        return -1;
    }

    memset(ta, 0, sizeof(*ta));
    ta->dn.data = dn.data;
    ta->dn.len = dn.len;
    if (br_x509_decoder_isCA(&dc)) ta->flags |= BR_X509_TA_CA;
    ta->pkey.key_type = pk->key_type;

    if (pk->key_type == BR_KEYTYPE_RSA) {
        ta->pkey.key.rsa.n = dup_bytes(pk->key.rsa.n, pk->key.rsa.nlen);
        ta->pkey.key.rsa.nlen = pk->key.rsa.nlen;
        ta->pkey.key.rsa.e = dup_bytes(pk->key.rsa.e, pk->key.rsa.elen);
        ta->pkey.key.rsa.elen = pk->key.rsa.elen;
        if (ta->pkey.key.rsa.n == NULL || ta->pkey.key.rsa.e == NULL) goto oom;
    } else if (pk->key_type == BR_KEYTYPE_EC) {
        ta->pkey.key.ec.curve = pk->key.ec.curve;
        ta->pkey.key.ec.q = dup_bytes(pk->key.ec.q, pk->key.ec.qlen);
        ta->pkey.key.ec.qlen = pk->key.ec.qlen;
        if (ta->pkey.key.ec.q == NULL) goto oom;
    } else {
        snprintf(err, errlen, "unsupported public key type %d", pk->key_type);
        free_ta(ta);
        return -1;
    }
    return 0;

oom:
    snprintf(err, errlen, "out of memory");
    free_ta(ta);
    return -1;
}

int ta_load_pem_file(const char *path, ta_set *out, char *err, size_t errlen)
{
    bytes file = { NULL, 0, 0, 0 };
    bytes der = { NULL, 0, 0, 0 };
    br_pem_decoder_context pc;
    const unsigned char *p;
    size_t len;
    int collecting = 0, rc = -1;

    out->tas = NULL;
    out->count = 0;

    if (read_file(path, &file) != 0) {
        snprintf(err, errlen, "cannot read %s", path);
        goto done;
    }

    /* The decoder emits an object's end only after the footer's newline. */
    bytes_append(&file, "\n", 1);
    if (file.oom) {
        snprintf(err, errlen, "out of memory");
        goto done;
    }

    br_pem_decoder_init(&pc);
    p = file.data;
    len = file.len;
    while (len > 0) {
        size_t n = br_pem_decoder_push(&pc, p, len);

        p += n;
        len -= n;
        switch (br_pem_decoder_event(&pc)) {
        case BR_PEM_BEGIN_OBJ:
            collecting = strcmp(br_pem_decoder_name(&pc), "CERTIFICATE") == 0;
            der.len = 0;
            br_pem_decoder_setdest(&pc, collecting ? bytes_append : NULL, &der);
            break;
        case BR_PEM_END_OBJ:
            if (collecting) {
                br_x509_trust_anchor *grown = (br_x509_trust_anchor *)realloc(
                    out->tas, (out->count + 1) * sizeof(*grown));

                if (grown == NULL) {
                    snprintf(err, errlen, "out of memory");
                    goto done;
                }
                out->tas = grown;
                if (der.oom || make_anchor(der.data, der.len,
                                           &out->tas[out->count],
                                           err, errlen) != 0) {
                    if (der.oom) snprintf(err, errlen, "out of memory");
                    goto done;
                }
                out->count++;
                collecting = 0;
            }
            break;
        case BR_PEM_ERROR:
            snprintf(err, errlen, "malformed PEM in %s", path);
            goto done;
        default:
            break;
        }
    }

    if (out->count == 0) {
        snprintf(err, errlen, "no certificate in %s", path);
        goto done;
    }
    rc = 0;

done:
    free(file.data);
    free(der.data);
    if (rc != 0) ta_free(out);
    return rc;
}

void ta_free(ta_set *set)
{
    size_t i;

    for (i = 0; i < set->count; i++) free_ta(&set->tas[i]);
    free(set->tas);
    set->tas = NULL;
    set->count = 0;
}
