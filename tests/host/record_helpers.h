/*
 * record_helpers.h — shared helpers for the TLS 1.3 record boundary tests.
 */

#ifndef CERTAINLY_TEST_RECORD_HELPERS_H
#define CERTAINLY_TEST_RECORD_HELPERS_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../src/tls13_record.h"

#define SUITE_AES128  0x1301
#define SUITE_AES256  0x1302
#define SUITE_CHACHA  0x1303

#define GUARD_BYTES  64
#define GUARD_FILL   0xA5

static int failures = 0;

#define CHECK(cond, ...) do {                                  \
    if (!(cond)) {                                             \
        printf("FAIL %s:%d: ", __FILE__, __LINE__);            \
        printf(__VA_ARGS__);                                   \
        printf("\n");                                          \
        failures++;                                            \
    }                                                          \
} while (0)

static const struct { uint16_t id; size_t key_len; const char *name; } suites[] = {
    { SUITE_AES128, 16, "AES-128-GCM" },
    { SUITE_AES256, 32, "AES-256-GCM" },
    { SUITE_CHACHA, 32, "ChaCha20-Poly1305" },
};
#define NUM_SUITES (sizeof(suites) / sizeof(suites[0]))

static inline void init_ctx(tls13_record_ctx *ctx, size_t suite_idx)
{
    unsigned char key[32], iv[12];
    size_t i;
    for (i = 0; i < sizeof(key); i++) key[i] = (unsigned char)(0x10 + i);
    for (i = 0; i < sizeof(iv); i++) iv[i] = (unsigned char)(0x80 + i);
    tls13_record_init(ctx, key, suites[suite_idx].key_len, iv,
                      suites[suite_idx].id);
}

/*
 * A destination buffer with guard bytes on both sides. The region the
 * decrypt function may legitimately write is `data[0..cap)`; the guards
 * model the stack frame / adjacent connection fields it must not touch.
 */
typedef struct {
    unsigned char *raw;
    unsigned char *data;
    size_t cap;
} guarded_buf;

static inline void guarded_init(guarded_buf *g, size_t cap)
{
    g->raw = (unsigned char *)malloc(cap + 2 * GUARD_BYTES);
    g->data = g->raw + GUARD_BYTES;
    g->cap = cap;
    memset(g->raw, GUARD_FILL, cap + 2 * GUARD_BYTES);
}

static inline void guarded_free(guarded_buf *g) { free(g->raw); }

static inline int guards_intact(const guarded_buf *g)
{
    size_t i;
    for (i = 0; i < GUARD_BYTES; i++) {
        if (g->raw[i] != GUARD_FILL) return 0;
        if (g->data[g->cap + i] != GUARD_FILL) return 0;
    }
    return 1;
}

/* Every byte of the usable region still holds the fill pattern. */
static inline int data_untouched(const guarded_buf *g)
{
    size_t i;
    for (i = 0; i < g->cap; i++) if (g->data[i] != GUARD_FILL) return 0;
    return 1;
}

static inline int data_zeroed(const guarded_buf *g, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) if (g->data[i] != 0) return 0;
    return 1;
}

/*
 * Encrypt a record whose inner plaintext is content || type || pad zeros.
 * The library encrypter has no padding support, so for pad > 0 the real
 * type goes into the plaintext and the encrypter's own appended type byte
 * is 0, which is the first padding byte.
 * Returns the ciphertext length (payload + tag).
 */
static inline size_t seal_record(tls13_record_ctx *tx, const unsigned char *content,
                          size_t content_len, uint8_t type, size_t pad,
                          unsigned char *out)
{
    size_t out_len = 0;
    if (pad == 0) {
        tls13_record_encrypt(tx, content, content_len, type, out, &out_len);
    } else {
        unsigned char *pt = (unsigned char *)calloc(1, content_len + pad);
        memcpy(pt, content, content_len);
        pt[content_len] = type;
        tls13_record_encrypt(tx, pt, content_len + pad, 0, out, &out_len);
        free(pt);
    }
    return out_len;
}

#endif
