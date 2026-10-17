/*
 * tls13_record.c — TLS 1.3 record encryption/decryption
 *
 * The nonce for each record is computed as:
 *   nonce = base_IV XOR padded_sequence_number
 *
 * Where padded_sequence_number is the 64-bit sequence number
 * left-padded with zeros to 12 bytes.
 *
 * The AAD (additional authenticated data) is the 5-byte record header:
 *   content_type (0x17) + version (0x0303) + ciphertext_length
 *
 * The ciphertext_length includes the content type byte and the
 * 16-byte AEAD tag.
 */

#include "tls13_record.h"
#include <string.h>

/* TLS 1.3 cipher suite IDs */
#define TLS_AES_128_GCM_SHA256       0x1301
#define TLS_AES_256_GCM_SHA384       0x1302
#define TLS_CHACHA20_POLY1305_SHA256 0x1303

/*
 * Compute the per-record nonce by XORing the IV with the sequence number.
 *
 * The sequence number is a 64-bit counter placed in the low 8 bytes
 * of the 12-byte nonce. The high 4 bytes of IV are XORed with zeros
 * (i.e., unchanged).
 */
static void compute_nonce(const unsigned char *iv, uint64_t seq,
                          unsigned char *nonce)
{
    memcpy(nonce, iv, 12);
    /* XOR sequence number into the low 8 bytes of the nonce */
    nonce[4]  ^= (unsigned char)(seq >> 56);
    nonce[5]  ^= (unsigned char)(seq >> 48);
    nonce[6]  ^= (unsigned char)(seq >> 40);
    nonce[7]  ^= (unsigned char)(seq >> 32);
    nonce[8]  ^= (unsigned char)(seq >> 24);
    nonce[9]  ^= (unsigned char)(seq >> 16);
    nonce[10] ^= (unsigned char)(seq >> 8);
    nonce[11] ^= (unsigned char)(seq);
}

/*
 * Build the AAD (Additional Authenticated Data) for a TLS 1.3 record.
 *
 * AAD = content_type (0x17) || version (0x0303) || ciphertext_length
 *
 * The ciphertext_length is the total encrypted payload size:
 *   plaintext + 1 (content type byte) + 16 (AEAD tag)
 */
static void build_aad(size_t ciphertext_len, unsigned char *aad)
{
    aad[0] = 0x17;  /* application_data */
    aad[1] = 0x03;  /* TLS 1.2 (legacy) */
    aad[2] = 0x03;
    aad[3] = (unsigned char)(ciphertext_len >> 8);
    aad[4] = (unsigned char)(ciphertext_len);
}

void tls13_record_init(tls13_record_ctx *ctx,
                       const void *key, size_t key_len,
                       const void *iv,
                       uint16_t cipher_suite)
{
    memcpy(ctx->key, key, key_len);
    ctx->key_len = key_len;
    memcpy(ctx->iv, iv, 12);
    ctx->seq = 0;
    ctx->cipher_suite = cipher_suite;
    if (cipher_suite != TLS_CHACHA20_POLY1305_SHA256) {
        br_aes_ct_ctr_init(&ctx->aes, ctx->key, ctx->key_len);
        br_gcm_init(&ctx->gcm, &ctx->aes.vtable, br_ghash_ctmul32);
    }
}

int tls13_record_encrypt(tls13_record_ctx *ctx,
                         const void *plaintext, size_t pt_len,
                         uint8_t ct,
                         void *out, size_t *out_len)
{
    unsigned char nonce[12];
    unsigned char aad[5];
    size_t total_ct_len;
    unsigned char *out_buf = (unsigned char *)out;

    /* Total ciphertext = plaintext + content type byte + AEAD tag */
    total_ct_len = pt_len + 1 + TLS13_TAG_SIZE;

    compute_nonce(ctx->iv, ctx->seq, nonce);
    build_aad(total_ct_len, aad);

    /* Copy plaintext + append content type byte */
    memcpy(out_buf, plaintext, pt_len);
    out_buf[pt_len] = ct;

    /* Encrypt in-place */
    if (ctx->cipher_suite == TLS_CHACHA20_POLY1305_SHA256) {
        br_poly1305_ctmul_run(ctx->key, nonce,
                              out_buf, pt_len + 1,
                              aad, sizeof(aad),
                              out_buf + pt_len + 1, /* tag output */
                              br_chacha20_ct_run,
                              1 /* encrypt */);
    } else {
        /* AES-GCM */
        /* Rebind after a context copy: GCM keeps a pointer to the AES
         * schedule. Only nonce/counters/AAD change between records. */
        br_gcm_context *gcm = &ctx->gcm;
        gcm->bctx = &ctx->aes.vtable;
        br_gcm_reset(gcm, nonce, 12);
        br_gcm_aad_inject(gcm, aad, sizeof(aad));
        br_gcm_flip(gcm);
        br_gcm_run(gcm, 1 /* encrypt */, out_buf, pt_len + 1);
        br_gcm_get_tag(gcm, out_buf + pt_len + 1);
    }

    *out_len = total_ct_len;
    ctx->seq++;
    return 0;
}

int tls13_record_decrypt(tls13_record_ctx *ctx,
                         const void *ciphertext, size_t ct_len,
                         void *out, size_t out_cap,
                         size_t *out_len, uint8_t *out_ct)
{
    unsigned char nonce[12];
    unsigned char aad[5];
    unsigned char *dec_buf = (unsigned char *)out;
    const unsigned char *received_tag;
    size_t payload_len;
    size_t content_len;
    int ok;

    /* The length is peer-controlled: validate it against the protocol
     * limit and the destination before any byte is written to out. */
    if (ciphertext == NULL || out == NULL ||
        out_len == NULL || out_ct == NULL) return -1;
    if (ct_len < 1 + TLS13_TAG_SIZE) return -1;
    if (ct_len > TLS13_MAX_CIPHERTEXT) return -1;

    payload_len = ct_len - TLS13_TAG_SIZE;
    if (payload_len > out_cap) return -1;

    received_tag = (const unsigned char *)ciphertext + payload_len;

    compute_nonce(ctx->iv, ctx->seq, nonce);
    build_aad(ct_len, aad);

    /* Copy only the encrypted payload for in-place decryption; the tag
     * stays in the caller's buffer and is never written to. */
    memcpy(dec_buf, ciphertext, payload_len);

    if (ctx->cipher_suite == TLS_CHACHA20_POLY1305_SHA256) {
        /*
         * br_poly1305_ctmul_run decrypts in place but does NOT verify
         * the tag: it writes the computed tag to the buffer it is given,
         * and "the caller is responsible for checking that the computed
         * tag matches the expected value" (bearssl_block.h). Compare it
         * against the received tag — otherwise any record would be
         * accepted, and a wrong key would go unnoticed.
         */
        unsigned char computed_tag[TLS13_TAG_SIZE];
        unsigned char diff = 0;
        size_t i;

        br_poly1305_ctmul_run(ctx->key, nonce,
                              dec_buf, payload_len,
                              aad, sizeof(aad),
                              computed_tag,
                              br_chacha20_ct_run,
                              0 /* decrypt */);
        for (i = 0; i < sizeof(computed_tag); i++) {
            diff |= (unsigned char)(received_tag[i] ^ computed_tag[i]);
        }
        ok = (diff == 0);
    } else {
        /* AES-GCM */
        /* Rebind after a context copy: GCM keeps a pointer to the AES
         * schedule. Only nonce/counters/AAD change between records. */
        br_gcm_context *gcm = &ctx->gcm;
        gcm->bctx = &ctx->aes.vtable;
        br_gcm_reset(gcm, nonce, 12);
        br_gcm_aad_inject(gcm, aad, sizeof(aad));
        br_gcm_flip(gcm);
        br_gcm_run(gcm, 0 /* decrypt */, dec_buf, payload_len);
        ok = br_gcm_check_tag(gcm, received_tag);
    }

    if (!ok) goto fail;

    /* Extract real content type: last non-zero byte of decrypted payload.
     * RFC 8446: "The content type is the real content type of the record.
     * The padding is all zeros." */
    {
        size_t i = payload_len;
        while (i > 0 && dec_buf[i - 1] == 0) i--;
        if (i == 0) goto fail; /* all zeros — invalid */
        content_len = i - 1;
        if (content_len > TLS13_MAX_PLAINTEXT) goto fail;
        *out_ct = dec_buf[i - 1];
        *out_len = content_len;
    }

    ctx->seq++;
    return 0;

fail:
    /* Don't leave unauthenticated or rejected plaintext in the caller's
     * buffer, where a later length mix-up could expose it. */
    memset(dec_buf, 0, payload_len);
    return -1;
}
