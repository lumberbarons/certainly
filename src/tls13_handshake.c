/*
 * tls13_handshake.c — TLS 1.3 handshake state machine
 */

#include "tls13_handshake.h"
#include <string.h>

/* ── Transcript Hashing ── */

void tls13_transcript_init(tls13_transcript *t, const br_hash_class *hash)
{
    t->hash = hash;
    if (hash == &br_sha256_vtable) {
        t->hash_len = 32;
        br_sha256_init(&t->sha256);
    } else {
        t->hash_len = 48;
        br_sha384_init(&t->sha384);
    }
}

void tls13_transcript_update(tls13_transcript *t,
                             const void *data, size_t len)
{
    if (t->hash == &br_sha256_vtable) {
        br_sha256_update(&t->sha256, data, len);
    } else {
        br_sha384_update(&t->sha384, data, len);
    }
}

void tls13_transcript_snapshot(const tls13_transcript *t,
                               void *out_hash)
{
    /* Copy the hash context and finalize the copy.
     * The original continues accumulating. */
    if (t->hash == &br_sha256_vtable) {
        br_sha256_context copy = t->sha256;
        br_sha256_out(&copy, out_hash);
    } else {
        br_sha384_context copy = t->sha384;
        br_sha384_out(&copy, out_hash);
    }
}

void tls13_transcript_reset_for_hrr(tls13_transcript *t)
{
    /*
     * RFC 8446 Section 4.4.1: When HRR is received, the transcript
     * is replaced with a synthetic message_hash:
     *
     *   Hash(message_hash || 0x00 || uint24(Hash.length) || Hash(CH1))
     *
     * Where Hash(CH1) is the current transcript hash (of just ClientHello1).
     */
    unsigned char ch1_hash[64];
    unsigned char synthetic[4 + 64]; /* header + hash */

    tls13_transcript_snapshot(t, ch1_hash);

    synthetic[0] = TLS13_HT_MESSAGE_HASH;  /* type 254 */
    synthetic[1] = 0;
    synthetic[2] = 0;
    synthetic[3] = (unsigned char)t->hash_len;
    memcpy(synthetic + 4, ch1_hash, t->hash_len);

    /* Re-init and feed the synthetic message */
    tls13_transcript_init(t, t->hash);
    tls13_transcript_update(t, synthetic, 4 + t->hash_len);
}

void tls13_handshake_init(tls13_hs_ctx *hs)
{
    memset(hs, 0, sizeof(tls13_hs_ctx));
    hs->state = kTLS13_SendClientHello;
}
