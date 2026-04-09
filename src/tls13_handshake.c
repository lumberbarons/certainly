/*
 * tls13_handshake.c — TLS 1.3 handshake state machine
 *
 * This file implements the TLS 1.3 handshake message construction
 * and parsing, bypassing BearSSL's T0-based handshake engine entirely.
 * We use BearSSL only for crypto primitives (HKDF, X25519, AEAD)
 * and buffer I/O.
 */

#include "tls13_handshake.h"
#include "entropy.h"
#include <string.h>

/* ── Wire Format Helpers ── */

/*
 * Write a 16-bit big-endian value into a buffer.
 * TLS uses network byte order (big-endian) for all multi-byte integers.
 */
static void put_u16(unsigned char *p, uint16_t v)
{
    p[0] = (unsigned char)(v >> 8);
    p[1] = (unsigned char)(v);
}

/*
 * Write a 24-bit big-endian value into a buffer.
 * Used for handshake message lengths (3-byte length field).
 */
static void put_u24(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v >> 16);
    p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v);
}

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

/* ── X25519 Key Generation ── */

/*
 * Generate an X25519 ephemeral key pair for the key_share extension.
 *
 * Uses BearSSL's EC implementation (br_ec_c25519_m15) which works well
 * on the 68K/PPC Mac. The private key is 32 bytes of random data
 * (with clamping applied by BearSSL internally), and the public key
 * is the X25519 public point (also 32 bytes).
 *
 * The PRNG is seeded from our entropy pool via a standalone
 * br_hmac_drbg_context — we can't use BearSSL's engine PRNG because
 * the engine hasn't started its own handshake.
 */
static int tls13_generate_x25519_keypair(tls13_hs_ctx *hs,
                                         br_hmac_drbg_context *rng)
{
    const br_ec_impl *ec = &br_ec_c25519_m15;
    br_ec_private_key sk;
    unsigned char kbuf_priv[BR_EC_KBUF_PRIV_MAX_SIZE];
    unsigned char kbuf_pub[BR_EC_KBUF_PUB_MAX_SIZE];
    size_t priv_len, pub_len;

    /* Generate private key */
    priv_len = br_ec_keygen(&rng->vtable, ec, &sk,
                            kbuf_priv, BR_EC_curve25519);
    if (priv_len == 0) {
        return -1;
    }

    /* Compute public key from private key */
    pub_len = br_ec_compute_pub(ec, NULL, kbuf_pub, &sk);
    if (pub_len == 0) {
        return -1;
    }

    /*
     * Store the key pair. For X25519:
     * - Private key is 32 bytes (the scalar)
     * - Public key from BearSSL is 32 bytes (the u-coordinate)
     *
     * BearSSL's br_ec_compute_pub for Curve25519 returns just the
     * 32-byte u-coordinate (no 0x04 prefix like NIST curves).
     */
    memcpy(hs->ecdhe_secret, sk.x, 32);
    memcpy(hs->ecdhe_public, kbuf_pub, 32);

    /* Wipe the temporary private key buffer */
    {
        volatile unsigned char *p = (volatile unsigned char *)kbuf_priv;
        size_t i;
        for (i = 0; i < sizeof(kbuf_priv); i++) p[i] = 0;
    }

    return 0;
}

/* ── ClientHello Builder ── */

/*
 * TLS 1.2 cipher suites to include for fallback compatibility.
 * These match the suites configured in certainly.c setup_bearssl().
 * Listed in preference order: ChaCha20 first (faster on PPC without
 * AES hardware), ECDSA interleaved before RSA.
 */
static const uint16_t tls12_cipher_suites[] = {
    0xCCA9,  /* TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 */
    0xCCA8,  /* TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */
    0xC02B,  /* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
    0xC02F,  /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
    0xC02C,  /* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */
    0xC030,  /* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 */
};

/*
 * TLS 1.3 cipher suites. Listed in preference order.
 * ChaCha20 first for PPC performance.
 */
static const uint16_t tls13_cipher_suites[] = {
    TLS13_CHACHA20_POLY1305_SHA256,  /* 0x1303 */
    TLS13_AES_128_GCM_SHA256,       /* 0x1301 */
    TLS13_AES_256_GCM_SHA384,       /* 0x1302 */
};

/*
 * Signature algorithms for the signature_algorithms extension.
 * These tell the server which signature schemes we can verify.
 */
static const uint16_t sig_algorithms[] = {
    TLS13_SIG_RSA_PSS_RSAE_SHA256,      /* 0x0804 */
    TLS13_SIG_RSA_PSS_RSAE_SHA384,      /* 0x0805 */
    TLS13_SIG_ECDSA_SECP256R1_SHA256,   /* 0x0403 */
    TLS13_SIG_ECDSA_SECP384R1_SHA384,   /* 0x0503 */
    TLS13_SIG_RSA_PKCS1_SHA256,         /* 0x0401 — for cert chain only */
    TLS13_SIG_RSA_PKCS1_SHA384,         /* 0x0501 — for cert chain only */
};

/*
 * Build a ClientHello message into hs->msg_buf.
 *
 * The message is wrapped in a TLS record (5-byte header + handshake message).
 * On return, hs->msg_buf[0..hs->msg_len-1] contains the complete TLS record
 * ready to send on the wire.
 *
 * The handshake portion (excluding the 5-byte record header) is fed into
 * the transcript hash.
 *
 * Parameters:
 *   hs       — handshake context (key pair must already be generated)
 *   hostname — server name for SNI extension
 *   rng      — PRNG for client_random and legacy_session_id
 *
 * Returns 0 on success, -1 if the message doesn't fit in msg_buf.
 */
static int tls13_build_client_hello(tls13_hs_ctx *hs,
                                    const char *hostname,
                                    br_hmac_drbg_context *rng)
{
    unsigned char *buf = hs->msg_buf;
    size_t buf_size = sizeof(hs->msg_buf);
    size_t pos = 0;
    size_t hostname_len = strlen(hostname);
    size_t num_tls13_suites = sizeof(tls13_cipher_suites) / sizeof(tls13_cipher_suites[0]);
    size_t num_tls12_suites = sizeof(tls12_cipher_suites) / sizeof(tls12_cipher_suites[0]);
    size_t total_suites = num_tls13_suites + num_tls12_suites;
    size_t ext_start, ext_len_pos;
    size_t hs_len_pos;
    size_t i;

    /*
     * TLS Record Header (5 bytes)
     * Will be filled in at the end once we know the total length.
     * content_type = 22 (handshake)
     * version = 0x0301 (TLS 1.0 — required by RFC 8446 for compat)
     * length = (filled in later)
     */
    if (pos + 5 > buf_size) return -1;
    buf[pos++] = TLS13_CT_HANDSHAKE;   /* content_type = 22 */
    buf[pos++] = 0x03;                  /* version high = 3 */
    buf[pos++] = 0x01;                  /* version low = 1 (TLS 1.0) */
    pos += 2;                           /* skip length (filled later) */

    /*
     * Handshake Header (4 bytes)
     * type = 1 (ClientHello)
     * uint24 length = (filled in later)
     */
    if (pos + 4 > buf_size) return -1;
    buf[pos++] = TLS13_HT_CLIENT_HELLO;  /* type = 1 */
    hs_len_pos = pos;
    pos += 3;  /* skip uint24 length (filled later) */

    /*
     * ClientHello body starts here
     */

    /* legacy_version: 0x0303 (TLS 1.2) — required for middlebox compat */
    if (pos + 2 > buf_size) return -1;
    put_u16(buf + pos, TLS12_VERSION);
    pos += 2;

    /* Random: 32 bytes of cryptographic randomness */
    if (pos + 32 > buf_size) return -1;
    br_hmac_drbg_generate(rng, buf + pos, 32);
    pos += 32;

    /*
     * legacy_session_id: 32 random bytes.
     * RFC 8446 Section 4.1.2: MUST be set to a 32-byte value by a client
     * that wishes to use middlebox compatibility mode (we do).
     * A random value is recommended.
     */
    if (pos + 1 + 32 > buf_size) return -1;
    buf[pos++] = 32;  /* session_id length */
    br_hmac_drbg_generate(rng, buf + pos, 32);
    pos += 32;

    /*
     * Cipher suites: TLS 1.3 suites first, then TLS 1.2 suites.
     * TLS 1.3 suites go first so the server prefers them.
     * TLS 1.2 suites are included for fallback compatibility.
     */
    if (pos + 2 + total_suites * 2 > buf_size) return -1;
    put_u16(buf + pos, (uint16_t)(total_suites * 2));
    pos += 2;
    for (i = 0; i < num_tls13_suites; i++) {
        put_u16(buf + pos, tls13_cipher_suites[i]);
        pos += 2;
    }
    for (i = 0; i < num_tls12_suites; i++) {
        put_u16(buf + pos, tls12_cipher_suites[i]);
        pos += 2;
    }

    /*
     * legacy_compression_methods: just null compression (0x00).
     * TLS 1.3 does not support compression.
     */
    if (pos + 2 > buf_size) return -1;
    buf[pos++] = 1;   /* length of compression methods */
    buf[pos++] = 0;   /* null compression */

    /*
     * Extensions
     * We write a 2-byte placeholder for the total extensions length,
     * then each extension, then go back and fill in the length.
     */
    if (pos + 2 > buf_size) return -1;
    ext_len_pos = pos;
    pos += 2;  /* skip extensions length (filled later) */
    ext_start = pos;

    /* ── Extension: SNI (Server Name Indication) — type 0 ── */
    {
        /*
         * Format:
         *   ext_type (2)
         *   ext_data_length (2)
         *   server_name_list_length (2)
         *   name_type (1) = 0 (hostname)
         *   name_length (2)
         *   hostname (variable)
         */
        size_t sni_ext_len = 2 + 1 + 2 + hostname_len;  /* list_len + type + name_len + name */
        if (pos + 4 + sni_ext_len > buf_size) return -1;
        put_u16(buf + pos, TLS13_EXT_SERVER_NAME);
        pos += 2;
        put_u16(buf + pos, (uint16_t)sni_ext_len);
        pos += 2;
        put_u16(buf + pos, (uint16_t)(sni_ext_len - 2));  /* server_name_list length */
        pos += 2;
        buf[pos++] = 0;  /* name_type = hostname */
        put_u16(buf + pos, (uint16_t)hostname_len);
        pos += 2;
        memcpy(buf + pos, hostname, hostname_len);
        pos += hostname_len;
    }

    /* ── Extension: Supported Groups — type 10 ── */
    {
        /*
         * Format:
         *   ext_type (2)
         *   ext_data_length (2)
         *   named_group_list_length (2)
         *   named_group (2) = 0x001D (X25519)
         */
        if (pos + 4 + 4 > buf_size) return -1;
        put_u16(buf + pos, TLS13_EXT_SUPPORTED_GROUPS);
        pos += 2;
        put_u16(buf + pos, 4);  /* ext_data_length */
        pos += 2;
        put_u16(buf + pos, 2);  /* named_group_list_length */
        pos += 2;
        put_u16(buf + pos, TLS13_GROUP_X25519);
        pos += 2;
    }

    /* ── Extension: Signature Algorithms — type 13 ── */
    {
        /*
         * Format:
         *   ext_type (2)
         *   ext_data_length (2)
         *   sig_alg_list_length (2)
         *   signature_scheme (2) * N
         */
        size_t num_sigs = sizeof(sig_algorithms) / sizeof(sig_algorithms[0]);
        size_t list_len = num_sigs * 2;
        if (pos + 4 + 2 + list_len > buf_size) return -1;
        put_u16(buf + pos, TLS13_EXT_SIGNATURE_ALGORITHMS);
        pos += 2;
        put_u16(buf + pos, (uint16_t)(2 + list_len));  /* ext_data_length */
        pos += 2;
        put_u16(buf + pos, (uint16_t)list_len);  /* sig_alg_list_length */
        pos += 2;
        for (i = 0; i < num_sigs; i++) {
            put_u16(buf + pos, sig_algorithms[i]);
            pos += 2;
        }
    }

    /* ── Extension: Supported Versions — type 43 ── */
    {
        /*
         * Format:
         *   ext_type (2)
         *   ext_data_length (2)
         *   versions_length (1)
         *   version (2) = 0x0304 (TLS 1.3)
         *   version (2) = 0x0303 (TLS 1.2)
         *
         * This is how we signal TLS 1.3 support. The legacy_version field
         * in the ClientHello body stays at 0x0303 for middlebox compat,
         * and the server looks HERE for the actual version list.
         */
        if (pos + 4 + 5 > buf_size) return -1;
        put_u16(buf + pos, TLS13_EXT_SUPPORTED_VERSIONS);
        pos += 2;
        put_u16(buf + pos, 5);  /* ext_data_length */
        pos += 2;
        buf[pos++] = 4;  /* versions_length (2 versions * 2 bytes) */
        put_u16(buf + pos, TLS13_VERSION);   /* 0x0304 — TLS 1.3 */
        pos += 2;
        put_u16(buf + pos, TLS12_VERSION);   /* 0x0303 — TLS 1.2 */
        pos += 2;
    }

    /* ── Extension: Key Share — type 51 ── */
    {
        /*
         * Format:
         *   ext_type (2)
         *   ext_data_length (2)
         *   client_shares_length (2)
         *   named_group (2) = 0x001D (X25519)
         *   key_exchange_length (2) = 32
         *   key_exchange (32) = our X25519 public key
         *
         * This is the "optimistic" key share — we include our public key
         * right in the ClientHello so the server can complete the key
         * exchange in its ServerHello without a round trip. If the server
         * wants a different group, it sends HelloRetryRequest.
         */
        if (pos + 4 + 2 + 2 + 2 + 32 > buf_size) return -1;
        put_u16(buf + pos, TLS13_EXT_KEY_SHARE);
        pos += 2;
        put_u16(buf + pos, 38);  /* ext_data_length: 2 + 2 + 2 + 32 */
        pos += 2;
        put_u16(buf + pos, 36);  /* client_shares_length: 2 + 2 + 32 */
        pos += 2;
        put_u16(buf + pos, TLS13_GROUP_X25519);
        pos += 2;
        put_u16(buf + pos, 32);  /* key_exchange_length */
        pos += 2;
        memcpy(buf + pos, hs->ecdhe_public, 32);
        pos += 32;
    }

    /* ── Extension: Cookie — type 44 (only on HelloRetryRequest retry) ── */
    if (hs->cookie_len > 0) {
        /*
         * When the server sends HelloRetryRequest with a cookie,
         * we must echo it back in the retry ClientHello. This handles
         * the Cloudflare DoS protection case.
         *
         * Format:
         *   ext_type (2)
         *   ext_data_length (2)
         *   cookie_length (2)
         *   cookie (variable)
         */
        if (pos + 4 + 2 + hs->cookie_len > buf_size) return -1;
        put_u16(buf + pos, TLS13_EXT_COOKIE);
        pos += 2;
        put_u16(buf + pos, (uint16_t)(2 + hs->cookie_len));
        pos += 2;
        put_u16(buf + pos, (uint16_t)hs->cookie_len);
        pos += 2;
        memcpy(buf + pos, hs->cookie, hs->cookie_len);
        pos += hs->cookie_len;
    }

    /*
     * Backpatch lengths.
     *
     * We now know the total size of everything, so fill in the
     * length fields we skipped earlier.
     */

    /* Extensions length (2 bytes at ext_len_pos) */
    put_u16(buf + ext_len_pos, (uint16_t)(pos - ext_start));

    /* Handshake message length (3 bytes at hs_len_pos) */
    put_u24(buf + hs_len_pos, (uint32_t)(pos - hs_len_pos - 3));

    /* TLS record length (2 bytes at offset 3) */
    put_u16(buf + 3, (uint16_t)(pos - 5));

    hs->msg_len = pos;
    hs->msg_offset = 0;

    /*
     * Update the transcript hash with the handshake message.
     * The transcript includes everything from the handshake header
     * (type + uint24 length) through the end — NOT the 5-byte
     * TLS record header.
     */
    tls13_transcript_update(&hs->transcript, buf + 5, pos - 5);

    return 0;
}

/* ── CCS (Change Cipher Spec) Builder ── */

/*
 * Build a Change Cipher Spec record into a buffer.
 *
 * CCS is NOT a TLS 1.3 concept — it's sent purely for middlebox
 * compatibility (RFC 8446 Appendix D.4). Middleboxes (corporate
 * firewalls, load balancers) that were designed for TLS 1.2 expect
 * to see a CCS message after the ClientHello. Without it, they may
 * drop the connection thinking something is wrong.
 *
 * The CCS is sent in the clear (before any encryption starts) and
 * the server ignores it. It's just one byte: 0x01.
 *
 * Format:
 *   content_type (1) = 20
 *   version (2) = 0x0303 (TLS 1.2)
 *   length (2) = 1
 *   payload (1) = 0x01
 *
 * The buffer must be at least 6 bytes. Returns the record length (6).
 */
static size_t tls13_build_ccs(unsigned char *buf)
{
    buf[0] = TLS13_CT_CHANGE_CIPHER_SPEC;  /* content_type = 20 */
    buf[1] = 0x03;                          /* version high */
    buf[2] = 0x03;                          /* version low (TLS 1.2) */
    buf[3] = 0x00;                          /* length high */
    buf[4] = 0x01;                          /* length low */
    buf[5] = 0x01;                          /* CCS payload */
    return 6;
}

/* ── Handshake State Machine ── */

/*
 * Handle the kTLS13_SendClientHello state.
 *
 * Generates the X25519 key pair, builds the ClientHello message
 * (with all extensions), initializes the transcript hash, and
 * writes the complete TLS record into msg_buf for sending.
 *
 * After this returns kTLS13_WantWrite, the caller drains msg_buf
 * to the network (via ot_transport_send or BearSSL's sendrec),
 * then advances to kTLS13_SendCCS.
 */
static tls13_hs_result tls13_state_send_client_hello(tls13_hs_ctx *hs,
                                                     br_ssl_engine_context *eng,
                                                     const char *hostname)
{
    br_hmac_drbg_context rng;
    unsigned char seed[32];
    int ret;

    /*
     * Initialize a standalone PRNG for key generation and random bytes.
     *
     * We can't use BearSSL's engine PRNG because the engine hasn't
     * started its own handshake (we're bypassing T0). Instead, we
     * create our own HMAC_DRBG seeded from the entropy pool.
     *
     * We extract seed material by injecting entropy into the engine
     * (which has already been done by certainly.c) and then using
     * the engine's PRNG to generate our seed. If the engine's PRNG
     * is available, use it; otherwise seed from the raw entropy pool.
     */
    if (eng->rng_init_done) {
        /* Engine PRNG is seeded — use it to seed our standalone PRNG */
        br_hmac_drbg_generate(&eng->rng, seed, sizeof(seed));
    } else {
        /*
         * Engine PRNG not ready — seed the engine first, then use it.
         * entropy_seed_engine() injects pool data into the engine's
         * HMAC_DRBG.
         */
        entropy_seed_engine(eng);
        br_hmac_drbg_generate(&eng->rng, seed, sizeof(seed));
    }

    br_hmac_drbg_init(&rng, &br_sha256_vtable, seed, sizeof(seed));

    /* Wipe the seed from the stack */
    {
        volatile unsigned char *p = (volatile unsigned char *)seed;
        size_t si;
        for (si = 0; si < sizeof(seed); si++) p[si] = 0;
    }

    /*
     * Initialize transcript hash.
     * Default to SHA-256; will be confirmed when we receive ServerHello
     * and learn the negotiated cipher suite. SHA-256 is used by
     * TLS_CHACHA20_POLY1305_SHA256 and TLS_AES_128_GCM_SHA256 (our
     * top two preferences), so this is almost always correct.
     */
    if (!hs->hrr_received) {
        tls13_transcript_init(&hs->transcript, &br_sha256_vtable);
    }
    /* If HRR was received, transcript was already reset by the HRR handler */

    /* Generate X25519 ephemeral key pair (unless retrying after HRR) */
    if (!hs->hrr_received) {
        ret = tls13_generate_x25519_keypair(hs, &rng);
        if (ret != 0) {
            hs->error = BR_ERR_BAD_STATE;
            return kTLS13_Error;
        }
    }

    /* Build the ClientHello message */
    ret = tls13_build_client_hello(hs, hostname, &rng);
    if (ret != 0) {
        hs->error = BR_ERR_TOO_LARGE;
        return kTLS13_Error;
    }

    /* Wipe the standalone PRNG */
    memset(&rng, 0, sizeof(rng));

    return kTLS13_WantWrite;
}

/*
 * Handle the kTLS13_SendCCS state.
 *
 * Builds the CCS record into msg_buf for sending. The CCS is NOT
 * part of the TLS 1.3 handshake — it's purely for middlebox
 * compatibility and is not included in the transcript hash.
 */
static tls13_hs_result tls13_state_send_ccs(tls13_hs_ctx *hs)
{
    hs->msg_len = tls13_build_ccs(hs->msg_buf);
    hs->msg_offset = 0;
    return kTLS13_WantWrite;
}

/*
 * Main handshake state machine driver.
 *
 * Called repeatedly from the pump loop. Returns:
 *   kTLS13_WantWrite — msg_buf has data to send, call again after sending
 *   kTLS13_WantRead  — need more data from network, call again after recv
 *   kTLS13_OK        — state completed, call again immediately
 *   kTLS13_Complete  — handshake finished successfully
 *   kTLS13_Fallback12 — server chose TLS 1.2, fall back
 *   kTLS13_Error     — handshake failed, check hs->error
 */
tls13_hs_result tls13_handshake_step(tls13_hs_ctx *hs,
                                     br_ssl_engine_context *eng,
                                     const char *hostname)
{
    switch (hs->state) {
    case kTLS13_SendClientHello: {
        tls13_hs_result r = tls13_state_send_client_hello(hs, eng, hostname);
        if (r == kTLS13_WantWrite) {
            hs->state = kTLS13_SendCCS;
        }
        return r;
    }

    case kTLS13_SendCCS: {
        tls13_hs_result r = tls13_state_send_ccs(hs);
        if (r == kTLS13_WantWrite) {
            hs->state = kTLS13_RecvServerHello;
        }
        return r;
    }

    case kTLS13_RecvServerHello:
        /* TODO: Task 5 — parse ServerHello, handle HRR */
        return kTLS13_WantRead;

    case kTLS13_RecvEncryptedExtensions:
        /* TODO: Task 6 */
        return kTLS13_WantRead;

    case kTLS13_RecvCertRequestOrCert:
        /* TODO: Task 6 */
        return kTLS13_WantRead;

    case kTLS13_RecvCertificate:
        /* TODO: Task 6 */
        return kTLS13_WantRead;

    case kTLS13_RecvCertificateVerify:
        /* TODO: Task 6 */
        return kTLS13_WantRead;

    case kTLS13_RecvFinished:
        /* TODO: Task 6 */
        return kTLS13_WantRead;

    case kTLS13_SendFinished:
        /* TODO: Task 7 */
        return kTLS13_WantWrite;

    case kTLS13_Complete:
        return kTLS13_OK;

    default:
        hs->error = BR_ERR_BAD_STATE;
        return kTLS13_Error;
    }
}
