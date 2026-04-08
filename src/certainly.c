/*
 * certainly.c — Core implementation
 *
 * This file is the glue between the public API, BearSSL, and Open Transport.
 * Its main job is the pump loop — shuttling bytes between OT and BearSSL's
 * state machine buffers.
 */

#include "certainly_internal.h"

#include <Memory.h>   /* NewPtrClear, DisposePtr */
#include <string.h>

/* ── Library lifecycle ── */

MacTLS_Error MacTLS_Init(void)
{
    entropy_init();
    return kMacTLS_OK;
}

void MacTLS_Shutdown(void)
{
    /* Currently nothing to clean up at library level */
}

/* ── BearSSL setup helpers ── */

/*
 * Initialize BearSSL's client context for a TLS 1.2 connection.
 *
 * This configures:
 *   1. Which cipher suites to offer (we pick a practical subset)
 *   2. The X.509 certificate validator with our trust anchors
 *   3. The I/O buffer
 *   4. The server name for SNI
 *
 * CIPHER SUITES — what the client and server negotiate:
 *   A cipher suite specifies four algorithms:
 *     - Key exchange: how client+server agree on a shared secret
 *       (ECDHE = Elliptic Curve Diffie-Hellman Ephemeral — forward secrecy)
 *     - Authentication: how the server proves identity (RSA or ECDSA)
 *     - Encryption: how data is encrypted (AES-128-GCM, ChaCha20-Poly1305)
 *     - MAC: message integrity (included in GCM/Poly1305 — AEAD ciphers)
 *
 *   We offer modern AEAD suites only. The server picks the best one it supports.
 */
static void setup_bearssl(MacTLS_Context *ctx)
{
    /*
     * Cipher suites, in preference order.
     * These are the most commonly supported modern suites:
     */
    static const uint16_t suites[] = {
        BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    };

    const br_x509_trust_anchor *tas;
    size_t tas_count;

    /* Use custom trust anchors if configured, otherwise defaults */
    if (ctx->config && ctx->config->custom_tas) {
        tas       = ctx->config->custom_tas;
        tas_count = ctx->config->custom_tas_count;
    } else {
        tas       = TAs;
        tas_count = TAs_NUM;
    }

    /*
     * br_ssl_client_init_full sets up the client context with
     * sensible defaults: all hash functions, all standard cipher
     * suites, the minimal X.509 validator. We then override the
     * cipher suite list to only offer AEAD suites.
     */
    br_ssl_client_init_full(&ctx->sc, &ctx->xc, tas, tas_count);

    /* Override with our preferred cipher suites */
    br_ssl_engine_set_suites(&ctx->sc.eng, suites,
                             sizeof(suites) / sizeof(suites[0]));

    /*
     * Set the I/O buffer. BearSSL uses this to assemble and
     * disassemble TLS records. In mono (half-duplex) mode, a single
     * buffer handles both directions — BearSSL alternates between
     * reading into it and writing from it.
     */
    br_ssl_engine_set_buffer(&ctx->sc.eng, ctx->iobuf,
                             sizeof(ctx->iobuf), 0);

    /* Seed the PRNG with our entropy pool */
    entropy_seed_engine(&ctx->sc.eng);

    /*
     * Start the TLS handshake. This tells BearSSL "begin as a client
     * connecting to this hostname." The hostname is used for:
     *   - SNI (Server Name Indication): sent in the ClientHello so
     *     the server knows which certificate to present. Essential
     *     when one IP hosts multiple HTTPS domains.
     *   - Certificate validation: the X.509 validator checks that
     *     the server's cert matches this hostname.
     */
    br_ssl_client_reset(&ctx->sc, ctx->host, 0);
}

/* ── Connection lifecycle ── */

MacTLS_Context *MacTLS_Create(const char *host, uint16_t port)
{
    return MacTLS_CreateWithConfig(host, port, NULL);
}

MacTLS_Context *MacTLS_CreateWithConfig(const char *host, uint16_t port,
                                        MacTLS_Config *cfg)
{
    MacTLS_Context *ctx;

    ctx = (MacTLS_Context *)NewPtrClear(sizeof(MacTLS_Context));
    if (ctx == NULL) return NULL;

    ctx->state  = kMacTLS_Connecting;
    ctx->config = cfg;

    /* Save hostname for SNI */
    strncpy(ctx->host, host, sizeof(ctx->host) - 1);
    ctx->host[sizeof(ctx->host) - 1] = '\0';

    /* Start TCP connection */
    ctx->transport = ot_transport_create(host, port);
    if (ctx->transport == NULL) {
        ctx->state = kMacTLS_Error;
        ctx->error = kMacTLS_ErrMemory;
        return ctx;
    }

    /* Set up BearSSL (doesn't do any I/O yet — just configures) */
    setup_bearssl(ctx);

    return ctx;
}

/*
 * The pump loop — the heart of Certainly.
 *
 * This function moves bytes between three layers:
 *   App ↔ BearSSL ↔ OT
 *
 * Each call does a bounded amount of work and returns. It NEVER
 * blocks. Call it from your event loop alongside WaitNextEvent.
 */
MacTLS_State MacTLS_Pump(MacTLS_Context *ctx)
{
    unsigned int    st;
    unsigned char  *buf;
    size_t          len;
    int             n;

    if (ctx->state == kMacTLS_Error ||
        ctx->state == kMacTLS_Closed) {
        return ctx->state;
    }

    /* Step 1: Pump the OT transport layer */
    {
        OTTransportState tstate = ot_transport_pump(ctx->transport);

        if (tstate == kOTTransport_Error) {
            ctx->state = kMacTLS_Error;
            ctx->error = kMacTLS_ErrConnect;
            return ctx->state;
        }

        /* Still waiting for TCP? Nothing for BearSSL to do yet. */
        if (tstate == kOTTransport_ResolvingDNS ||
            tstate == kOTTransport_Connecting) {
            ctx->state = kMacTLS_Connecting;
            return ctx->state;
        }
    }

    /*
     * Step 2: Feed BearSSL's state machine.
     *
     * We check what BearSSL needs and give it what we can.
     * The state bitmask tells us which operations are possible:
     *
     *   BR_SSL_SENDREC — BearSSL has encrypted data to send.
     *     → Pull bytes from BearSSL, push to OT.
     *
     *   BR_SSL_RECVREC — BearSSL wants encrypted data from the network.
     *     → Pull bytes from OT, push to BearSSL.
     *
     *   BR_SSL_SENDAPP — BearSSL can accept plaintext to encrypt.
     *     → (handled by MacTLS_Write, not here)
     *
     *   BR_SSL_RECVAPP — BearSSL has decrypted plaintext ready.
     *     → (handled by MacTLS_Read, not here)
     *
     *   BR_SSL_CLOSED — Session is over.
     */
    st = br_ssl_engine_current_state(&ctx->sc.eng);

    if (st == BR_SSL_CLOSED) {
        int err = br_ssl_engine_last_error(&ctx->sc.eng);
        if (err == BR_ERR_OK) {
            ctx->state = kMacTLS_Closed;
        } else if (err == BR_ERR_X509_NOT_TRUSTED ||
                   err == BR_ERR_X509_BAD_SERVER_NAME) {
            ctx->state = kMacTLS_Error;
            ctx->error = kMacTLS_ErrCertificate;
        } else {
            ctx->state = kMacTLS_Error;
            ctx->error = kMacTLS_ErrHandshake;
        }
        return ctx->state;
    }

    /* Send: BearSSL → OT */
    if (st & BR_SSL_SENDREC) {
        buf = br_ssl_engine_sendrec_buf(&ctx->sc.eng, &len);
        if (len > 0) {
            n = ot_transport_send(ctx->transport, buf, len);
            if (n > 0) {
                br_ssl_engine_sendrec_ack(&ctx->sc.eng, n);
            } else if (n < 0) {
                ctx->state = kMacTLS_Error;
                ctx->error = kMacTLS_ErrWrite;
                return ctx->state;
            }
        }
    }

    /* Receive: OT → BearSSL */
    if (st & BR_SSL_RECVREC) {
        buf = br_ssl_engine_recvrec_buf(&ctx->sc.eng, &len);
        if (len > 0) {
            n = ot_transport_recv(ctx->transport, buf, len);
            if (n > 0) {
                br_ssl_engine_recvrec_ack(&ctx->sc.eng, n);
            } else if (n < 0) {
                ctx->state = kMacTLS_Error;
                ctx->error = kMacTLS_ErrRead;
                return ctx->state;
            }
        }
    }

    /* Update state based on what BearSSL is doing */
    st = br_ssl_engine_current_state(&ctx->sc.eng);

    if (st & (BR_SSL_SENDAPP | BR_SSL_RECVAPP)) {
        /* Application data channels are open — handshake is done */
        ctx->state = kMacTLS_Connected;
    } else if (st & (BR_SSL_SENDREC | BR_SSL_RECVREC)) {
        /* Only record-level I/O — still handshaking */
        ctx->state = kMacTLS_Handshaking;
    }

    return ctx->state;
}

void MacTLS_Close(MacTLS_Context *ctx)
{
    if (ctx == NULL) return;

    if (ctx->state == kMacTLS_Connected ||
        ctx->state == kMacTLS_Handshaking) {
        /*
         * Send TLS close_notify alert. This tells the server
         * "I'm done, close the encrypted session." It's the TLS
         * equivalent of hanging up politely rather than just
         * dropping the connection.
         */
        br_ssl_engine_close(&ctx->sc.eng);
        ctx->state = kMacTLS_Closing;

        /* Pump once to flush the close_notify */
        MacTLS_Pump(ctx);
    }

    /* Close the TCP connection */
    if (ctx->transport) {
        ot_transport_close(ctx->transport);
        ot_transport_destroy(ctx->transport);
        ctx->transport = NULL;
    }

    ctx->state = kMacTLS_Closed;
    DisposePtr((Ptr)ctx);
}

/* ── Data transfer ── */

int MacTLS_Write(MacTLS_Context *ctx, const void *data, size_t len)
{
    unsigned char *buf;
    size_t         avail;

    if (ctx->state != kMacTLS_Connected) return -1;

    /*
     * Get BearSSL's sendapp buffer — this is where plaintext goes
     * before BearSSL encrypts it into a TLS record.
     */
    buf = br_ssl_engine_sendapp_buf(&ctx->sc.eng, &avail);
    if (buf == NULL || avail == 0) return 0;

    if (len > avail) len = avail;
    memcpy(buf, data, len);

    /*
     * Tell BearSSL we wrote len bytes. BearSSL will encrypt them
     * on the next engine cycle and make them available via sendrec.
     */
    br_ssl_engine_sendapp_ack(&ctx->sc.eng, len);

    /*
     * Flush — tell BearSSL to wrap what we've written into a TLS
     * record now, rather than waiting for more data. For HTTP
     * requests, you want each write to go out promptly.
     */
    br_ssl_engine_flush(&ctx->sc.eng, 0);

    return (int)len;
}

int MacTLS_Read(MacTLS_Context *ctx, void *buf, size_t len)
{
    unsigned char *src;
    size_t         avail;

    if (ctx->state != kMacTLS_Connected &&
        ctx->state != kMacTLS_Closing) return -1;

    /*
     * Get BearSSL's recvapp buffer — this is where decrypted
     * plaintext lands after BearSSL processes incoming TLS records.
     */
    src = br_ssl_engine_recvapp_buf(&ctx->sc.eng, &avail);
    if (src == NULL || avail == 0) return 0;

    if (len > avail) len = avail;
    memcpy(buf, src, len);

    /* Tell BearSSL we consumed len bytes */
    br_ssl_engine_recvapp_ack(&ctx->sc.eng, len);

    return (int)len;
}

size_t MacTLS_Available(const MacTLS_Context *ctx)
{
    unsigned char *buf;
    size_t         avail;

    if (ctx->state != kMacTLS_Connected) return 0;

    buf = br_ssl_engine_recvapp_buf(
        &((MacTLS_Context *)ctx)->sc.eng, &avail);
    return (buf != NULL) ? avail : 0;
}

/* ── Status ── */

MacTLS_State MacTLS_GetState(const MacTLS_Context *ctx)
{
    return ctx->state;
}

MacTLS_Error MacTLS_GetError(const MacTLS_Context *ctx)
{
    return ctx->error;
}

OSStatus MacTLS_GetOTError(const MacTLS_Context *ctx)
{
    if (ctx->transport) {
        return ctx->transport->lastError;
    }
    return noErr;
}

/* ── Configuration ── */

MacTLS_Config *MacTLS_ConfigCreate(void)
{
    return (MacTLS_Config *)NewPtrClear(sizeof(MacTLS_Config));
}

void MacTLS_ConfigFree(MacTLS_Config *cfg)
{
    if (cfg) DisposePtr((Ptr)cfg);
}

MacTLS_Error MacTLS_ConfigAddCA(MacTLS_Config *cfg,
                                const void *der, size_t len)
{
    /*
     * TODO: implement DER certificate decoding and storage.
     * For now, custom CAs require building a br_x509_trust_anchor
     * array manually and setting cfg->custom_tas directly.
     */
    (void)cfg; (void)der; (void)len;
    return kMacTLS_ErrMemory;
}

/* ── Entropy ── */

void MacTLS_AddEntropy(const void *data, size_t len)
{
    entropy_add(data, len);
}
