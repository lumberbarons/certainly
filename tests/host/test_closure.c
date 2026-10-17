/*
 * test_closure.c — host-side tests for how Certainly ends a connection.
 *
 * src/certainly.c is compiled against fake Mac headers (tests/host/fake)
 * and this file's scripted transport. Encrypted records are produced with
 * the real TLS 1.3 record layer using keys shared with the context under
 * test, so the pump sees exactly what an authenticated peer (or an
 * attacker splicing plaintext in) would put on the wire.
 *
 * What this cannot cover: Open Transport event timing and a live TLS 1.2
 * handshake. Those need the Retro68 build in an emulator or on hardware.
 *
 * Build and run:
 *   cd tests/host && make test_closure && ./test_closure
 */

#include "certainly_internal.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int failures = 0;
static int passes   = 0;

#define CHECK_INT(name, expected, actual) do {                        \
    long _e = (long)(expected), _a = (long)(actual);                  \
    if (_e == _a) { passes++; printf("PASS: %s\n", name); }           \
    else { failures++; printf("FAIL: %s expected=%ld actual=%ld\n",   \
                              name, _e, _a); }                        \
} while (0)

/* Internal to BearSSL (inner.h) but exported; used only to put the engine
 * into the closed states a real exchange would leave it in. */
void br_ssl_engine_fail(br_ssl_engine_context *rc, int err);

/* ── Fake entropy (the real one reads Mac OS hardware state) ── */

void entropy_init(void) {}
void entropy_add(const void *data, size_t len) { (void)data; (void)len; }
void entropy_seed_engine(br_ssl_engine_context *eng)
{
    static const unsigned char seed[32] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    br_ssl_engine_inject_entropy(eng, seed, sizeof(seed));
}

/* ── Scripted transport ── */

enum { END_NONE = 0, END_FIN, END_RESET };

static struct {
    unsigned char wire[40000];  /* bytes the network will deliver */
    size_t        wire_len, wire_pos;
    int           end;          /* what happens once wire is consumed */
    int           send_fails;   /* ot_transport_send returns -1 */
} net;

OTTransport *ot_transport_create(const char *host, uint16_t port)
{
    OTTransport *t = calloc(1, sizeof(*t));
    (void)host;
    t->port  = port;
    t->state = kOTTransport_Connected;
    return t;
}

OTTransportState ot_transport_pump(OTTransport *t)
{
    if (t->disconnectReceived) t->state = kOTTransport_Error;
    return t->state;
}

int ot_transport_send(OTTransport *t, const void *buf, size_t len)
{
    (void)t; (void)buf;
    return net.send_fails ? -1 : (int)len;
}

int ot_transport_recv(OTTransport *t, void *buf, size_t len)
{
    size_t avail = net.wire_len - net.wire_pos;
    if (t->state != kOTTransport_Connected &&
        t->state != kOTTransport_Closing) return -1;
    if (avail > 0) {
        size_t n = avail < len ? avail : len;
        memcpy(buf, net.wire + net.wire_pos, n);
        net.wire_pos += n;
        if (net.wire_pos == net.wire_len) {
            if (net.end == END_FIN)   t->ordRelReceived = true;
            if (net.end == END_RESET) t->disconnectReceived = true;
        }
        return (int)n;
    }
    if (net.end == END_FIN)   t->ordRelReceived = true;
    if (net.end == END_RESET) t->disconnectReceived = true;
    return t->ordRelReceived ? -1 : 0;
}

void ot_transport_close(OTTransport *t)   { (void)t; }
void ot_transport_destroy(OTTransport *t) { free(t); }

/* ── Peer simulation ── */

static tls13_record_ctx peer;   /* encrypts what the server "sends" */

static const unsigned char kKey[16] = { 'k','e','y','0','k','e','y','1',
                                        'k','e','y','2','k','e','y','3' };
static const unsigned char kIv[12]  = { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2 };

static void wire_append(const void *p, size_t n)
{
    memcpy(net.wire + net.wire_len, p, n);
    net.wire_len += n;
}

static void wire_encrypted(uint8_t inner_type, const void *pt, size_t len)
{
    unsigned char rec[5 + 16384 + 1 + TLS13_TAG_SIZE];
    size_t ct_len;
    tls13_record_encrypt(&peer, pt, len, inner_type, rec + 5, &ct_len);
    rec[0] = 0x17; rec[1] = 0x03; rec[2] = 0x03;
    rec[3] = (unsigned char)(ct_len >> 8);
    rec[4] = (unsigned char)ct_len;
    wire_append(rec, 5 + ct_len);
}

static void wire_data(const char *s)
{
    wire_encrypted(TLS13_CT_APPLICATION_DATA, s, strlen(s));
}

static void wire_alert(unsigned char level, unsigned char desc)
{
    unsigned char a[2];
    a[0] = level; a[1] = desc;
    wire_encrypted(TLS13_CT_ALERT, a, 2);
}

static void wire_plain_alert(unsigned char level, unsigned char desc)
{
    unsigned char rec[7] = { TLS13_CT_ALERT, 0x03, 0x03, 0x00, 0x02 };
    rec[5] = level; rec[6] = desc;
    wire_append(rec, sizeof(rec));
}

static void scenario(int end)
{
    memset(&net, 0, sizeof(net));
    net.end = end;
    tls13_record_init(&peer, kKey, sizeof(kKey), kIv,
                      TLS13_AES_128_GCM_SHA256);
}

/* A context that finished a TLS 1.3 handshake with the peer above. */
static MacTLS_Context *connected13(void)
{
    MacTLS_Context *ctx = MacTLS_Create("example.test", 443);
    tls13_record_init(&ctx->hs13.read_ctx, kKey, sizeof(kKey), kIv,
                      TLS13_AES_128_GCM_SHA256);
    ctx->tls13_started = true;
    ctx->tls13_active  = true;
    ctx->hs13.is_tls13 = true;
    ctx->state         = kMacTLS_Connected;
    return ctx;
}

/* Pump and drain like Postman until the connection reaches a final state. */
static MacTLS_State run(MacTLS_Context *ctx, char *got, size_t cap)
{
    size_t len = 0;
    int i;
    got[0] = '\0';
    for (i = 0; i < 50; i++) {
        MacTLS_State st = MacTLS_Pump(ctx);
        int n;
        while ((n = MacTLS_Read(ctx, got + len, cap - len - 1)) > 0)
            len += (size_t)n;
        got[len] = '\0';
        if (st == kMacTLS_Closed || st == kMacTLS_Error) return st;
    }
    return MacTLS_GetState(ctx);   /* never settled: a hang */
}

static void expect_end(const char *name, MacTLS_Context *ctx, MacTLS_State st,
                       MacTLS_State want_state, MacTLS_Error want_err)
{
    char label[160];
    snprintf(label, sizeof(label), "%s: state", name);
    CHECK_INT(label, want_state, st);
    snprintf(label, sizeof(label), "%s: error", name);
    CHECK_INT(label, want_err, MacTLS_GetError(ctx));
}

/* ── TLS 1.3: authenticated close ── */

static void test_close_notify(void)
{
    char got[256];
    MacTLS_Context *ctx;
    MacTLS_State st;

    scenario(END_FIN);
    wire_data("hello ");
    wire_data("world");
    wire_alert(1, 0);
    ctx = connected13();
    st = run(ctx, got, sizeof(got));
    expect_end("close_notify after data", ctx, st, kMacTLS_Closed, kMacTLS_OK);
    CHECK_INT("close_notify after data: all data delivered", 0,
              strcmp(got, "hello world"));
    MacTLS_Close(ctx);

    /* The level byte is ignored in TLS 1.3 */
    scenario(END_FIN);
    wire_alert(2, 0);
    ctx = connected13();
    st = run(ctx, got, sizeof(got));
    expect_end("close_notify with level 2", ctx, st, kMacTLS_Closed, kMacTLS_OK);
    MacTLS_Close(ctx);

    /* close_notify with no FIN yet is already a clean end */
    scenario(END_NONE);
    wire_data("x");
    wire_alert(1, 0);
    ctx = connected13();
    st = run(ctx, got, sizeof(got));
    expect_end("close_notify, connection left open", ctx, st, kMacTLS_Closed,
               kMacTLS_OK);
    CHECK_INT("close_notify, connection left open: data", 0, strcmp(got, "x"));
    MacTLS_Close(ctx);

    /* Data after close_notify must be discarded */
    scenario(END_FIN);
    wire_data("kept");
    wire_alert(1, 0);
    wire_data("injected");
    ctx = connected13();
    st = run(ctx, got, sizeof(got));
    expect_end("data after close_notify", ctx, st, kMacTLS_Closed, kMacTLS_OK);
    CHECK_INT("data after close_notify: not delivered", 0, strcmp(got, "kept"));
    MacTLS_Close(ctx);

    /* user_canceled is advisory; only the following close_notify ends it */
    scenario(END_FIN);
    wire_data("a");
    wire_alert(1, 90);
    wire_data("b");
    wire_alert(1, 0);
    ctx = connected13();
    st = run(ctx, got, sizeof(got));
    expect_end("user_canceled then close_notify", ctx, st, kMacTLS_Closed,
               kMacTLS_OK);
    CHECK_INT("user_canceled then close_notify: data", 0, strcmp(got, "ab"));
    MacTLS_Close(ctx);
}

/* ── TLS 1.3: unauthenticated or hostile endings ── */

static void test_plaintext_alert_rejected(void)
{
    char got[256];
    MacTLS_Context *ctx;
    MacTLS_State st;

    /* On-path attacker injects a plaintext close_notify after a valid prefix */
    scenario(END_FIN);
    wire_data("valid prefix");
    wire_plain_alert(1, 0);
    ctx = connected13();
    st = run(ctx, got, sizeof(got));
    expect_end("plaintext close_notify", ctx, st, kMacTLS_Error, kMacTLS_ErrRead);
    CHECK_INT("plaintext close_notify: prefix still readable", 0,
              strcmp(got, "valid prefix"));
    MacTLS_Close(ctx);

    /* Same without a FIN: the connection is left open by the attacker */
    scenario(END_NONE);
    wire_plain_alert(1, 0);
    ctx = connected13();
    st = run(ctx, got, sizeof(got));
    expect_end("plaintext close_notify, no FIN", ctx, st, kMacTLS_Error,
               kMacTLS_ErrRead);
    MacTLS_Close(ctx);

    /* A plaintext fatal alert is no more trustworthy */
    scenario(END_NONE);
    wire_plain_alert(2, 40);
    ctx = connected13();
    st = run(ctx, got, sizeof(got));
    expect_end("plaintext fatal alert", ctx, st, kMacTLS_Error, kMacTLS_ErrRead);
    MacTLS_Close(ctx);

    /* Records of any other outer type are rejected too */
    scenario(END_NONE);
    {
        unsigned char rec[6] = { 0x18, 0x03, 0x03, 0x00, 0x01, 0x00 };
        wire_append(rec, sizeof(rec));
    }
    ctx = connected13();
    st = run(ctx, got, sizeof(got));
    expect_end("unknown outer record type", ctx, st, kMacTLS_Error,
               kMacTLS_ErrRead);
    MacTLS_Close(ctx);
}

static void test_fatal_and_malformed_alerts(void)
{
    char got[256];
    MacTLS_Context *ctx;
    MacTLS_State st;

    scenario(END_FIN);
    wire_data("partial");
    wire_alert(2, 40);   /* handshake_failure */
    ctx = connected13();
    st = run(ctx, got, sizeof(got));
    expect_end("fatal alert", ctx, st, kMacTLS_Error, kMacTLS_ErrPeerAlert);
    CHECK_INT("fatal alert: description exposed", BR_ERR_RECV_FATAL_ALERT + 40,
              MacTLS_GetBearSSLError(ctx));
    CHECK_INT("fatal alert: earlier data was delivered", 0,
              strcmp(got, "partial"));
    MacTLS_Close(ctx);

    /* Level is ignored: a "warning" level non-close alert is still fatal */
    scenario(END_FIN);
    wire_alert(1, 80);   /* internal_error */
    ctx = connected13();
    st = run(ctx, got, sizeof(got));
    expect_end("warning-level internal_error", ctx, st, kMacTLS_Error,
               kMacTLS_ErrPeerAlert);
    MacTLS_Close(ctx);

    /* One-byte alert */
    scenario(END_FIN);
    {
        unsigned char one = 0;
        wire_encrypted(TLS13_CT_ALERT, &one, 1);
    }
    ctx = connected13();
    st = run(ctx, got, sizeof(got));
    expect_end("1-byte alert", ctx, st, kMacTLS_Error, kMacTLS_ErrRead);
    MacTLS_Close(ctx);

    /* Three-byte alert */
    scenario(END_FIN);
    {
        unsigned char three[3] = { 1, 0, 0 };
        wire_encrypted(TLS13_CT_ALERT, three, 3);
    }
    ctx = connected13();
    st = run(ctx, got, sizeof(got));
    expect_end("3-byte alert", ctx, st, kMacTLS_Error, kMacTLS_ErrRead);
    MacTLS_Close(ctx);

    /* Empty alert */
    scenario(END_FIN);
    wire_encrypted(TLS13_CT_ALERT, "", 0);
    ctx = connected13();
    st = run(ctx, got, sizeof(got));
    expect_end("empty alert", ctx, st, kMacTLS_Error, kMacTLS_ErrRead);
    MacTLS_Close(ctx);
}

static void test_truncation(void)
{
    char got[256];
    MacTLS_Context *ctx;
    MacTLS_State st;

    /* The classic attack: valid prefix, then the transport just ends */
    scenario(END_FIN);
    wire_data("Content-Length: 10\r\n\r\nHello");
    ctx = connected13();
    st = run(ctx, got, sizeof(got));
    expect_end("FIN without close_notify", ctx, st, kMacTLS_Error,
               kMacTLS_ErrTruncated);
    CHECK_INT("FIN without close_notify: prefix delivered", 0,
              strcmp(got, "Content-Length: 10\r\n\r\nHello"));
    MacTLS_Close(ctx);

    scenario(END_RESET);
    wire_data("prefix");
    ctx = connected13();
    st = run(ctx, got, sizeof(got));
    expect_end("reset without close_notify", ctx, st, kMacTLS_Error,
               kMacTLS_ErrTruncated);
    CHECK_INT("reset without close_notify: prefix delivered", 0,
              strcmp(got, "prefix"));
    MacTLS_Close(ctx);

    scenario(END_FIN);
    ctx = connected13();
    st = run(ctx, got, sizeof(got));
    expect_end("FIN before any data", ctx, st, kMacTLS_Error, kMacTLS_ErrTruncated);
    MacTLS_Close(ctx);

    /* FIN in the middle of a record can never complete: must not hang */
    scenario(END_FIN);
    wire_data("first");
    wire_data("second");
    net.wire_len -= 7;
    ctx = connected13();
    st = run(ctx, got, sizeof(got));
    expect_end("FIN mid-record", ctx, st, kMacTLS_Error, kMacTLS_ErrTruncated);
    CHECK_INT("FIN mid-record: complete records delivered", 0,
              strcmp(got, "first"));
    MacTLS_Close(ctx);

    /* FIN in the middle of the record header */
    scenario(END_FIN);
    {
        unsigned char hdr[3] = { 0x17, 0x03, 0x03 };
        wire_append(hdr, sizeof(hdr));
    }
    ctx = connected13();
    st = run(ctx, got, sizeof(got));
    expect_end("FIN mid-header", ctx, st, kMacTLS_Error, kMacTLS_ErrTruncated);
    MacTLS_Close(ctx);

    /* Buffered data must be drained before the verdict, not lost with it */
    scenario(END_FIN);
    wire_data("one");
    wire_data("two");
    wire_data("three");
    ctx = connected13();
    st = run(ctx, got, sizeof(got));
    expect_end("several records then FIN", ctx, st, kMacTLS_Error,
               kMacTLS_ErrTruncated);
    CHECK_INT("several records then FIN: all delivered", 0,
              strcmp(got, "onetwothree"));
    MacTLS_Close(ctx);
}

/* ── Transport reset must not mask what the buffered records say ── */

static void preload(MacTLS_Context *ctx)
{
    /* Bytes OT already handed over before the reset arrived. */
    memcpy(ctx->tls13_recv_buf, net.wire, net.wire_len);
    ctx->tls13_recv_len = net.wire_len;
    net.wire_len = net.wire_pos = 0;
}

static void test_reset_keeps_verdict(void)
{
    char got[256];
    MacTLS_Context *ctx;
    MacTLS_State st;

    /* Corrupted record + reset: decryption failure, not Closed */
    scenario(END_RESET);
    wire_data("tampered");
    net.wire[net.wire_len - 3] ^= 0x55;
    ctx = connected13();
    preload(ctx);
    ctx->transport->disconnectReceived = true;
    st = run(ctx, got, sizeof(got));
    expect_end("bad MAC then reset", ctx, st, kMacTLS_Error, kMacTLS_ErrRead);
    CHECK_INT("bad MAC then reset: nothing delivered", 0, (int)strlen(got));
    MacTLS_Close(ctx);

    /* Fatal alert + reset */
    scenario(END_RESET);
    wire_alert(2, 20);   /* bad_record_mac */
    ctx = connected13();
    preload(ctx);
    ctx->transport->disconnectReceived = true;
    st = run(ctx, got, sizeof(got));
    expect_end("fatal alert then reset", ctx, st, kMacTLS_Error,
               kMacTLS_ErrPeerAlert);
    MacTLS_Close(ctx);

    /* Plaintext alert + reset */
    scenario(END_RESET);
    wire_data("data");
    wire_plain_alert(1, 0);
    ctx = connected13();
    preload(ctx);
    ctx->transport->disconnectReceived = true;
    st = run(ctx, got, sizeof(got));
    expect_end("plaintext close_notify then reset", ctx, st, kMacTLS_Error,
               kMacTLS_ErrRead);
    MacTLS_Close(ctx);

    /* Authenticated close_notify already buffered when the reset hit */
    scenario(END_RESET);
    wire_data("complete");
    wire_alert(1, 0);
    ctx = connected13();
    preload(ctx);
    ctx->transport->disconnectReceived = true;
    st = run(ctx, got, sizeof(got));
    expect_end("close_notify buffered then reset", ctx, st, kMacTLS_Closed,
               kMacTLS_OK);
    CHECK_INT("close_notify buffered then reset: data", 0, strcmp(got, "complete"));
    MacTLS_Close(ctx);

    /* Valid data but no close_notify buffered before the reset */
    scenario(END_RESET);
    wire_data("a");
    wire_data("b");
    ctx = connected13();
    preload(ctx);
    ctx->transport->disconnectReceived = true;
    st = run(ctx, got, sizeof(got));
    expect_end("buffered data then reset", ctx, st, kMacTLS_Error,
               kMacTLS_ErrTruncated);
    CHECK_INT("buffered data then reset: data drained", 0, strcmp(got, "ab"));
    MacTLS_Close(ctx);
}

/* ── Handshake phase ── */

static void test_handshake_close(void)
{
    char got[16];
    MacTLS_Context *ctx;
    MacTLS_State st;

    scenario(END_FIN);
    ctx = MacTLS_Create("example.test", 443);
    st = run(ctx, got, sizeof(got));
    expect_end("FIN during TLS 1.3 handshake", ctx, st, kMacTLS_Error,
               kMacTLS_ErrTruncated);
    MacTLS_Close(ctx);
}

/* ── TLS 1.2 (BearSSL engine) ── */

static MacTLS_Context *handshaking12(void)
{
    MacTLS_Context *ctx = MacTLS_Create("example.test", 443);
    /* The state a TLS 1.3 attempt leaves after falling back to 1.2. */
    ctx->hs13.state = kTLS13_RecvServerHello;
    br_ssl_client_reset(&ctx->sc, ctx->host, 0);
    ctx->state = kMacTLS_Handshaking;
    return ctx;
}

static void test_tls12(void)
{
    char got[16];
    MacTLS_Context *ctx;
    MacTLS_State st;

    /* Peer closes after our ClientHello went out */
    scenario(END_FIN);
    ctx = handshaking12();
    st = run(ctx, got, sizeof(got));
    expect_end("1.2: FIN without close_notify", ctx, st, kMacTLS_Error,
               kMacTLS_ErrTruncated);
    CHECK_INT("1.2: premature close is reported as BR_ERR_IO", BR_ERR_IO,
              MacTLS_GetBearSSLError(ctx));
    MacTLS_Close(ctx);

    scenario(END_RESET);
    ctx = handshaking12();
    st = run(ctx, got, sizeof(got));
    expect_end("1.2: reset without close_notify", ctx, st, kMacTLS_Error,
               kMacTLS_ErrTruncated);
    MacTLS_Close(ctx);

    /* Peer already gone when we try to send */
    scenario(END_FIN);
    net.send_fails = 1;
    ctx = handshaking12();
    ctx->transport->ordRelReceived = true;
    st = run(ctx, got, sizeof(got));
    expect_end("1.2: send fails, no close_notify", ctx, st, kMacTLS_Error,
               kMacTLS_ErrTruncated);
    MacTLS_Close(ctx);

    /* ...but if its close_notify was processed, the failed reply is benign */
    scenario(END_FIN);
    net.send_fails = 1;
    ctx = handshaking12();
    ctx->transport->ordRelReceived = true;
    ctx->sc.eng.shutdown_recv = 1;
    st = run(ctx, got, sizeof(got));
    expect_end("1.2: send fails after close_notify", ctx, st, kMacTLS_Closed,
               kMacTLS_OK);
    MacTLS_Close(ctx);

    /* A fatal alert received by the engine is reported as such */
    scenario(END_NONE);
    ctx = handshaking12();
    br_ssl_engine_fail(&ctx->sc.eng, BR_ERR_RECV_FATAL_ALERT + 40);
    st = run(ctx, got, sizeof(got));
    expect_end("1.2: fatal alert", ctx, st, kMacTLS_Error, kMacTLS_ErrPeerAlert);
    CHECK_INT("1.2: fatal alert code", BR_ERR_RECV_FATAL_ALERT + 40,
              MacTLS_GetBearSSLError(ctx));
    MacTLS_Close(ctx);

    /* A reset that arrives after the engine already saw close_notify */
    scenario(END_RESET);
    ctx = handshaking12();
    br_ssl_engine_fail(&ctx->sc.eng, BR_ERR_OK);
    ctx->transport->disconnectReceived = true;
    st = run(ctx, got, sizeof(got));
    expect_end("1.2: reset after close_notify", ctx, st, kMacTLS_Closed,
               kMacTLS_OK);
    MacTLS_Close(ctx);

    /* ...and one after the engine saw a fatal alert keeps that verdict */
    scenario(END_RESET);
    ctx = handshaking12();
    br_ssl_engine_fail(&ctx->sc.eng, BR_ERR_RECV_FATAL_ALERT + 10);
    ctx->transport->disconnectReceived = true;
    st = run(ctx, got, sizeof(got));
    expect_end("1.2: reset after fatal alert", ctx, st, kMacTLS_Error,
               kMacTLS_ErrPeerAlert);
    MacTLS_Close(ctx);

    /* A cleanly closed engine (close_notify) is still a normal Closed */
    scenario(END_NONE);
    ctx = handshaking12();
    br_ssl_engine_fail(&ctx->sc.eng, BR_ERR_OK);   /* closed, no error */
    st = run(ctx, got, sizeof(got));
    expect_end("1.2: engine closed cleanly", ctx, st, kMacTLS_Closed, kMacTLS_OK);
    MacTLS_Close(ctx);
}

int main(void)
{
    MacTLS_Init();
    test_close_notify();
    test_plaintext_alert_rejected();
    test_fatal_and_malformed_alerts();
    test_truncation();
    test_reset_keeps_verdict();
    test_handshake_close();
    test_tls12();

    printf("\n%d passed, %d failed\n", passes, failures);
    return failures == 0 ? 0 : 1;
}
