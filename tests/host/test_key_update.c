/*
 * test_key_update.c — post-handshake KeyUpdate (RFC 8446 section 4.6.3)
 *
 * Compiles the production pump (src/certainly.c) against stub Mac headers
 * and a fake transport, then plays a server that rekeys mid-connection.
 * The checks cover both directions: the receive keys must follow the
 * server's KeyUpdate, and an update_requested KeyUpdate must be answered on
 * the wire, under the old write keys, before any application data under the
 * new ones.
 *
 * Build and run on the HOST machine:
 *   cd tests/host && make test_key_update && ./test_key_update
 */

#include "record_helpers.h"
#include "../../src/certainly.c"

/* ── Fake transport and platform services ── */

static const unsigned char *feed;
static size_t feed_len;
static size_t feed_pos;

static unsigned char wire[4096];
static size_t wire_len;
static bool send_blocked;
static int send_stall_calls;   /* next n sends accept nothing */

OTTransport *ot_transport_create(const char *h, uint16_t p) { (void)h; (void)p; return NULL; }
OTTransportState ot_transport_pump(OTTransport *t) { (void)t; return kOTTransport_Connected; }
void ot_transport_close(OTTransport *t) { (void)t; }
void ot_transport_destroy(OTTransport *t) { (void)t; }

int ot_transport_send(OTTransport *t, const void *b, size_t n)
{
    (void)t;
    if (send_blocked) return 0;
    if (send_stall_calls > 0) { send_stall_calls--; return 0; }
    memcpy(wire + wire_len, b, n);
    wire_len += n;
    return (int)n;
}

int ot_transport_recv(OTTransport *t, void *buf, size_t len)
{
    size_t n = feed_len - feed_pos;
    (void)t;
    if (n > len) n = len;
    memcpy(buf, feed + feed_pos, n);
    feed_pos += n;
    return (int)n;
}

void entropy_init(void) {}
void entropy_shutdown(void) {}
void entropy_add(const void *data, size_t len) { (void)data; (void)len; }
void entropy_set_provider(entropy_provider_fn fn, void *user) { (void)fn; (void)user; }
entropy_status entropy_seed_trusted(const void *seed, size_t len)
{
    (void)seed; (void)len;
    return kEntropy_OK;
}
entropy_status entropy_get_trusted(void *out, size_t len)
{
    (void)out; (void)len;
    return kEntropy_OK;
}
entropy_status entropy_seed_engine(br_ssl_engine_context *eng)
{
    (void)eng;
    return kEntropy_OK;
}
const br_x509_trust_anchor TAs[1];
const size_t TAs_NUM = 0;

/* ── Fixture ── */

/*
 * One direction as the peer sees it: the traffic secret plus a record
 * context keyed from it. rekey() is the peer's side of a KeyUpdate.
 */
typedef struct {
    unsigned char secret[64];
    tls13_record_ctx rec;
} peer_dir;

typedef struct {
    MacTLS_Context *ctx;
    tls13_keysched ks;     /* only for the peer's ratchet */
    peer_dir to_client;    /* server write, client read */
    peer_dir from_client;  /* client write, server read */
    size_t suite;
} fixture;

static void peer_dir_start(fixture *f, peer_dir *d, unsigned char fill,
                           tls13_record_ctx *client_side)
{
    unsigned char key[32], iv[12];
    size_t i, key_len = suites[f->suite].key_len;

    for (i = 0; i < sizeof(d->secret); i++) d->secret[i] = (unsigned char)(fill + i);
    for (i = 0; i < sizeof(key); i++) key[i] = (unsigned char)(fill ^ (0x30 + i));
    for (i = 0; i < sizeof(iv); i++) iv[i] = (unsigned char)(fill ^ (0x70 + i));
    tls13_record_init(&d->rec, key, key_len, iv, suites[f->suite].id);
    tls13_record_init(client_side, key, key_len, iv, suites[f->suite].id);
}

static void peer_rekey(fixture *f, peer_dir *d)
{
    unsigned char key[32], iv[12];

    tls13_ks_update_traffic_secret(&f->ks, d->secret,
                                   suites[f->suite].key_len, key, iv);
    tls13_record_init(&d->rec, key, suites[f->suite].key_len, iv,
                      suites[f->suite].id);
}

static void fixture_init(fixture *f, size_t suite)
{
    tls13_hs_ctx *hs;

    memset(f, 0, sizeof(*f));
    f->suite = suite;
    f->ctx = (MacTLS_Context *)calloc(1, sizeof(*f->ctx));
    f->ctx->transport = (OTTransport *)calloc(1, sizeof(OTTransport));
    f->ctx->state = kMacTLS_Connected;
    f->ctx->tls13_active = true;
    f->ctx->tls13_started = true;

    hs = &f->ctx->hs13;
    hs->cipher_suite = suites[suite].id;
    tls13_ks_init(&hs->ks, &br_sha256_vtable);
    tls13_ks_init(&f->ks, &br_sha256_vtable);
    peer_dir_start(f, &f->to_client, 0x11, &hs->read_ctx);
    peer_dir_start(f, &f->from_client, 0x22, &hs->write_ctx);
    memcpy(hs->server_app_secret, f->to_client.secret, 32);
    memcpy(hs->client_app_secret, f->from_client.secret, 32);

    wire_len = 0;
    send_blocked = false;
    send_stall_calls = 0;
    feed_len = feed_pos = 0;
}

static void fixture_free(fixture *f)
{
    free(f->ctx->transport);
    free(f->ctx);
}

/* Server record carrying `body` as handshake content, sealed under the
 * server's current write keys, appended to out at *out_len. */
static void push_record(fixture *f, uint8_t type, const unsigned char *body,
                        size_t body_len, unsigned char *out, size_t *out_len)
{
    size_t sealed_len = seal_record(&f->to_client.rec, body, body_len, type, 0,
                                    out + *out_len + 5);

    out[*out_len + 0] = TLS13_CT_APPLICATION_DATA;
    out[*out_len + 1] = 3;
    out[*out_len + 2] = 3;
    out[*out_len + 3] = (unsigned char)(sealed_len >> 8);
    out[*out_len + 4] = (unsigned char)sealed_len;
    *out_len += 5 + sealed_len;
}

static void push_key_update(fixture *f, unsigned char request,
                            unsigned char *out, size_t *out_len)
{
    unsigned char msg[5] = { TLS13_HT_KEY_UPDATE, 0, 0, 1, 0 };
    msg[4] = request;
    push_record(f, TLS13_CT_HANDSHAKE, msg, sizeof(msg), out, out_len);
}

static void push_app(fixture *f, const char *text, unsigned char *out,
                     size_t *out_len)
{
    push_record(f, TLS13_CT_APPLICATION_DATA, (const unsigned char *)text,
                strlen(text), out, out_len);
}

static MacTLS_State pump_with(fixture *f, const unsigned char *bytes, size_t n)
{
    feed = bytes;
    feed_len = n;
    feed_pos = 0;
    return MacTLS_Pump(f->ctx);
}

/* Decrypt the next record the client put on the wire with `rx`. */
static int take_client_record(tls13_record_ctx *rx, size_t *pos,
                              unsigned char *plain, size_t *plain_len,
                              uint8_t *type)
{
    unsigned char scratch[TLS13_DECRYPT_BUF_SIZE];
    size_t len;

    if (*pos + 5 > wire_len) return -1;
    len = ((size_t)wire[*pos + 3] << 8) | wire[*pos + 4];
    if (*pos + 5 + len > wire_len) return -1;
    if (tls13_record_decrypt(rx, wire + *pos + 5, len, scratch, sizeof(scratch),
                             plain_len, type) != 0) return -1;
    memcpy(plain, scratch, *plain_len);
    *pos += 5 + len;
    return 0;
}

static int expect_data(fixture *f, const char *want)
{
    unsigned char got[64];
    int n = MacTLS_Read(f->ctx, got, sizeof(got));
    return n == (int)strlen(want) && memcmp(got, want, (size_t)n) == 0;
}

/* ── Tests ── */

/* update_not_requested: receive keys follow, nothing is sent back. */
static void test_not_requested(size_t s)
{
    fixture f;
    unsigned char in[512];
    size_t in_len = 0;
    MacTLS_State st;

    fixture_init(&f, s);
    push_app(&f, "before", in, &in_len);
    push_key_update(&f, 0, in, &in_len);
    peer_rekey(&f, &f.to_client);
    push_app(&f, "after", in, &in_len);

    st = pump_with(&f, in, in_len);
    CHECK(st == kMacTLS_Connected, "%s: state=%d error=%d", suites[s].name,
          st, f.ctx->error);
    CHECK(expect_data(&f, "before"), "%s: first record lost", suites[s].name);
    st = pump_with(&f, in, 0);
    CHECK(expect_data(&f, "after"), "%s: data under new keys not delivered",
          suites[s].name);
    CHECK(f.ctx->hs13.read_ctx.seq == 1,
          "%s: read seq=%llu after rekey", suites[s].name,
          (unsigned long long)f.ctx->hs13.read_ctx.seq);
    CHECK(wire_len == 0 && f.ctx->hs13.write_ctx.seq == 0,
          "%s: replied to update_not_requested", suites[s].name);
    fixture_free(&f);
}

/*
 * update_requested: the reply is a KeyUpdate(update_not_requested) under
 * the old write keys; application data after it uses the ratcheted keys.
 */
static void test_requested(size_t s)
{
    fixture f;
    unsigned char in[256], plain[64];
    size_t in_len = 0, pos = 0, plain_len;
    uint8_t type;
    int n;

    fixture_init(&f, s);
    push_key_update(&f, 1, in, &in_len);
    CHECK(pump_with(&f, in, in_len) == kMacTLS_Connected,
          "%s: state after update_requested", suites[s].name);

    CHECK(take_client_record(&f.from_client.rec, &pos, plain, &plain_len, &type) == 0 &&
          type == TLS13_CT_HANDSHAKE && plain_len == 5 &&
          memcmp(plain, "\x18\x00\x00\x01\x00", 5) == 0,
          "%s: no KeyUpdate(update_not_requested) under the old keys",
          suites[s].name);
    CHECK(pos == wire_len, "%s: %zu extra bytes on the wire", suites[s].name,
          wire_len - pos);

    peer_rekey(&f, &f.from_client);
    n = MacTLS_Write(f.ctx, "hello", 5);
    CHECK(n == 5, "%s: write after reply returned %d", suites[s].name, n);
    MacTLS_Pump(f.ctx);
    CHECK(take_client_record(&f.from_client.rec, &pos, plain, &plain_len, &type) == 0 &&
          type == TLS13_CT_APPLICATION_DATA && plain_len == 5 &&
          memcmp(plain, "hello", 5) == 0,
          "%s: application data not under the ratcheted keys", suites[s].name);
    fixture_free(&f);
}

/*
 * A record still queued for sending was encrypted under the old keys, so the
 * reply must follow it, and no new application data may be accepted until
 * the reply is out.
 */
static void test_reply_waits_for_queued_record(size_t s)
{
    fixture f;
    unsigned char in[256], plain[64];
    size_t in_len = 0, pos = 0, plain_len;
    uint8_t type;

    fixture_init(&f, s);

    CHECK(MacTLS_Write(f.ctx, "queued", 6) == 6, "%s: initial write",
          suites[s].name);
    /* The first send stalls, so the KeyUpdate arrives while "queued" is
     * still unsent; the pump's last flush then drains it, leaving the send
     * buffer empty with the reply still pending. */
    send_stall_calls = 1;
    push_key_update(&f, 1, in, &in_len);
    CHECK(pump_with(&f, in, in_len) == kMacTLS_Connected,
          "%s: state with a stalled send", suites[s].name);
    CHECK(f.ctx->hs13.key_update_out_len > 0 &&
          f.ctx->tls13_send_offset == f.ctx->tls13_send_len,
          "%s: setup: expected an empty send buffer and a pending reply",
          suites[s].name);
    CHECK(MacTLS_Write(f.ctx, "early", 5) == 0,
          "%s: write accepted while the reply was pending", suites[s].name);

    MacTLS_Pump(f.ctx);
    MacTLS_Pump(f.ctx);
    CHECK(take_client_record(&f.from_client.rec, &pos, plain, &plain_len, &type) == 0 &&
          type == TLS13_CT_APPLICATION_DATA && plain_len == 6 &&
          memcmp(plain, "queued", 6) == 0,
          "%s: queued record not first on the wire", suites[s].name);
    CHECK(take_client_record(&f.from_client.rec, &pos, plain, &plain_len, &type) == 0 &&
          type == TLS13_CT_HANDSHAKE && plain_len == 5 &&
          memcmp(plain, "\x18\x00\x00\x01\x00", 5) == 0,
          "%s: KeyUpdate did not follow the queued record", suites[s].name);

    peer_rekey(&f, &f.from_client);
    CHECK(MacTLS_Write(f.ctx, "late", 4) == 4, "%s: write after reply sent",
          suites[s].name);
    MacTLS_Pump(f.ctx);
    CHECK(take_client_record(&f.from_client.rec, &pos, plain, &plain_len, &type) == 0 &&
          type == TLS13_CT_APPLICATION_DATA && plain_len == 4 &&
          memcmp(plain, "late", 4) == 0,
          "%s: later write not under the ratcheted keys", suites[s].name);
    fixture_free(&f);
}

/* Several requests while silent get one answer (RFC 8446 section 4.6.3). */
static void test_requests_coalesce(size_t s)
{
    fixture f;
    unsigned char in[512], plain[64];
    size_t in_len = 0, pos = 0, plain_len;
    uint8_t type;

    fixture_init(&f, s);
    push_key_update(&f, 1, in, &in_len);
    peer_rekey(&f, &f.to_client);
    push_key_update(&f, 1, in, &in_len);
    peer_rekey(&f, &f.to_client);
    push_app(&f, "still alive", in, &in_len);

    CHECK(pump_with(&f, in, in_len) == kMacTLS_Connected,
          "%s: state after two requests (error=%d)", suites[s].name,
          f.ctx->error);
    CHECK(expect_data(&f, "still alive"), "%s: data after two updates",
          suites[s].name);
    CHECK(take_client_record(&f.from_client.rec, &pos, plain, &plain_len, &type) == 0 &&
          type == TLS13_CT_HANDSHAKE, "%s: no reply", suites[s].name);
    CHECK(pos == wire_len, "%s: more than one reply sent", suites[s].name);
    CHECK(f.ctx->hs13.write_ctx.seq == 0,
          "%s: write keys ratcheted more than once", suites[s].name);
    fixture_free(&f);
}

/* Malformed or illegal KeyUpdates end the connection. */
static void expect_fatal(size_t s, const char *what, const unsigned char *msgs,
                         size_t msgs_len)
{
    fixture f;
    unsigned char in[256];
    size_t in_len = 0;
    MacTLS_State st;

    fixture_init(&f, s);
    push_record(&f, TLS13_CT_HANDSHAKE, msgs, msgs_len, in, &in_len);
    st = pump_with(&f, in, in_len);
    CHECK(st == kMacTLS_Error && f.ctx->error == kMacTLS_ErrHandshake,
          "%s: %s: state=%d error=%d", suites[s].name, what, st, f.ctx->error);
    fixture_free(&f);
}

static void test_rejected(size_t s)
{
    expect_fatal(s, "request_update=2", (const unsigned char *)"\x18\0\0\1\2", 5);
    expect_fatal(s, "request_update=255", (const unsigned char *)"\x18\0\0\1\xff", 5);
    expect_fatal(s, "empty body", (const unsigned char *)"\x18\0\0\0", 4);
    expect_fatal(s, "two-byte body", (const unsigned char *)"\x18\0\0\2\0\0", 6);
    expect_fatal(s, "truncated header", (const unsigned char *)"\x18\0\0", 3);
    /* A key change cannot sit in the middle of a record. */
    expect_fatal(s, "KeyUpdate before another message",
                 (const unsigned char *)"\x18\0\0\1\0\x18\0\0\1\0", 10);
}

/* NewSessionTicket ahead of a KeyUpdate in one record is legal. */
static void test_ticket_then_update(size_t s)
{
    fixture f;
    unsigned char in[256], msgs[9 + 5];
    size_t in_len = 0;
    MacTLS_State st;

    fixture_init(&f, s);
    memcpy(msgs, "\x04\0\0\5ticke", 9);
    memcpy(msgs + 9, "\x18\0\0\1\0", 5);
    push_record(&f, TLS13_CT_HANDSHAKE, msgs, sizeof(msgs), in, &in_len);
    peer_rekey(&f, &f.to_client);
    push_app(&f, "ok", in, &in_len);
    st = pump_with(&f, in, in_len);
    CHECK(st == kMacTLS_Connected, "%s: state=%d error=%d", suites[s].name,
          st, f.ctx->error);
    pump_with(&f, in, 0);
    CHECK(expect_data(&f, "ok"), "%s: data after ticket+update", suites[s].name);
    fixture_free(&f);
}

int main(void)
{
    size_t s;
    for (s = 0; s < NUM_SUITES; s++) {
        test_not_requested(s);
        test_requested(s);
        test_reply_waits_for_queued_record(s);
        test_requests_coalesce(s);
        test_rejected(s);
        test_ticket_then_update(s);
        printf("done: %s\n", suites[s].name);
    }
    if (failures) {
        printf("%d check(s) FAILED\n", failures);
        return 1;
    }
    printf("test_key_update: all checks passed\n");
    return 0;
}
