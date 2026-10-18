/*
 * test_record_app.c — application-data path record decryption bounds
 *
 * Compiles the production pump (src/certainly.c) against stub Mac
 * headers and a fake transport, then feeds it records through
 * MacTLS_Pump(). This reaches the real tls13_recv_records(), whose
 * decrypt destination is hs13.plain_buf. Unauthenticated records up to the
 * 16-bit length limit must never write past that buffer; run under ASan
 * (make asan) to catch any overrun.
 *
 * Build and run on the HOST machine:
 *   cd tests/host && make test_record_app && ./test_record_app
 */

#include "record_helpers.h"
#include "../../src/certainly.c"

/* ── Fake transport and platform services ── */

static const unsigned char *feed;
static size_t feed_len;
static size_t feed_pos;

OTTransport *ot_transport_create(const char *h, uint16_t p) { (void)h; (void)p; return NULL; }
OTTransportState ot_transport_pump(OTTransport *t) { (void)t; return kOTTransport_Connected; }
int ot_transport_send(OTTransport *t, const void *b, size_t n) { (void)t; (void)b; return (int)n; }
void ot_transport_close(OTTransport *t) { (void)t; }
void ot_transport_destroy(OTTransport *t) { (void)t; }

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
void entropy_add(const void *data, size_t len) { (void)data; (void)len; }
void entropy_seed_engine(br_ssl_engine_context *eng) { (void)eng; }
const br_x509_trust_anchor TAs[1];
const size_t TAs_NUM = 0;

/* ── Fixture ── */

static MacTLS_Context *new_connection(size_t suite)
{
    MacTLS_Context *ctx = (MacTLS_Context *)calloc(1, sizeof(*ctx));
    ctx->transport = (OTTransport *)calloc(1, sizeof(OTTransport));
    ctx->state = kMacTLS_Connected;
    ctx->tls13_active = true;
    ctx->tls13_started = true;
    init_ctx(&ctx->hs13.read_ctx, suite);
    return ctx;
}

static void free_connection(MacTLS_Context *ctx)
{
    free(ctx->transport);
    free(ctx);
}

/* Header plus an arbitrary payload, as the server would put it on the wire. */
static unsigned char *wire_record(const unsigned char *payload, size_t len,
                                  size_t *wire_len)
{
    unsigned char *w = (unsigned char *)malloc(5 + len);
    w[0] = TLS13_CT_APPLICATION_DATA;
    w[1] = 3;
    w[2] = 3;
    w[3] = (unsigned char)(len >> 8);
    w[4] = (unsigned char)len;
    memcpy(w + 5, payload, len);
    *wire_len = 5 + len;
    return w;
}

static void set_feed(const unsigned char *b, size_t n)
{
    feed = b;
    feed_len = n;
    feed_pos = 0;
}

/* Full 16384-byte payloads, with and without padding, deliver intact. */
static void test_legal_full_record(size_t s)
{
    static const size_t pads[] = { 0, 1, 239 };
    size_t pi;

    for (pi = 0; pi < sizeof(pads) / sizeof(pads[0]); pi++) {
        MacTLS_Context *ctx = new_connection(s);
        tls13_record_ctx tx;
        unsigned char *content = (unsigned char *)malloc(TLS13_MAX_PLAINTEXT);
        unsigned char *sealed = (unsigned char *)malloc(TLS13_MAX_CIPHERTEXT);
        unsigned char *wire;
        unsigned char *got = (unsigned char *)malloc(TLS13_MAX_PLAINTEXT);
        size_t i, sealed_len, wire_len;
        MacTLS_State st;
        int n;

        for (i = 0; i < TLS13_MAX_PLAINTEXT; i++) content[i] = (unsigned char)(i * 13 + 1);
        init_ctx(&tx, s);
        sealed_len = seal_record(&tx, content, TLS13_MAX_PLAINTEXT,
                                 TLS13_CT_APPLICATION_DATA, pads[pi], sealed);
        wire = wire_record(sealed, sealed_len, &wire_len);
        set_feed(wire, wire_len);

        st = MacTLS_Pump(ctx);
        CHECK(st == kMacTLS_Connected, "%s pad=%zu: state=%d error=%d",
              suites[s].name, pads[pi], st, ctx->error);
        CHECK(MacTLS_Available(ctx) == TLS13_MAX_PLAINTEXT,
              "%s pad=%zu: available=%zu", suites[s].name, pads[pi],
              MacTLS_Available(ctx));
        n = MacTLS_Read(ctx, got, TLS13_MAX_PLAINTEXT);
        CHECK(n == TLS13_MAX_PLAINTEXT && memcmp(got, content, TLS13_MAX_PLAINTEXT) == 0,
              "%s pad=%zu: read %d bytes, mismatch", suites[s].name, pads[pi], n);
        CHECK(ctx->tls13_recv_len == 0, "%s pad=%zu: %zu bytes left in recv_buf",
              suites[s].name, pads[pi], ctx->tls13_recv_len);

        free(got); free(wire); free(sealed); free(content);
        free_connection(ctx);
    }
}

/*
 * Forged records at the largest legal length and everything above the
 * limit up to what a 16-bit length can claim. None may deliver data; all must end the
 * connection with a read error instead of stalling.
 */
static void test_rejected_records(size_t s)
{
    static const size_t lens[] = {
        17, 16401, 16448, TLS13_MAX_CIPHERTEXT,
        TLS13_MAX_CIPHERTEXT + 1, 17000, 65535
    };
    size_t li;

    for (li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
        MacTLS_Context *ctx = new_connection(s);
        unsigned char *junk = (unsigned char *)malloc(lens[li]);
        unsigned char *wire;
        size_t wire_len;
        MacTLS_State st;

        memset(junk, 0x41, lens[li]);
        wire = wire_record(junk, lens[li], &wire_len);
        set_feed(wire, wire_len);

        /* The receive buffer is smaller than the largest claimed record,
         * so pump until the feed is drained or the connection fails. */
        st = MacTLS_Pump(ctx);
        CHECK(st == kMacTLS_Error && ctx->error == kMacTLS_ErrRead,
              "%s len=%zu: state=%d error=%d", suites[s].name, lens[li],
              st, ctx->error);
        CHECK(ctx->tls13_app_len == 0, "%s len=%zu: delivered %zu bytes",
              suites[s].name, lens[li], ctx->tls13_app_len);
        CHECK(ctx->hs13.read_ctx.seq == 0, "%s len=%zu: seq advanced",
              suites[s].name, lens[li]);

        free(wire); free(junk);
        free_connection(ctx);
    }
}

/* A rejected record must not poison the connection's earlier good data. */
static void test_good_then_forged(size_t s)
{
    MacTLS_Context *ctx = new_connection(s);
    tls13_record_ctx tx;
    unsigned char content[100], sealed[200], got[100];
    unsigned char *junk = (unsigned char *)malloc(16448);
    unsigned char *w1, *w2, *both;
    size_t sealed_len, w1_len, w2_len;
    MacTLS_State st;

    memset(content, 0x61, sizeof(content));
    memset(junk, 0x41, 16448);
    init_ctx(&tx, s);
    sealed_len = seal_record(&tx, content, sizeof(content),
                             TLS13_CT_APPLICATION_DATA, 0, sealed);
    w1 = wire_record(sealed, sealed_len, &w1_len);
    w2 = wire_record(junk, 16448, &w2_len);
    both = (unsigned char *)malloc(w1_len + w2_len);
    memcpy(both, w1, w1_len);
    memcpy(both + w1_len, w2, w2_len);
    set_feed(both, w1_len + w2_len);

    st = MacTLS_Pump(ctx);
    CHECK(st == kMacTLS_Connected && MacTLS_Available(ctx) == sizeof(content),
          "%s: good record not delivered (state=%d avail=%zu)",
          suites[s].name, st, MacTLS_Available(ctx));
    CHECK(MacTLS_Read(ctx, got, sizeof(got)) == (int)sizeof(got) &&
          memcmp(got, content, sizeof(got)) == 0, "%s: good data corrupted",
          suites[s].name);
    st = MacTLS_Pump(ctx);
    CHECK(st == kMacTLS_Error, "%s: forged follow-up state=%d",
          suites[s].name, st);

    free(both); free(w1); free(w2); free(junk);
    free_connection(ctx);
}

int main(void)
{
    size_t s;
    for (s = 0; s < NUM_SUITES; s++) {
        test_legal_full_record(s);
        test_rejected_records(s);
        test_good_then_forged(s);
        printf("done: %s\n", suites[s].name);
    }
    if (failures) {
        printf("%d check(s) FAILED\n", failures);
        return 1;
    }
    printf("test_record_app: all checks passed\n");
    return 0;
}
