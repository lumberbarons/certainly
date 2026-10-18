/*
 * test_record_handshake.c — handshake-path record decryption bounds
 *
 * Drives the production tls13_read_encrypted_hs() (by including the
 * handshake source) with legal, over-limit and forged records. The
 * handshake context stores its decrypt destination (plain_buf) directly
 * ahead of plain_len, plain_offset and the other connection fields, so an
 * overrun there silently corrupts the connection instead of crashing.
 * The tests snapshot everything that follows plain_buf and require it
 * to survive a rejected record unchanged.
 *
 * Build and run on the HOST machine:
 *   cd tests/host && make test_record_handshake && ./test_record_handshake
 */

#include "record_helpers.h"
#include "../../src/tls13_handshake.c"

/* The handshake code seeds BearSSL's PRNG from Mac OS entropy sources. */
void entropy_seed_engine(br_ssl_engine_context *eng) { (void)eng; }

#define RECV_CAP  TLS13_MAX_RECORD_SIZE   /* tls13_recv_buf in MacTLS_Context */

typedef struct {
    tls13_hs_ctx *hs;
    unsigned char *recv;
    size_t recv_len;
    unsigned char *snapshot;
} fixture;

static void fixture_init(fixture *f, size_t suite)
{
    f->hs = (tls13_hs_ctx *)calloc(1, sizeof(*f->hs));
    f->recv = (unsigned char *)calloc(1, RECV_CAP);
    f->recv_len = 0;
    tls13_handshake_init(f->hs);
    f->hs->state = kTLS13_RecvEncryptedExtensions;
    init_ctx(&f->hs->read_ctx, suite);

    /* Fill everything after plain_buf with a pattern so any spill is visible. */
    memset((unsigned char *)f->hs + offsetof(tls13_hs_ctx, plain_len), 0x5A,
           sizeof(*f->hs) - offsetof(tls13_hs_ctx, plain_len));
    f->hs->plain_len = 0;
    f->hs->plain_offset = 0;
    f->hs->error = 0;
    f->snapshot = (unsigned char *)malloc(sizeof(*f->hs));
    memcpy(f->snapshot, f->hs, sizeof(*f->hs));
}

static void fixture_free(fixture *f)
{
    free(f->hs);
    free(f->recv);
    free(f->snapshot);
}

/*
 * Connection state outside the decrypt destination is unchanged: every
 * field after plain_buf (plain_len, plain_offset, cookie, cipher suite,
 * pointers, ...) except the reported error, and with `check_head` also
 * everything between the key material and plain_buf (msg_buf and friends,
 * which only a successful read may change). The record contexts are
 * skipped because decrypting legitimately advances them.
 */
static int hs_fields_intact(const fixture *f, int check_head)
{
    const unsigned char *a = (const unsigned char *)f->hs;
    const unsigned char *b = f->snapshot;
    size_t err_off = offsetof(tls13_hs_ctx, error);
    size_t head_off = offsetof(tls13_hs_ctx, ecdhe_secret);
    size_t pb_off = offsetof(tls13_hs_ctx, plain_buf);
    size_t pb_end = pb_off + sizeof(f->hs->plain_buf);

    if (check_head && memcmp(a + head_off, b + head_off, pb_off - head_off) != 0)
        return 0;
    return memcmp(a + pb_end, b + pb_end, err_off - pb_end) == 0 &&
           memcmp(a + err_off + sizeof(int), b + err_off + sizeof(int),
                  sizeof(*f->hs) - err_off - sizeof(int)) == 0;
}

static void put_record(fixture *f, const unsigned char *payload, size_t len)
{
    f->recv[0] = TLS13_CT_APPLICATION_DATA;
    f->recv[1] = 3;
    f->recv[2] = 3;
    f->recv[3] = (unsigned char)(len >> 8);
    f->recv[4] = (unsigned char)len;
    memcpy(f->recv + 5, payload, len);
    f->recv_len = 5 + len;
}

static void read_one(fixture *f, tls13_hs_result *res, uint8_t *type,
                     size_t *len)
{
    *res = tls13_read_encrypted_hs(f->hs, f->recv, &f->recv_len, type,
                                   f->hs->msg_buf, len);
}

/* An EncryptedExtensions-shaped message totalling exactly `total` bytes. */
static unsigned char *make_hs_message(size_t total)
{
    unsigned char *m = (unsigned char *)calloc(1, total);
    size_t body = total - 4;
    m[0] = TLS13_HT_ENCRYPTED_EXTENSIONS;
    m[1] = (unsigned char)(body >> 16);
    m[2] = (unsigned char)(body >> 8);
    m[3] = (unsigned char)body;
    if (total > 4) memset(m + 4, 0x33, body);
    return m;
}

/* A full 16384-byte handshake message in one record, with and without padding. */
static void test_legal_full_record(size_t s)
{
    static const size_t pads[] = { 0, 100, 239 };
    size_t pi;

    for (pi = 0; pi < sizeof(pads) / sizeof(pads[0]); pi++) {
        fixture f;
        tls13_record_ctx tx;
        unsigned char *msg = make_hs_message(TLS13_MAX_PLAINTEXT);
        unsigned char *sealed = (unsigned char *)malloc(TLS13_MAX_CIPHERTEXT);
        size_t sealed_len, out_len = 0;
        uint8_t type = 0;
        tls13_hs_result res;

        fixture_init(&f, s);
        init_ctx(&tx, s);
        sealed_len = seal_record(&tx, msg, TLS13_MAX_PLAINTEXT,
                                 TLS13_CT_HANDSHAKE, pads[pi], sealed);
        put_record(&f, sealed, sealed_len);
        read_one(&f, &res, &type, &out_len);

        CHECK(res == kTLS13_OK, "%s pad=%zu: legal 16384-byte record result=%d err=%d",
              suites[s].name, pads[pi], res, f.hs->error);
        CHECK(out_len == TLS13_MAX_PLAINTEXT && type == TLS13_HT_ENCRYPTED_EXTENSIONS,
              "%s pad=%zu: out_len=%zu type=%u", suites[s].name, pads[pi],
              out_len, type);
        CHECK(res == kTLS13_OK && memcmp(f.hs->msg_buf, msg, TLS13_MAX_PLAINTEXT) == 0,
              "%s pad=%zu: message mismatch", suites[s].name, pads[pi]);
        CHECK(f.recv_len == 0, "%s pad=%zu: record not consumed (%zu left)",
              suites[s].name, pads[pi], f.recv_len);
        CHECK(f.hs->plain_len == 0 && f.hs->plain_offset == 0,
              "%s pad=%zu: plain cursor not reset", suites[s].name, pads[pi]);
        CHECK(hs_fields_intact(&f, 0), "%s pad=%zu: adjacent fields changed",
              suites[s].name, pads[pi]);
        free(msg);
        free(sealed);
        fixture_free(&f);
    }
}

/* Forged records at and under the length limit: rejected on the tag. */
static void test_forged_records(size_t s)
{
    static const size_t lens[] = { 17, 16401, 16448, TLS13_MAX_CIPHERTEXT };
    size_t li;

    for (li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
        fixture f;
        unsigned char *junk = (unsigned char *)malloc(lens[li]);
        size_t out_len = 0xdead;
        uint8_t type = 0x77;
        tls13_hs_result res;

        memset(junk, 0x41, lens[li]);
        fixture_init(&f, s);
        put_record(&f, junk, lens[li]);
        read_one(&f, &res, &type, &out_len);

        CHECK(res == kTLS13_Error && f.hs->error == BR_ERR_BAD_MAC,
              "%s len=%zu: forged record result=%d err=%d",
              suites[s].name, lens[li], res, f.hs->error);
        CHECK(f.hs->plain_len == 0 && f.hs->plain_offset == 0,
              "%s len=%zu: plain_len=0x%zx plain_offset=0x%zx",
              suites[s].name, lens[li], f.hs->plain_len, f.hs->plain_offset);
        CHECK(hs_fields_intact(&f, 1), "%s len=%zu: adjacent fields corrupted",
              suites[s].name, lens[li]);
        free(junk);
        fixture_free(&f);
    }
}

/* Over-limit record headers are refused whether or not the body arrived. */
static void test_over_limit_header(size_t s)
{
    static const size_t lens[] = {
        TLS13_MAX_CIPHERTEXT + 1, 32768, 65535
    };
    size_t li, full;

    for (li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
        for (full = 0; full < 2; full++) {
            fixture f;
            size_t out_len = 0xdead;
            uint8_t type = 0x77;
            tls13_hs_result res;

            fixture_init(&f, s);
            f.recv[0] = TLS13_CT_APPLICATION_DATA;
            f.recv[1] = 3;
            f.recv[2] = 3;
            f.recv[3] = (unsigned char)(lens[li] >> 8);
            f.recv[4] = (unsigned char)lens[li];
            memset(f.recv + 5, 0x41, RECV_CAP - 5);
            f.recv_len = full ? RECV_CAP : 5;
            read_one(&f, &res, &type, &out_len);

            CHECK(res == kTLS13_Error,
                  "%s len=%zu full=%zu: result=%d (a stalled WantRead means the "
                  "connection would hang)", suites[s].name, lens[li], full, res);
            CHECK(f.hs->plain_len == 0 && hs_fields_intact(&f, 1),
                  "%s len=%zu full=%zu: context modified",
                  suites[s].name, lens[li], full);
            fixture_free(&f);
        }
    }
}

/* Authentic but over-limit content is rejected and leaves no residue. */
static void test_content_over_limit(size_t s)
{
    fixture f;
    tls13_record_ctx tx;
    size_t n = TLS13_MAX_PLAINTEXT + 1;
    unsigned char *msg = make_hs_message(n);
    unsigned char *sealed = (unsigned char *)malloc(TLS13_MAX_CIPHERTEXT);
    size_t sealed_len, out_len = 0xdead;
    uint8_t type = 0x77;
    tls13_hs_result res;

    fixture_init(&f, s);
    init_ctx(&tx, s);
    sealed_len = seal_record(&tx, msg, n, TLS13_CT_HANDSHAKE, 0, sealed);
    put_record(&f, sealed, sealed_len);
    read_one(&f, &res, &type, &out_len);
    CHECK(res == kTLS13_Error, "%s: 16385-byte content result=%d",
          suites[s].name, res);
    CHECK(f.hs->plain_len == 0 && hs_fields_intact(&f, 1),
          "%s: over-limit content changed context", suites[s].name);
    free(msg);
    free(sealed);
    fixture_free(&f);
}

/* The same forged records through the public state-machine entry point. */
static void test_through_handshake_step(size_t s)
{
    fixture f;
    unsigned char *junk = (unsigned char *)malloc(16448);
    tls13_hs_result res;

    memset(junk, 0x41, 16448);
    fixture_init(&f, s);
    put_record(&f, junk, 16448);
    res = tls13_handshake_step(f.hs, f.recv, &f.recv_len, "example.com");
    CHECK(res == kTLS13_Error, "%s: step result=%d", suites[s].name, res);
    CHECK(f.hs->plain_len == 0, "%s: step left plain_len=0x%zx",
          suites[s].name, f.hs->plain_len);
    free(junk);
    fixture_free(&f);
}

/* A cleartext record claiming more than 2^14 bytes can never complete. */
static void test_server_hello_over_limit(void)
{
    static const size_t lens[] = {
        TLS13_MAX_PLAINTEXT + 1, TLS13_MAX_CIPHERTEXT, 32768, 65535
    };
    size_t li, full;

    for (li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
        for (full = 0; full < 2; full++) {
            fixture f;
            tls13_hs_result res;

            fixture_init(&f, 0);
            f.recv[0] = TLS13_CT_HANDSHAKE;
            f.recv[1] = 3;
            f.recv[2] = 3;
            f.recv[3] = (unsigned char)(lens[li] >> 8);
            f.recv[4] = (unsigned char)lens[li];
            f.recv_len = full ? RECV_CAP : 5;
            res = tls13_state_recv_server_hello(f.hs, f.recv, &f.recv_len);

            CHECK(res == kTLS13_Error && f.hs->error == BR_ERR_TOO_LARGE,
                  "len=%zu full=%zu: ServerHello result=%d err=%d (a stalled "
                  "WantRead means the connection would hang)",
                  lens[li], full, res, f.hs->error);
            fixture_free(&f);
        }
    }
}

int main(void)
{
    size_t s;
    for (s = 0; s < NUM_SUITES; s++) {
        test_legal_full_record(s);
        test_forged_records(s);
        test_over_limit_header(s);
        test_content_over_limit(s);
        test_through_handshake_step(s);
        printf("done: %s\n", suites[s].name);
    }
    test_server_hello_over_limit();
    if (failures) {
        printf("%d check(s) FAILED\n", failures);
        return 1;
    }
    printf("test_record_handshake: all checks passed\n");
    return 0;
}
