/*
 * test_record.c — tls13_record_decrypt bounds and framing
 *
 * The record length is attacker-controlled and is checked before any
 * authentication, so these tests assert that an out-of-range or
 * unauthenticated record never writes outside the capacity the caller
 * declared. Every destination is surrounded by guard bytes; build with
 * ASan (make asan) to also catch overruns of the guards themselves.
 *
 * Build and run on the HOST machine:
 *   cd tests/host && make test_record && ./test_record
 */

#include "record_helpers.h"

#define PAYLOAD_MAX  TLS13_DECRYPT_BUF_SIZE

static unsigned char *make_content(size_t n)
{
    unsigned char *c = (unsigned char *)malloc(n ? n : 1);
    size_t i;
    for (i = 0; i < n; i++) c[i] = (unsigned char)(i * 7 + 3);
    if (n) c[n - 1] |= 1;          /* never zero, so it cannot look like padding */
    return c;
}

/* Legal records decrypt exactly, for each suite and size, with padding. */
static void test_legal_records(size_t s)
{
    static const size_t sizes[] = { 1, 2, 255, 1024, 16383, TLS13_MAX_PLAINTEXT };
    static const size_t pads[]  = { 0, 1, 100 };
    size_t si, pi;

    for (si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
        for (pi = 0; pi < sizeof(pads) / sizeof(pads[0]); pi++) {
            tls13_record_ctx tx, rx;
            guarded_buf g;
            unsigned char *content = make_content(sizes[si]);
            unsigned char *rec = (unsigned char *)malloc(TLS13_MAX_CIPHERTEXT + 1);
            size_t rec_len, out_len = 0;
            uint8_t ct = 0;
            int r;

            init_ctx(&tx, s);
            init_ctx(&rx, s);
            rec_len = seal_record(&tx, content, sizes[si],
                                  TLS13_CT_APPLICATION_DATA, pads[pi], rec);
            guarded_init(&g, PAYLOAD_MAX);
            r = tls13_record_decrypt(&rx, rec, rec_len, g.data, g.cap,
                                     &out_len, &ct);
            CHECK(r == 0, "%s len=%zu pad=%zu: decrypt returned %d",
                  suites[s].name, sizes[si], pads[pi], r);
            CHECK(out_len == sizes[si], "%s len=%zu pad=%zu: out_len=%zu",
                  suites[s].name, sizes[si], pads[pi], out_len);
            CHECK(ct == TLS13_CT_APPLICATION_DATA, "%s: content type %u",
                  suites[s].name, ct);
            CHECK(r == 0 && memcmp(g.data, content, sizes[si]) == 0,
                  "%s len=%zu pad=%zu: plaintext mismatch",
                  suites[s].name, sizes[si], pads[pi]);
            CHECK(guards_intact(&g), "%s len=%zu pad=%zu: guard overwritten",
                  suites[s].name, sizes[si], pads[pi]);
            CHECK(rx.seq == 1, "%s: seq=%llu after success",
                  suites[s].name, (unsigned long long)rx.seq);
            guarded_free(&g);
            free(rec);
            free(content);
        }
    }
}

/* The largest legal record: 16384 content + type + padding + tag = 16640. */
static void test_max_ciphertext(size_t s)
{
    tls13_record_ctx tx, rx;
    guarded_buf g;
    unsigned char *content = make_content(TLS13_MAX_PLAINTEXT);
    unsigned char *rec = (unsigned char *)malloc(TLS13_MAX_CIPHERTEXT + 1);
    size_t pad = TLS13_MAX_CIPHERTEXT - TLS13_TAG_SIZE - TLS13_MAX_PLAINTEXT - 1;
    size_t rec_len, out_len = 0;
    uint8_t ct = 0;
    int r;

    init_ctx(&tx, s);
    init_ctx(&rx, s);
    rec_len = seal_record(&tx, content, TLS13_MAX_PLAINTEXT,
                          TLS13_CT_HANDSHAKE, pad, rec);
    CHECK(rec_len == TLS13_MAX_CIPHERTEXT, "%s: sealed %zu bytes",
          suites[s].name, rec_len);

    guarded_init(&g, PAYLOAD_MAX);
    r = tls13_record_decrypt(&rx, rec, rec_len, g.data, g.cap, &out_len, &ct);
    CHECK(r == 0 && out_len == TLS13_MAX_PLAINTEXT && ct == TLS13_CT_HANDSHAKE,
          "%s: max record r=%d out_len=%zu ct=%u", suites[s].name, r, out_len, ct);
    CHECK(r == 0 && memcmp(g.data, content, TLS13_MAX_PLAINTEXT) == 0,
          "%s: max record plaintext mismatch", suites[s].name);
    CHECK(guards_intact(&g), "%s: max record overwrote guard", suites[s].name);
    guarded_free(&g);
    free(rec);
    free(content);
}

/*
 * A buffer of exactly the payload size is enough; one byte less is
 * refused without a single write, even though the record is legal.
 */
static void test_capacity_boundary(size_t s)
{
    tls13_record_ctx tx, rx;
    guarded_buf g;
    unsigned char *content = make_content(TLS13_MAX_PLAINTEXT);
    unsigned char rec[TLS13_MAX_CIPHERTEXT];
    size_t rec_len, out_len = 0, payload;
    uint8_t ct = 0;
    int r;

    init_ctx(&tx, s);
    init_ctx(&rx, s);
    rec_len = seal_record(&tx, content, TLS13_MAX_PLAINTEXT,
                          TLS13_CT_APPLICATION_DATA, 0, rec);
    payload = rec_len - TLS13_TAG_SIZE;

    /* The previous production buffer size cannot hold a full record. */
    guarded_init(&g, TLS13_MAX_PLAINTEXT);
    r = tls13_record_decrypt(&rx, rec, rec_len, g.data, g.cap, &out_len, &ct);
    CHECK(r != 0, "%s: 16384-byte buffer accepted a %zu-byte payload",
          suites[s].name, payload);
    CHECK(data_untouched(&g) && guards_intact(&g),
          "%s: undersized buffer was written", suites[s].name);
    CHECK(rx.seq == 0, "%s: seq advanced on capacity failure", suites[s].name);
    guarded_free(&g);

    guarded_init(&g, payload - 1);
    r = tls13_record_decrypt(&rx, rec, rec_len, g.data, g.cap, &out_len, &ct);
    CHECK(r != 0, "%s: cap=payload-1 accepted", suites[s].name);
    CHECK(data_untouched(&g) && guards_intact(&g),
          "%s: cap=payload-1 was written", suites[s].name);
    guarded_free(&g);

    guarded_init(&g, payload);
    r = tls13_record_decrypt(&rx, rec, rec_len, g.data, g.cap, &out_len, &ct);
    CHECK(r == 0 && out_len == TLS13_MAX_PLAINTEXT,
          "%s: cap=payload rejected (r=%d)", suites[s].name, r);
    CHECK(guards_intact(&g), "%s: cap=payload overwrote guard", suites[s].name);
    guarded_free(&g);
    free(content);
}

/*
 * Over-limit lengths from an attacker need no valid tag. None of them
 * may write to the destination, including when the destination is large.
 */
static void test_oversized_ciphertext(size_t s)
{
    static const size_t lens[] = {
        TLS13_MAX_CIPHERTEXT + 1, 17000, 32768, 65535
    };
    unsigned char *rec = (unsigned char *)malloc(65535);
    size_t li;

    memset(rec, 0x41, 65535);
    for (li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
        tls13_record_ctx rx;
        guarded_buf g;
        size_t out_len = 0xdead;
        uint8_t ct = 0x77;
        int r;

        init_ctx(&rx, s);
        /* Big enough destination: the protocol limit must still apply. */
        guarded_init(&g, 65535);
        r = tls13_record_decrypt(&rx, rec, lens[li], g.data, g.cap,
                                 &out_len, &ct);
        CHECK(r != 0, "%s: ct_len=%zu accepted", suites[s].name, lens[li]);
        CHECK(data_untouched(&g) && guards_intact(&g),
              "%s: ct_len=%zu wrote to out", suites[s].name, lens[li]);
        CHECK(out_len == 0xdead && ct == 0x77,
              "%s: ct_len=%zu modified outputs", suites[s].name, lens[li]);
        CHECK(rx.seq == 0, "%s: ct_len=%zu advanced seq", suites[s].name, lens[li]);
        guarded_free(&g);

        /* The production-sized destination. */
        guarded_init(&g, TLS13_MAX_PLAINTEXT);
        r = tls13_record_decrypt(&rx, rec, lens[li], g.data, g.cap,
                                 &out_len, &ct);
        CHECK(r != 0 && data_untouched(&g) && guards_intact(&g),
              "%s: ct_len=%zu overran 16384-byte buffer",
              suites[s].name, lens[li]);
        guarded_free(&g);
    }
    free(rec);
}

/* Short, empty and all-zero payloads are malformed. */
static void test_malformed(size_t s)
{
    tls13_record_ctx tx, rx;
    guarded_buf g;
    unsigned char zeros[64] = {0};
    unsigned char rec[128];
    size_t rec_len = 0, out_len = 0xdead;
    uint8_t ct = 0x77;
    size_t n;

    for (n = 0; n < 1 + TLS13_TAG_SIZE; n++) {
        init_ctx(&rx, s);
        guarded_init(&g, 64);
        CHECK(tls13_record_decrypt(&rx, rec, n, g.data, g.cap, &out_len, &ct) != 0,
              "%s: ct_len=%zu accepted", suites[s].name, n);
        CHECK(data_untouched(&g) && guards_intact(&g),
              "%s: ct_len=%zu wrote to out", suites[s].name, n);
        guarded_free(&g);
    }

    /* Authentic record whose payload is all zero: no content type. */
    init_ctx(&tx, s);
    init_ctx(&rx, s);
    tls13_record_encrypt(&tx, zeros, 31, 0, rec, &rec_len);
    guarded_init(&g, 64);
    CHECK(tls13_record_decrypt(&rx, rec, rec_len, g.data, g.cap, &out_len, &ct) != 0,
          "%s: all-zero payload accepted", suites[s].name);
    CHECK(rx.seq == 0 && guards_intact(&g) && data_zeroed(&g, rec_len - TLS13_TAG_SIZE),
          "%s: all-zero payload left state/plaintext", suites[s].name);
    guarded_free(&g);

    /* NULL arguments are refused rather than dereferenced. */
    init_ctx(&rx, s);
    guarded_init(&g, 64);
    CHECK(tls13_record_decrypt(&rx, rec, 32, g.data, g.cap, NULL, &ct) != 0,
          "%s: NULL out_len accepted", suites[s].name);
    CHECK(tls13_record_decrypt(&rx, rec, 32, g.data, g.cap, &out_len, NULL) != 0,
          "%s: NULL out_ct accepted", suites[s].name);
    CHECK(data_untouched(&g), "%s: NULL arg path wrote", suites[s].name);
    guarded_free(&g);
}

/*
 * Bad tags and corrupted payloads fail at every legal size. The
 * destination must carry no unauthenticated plaintext afterwards, the
 * sequence number must stay put, and the next genuine record must
 * still decrypt.
 */
static void test_invalid_tag(size_t s)
{
    static const size_t sizes[] = { 1, 100, TLS13_MAX_PLAINTEXT };
    size_t si, flip;

    for (si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
        for (flip = 0; flip < 3; flip++) {
            tls13_record_ctx tx, rx;
            guarded_buf g;
            unsigned char *content = make_content(sizes[si]);
            unsigned char *rec = (unsigned char *)malloc(TLS13_MAX_CIPHERTEXT);
            size_t rec_len, out_len = 0xdead;
            uint8_t ct = 0x77;
            int r;

            init_ctx(&tx, s);
            init_ctx(&rx, s);
            rec_len = seal_record(&tx, content, sizes[si],
                                  TLS13_CT_APPLICATION_DATA, 0, rec);
            if (flip == 0) rec[rec_len - 1] ^= 0x01;     /* last tag byte */
            else if (flip == 1) rec[rec_len - TLS13_TAG_SIZE] ^= 0x80; /* first */
            else rec[0] ^= 0x01;                          /* ciphertext */

            guarded_init(&g, PAYLOAD_MAX);
            r = tls13_record_decrypt(&rx, rec, rec_len, g.data, g.cap,
                                     &out_len, &ct);
            CHECK(r != 0, "%s len=%zu flip=%zu: forged record accepted",
                  suites[s].name, sizes[si], flip);
            CHECK(guards_intact(&g), "%s len=%zu flip=%zu: guard overwritten",
                  suites[s].name, sizes[si], flip);
            CHECK(data_zeroed(&g, rec_len - TLS13_TAG_SIZE),
                  "%s len=%zu flip=%zu: unauthenticated plaintext left in out",
                  suites[s].name, sizes[si], flip);
            CHECK(out_len == 0xdead && ct == 0x77,
                  "%s len=%zu flip=%zu: outputs modified on failure",
                  suites[s].name, sizes[si], flip);
            CHECK(rx.seq == 0, "%s len=%zu flip=%zu: seq advanced",
                  suites[s].name, sizes[si], flip);
            guarded_free(&g);
            free(rec);
            free(content);
        }
    }
}

/*
 * Authentic content one byte past the limit is rejected after
 * authentication (record_overflow) and nothing is retained.
 */
static void test_content_over_limit(size_t s)
{
    tls13_record_ctx tx, rx;
    guarded_buf g;
    size_t n = TLS13_MAX_PLAINTEXT + 1;
    unsigned char *content = make_content(n);
    unsigned char *rec = (unsigned char *)malloc(TLS13_MAX_CIPHERTEXT);
    size_t rec_len, out_len = 0xdead;
    uint8_t ct = 0x77;

    init_ctx(&tx, s);
    init_ctx(&rx, s);
    rec_len = seal_record(&tx, content, n, TLS13_CT_APPLICATION_DATA, 0, rec);
    CHECK(rec_len <= TLS13_MAX_CIPHERTEXT, "%s: test record too long",
          suites[s].name);
    guarded_init(&g, PAYLOAD_MAX);
    CHECK(tls13_record_decrypt(&rx, rec, rec_len, g.data, g.cap, &out_len, &ct) != 0,
          "%s: 16385-byte content accepted", suites[s].name);
    CHECK(guards_intact(&g) && data_zeroed(&g, rec_len - TLS13_TAG_SIZE),
          "%s: over-limit content left in out", suites[s].name);
    CHECK(rx.seq == 0, "%s: over-limit advanced seq", suites[s].name);
    guarded_free(&g);
    free(rec);
    free(content);
}

int main(void)
{
    size_t s;
    for (s = 0; s < NUM_SUITES; s++) {
        test_legal_records(s);
        test_max_ciphertext(s);
        test_capacity_boundary(s);
        test_oversized_ciphertext(s);
        test_malformed(s);
        test_invalid_tag(s);
        test_content_over_limit(s);
        printf("done: %s\n", suites[s].name);
    }
    if (failures) {
        printf("%d check(s) FAILED\n", failures);
        return 1;
    }
    printf("test_record: all checks passed\n");
    return 0;
}
