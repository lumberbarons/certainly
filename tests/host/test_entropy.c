/*
 * Host tests for the trusted-seed requirement.
 *
 * Every source is substituted: the platform hook is a stub and the
 * trusted bytes are fixed vectors, so nothing here depends on timer
 * behaviour or on the host's own randomness.
 */

#include <stdio.h>
#include <string.h>

#include <bearssl.h>

#include "entropy.h"
#include "tls13_handshake.h"

static int failures;

#define CHECK(cond) do { \
    if (!(cond)) { \
        printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        failures++; \
    } \
} while (0)

/* Stub for the Mac OS hook: mode 0 contributes nothing (no jitter at all),
 * mode 1 contributes a constant, mode 2 a varying counter. */
static int g_platform_mode;
static unsigned g_platform_calls;

void entropy_platform_gather(void)
{
    unsigned char b[8];

    g_platform_calls++;
    if (g_platform_mode == 0) return;
    memset(b, g_platform_mode == 1 ? 0x5a : (int)g_platform_calls, sizeof(b));
    entropy_add(b, sizeof(b));
}

static void reset(int platform_mode)
{
    entropy_shutdown();
    g_platform_mode = platform_mode;
    g_platform_calls = 0;
    entropy_init();
}

static void fill_seed(unsigned char *s, size_t n, unsigned char base)
{
    size_t i;

    for (i = 0; i < n; i++) s[i] = (unsigned char)(base + 7 * i);
}

/* Provider substitutes */
static int p_fail(void *u, void *out, size_t len)
{
    (void)u; (void)out; (void)len;
    return 0;
}

static int p_constant(void *u, void *out, size_t len)
{
    (void)u;
    memset(out, 0, len);
    return 1;
}

static int p_counter(void *u, void *out, size_t len)
{
    unsigned char *n = (unsigned char *)u;

    fill_seed((unsigned char *)out, len, *n);
    (*n)++;
    return 1;
}

static void new_engine(br_ssl_client_context *sc, br_x509_minimal_context *xc)
{
    br_ssl_client_init_full(sc, xc, NULL, 0);
}

static void test_no_source_fails(void)
{
    unsigned char out[32], zero[32];
    br_ssl_client_context sc;
    br_x509_minimal_context xc;
    int mode;

    printf("no trusted source fails, whatever the platform offers\n");
    memset(zero, 0, sizeof(zero));
    for (mode = 0; mode <= 2; mode++) {
        reset(mode);
        entropy_add("supplemental", 12);
        memset(out, 0, sizeof(out));
        CHECK(entropy_get_trusted(out, sizeof(out)) == kEntropy_Unavailable);
        CHECK(memcmp(out, zero, sizeof(out)) == 0);

        new_engine(&sc, &xc);
        CHECK(entropy_seed_engine(&sc.eng) == kEntropy_Unavailable);
        CHECK(sc.eng.rng_init_done != 2);
    }
}

static void test_seed_validation(void)
{
    unsigned char seed[64], out[32];

    printf("unusable seeds are rejected and leave no source behind\n");
    reset(0);
    memset(seed, 0, sizeof(seed));
    CHECK(entropy_seed_trusted(seed, sizeof(seed)) == kEntropy_Rejected);
    memset(seed, 0xff, sizeof(seed));
    CHECK(entropy_seed_trusted(seed, sizeof(seed)) == kEntropy_Rejected);
    fill_seed(seed, sizeof(seed), 1);
    CHECK(entropy_seed_trusted(seed, ENTROPY_SEED_BYTES - 1) == kEntropy_Rejected);
    CHECK(entropy_seed_trusted(NULL, 32) == kEntropy_Rejected);
    CHECK(entropy_get_trusted(out, sizeof(out)) == kEntropy_Unavailable);
}

static void test_explicit_seed_succeeds_deterministically(void)
{
    unsigned char seed[32], a[32], b[32], c[32];
    br_ssl_client_context sc;
    br_x509_minimal_context xc;

    printf("explicit trusted seed succeeds and is timer independent\n");
    fill_seed(seed, sizeof(seed), 1);

    reset(0);
    CHECK(entropy_seed_trusted(seed, sizeof(seed)) == kEntropy_OK);
    CHECK(entropy_get_trusted(a, sizeof(a)) == kEntropy_OK);
    CHECK(entropy_get_trusted(c, sizeof(c)) == kEntropy_OK);
    CHECK(memcmp(a, c, sizeof(a)) != 0);        /* connections differ */

    reset(0);
    CHECK(entropy_seed_trusted(seed, sizeof(seed)) == kEntropy_OK);
    CHECK(entropy_get_trusted(b, sizeof(b)) == kEntropy_OK);
    CHECK(memcmp(a, b, sizeof(a)) == 0);        /* same inputs, same output */

    fill_seed(seed, sizeof(seed), 2);
    reset(0);
    CHECK(entropy_seed_trusted(seed, sizeof(seed)) == kEntropy_OK);
    CHECK(entropy_get_trusted(b, sizeof(b)) == kEntropy_OK);
    CHECK(memcmp(a, b, sizeof(a)) != 0);        /* the seed matters */

    reset(0);
    CHECK(entropy_seed_trusted(seed, sizeof(seed)) == kEntropy_OK);
    new_engine(&sc, &xc);
    CHECK(entropy_seed_engine(&sc.eng) == kEntropy_OK);
    CHECK(sc.eng.rng_init_done == 2);
}

static void test_supplemental_is_only_additional(void)
{
    unsigned char seed[32], a[32], b[32];

    printf("supplemental input mixes in but never replaces the seed\n");
    fill_seed(seed, sizeof(seed), 3);

    reset(0);
    entropy_seed_trusted(seed, sizeof(seed));
    entropy_get_trusted(a, sizeof(a));

    reset(0);
    entropy_add("extra", 5);
    entropy_seed_trusted(seed, sizeof(seed));
    entropy_get_trusted(b, sizeof(b));
    CHECK(memcmp(a, b, sizeof(a)) != 0);

    /* Same supplemental data, different seed: still different. */
    fill_seed(seed, sizeof(seed), 4);
    reset(0);
    entropy_add("extra", 5);
    entropy_seed_trusted(seed, sizeof(seed));
    entropy_get_trusted(a, sizeof(a));
    CHECK(memcmp(a, b, sizeof(a)) != 0);
}

static void test_provider(void)
{
    unsigned char seed[32], a[32], b[32], n = 9;
    br_ssl_client_context sc;
    br_x509_minimal_context xc;

    printf("provider substitution\n");
    fill_seed(seed, sizeof(seed), 5);

    reset(0);
    entropy_set_provider(p_fail, NULL);
    CHECK(entropy_get_trusted(a, sizeof(a)) == kEntropy_Unavailable);

    /* A failing provider is not masked by an available seed. */
    CHECK(entropy_seed_trusted(seed, sizeof(seed)) == kEntropy_OK);
    CHECK(entropy_get_trusted(a, sizeof(a)) == kEntropy_Unavailable);
    new_engine(&sc, &xc);
    CHECK(entropy_seed_engine(&sc.eng) == kEntropy_Unavailable);
    CHECK(sc.eng.rng_init_done != 2);

    entropy_set_provider(p_constant, NULL);
    CHECK(entropy_get_trusted(a, sizeof(a)) == kEntropy_Rejected);
    new_engine(&sc, &xc);
    CHECK(entropy_seed_engine(&sc.eng) == kEntropy_Rejected);
    CHECK(sc.eng.rng_init_done != 2);

    reset(0);
    entropy_set_provider(p_counter, &n);
    CHECK(entropy_get_trusted(a, sizeof(a)) == kEntropy_OK);
    CHECK(entropy_get_trusted(b, sizeof(b)) == kEntropy_OK);
    CHECK(memcmp(a, b, sizeof(a)) != 0);
    new_engine(&sc, &xc);
    CHECK(entropy_seed_engine(&sc.eng) == kEntropy_OK);
    CHECK(sc.eng.rng_init_done == 2);

    /* Removing the provider (and with no seed) fails closed again. */
    entropy_set_provider(NULL, NULL);
    CHECK(entropy_get_trusted(a, sizeof(a)) == kEntropy_Unavailable);
}

static void test_shutdown_discards_trust(void)
{
    unsigned char seed[32], a[32], n = 1;

    printf("shutdown discards seed and provider\n");
    fill_seed(seed, sizeof(seed), 6);
    reset(0);
    entropy_seed_trusted(seed, sizeof(seed));
    entropy_set_provider(p_counter, &n);
    entropy_shutdown();
    CHECK(entropy_get_trusted(a, sizeof(a)) == kEntropy_Unavailable);
}

/* ── TLS 1.3 path: no private key without a trusted seed ── */

static tls13_hs_result first_step(tls13_hs_ctx *hs, br_ssl_engine_context *eng)
{
    size_t rlen = 0;
    unsigned char rbuf[1];

    tls13_handshake_init(hs);
    hs->eng = eng;
    return tls13_handshake_step(hs, rbuf, &rlen, "example.com");
}

static int all_zero(const unsigned char *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) if (p[i]) return 0;
    return 1;
}

static void test_tls13_requires_trusted_seed(void)
{
    static tls13_hs_ctx hs, hs2, hs3;
    unsigned char seed[32];
    br_ssl_client_context sc;
    br_x509_minimal_context xc;

    printf("TLS 1.3 ClientHello needs a trusted-seeded engine\n");

    /* Engine never seeded. */
    reset(0);
    new_engine(&sc, &xc);
    CHECK(first_step(&hs, &sc.eng) == kTLS13_Error);
    CHECK(hs.error == BR_ERR_NO_RANDOM);
    CHECK(all_zero(hs.ecdhe_secret, sizeof(hs.ecdhe_secret)));
    CHECK(all_zero(hs.ecdhe_public, sizeof(hs.ecdhe_public)));
    CHECK(hs.msg_len == 0);

    /* Engine "seeded" by anything short of the trusted path (rng_init_done
     * of 1 is what BearSSL sets once the DRBG exists but has no seed). */
    new_engine(&sc, &xc);
    sc.eng.rng_init_done = 1;
    CHECK(first_step(&hs, &sc.eng) == kTLS13_Error);
    CHECK(hs.error == BR_ERR_NO_RANDOM);
    CHECK(all_zero(hs.ecdhe_secret, sizeof(hs.ecdhe_secret)));

    /* Trusted seed: handshake proceeds; same seed gives same key share. */
    fill_seed(seed, sizeof(seed), 7);
    reset(0);
    entropy_seed_trusted(seed, sizeof(seed));
    new_engine(&sc, &xc);
    CHECK(entropy_seed_engine(&sc.eng) == kEntropy_OK);
    CHECK(first_step(&hs2, &sc.eng) == kTLS13_WantWrite);
    CHECK(hs2.error == 0);
    CHECK(!all_zero(hs2.ecdhe_public, sizeof(hs2.ecdhe_public)));

    reset(0);
    entropy_seed_trusted(seed, sizeof(seed));
    new_engine(&sc, &xc);
    CHECK(entropy_seed_engine(&sc.eng) == kEntropy_OK);
    CHECK(first_step(&hs3, &sc.eng) == kTLS13_WantWrite);
    CHECK(memcmp(hs2.ecdhe_public, hs3.ecdhe_public, 32) == 0);
}

int main(void)
{
    test_no_source_fails();
    test_seed_validation();
    test_explicit_seed_succeeds_deterministically();
    test_supplemental_is_only_additional();
    test_provider();
    test_shutdown_discards_trust();
    test_tls13_requires_trusted_seed();

    if (failures) {
        printf("%d check(s) failed\n", failures);
        return 1;
    }
    printf("all entropy tests passed\n");
    return 0;
}
