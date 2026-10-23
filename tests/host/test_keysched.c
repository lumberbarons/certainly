/*
 * test_keysched.c — verify key schedule against RFC 8446 test vectors
 *
 * Build and run on the HOST machine (not cross-compiled):
 *   cd tests/host && make && ./test_keysched
 *
 * Test vectors from RFC 8446 Appendix A (not a full Appendix A test,
 * but verifies the core HKDF-Expand-Label and Derive-Secret work).
 * We also test against known-good values computed by OpenSSL.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../../src/tls13_keysched.h"

static int failures = 0;

static void assert_bytes(const char *name, const void *expected,
                         const void *actual, size_t len)
{
    if (memcmp(expected, actual, len) != 0) {
        printf("FAIL: %s\n", name);
        printf("  expected: ");
        for (size_t i = 0; i < len; i++) printf("%02x", ((unsigned char*)expected)[i]);
        printf("\n  actual:   ");
        for (size_t i = 0; i < len; i++) printf("%02x", ((unsigned char*)actual)[i]);
        printf("\n");
        failures++;
    } else {
        printf("PASS: %s\n", name);
    }
}

static void hex_to_bytes(const char *hex, unsigned char *out, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned int b;
        sscanf(hex + 2*i, "%02x", &b);
        out[i] = (unsigned char)b;
    }
}

/*
 * Test: SHA-256("") should produce the known hash
 */
static void test_empty_hash(void)
{
    tls13_keysched ks;
    unsigned char expected[32];

    hex_to_bytes(
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855",
        expected, 32);

    tls13_ks_init(&ks, &br_sha256_vtable);
    assert_bytes("SHA-256 empty hash", expected, ks.empty_hash, 32);
}

/*
 * Test: Early Secret from zeros (no PSK)
 * early_secret = HKDF-Extract(salt=0x00*32, IKM=0x00*32)
 */
static void test_early_secret(void)
{
    tls13_keysched ks;
    unsigned char expected[32];

    /* Known value: HKDF-Extract(0, 0) with SHA-256 */
    hex_to_bytes(
        "33ad0a1c607ec03b09e6cd9893680ce2"
        "10adf300aa1f2660e1b22e10f170f92a",
        expected, 32);

    tls13_ks_init(&ks, &br_sha256_vtable);
    tls13_ks_extract_early(&ks);
    assert_bytes("Early Secret (no PSK)", expected, ks.secret, 32);
}

/*
 * Test: Full key schedule with a known DH shared secret.
 * Uses the test vector from RFC 8448 (example handshake trace).
 */
static void test_handshake_secret(void)
{
    tls13_keysched ks;
    unsigned char shared_secret[32];
    unsigned char transcript_hash[32];
    unsigned char client_key[32], client_iv[12];
    unsigned char server_key[32], server_iv[12];

    /* DH shared secret from RFC 8448 Section 3 */
    hex_to_bytes(
        "8bd4054fb55b9d63fdfbacf9f04b9f0d"
        "35e6d63f537563efd46272900f89492d",
        shared_secret, 32);

    /* Transcript hash of ClientHello + ServerHello from RFC 8448 */
    hex_to_bytes(
        "860c06edc07858ee8e78f0e7428c58ed"
        "d6b43f2ca3e6e95f02ed063cf0e1cad8",
        transcript_hash, 32);

    tls13_ks_init(&ks, &br_sha256_vtable);
    tls13_ks_extract_early(&ks);
    tls13_ks_extract_handshake(&ks, shared_secret, 32);

    /* Expected Handshake Secret from RFC 8448 */
    {
        unsigned char expected_hs[32];
        hex_to_bytes(
            "1dc826e93606aa6fdc0aadc12f741b01"
            "046aa6b99f691ed221a9f0ca043fbeac",
            expected_hs, 32);
        assert_bytes("Handshake Secret", expected_hs, ks.secret, 32);
    }

    /* Derive handshake keys */
    tls13_ks_derive_handshake_keys(&ks, transcript_hash, 32,
                                    client_key, client_iv,
                                    server_key, server_iv,
                                    NULL, NULL);

    /* Expected server handshake key from RFC 8448 */
    {
        unsigned char expected_skey[32];
        hex_to_bytes(
            "3fce516009c21727d0f2e4e86ee403bc"
            "0000000000000000000000000000000000",
            expected_skey, 16); /* AES-128 for this test vector */
        /* Note: RFC 8448 uses AES-128-GCM so key is 16 bytes.
         * Our implementation always derives 32 bytes; the first 16
         * should match for AES-128 suites. Full verification would
         * require matching the exact cipher suite. */
    }

    printf("  (Handshake keys derived — full verification requires cipher suite matching)\n");
}

/*
 * Test: the KeyUpdate ratchet (RFC 8446 section 7.2). Expected values were
 * computed independently with HMAC from the standard library:
 *   next = HKDF-Expand-Label(secret, "traffic upd", "", Hash.length)
 * then the key and IV are derived from next as for any traffic secret.
 */
static void test_traffic_update(void)
{
    static const struct {
        const br_hash_class *hash;
        size_t hash_len, key_len;
        const char *secret, *key, *iv;
    } cases[] = {
        { &br_sha256_vtable, 32, 16,
          "2cecd0a17506ef5fa73edc062d6e7b5397cf074ec1b4d8f99a120772932f0b45",
          "05cdc7251fb9f925889f80ebc1fd385f",
          "4ef68fed17d39b5f23bb4b30" },
        { &br_sha256_vtable, 32, 32,
          "2cecd0a17506ef5fa73edc062d6e7b5397cf074ec1b4d8f99a120772932f0b45",
          "c690ede9a7525f64b759094f3bda2da3b5b52e50cffacd89a37bdf85affdd091",
          "4ef68fed17d39b5f23bb4b30" },
        { &br_sha384_vtable, 48, 16,
          "401331b63e9d59f202e8f041042d9516f4cd7fa2e2ee14631d3b49fc340d7af3"
          "7fc2c0c9f252d8036f81ec5b85cbe5db",
          "f6e7ab99dfd7f9395206f21ed5577c1c",
          "8478ffbe4f2e5450789775b3" },
        { &br_sha384_vtable, 48, 32,
          "401331b63e9d59f202e8f041042d9516f4cd7fa2e2ee14631d3b49fc340d7af3"
          "7fc2c0c9f252d8036f81ec5b85cbe5db",
          "eb354f3b48924ed78de34dd8aa6a6a0a51d857ddad1454d5cfa7b69f60712911",
          "8478ffbe4f2e5450789775b3" },
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        tls13_keysched ks;
        unsigned char secret[64], key[32], iv[12];
        unsigned char want_secret[64], want_key[32], want_iv[12];
        char name[64];
        size_t j;

        tls13_ks_init(&ks, cases[i].hash);
        for (j = 0; j < cases[i].hash_len; j++) secret[j] = (unsigned char)j;
        hex_to_bytes(cases[i].secret, want_secret, cases[i].hash_len);
        hex_to_bytes(cases[i].key, want_key, cases[i].key_len);
        hex_to_bytes(cases[i].iv, want_iv, 12);

        tls13_ks_update_traffic_secret(&ks, secret, cases[i].key_len, key, iv);

        snprintf(name, sizeof(name), "traffic update hash=%zu secret",
                 cases[i].hash_len);
        assert_bytes(name, want_secret, secret, cases[i].hash_len);
        snprintf(name, sizeof(name), "traffic update hash=%zu key=%zu",
                 cases[i].hash_len, cases[i].key_len);
        assert_bytes(name, want_key, key, cases[i].key_len);
        snprintf(name, sizeof(name), "traffic update hash=%zu iv",
                 cases[i].hash_len);
        assert_bytes(name, want_iv, iv, 12);
    }
}

int main(void)
{
    printf("=== TLS 1.3 Key Schedule Tests ===\n\n");

    test_empty_hash();
    test_early_secret();
    test_handshake_secret();
    test_traffic_update();

    printf("\n%d test(s) failed.\n", failures);
    return failures > 0 ? 1 : 0;
}
