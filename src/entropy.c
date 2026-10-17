/*
 * entropy.c — trusted seed handling (portable; no Mac OS calls)
 *
 * Seeds come from one of two places, both supplied by the application:
 * a provider callback, or bytes handed to entropy_seed_trusted() that
 * feed a library-owned HMAC_DRBG. The supplemental pool is folded in as
 * additional input only. See entropy.h for the contract.
 */

#include "entropy.h"

#include <string.h>

#define POOL_SIZE 256

static uint8_t               g_pool[POOL_SIZE];
static size_t                g_pool_offset;

static br_hmac_drbg_context  g_drbg;
static int                   g_drbg_seeded;

static entropy_provider_fn   g_provider;
static void                 *g_provider_user;

static void wipe(void *p, size_t len)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    size_t i;

    for (i = 0; i < len; i++) v[i] = 0;
}

static void pool_mix(const void *data, size_t len)
{
    const uint8_t *src = (const uint8_t *)data;
    size_t i;

    for (i = 0; i < len; i++) {
        g_pool[g_pool_offset] ^= src[i];
        g_pool_offset = (g_pool_offset + 1) % POOL_SIZE;
    }
}

/* Rejects only the degenerate case of a constant buffer. */
static int bytes_usable(const uint8_t *b, size_t len)
{
    size_t i;

    for (i = 1; i < len; i++) {
        if (b[i] != b[0]) return 1;
    }
    return 0;
}

void entropy_init(void)
{
    wipe(g_pool, sizeof(g_pool));
    g_pool_offset = 0;
    entropy_platform_gather();
}

void entropy_shutdown(void)
{
    wipe(g_pool, sizeof(g_pool));
    g_pool_offset = 0;
    wipe(&g_drbg, sizeof(g_drbg));
    g_drbg_seeded = 0;
    g_provider = NULL;
    g_provider_user = NULL;
}

void entropy_add(const void *data, size_t len)
{
    if (data != NULL) pool_mix(data, len);
}

void entropy_set_provider(entropy_provider_fn fn, void *user)
{
    g_provider = fn;
    g_provider_user = user;
}

entropy_status entropy_seed_trusted(const void *seed, size_t len)
{
    if (seed == NULL || len < ENTROPY_SEED_BYTES ||
        !bytes_usable((const uint8_t *)seed, len)) {
        return kEntropy_Rejected;
    }

    if (g_drbg_seeded) {
        br_hmac_drbg_update(&g_drbg, seed, len);
    } else {
        br_hmac_drbg_init(&g_drbg, &br_sha256_vtable, seed, len);
        g_drbg_seeded = 1;
    }
    return kEntropy_OK;
}

entropy_status entropy_get_trusted(void *out, size_t len)
{
    if (g_provider != NULL) {
        uint8_t raw[ENTROPY_SEED_BYTES];
        br_hmac_drbg_context d;

        if (!g_provider(g_provider_user, raw, sizeof(raw))) {
            wipe(raw, sizeof(raw));
            return kEntropy_Unavailable;
        }
        if (!bytes_usable(raw, sizeof(raw))) {
            wipe(raw, sizeof(raw));
            return kEntropy_Rejected;
        }

        entropy_platform_gather();
        br_hmac_drbg_init(&d, &br_sha256_vtable, raw, sizeof(raw));
        br_hmac_drbg_update(&d, g_pool, sizeof(g_pool));
        br_hmac_drbg_generate(&d, out, len);
        wipe(raw, sizeof(raw));
        wipe(&d, sizeof(d));
        return kEntropy_OK;
    }

    if (!g_drbg_seeded) return kEntropy_Unavailable;

    entropy_platform_gather();
    br_hmac_drbg_update(&g_drbg, g_pool, sizeof(g_pool));
    br_hmac_drbg_generate(&g_drbg, out, len);
    return kEntropy_OK;
}

entropy_status entropy_seed_engine(br_ssl_engine_context *eng)
{
    uint8_t seed[ENTROPY_SEED_BYTES];
    entropy_status st;

    st = entropy_get_trusted(seed, sizeof(seed));
    if (st != kEntropy_OK) return st;

    /*
     * BearSSL treats any injected bytes as sufficient and marks the DRBG
     * seeded, which is why this is only reached with trusted bytes.
     */
    br_ssl_engine_inject_entropy(eng, seed, sizeof(seed));
    wipe(seed, sizeof(seed));

    return eng->rng_init_done == 2 ? kEntropy_OK : kEntropy_Unavailable;
}
