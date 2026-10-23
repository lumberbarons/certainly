/*
 * perf_legacy_entropy.c — the three-function entropy interface of library
 * trees that predate the trusted-seed requirement, backed by the OS.
 *
 * Only for measuring such a tree: its own entropy.c reads Mac timers and
 * cannot compile on the host. Seeding cost is not what the harness
 * measures, so a plain OS read stands in for it.
 */

#include <bearssl.h>
#include <stddef.h>
#include <stdlib.h>

void entropy_init(void)
{
}

void entropy_seed_engine(br_ssl_engine_context *eng)
{
    unsigned char seed[32];

    arc4random_buf(seed, sizeof(seed));
    br_ssl_engine_inject_entropy(eng, seed, sizeof(seed));
}

void entropy_add(const void *data, size_t len)
{
    (void)data;
    (void)len;
}
