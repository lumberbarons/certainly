/*
 * entropy.h — trusted seeding for BearSSL's HMAC_DRBG
 *
 * Classic Mac OS has no cryptographic random number generator, and the
 * values its timers, mouse and settings expose carry no entropy
 * guarantee a library can verify. Certainly therefore refuses to
 * generate TLS key material until the application has supplied a
 * TRUSTED seed: bytes the caller vouches are unpredictable to an
 * attacker (a hardware RNG, a seed file provisioned from a good source
 * and renewed after each use, ...). Everything the library gathers on its
 * own is SUPPLEMENTAL — it is mixed in, but it never satisfies the
 * requirement and is never counted as entropy.
 */

#ifndef CERTAINLY_ENTROPY_H
#define CERTAINLY_ENTROPY_H

#include <bearssl.h>
#include <stddef.h>

/* Bytes of trusted seed drawn per connection (256 bits). */
#define ENTROPY_SEED_BYTES 32

typedef enum {
    kEntropy_OK = 0,
    kEntropy_Unavailable,   /* no trusted source configured, or it failed */
    kEntropy_Rejected       /* source supplied unusable bytes */
} entropy_status;

/*
 * Source of trusted bytes. Fill `out` with `len` bytes that are
 * unpredictable to an attacker and different on every call. Return
 * non-zero on success, zero if the bytes could not be produced.
 */
typedef int (*entropy_provider_fn)(void *user, void *out, size_t len);

/*
 * Reset the supplemental pool. Does not touch the trusted source, so
 * it may be called before or after it is configured.
 */
void entropy_init(void);

/* Wipe the pool, the trusted generator and the registered provider. */
void entropy_shutdown(void);

/*
 * Mix caller-supplied bytes into the supplemental pool. This can never
 * make entropy_get_trusted() succeed.
 */
void entropy_add(const void *data, size_t len);

/*
 * Register (or, with NULL, remove) the provider consulted for every
 * connection. A registered provider takes precedence over a seed given
 * to entropy_seed_trusted(), and its failure is never papered over by
 * falling back to another source.
 */
void entropy_set_provider(entropy_provider_fn fn, void *user);

/*
 * Seed the library's own generator with trusted bytes. `len` must be at
 * least ENTROPY_SEED_BYTES. Repeated calls add to the generator state.
 *
 * Seeds whose bytes are all identical (an uninitialised or zeroed
 * buffer) are rejected. That is a guard against misuse, not a test of
 * quality: it cannot detect a predictable seed in general.
 */
entropy_status entropy_seed_trusted(const void *seed, size_t len);

/*
 * Produce `len` bytes derived from the trusted source plus the
 * supplemental pool. Fails without writing a usable result if no
 * trusted source is available.
 */
entropy_status entropy_get_trusted(void *out, size_t len);

/*
 * Seed a BearSSL engine's DRBG from the trusted source. On any failure
 * the engine is left unseeded (rng_init_done != 2).
 */
entropy_status entropy_seed_engine(br_ssl_engine_context *eng);

/*
 * Platform hook: mix whatever the OS offers (timers, mouse, ...) into
 * the pool with entropy_add(). Implemented in entropy_mac.c; host tests
 * substitute their own.
 */
void entropy_platform_gather(void);

#endif /* CERTAINLY_ENTROPY_H */
