/*
 * entropy.c — Mac OS 9 entropy gathering
 *
 * HOW THIS WORKS:
 *
 * We maintain a 256-byte "pool" that accumulates entropy. Each
 * time we gather entropy, we:
 *   1. Read values from multiple OS sources (timers, mouse, etc.)
 *   2. XOR each source's bytes into the pool at a rotating offset
 *   3. When it's time to seed BearSSL, inject the entire pool
 *
 * BearSSL's HMAC_DRBG (inside the SSL engine) does the heavy
 * lifting of turning our messy entropy into cryptographic-quality
 * random bytes. HMAC_DRBG is standardized (NIST SP 800-90A) and
 * designed to handle imperfect entropy inputs — it mixes everything
 * together using HMAC-SHA256.
 *
 * We inject entropy multiple times (at init, per-connection) so
 * the pool improves over time as more mouse movements and timing
 * variations accumulate.
 */

#include "entropy.h"

#include <Timer.h>       /* Microseconds() */
#include <Events.h>      /* TickCount(), GetMouse() */
#include <LowMem.h>      /* LMGetTicks() */
#include <Gestalt.h>     /* ReadLocation() */
#include <OpenTransport.h> /* OTGetTimeStamp() */
#include <string.h>

#define POOL_SIZE 256

static uint8_t  g_pool[POOL_SIZE];
static size_t   g_pool_offset = 0;

/*
 * XOR bytes into the pool at the current offset, wrapping around.
 *
 * Why XOR? It's the simplest operation that:
 *   - Never reduces entropy (XOR with random data keeps randomness)
 *   - Is fast (no divisions, no branches)
 *   - Spreads bits across the pool as offset advances
 */
static void pool_mix(const void *data, size_t len)
{
    const uint8_t *src = (const uint8_t *)data;

    for (size_t i = 0; i < len; i++) {
        g_pool[g_pool_offset] ^= src[i];
        g_pool_offset = (g_pool_offset + 1) % POOL_SIZE;
    }
}

/*
 * Gather entropy from all available Mac OS sources.
 *
 * Each source provides different quality of randomness:
 *
 * Microseconds() — returns a UnsignedWide (64-bit microsecond counter).
 *   Quality: LOW. The counter itself is predictable, but the exact
 *   value at the moment we read it depends on how long the app has
 *   been running, which is somewhat unpredictable.
 *
 * TickCount() — returns ticks (1/60th sec) since boot.
 *   Quality: LOW. But boot time is unknown to a remote attacker.
 *
 * GetMouse() — returns cursor position.
 *   Quality: MEDIUM. Genuinely unpredictable if the user is moving
 *   the mouse. Even slight jitter contributes real entropy.
 *
 * OTGetTimeStamp() — OT's internal high-resolution timer.
 *   Quality: MEDIUM. Includes network interrupt timing jitter.
 *
 * Stack contents — read some bytes from our own stack.
 *   Quality: UNKNOWN. Whatever was left by previous function calls.
 *   Unpredictable, but could be zero on a clean stack.
 */
static void gather_sources(void)
{
    UnsignedWide    usecs;
    unsigned long   ticks;
    Point           mouse;
    OTTimeStamp     otTime;
    uint8_t         stackJunk[32];

    /* Microsecond timer */
    Microseconds(&usecs);
    pool_mix(&usecs, sizeof(usecs));

    /* Tick counter */
    ticks = TickCount();
    pool_mix(&ticks, sizeof(ticks));

    /* Mouse position */
    GetMouse(&mouse);
    pool_mix(&mouse, sizeof(mouse));

    /* Low-memory tick counter (slightly different path than TickCount) */
    ticks = LMGetTicks();
    pool_mix(&ticks, sizeof(ticks));

    /* OT high-resolution timestamp */
    OTGetTimeStamp(&otTime);
    pool_mix(&otTime, sizeof(otTime));

    /*
     * Stack junk — we intentionally do NOT initialize this array.
     * Whatever bytes happen to be on the stack get mixed in.
     * The compiler may warn about this — that's fine, it's deliberate.
     */
    pool_mix(stackJunk, sizeof(stackJunk));
}

void entropy_init(void)
{
    MachineLocation loc;

    /* Zero the pool */
    memset(g_pool, 0, POOL_SIZE);
    g_pool_offset = 0;

    /* Gather initial entropy */
    gather_sources();

    /*
     * ReadLocation gives us the machine's geographic settings
     * (latitude, longitude, timezone) from the Map control panel.
     * This doesn't change, but it's a one-time salt that a remote
     * attacker probably doesn't know.
     */
    ReadLocation(&loc);
    pool_mix(&loc, sizeof(loc));

    /* Gather again — the time elapsed during ReadLocation adds jitter */
    gather_sources();
}

void entropy_seed_engine(br_ssl_engine_context *eng)
{
    /* Gather fresh entropy right before seeding */
    gather_sources();

    /*
     * Inject the entire pool into BearSSL's PRNG.
     *
     * br_ssl_engine_inject_entropy is ADDITIVE — it stirs our bytes
     * into whatever entropy the engine already has. It never replaces.
     * So even if our pool is weak, it can only make things better,
     * never worse.
     */
    br_ssl_engine_inject_entropy(eng, g_pool, POOL_SIZE);
}

void entropy_add(const void *data, size_t len)
{
    pool_mix(data, len);
}
