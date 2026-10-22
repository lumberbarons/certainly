/*
 * host_ticks.c — TickCount() at 60 Hz and the monotonic clock behind it.
 */

#define _POSIX_C_SOURCE 200809L

#include "host_platform.h"

#include <time.h>

int64_t host_monotonic_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

unsigned long TickCount(void)
{
    return (unsigned long)(host_monotonic_ms() * 60 / 1000);
}

void host_unix_to_bearssl_time(int64_t unix_secs, uint32_t *days,
                               uint32_t *seconds)
{
    /* 719528 days separate 0000-01-01 from the Unix epoch. */
    *days = (uint32_t)(719528 + unix_secs / 86400);
    *seconds = (uint32_t)(unix_secs % 86400);
}
