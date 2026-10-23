/*
 * perf_memtrack.c — counters behind perf_memtrack.h. Compiled without the
 * force-include, so these wrappers call the real libc routines.
 */

#include "perf_memtrack.h"

#undef memcpy
#undef memmove

perf_copy_counters perf_copies;

void *perf_memcpy(void *dst, const void *src, size_t n)
{
    perf_copies.memcpy_calls++;
    perf_copies.memcpy_bytes += n;
    return memcpy(dst, src, n);
}

void *perf_memmove(void *dst, const void *src, size_t n)
{
    perf_copies.memmove_calls++;
    perf_copies.memmove_bytes += n;
    return memmove(dst, src, n);
}
