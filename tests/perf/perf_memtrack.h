/*
 * perf_memtrack.h — count the bytes the library itself copies.
 *
 * Force-included (-include) into the measured library sources, and never into
 * BearSSL or the platform shims, so the totals are Certainly's own buffer
 * handling: record compaction, plaintext hand-off, write staging. Copy
 * volume is deterministic for a given workload, which makes it a stable
 * regression signal where timings are not.
 *
 * Also declares TickCount for trees whose certainly.c relies on a Mac
 * header that the host stubs would otherwise not pull in.
 */

#ifndef CERTAINLY_PERF_MEMTRACK_H
#define CERTAINLY_PERF_MEMTRACK_H

#include <stddef.h>
#include <string.h>

#include <Events.h>

typedef struct {
    unsigned long long memcpy_calls;
    unsigned long long memcpy_bytes;
    unsigned long long memmove_calls;
    unsigned long long memmove_bytes;
} perf_copy_counters;

extern perf_copy_counters perf_copies;

void *perf_memcpy(void *dst, const void *src, size_t n);
void *perf_memmove(void *dst, const void *src, size_t n);

#undef memcpy
#undef memmove
#define memcpy(d, s, n)  perf_memcpy((d), (s), (n))
#define memmove(d, s, n) perf_memmove((d), (s), (n))

#endif /* CERTAINLY_PERF_MEMTRACK_H */
