/*
 * host_alloc.c — Memory Manager allocators with failure injection and
 * accounting.
 */

#include "host_platform.h"

#include <stdlib.h>

typedef char *Ptr;
typedef long Size;

/* Each block carries its size ahead of the payload, padded so the payload
 * keeps the 16-byte alignment calloc gives. */
#define HEADER 16

static long g_fail_after = -1;
static host_alloc_stats g_stats;

void host_alloc_fail_after(long n)
{
    g_fail_after = n;
}

void host_alloc_reset_stats(void)
{
    g_stats.allocations = 0;
    g_stats.total_bytes = 0;
    g_stats.peak_bytes = g_stats.live_bytes;
}

const host_alloc_stats *host_alloc_get_stats(void)
{
    return &g_stats;
}

Ptr NewPtrClear(Size n)
{
    unsigned char *block;

    if (g_fail_after == 0) return NULL;
    if (g_fail_after > 0) g_fail_after--;
    block = (unsigned char *)calloc(1, (size_t)n + HEADER);
    if (block == NULL) return NULL;
    *(size_t *)block = (size_t)n;
    g_stats.allocations++;
    g_stats.total_bytes += (size_t)n;
    g_stats.live_bytes += (size_t)n;
    if (g_stats.live_bytes > g_stats.peak_bytes) {
        g_stats.peak_bytes = g_stats.live_bytes;
    }
    return (Ptr)(block + HEADER);
}

void DisposePtr(Ptr p)
{
    unsigned char *block;

    if (p == NULL) return;
    block = (unsigned char *)p - HEADER;
    g_stats.live_bytes -= *(size_t *)block;
    free(block);
}
