/*
 * host_alloc.c — Memory Manager allocators with failure injection.
 */

#include "host_platform.h"

#include <stdlib.h>

typedef char *Ptr;
typedef long Size;

static long g_fail_after = -1;

void host_alloc_fail_after(long n)
{
    g_fail_after = n;
}

Ptr NewPtrClear(Size n)
{
    if (g_fail_after == 0) return NULL;
    if (g_fail_after > 0) g_fail_after--;
    return (Ptr)calloc(1, (size_t)n);
}

void DisposePtr(Ptr p)
{
    free(p);
}
