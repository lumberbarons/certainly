/* Host-test stub: Mac Memory Manager allocators backed by calloc/free. */
#ifndef HOST_STUB_MEMORY_H
#define HOST_STUB_MEMORY_H
#include <stdlib.h>
typedef char *Ptr;
typedef long Size;
static inline Ptr NewPtrClear(Size n) { return (Ptr)calloc(1, (size_t)n); }
static inline void DisposePtr(Ptr p) { free(p); }
#endif
