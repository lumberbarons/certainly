#ifndef FAKE_MEMORY_H
#define FAKE_MEMORY_H
#include <stdlib.h>
typedef char *Ptr;
#define NewPtrClear(n) ((Ptr)calloc(1, (n)))
#define DisposePtr(p)  free(p)
#endif
