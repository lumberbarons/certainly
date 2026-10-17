#include "seed_file.h"

#include <Files.h>
#include <string.h>

#include "certainly.h"

#define kSeedBytes 64

static void WipeBytes(unsigned char *p, size_t n)
{
    volatile unsigned char *v = p;
    size_t i;

    for (i = 0; i < n; i++) v[i] = 0;
}

const char *SeedFromFile(void)
{
    FSSpec        spec;
    short         ref;
    long          count;
    unsigned char seed[kSeedBytes];
    unsigned char next[kSeedBytes];
    const char   *result = NULL;
    Str255        name;

    name[0] = (unsigned char)strlen(kSeedFileName);
    memcpy(name + 1, kSeedFileName, name[0]);

    /* Relative to the default directory, which is the app's folder. */
    if (FSMakeFSSpec(0, 0, name, &spec) != noErr) {
        return "No trusted seed: \"" kSeedFileName "\" not found";
    }
    if (FSpOpenDF(&spec, fsRdWrPerm, &ref) != noErr) {
        return "No trusted seed: cannot open \"" kSeedFileName "\"";
    }

    count = kSeedBytes;
    FSRead(ref, &count, seed);
    if (count < kMacTLS_MinSeedBytes ||
        MacTLS_SeedTrusted(seed, (size_t)count) != kMacTLS_OK) {
        result = "No trusted seed: \"" kSeedFileName "\" is too short or invalid";
    } else if (MacTLS_ExportSeed(next, sizeof(next)) != kMacTLS_OK) {
        result = "No trusted seed: generator unavailable";
    } else {
        count = sizeof(next);
        if (SetFPos(ref, fsFromStart, 0) != noErr ||
            FSWrite(ref, &count, next) != noErr ||
            count != (long)sizeof(next) ||
            SetEOF(ref, sizeof(next)) != noErr) {
            result = "No trusted seed: cannot renew \"" kSeedFileName "\"";
        }
    }

    FSClose(ref);
    WipeBytes(seed, sizeof(seed));
    WipeBytes(next, sizeof(next));

    if (result != NULL) {
        /* Don't keep a seed that the next launch would reuse. */
        MacTLS_Shutdown();
    }
    return result;
}
