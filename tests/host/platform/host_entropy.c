/*
 * host_entropy.c — OS randomness for the trusted-seed provider.
 *
 * The provider is registered through MacTLS_SetEntropyProvider so the
 * portable entropy.c requirement stays in force; nothing here fakes
 * success. entropy_platform_gather() supplies only the supplemental
 * inputs the Mac build also treats as non-entropy.
 */

#define _POSIX_C_SOURCE 200809L

#include "host_platform.h"
#include "entropy.h"

#include <stdio.h>
#include <time.h>
#include <unistd.h>

int host_entropy_os_random(void *user, void *out, size_t len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    size_t got;

    (void)user;
    if (f == NULL) return 0;
    got = fread(out, 1, len, f);
    fclose(f);
    return got == len;
}

int host_entropy_fail(void *user, void *out, size_t len)
{
    (void)user; (void)out; (void)len;
    return 0;
}

void entropy_platform_gather(void)
{
    struct timespec ts;
    pid_t pid = getpid();

    clock_gettime(CLOCK_MONOTONIC, &ts);
    entropy_add(&ts, sizeof(ts));
    entropy_add(&pid, sizeof(pid));
}
