/*
 * entropy_mac.c — supplemental Mac OS 9 inputs
 *
 * Nothing here is entropy the library can vouch for: timers are
 * predictable on an idle machine, the mouse may not move, and the
 * location settings are constant. These values are only stirred in
 * as additional input so that a weak trusted seed is never made worse.
 * They cannot satisfy the trusted-seed requirement.
 */

#include "entropy.h"

#include <Timer.h>         /* Microseconds() */
#include <Events.h>        /* TickCount(), GetMouse() */
#include <LowMem.h>        /* LMGetTicks() */
#include <Gestalt.h>       /* ReadLocation() */
#include <string.h>

#define JITTER_SAMPLES 64

void entropy_platform_gather(void)
{
    UnsignedWide    usecs, prev;
    unsigned long   ticks = 0;
    Point           mouse;
    MachineLocation loc;
    unsigned char   jitter[JITTER_SAMPLES];
    int             i;

    memset(&usecs, 0, sizeof(usecs));
    memset(&prev, 0, sizeof(prev));
    memset(&mouse, 0, sizeof(mouse));
    memset(&loc, 0, sizeof(loc));

    Microseconds(&usecs);
    entropy_add(&usecs, sizeof(usecs));

    ticks = TickCount();
    entropy_add(&ticks, sizeof(ticks));

    GetMouse(&mouse);
    entropy_add(&mouse, sizeof(mouse));

    ticks = LMGetTicks();
    entropy_add(&ticks, sizeof(ticks));

    ReadLocation(&loc);
    entropy_add(&loc, sizeof(loc));

    /* Raw inter-sample deltas; no claim is made about their quality. */
    prev = usecs;
    for (i = 0; i < JITTER_SAMPLES; i++) {
        UnsignedWide now;

        Microseconds(&now);
        jitter[i] = (unsigned char)(now.lo - prev.lo);
        prev = now;
    }
    entropy_add(jitter, sizeof(jitter));
}
