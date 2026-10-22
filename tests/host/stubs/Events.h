/* Host-test stub: tick counter. */
#ifndef HOST_STUB_EVENTS_H
#define HOST_STUB_EVENTS_H
#ifdef HOST_PLATFORM
/* 60 Hz monotonic ticks, from platform/host_ticks.c. */
unsigned long TickCount(void);
#else
static inline unsigned long TickCount(void) { return 0; }
#endif
#endif
