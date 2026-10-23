/*
 * host_platform.h — native stand-ins for the Mac OS services under the
 * Certainly pump.
 *
 * These replace only what the library gets from the platform: Open
 * Transport (ot_transport.h), the Memory Manager, TickCount and the
 * supplemental entropy hook. Protocol, record and pump code is the
 * production source. Test-only; not a POSIX port of the library.
 */

#ifndef CERTAINLY_HOST_PLATFORM_H
#define CERTAINLY_HOST_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

/* ── Transport fault injection ── */

typedef struct {
    size_t   max_read;           /* cap on bytes per recv; 0 = unlimited */
    size_t   max_write;          /* cap on bytes per send; 0 = unlimited */
    unsigned wouldblock_every;   /* every Nth recv and send reports "no room /
                                    no data" without touching the socket;
                                    0 = never */
    int      single_connection;  /* refuse reconnects during one external-suite attempt */
} host_transport_faults;

/* Observations the pump cannot see through its interface. */
typedef struct {
    unsigned long connects;          /* sockets opened */
    unsigned long connect_attempts;
    unsigned      first_local_port;  /* correlate the initial handshake with peer reports */
    unsigned long bytes_sent;
    unsigned long bytes_received;
    unsigned long recv_calls;
    unsigned long send_calls;
    unsigned long recv_data_calls;   /* recv calls that returned bytes */
    unsigned long send_data_calls;   /* send calls that accepted bytes */
    unsigned long wouldblocks_injected;
    int           eof_seen;          /* orderly FIN from the peer */
    int           reset_seen;        /* connection reset or other hard error */
    int           last_errno;        /* errno behind reset_seen / connect failure */
} host_transport_stats;

void host_transport_set_faults(const host_transport_faults *faults);
void host_transport_reset_stats(void);
const host_transport_stats *host_transport_get_stats(void);

/* ── Allocation ── */

/* Fail every NewPtrClear after `n` more successes; negative disables. */
void host_alloc_fail_after(long n);

/* Memory Manager use since the last reset. peak_bytes is the high-water mark
 * of live_bytes, which carries over a reset so a leak stays visible. */
typedef struct {
    unsigned long allocations;
    size_t        total_bytes;
    size_t        live_bytes;
    size_t        peak_bytes;
} host_alloc_stats;

void host_alloc_reset_stats(void);
const host_alloc_stats *host_alloc_get_stats(void);

/* ── Entropy ── */

/* Trusted provider for MacTLS_SetEntropyProvider, backed by /dev/urandom. */
int host_entropy_os_random(void *user, void *out, size_t len);
/* A provider that always fails, for the missing-entropy setup path. */
int host_entropy_fail(void *user, void *out, size_t len);

/* ── Time ── */

/* Seconds since the Unix epoch to BearSSL's validation-time convention. */
void host_unix_to_bearssl_time(int64_t unix_secs, uint32_t *days,
                               uint32_t *seconds);
/* Milliseconds on the monotonic clock. */
int64_t host_monotonic_ms(void);

#endif /* CERTAINLY_HOST_PLATFORM_H */
