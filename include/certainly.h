/*
 * certainly.h — Public API for the Certainly TLS library
 *
 * Certainly provides TLS 1.2 and TLS 1.3 connectivity for classic Mac
 * OS 9 apps. It handles the handshake, record-layer encryption, and
 * certificate verification on top of Open Transport. Callers supply
 * plaintext (HTTP requests, etc.); Certainly handles the crypto.
 *
 * Usage pattern:
 *
 *   MacTLS_Init();
 *   MacTLS_SeedTrusted(seed, sizeof(seed));   // required, see "Entropy"
 *   ctx = MacTLS_Create("api.example.com", 443);
 *
 *   // In your event loop:
 *   while (running) {
 *       WaitNextEvent(everyEvent, &event, 1, NULL);
 *       HandleEvent(&event);
 *
 *       state = MacTLS_Pump(ctx);
 *       if (state == kMacTLS_Connected) {
 *           MacTLS_Write(ctx, request, strlen(request));
 *           n = MacTLS_Read(ctx, buf, sizeof(buf));
 *       }
 *   }
 *
 *   MacTLS_Close(ctx);
 *   MacTLS_Shutdown();
 */

#ifndef CERTAINLY_H
#define CERTAINLY_H

#include <OpenTransport.h>
#include <stdint.h>
#include <stddef.h>

/* ── Opaque types ── */
typedef struct MacTLS_Context MacTLS_Context;
typedef struct MacTLS_Config  MacTLS_Config;

/* ── Connection state ── */
typedef enum {
    kMacTLS_Idle,
    kMacTLS_Connecting,
    kMacTLS_Handshaking,
    kMacTLS_Connected,
    kMacTLS_Closing,
    kMacTLS_Closed,
    kMacTLS_Error
} MacTLS_State;

/* ── Error codes ── */
typedef enum {
    kMacTLS_OK = 0,
    kMacTLS_ErrMemory,
    kMacTLS_ErrDNS,
    kMacTLS_ErrConnect,
    kMacTLS_ErrHandshake,
    kMacTLS_ErrCertificate,
    kMacTLS_ErrRead,
    kMacTLS_ErrWrite,
    kMacTLS_ErrClosed,
    kMacTLS_ErrOT,
    kMacTLS_ErrEntropy      /* No trusted seed available (see "Entropy"). */
} MacTLS_Error;

typedef enum {
    kMacTLS_VersionUnknown = 0,    /* Handshake not yet complete. */
    kMacTLS_Version12,
    kMacTLS_Version13
} MacTLS_Version;

/* ── Library lifecycle ── */
MacTLS_Error MacTLS_Init(void);
void         MacTLS_Shutdown(void);

/* ── Connection lifecycle ── */

/*
 * Create a TLS connection context and begin connecting.
 *
 * Returns NULL only on allocation failure. On other errors (invalid hostname,
 * missing trusted seed, transport failure), returns a non-NULL context in kMacTLS_Error state.
 * ALWAYS check MacTLS_GetState() after Create — a NULL check alone is not
 * sufficient:
 *
 *   ctx = MacTLS_Create("example.com", 443);
 *   if (ctx == NULL || MacTLS_GetState(ctx) == kMacTLS_Error) {
 *       // handle error (call MacTLS_Close(ctx) if non-NULL)
 *   }
 */
MacTLS_Context *MacTLS_Create(const char *host, uint16_t port);
MacTLS_Context *MacTLS_CreateWithConfig(const char *host, uint16_t port,
                                        MacTLS_Config *cfg);
MacTLS_State    MacTLS_Pump(MacTLS_Context *ctx);
void            MacTLS_Close(MacTLS_Context *ctx);

/* ── Data transfer ── */
int    MacTLS_Write(MacTLS_Context *ctx, const void *data, size_t len);
int    MacTLS_Read(MacTLS_Context *ctx, void *buf, size_t len);
size_t MacTLS_Available(const MacTLS_Context *ctx);

/* ── Status ── */
MacTLS_State MacTLS_GetState(const MacTLS_Context *ctx);
MacTLS_Error MacTLS_GetError(const MacTLS_Context *ctx);
OSStatus     MacTLS_GetOTError(const MacTLS_Context *ctx);
int          MacTLS_GetBearSSLError(const MacTLS_Context *ctx);

/* Returns the negotiated protocol version, or kMacTLS_VersionUnknown
 * before the handshake completes (state != kMacTLS_Connected). */
MacTLS_Version MacTLS_GetVersion(const MacTLS_Context *ctx);

/* ── Configuration ── */
MacTLS_Config *MacTLS_ConfigCreate(void);
void           MacTLS_ConfigFree(MacTLS_Config *cfg);
MacTLS_Error   MacTLS_ConfigAddCA(MacTLS_Config *cfg,
                                  const void *der, size_t len);

/* ── Entropy ──
 *
 * Mac OS 9 has no cryptographic random number generator, and nothing the
 * library can read (timers, mouse, location settings) comes with an
 * entropy guarantee. TLS ephemeral keys and client randoms are therefore
 * generated only after the application supplies a TRUSTED seed: bytes it
 * vouches are unpredictable to an attacker, such as output of a hardware
 * RNG or a seed file provisioned from a good source (see
 * tools/make_seed.sh) and replaced after every use. The library cannot
 * check this claim; a predictable seed gives predictable keys.
 *
 * Without a trusted source, MacTLS_Create / MacTLS_CreateWithConfig
 * return a context in kMacTLS_Error state with error kMacTLS_ErrEntropy
 * before opening a connection or generating any key. Both the TLS 1.3 and
 * TLS 1.2 paths are covered, since both draw from the same generator.
 *
 * Provide the seed with MacTLS_SeedTrusted() or MacTLS_SetEntropyProvider();
 * either may be called before or after MacTLS_Init(), and
 * MacTLS_Shutdown() discards both.
 */

/* Minimum length accepted by MacTLS_SeedTrusted(). */
#define kMacTLS_MinSeedBytes 32

/*
 * Fill `out` with `len` bytes that are unpredictable to an attacker and
 * different on every call. Return non-zero on success, zero on failure
 * (which fails connection setup; there is no fallback to another source).
 * Called once per connection with len == 32.
 */
typedef int (*MacTLS_EntropyProvider)(void *userData, void *out, size_t len);

/*
 * Seed the library's generator with `len` >= kMacTLS_MinSeedBytes trusted
 * bytes. Repeated calls add to its state. Returns kMacTLS_ErrEntropy for
 * a short seed or one whose bytes are all identical (a misuse guard, not a
 * quality test). A provider, if registered, takes precedence.
 */
MacTLS_Error MacTLS_SeedTrusted(const void *seed, size_t len);

/* Register a provider consulted for every connection; NULL removes it. */
void MacTLS_SetEntropyProvider(MacTLS_EntropyProvider provider,
                               void *userData);

/*
 * Draw `len` >= kMacTLS_MinSeedBytes bytes from the trusted generator,
 * e.g. to write back a replacement seed file so the next launch does not
 * repeat this one. Returns kMacTLS_ErrEntropy if `len` is too short or no
 * trusted source is available.
 */
MacTLS_Error MacTLS_ExportSeed(void *out, size_t len);

/*
 * Mix extra bytes (user input timing, ...) into the supplemental pool.
 * This is only additional input: it never counts as, or substitutes for,
 * a trusted seed.
 */
void MacTLS_AddEntropy(const void *data, size_t len);

#endif /* CERTAINLY_H */
