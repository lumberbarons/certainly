/*
 * certainly.h — Public API for the Certainly TLS library
 *
 * Certainly provides TLS 1.2 connectivity for classic Mac OS 9 apps.
 * It handles the TLS handshake, encryption/decryption, and certificate
 * verification. You provide the plaintext (HTTP requests, etc.) and
 * Certainly handles the crypto.
 *
 * Usage pattern:
 *
 *   MacTLS_Init();
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
    kMacTLS_ErrOT
} MacTLS_Error;

/* ── Library lifecycle ── */
MacTLS_Error MacTLS_Init(void);
void         MacTLS_Shutdown(void);

/* ── Connection lifecycle ── */
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

/* ── Configuration ── */
MacTLS_Config *MacTLS_ConfigCreate(void);
void           MacTLS_ConfigFree(MacTLS_Config *cfg);
MacTLS_Error   MacTLS_ConfigAddCA(MacTLS_Config *cfg,
                                  const void *der, size_t len);

/* ── Entropy ── */
void MacTLS_AddEntropy(const void *data, size_t len);

#endif /* CERTAINLY_H */
