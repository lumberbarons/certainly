# Certainly: TLS Library for Classic Mac OS 9 — Design Specification

**Date:** 2026-04-07
**Status:** Approved

## Overview

Certainly is a static C library that provides TLS 1.2 (and eventually TLS 1.3) connectivity for classic Mac OS 9 applications running on PowerPC G3/G4 hardware. It enables Mac OS 9 apps to make HTTPS connections to modern servers — REST APIs, web services, and other TLS-secured endpoints.

### Primary Use Case

Building Mac OS 9 clients for modern services: Audiobookshelf, OpenAI-compatible LLM APIs, and similar REST/JSON endpoints. The library handles TLS; the application handles HTTP and application logic.

### Prior Art

- **Crypto Ancienne (cryanc):** TLSe-based, builds on Mac OS via MPW/MrC + GUSI. Proves TLS 1.2/1.3 is possible on classic Mac. Proxy architecture, not a library.
- **MacSSL:** MbedTLS port for CodeWarrior Pro 4. Achieves TLS 1.1 in practice. App-embedded, painful 64-bit struct emulation.
- **BearSSL:** Minimal TLS library. Zero-malloc, state-machine I/O, ~20KB code. Not yet ported to classic Mac.

## Architecture

### Layer Diagram

```
+----------------------------------+
|  Application                     |
|  (HTTP requests, JSON parsing)   |
+----------------------------------+
|  Certainly API                   |
|  MacTLS_Create / Pump / Read /   |
|  Write / Close                   |
+----------------------------------+
|  BearSSL Engine                  |
|  State machine: transforms       |
|  plaintext <-> TLS records       |
+----------------------------------+
|  OT Transport Layer              |
|  OTConnect / OTSnd / OTRcv       |
|  Async via notifier callbacks    |
+----------------------------------+
|  Open Transport (Mac OS 9)       |
|  TCP/IP stack                    |
+----------------------------------+
```

### Key Architectural Decisions

| Decision | Choice | Rationale |
|---|---|---|
| TLS engine | BearSSL | Zero-malloc, state-machine I/O (ideal for cooperative multitasking), smallest footprint (~20KB code, ~20KB RAM per connection), pluggable entropy, SNI support, TLS 1.2, à la carte cipher suites |
| Compiler | Retro68 (GCC 12.2) | Full C99/C17 support, modern toolchain, CMake builds, runs on host macOS. No CodeWarrior target. |
| Networking | Direct Open Transport | GUSI is unmaintained, requires CodeWarrior/MPW, and is overkill. OT's async notifier model maps naturally to BearSSL's state machine. Retro68 ships the `libOpenTransportLib.a` import stub; OT headers require installing Apple Universal Interfaces 3.4 into Retro68's `InterfacesAndLibraries` directory. |
| Library type | Static (.a) | Primary use case is author's own apps. Simpler distribution, no versioning issues. API is clean enough to wrap as CFM shared lib later if desired. |
| API model | Poll-based (Pump) | Simpler than callbacks in C. Natural fit for the classic Mac event loop — call MacTLS_Pump alongside WaitNextEvent. |
| CA storage | Compiled-in C arrays | No file I/O dependencies, no resource fork, ~15KB for 8-10 root CAs. BearSSL's brssl tool generates the C source. |
| Entropy | Application-supplied trusted seed into HMAC_DRBG; OS-derived values supplemental only | Mac OS 9 offers no verifiable entropy source, so the library fails closed without one. |
| TLS 1.3 | Phase 2 stretch goal | Extend BearSSL's state machine after TLS 1.2 is proven. BearSSL's architecture (modular crypto, state machine handshake) is the best base for this work. |

### BearSSL State Machine Model

BearSSL never performs I/O. It exposes four byte-buffer channels:

- **sendrec**: TLS records ready to send over TCP. Our OT layer reads from here and calls OTSnd.
- **recvrec**: Raw bytes received from TCP. Our OT layer writes here after OTRcv.
- **sendapp**: Application plaintext to encrypt. MacTLS_Write feeds this.
- **recvapp**: Decrypted plaintext for the application. MacTLS_Read drains this.

Each call to MacTLS_Pump:
1. Checks OT for received TCP data, pushes into recvrec.
2. Calls `br_ssl_engine_current_state()` to see what BearSSL needs.
3. If BearSSL has sendrec data ready, pulls it out and queues via OTSnd.
4. Returns current connection state.

This model means the CPU never blocks on network I/O. Each pump does a bounded amount of work, then returns control to the event loop.

### Open Transport Integration

OT is used in asynchronous mode with a notifier callback:

1. **Endpoint creation**: `OTOpenEndpointInContext()` with TCP configuration.
2. **Binding**: `OTBind()` to get a local address.
3. **Connection**: `OTConnect()` returns immediately; notifier fires `T_CONNECT` on completion.
4. **Data transfer**: `OTSnd()` / `OTRcv()` in non-blocking mode. Notifier fires `T_DATA` when data arrives.
5. **Teardown**: `OTSndDisconnect()` / `OTCloseProvider()`.

DNS resolution uses `OTInetStringToAddress()` (async, notifier-driven).

The transport layer is ~200-300 lines wrapping this into a clean internal interface.

## Public API

### Types

```c
typedef struct MacTLS_Context MacTLS_Context;  /* opaque handle */

typedef enum {
    kMacTLS_Idle,
    kMacTLS_Connecting,    /* TCP handshake in progress */
    kMacTLS_Handshaking,   /* TLS handshake in progress */
    kMacTLS_Connected,     /* encrypted tunnel is up */
    kMacTLS_Closing,       /* close_notify sent, draining */
    kMacTLS_Closed,        /* fully shut down */
    kMacTLS_Error
} MacTLS_State;

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
```

### Library Lifecycle

```c
MacTLS_Error MacTLS_Init(void);     /* call after InitOpenTransport */
void         MacTLS_Shutdown(void); /* call before CloseOpenTransport */
```

### Connection Lifecycle

```c
MacTLS_Context *MacTLS_Create(const char *host, uint16_t port);
MacTLS_Context *MacTLS_CreateWithConfig(const char *host, uint16_t port,
                                        MacTLS_Config *cfg);
MacTLS_State    MacTLS_Pump(MacTLS_Context *ctx);
void            MacTLS_Close(MacTLS_Context *ctx);
```

### Data Transfer

```c
int    MacTLS_Write(MacTLS_Context *ctx, const void *data, size_t len);
int    MacTLS_Read(MacTLS_Context *ctx, void *buf, size_t len);
size_t MacTLS_Available(const MacTLS_Context *ctx);
```

### Status

```c
MacTLS_State MacTLS_GetState(const MacTLS_Context *ctx);
MacTLS_Error MacTLS_GetError(const MacTLS_Context *ctx);
OSStatus     MacTLS_GetOTError(const MacTLS_Context *ctx);
```

### Configuration

```c
MacTLS_Config *MacTLS_ConfigCreate(void);
void           MacTLS_ConfigFree(MacTLS_Config *cfg);
MacTLS_Error   MacTLS_ConfigAddCA(MacTLS_Config *cfg,
                                  const void *der, size_t len);
```

### Entropy

```c
MacTLS_Error MacTLS_SeedTrusted(const void *seed, size_t len);
void         MacTLS_SetEntropyProvider(MacTLS_EntropyProvider fn, void *userData);
MacTLS_Error MacTLS_ExportSeed(void *out, size_t len);
void         MacTLS_AddEntropy(const void *data, size_t len);
```

## Entropy Strategy

> Revised: the original design injected an XOR pool of timer, mouse and
> settings values into BearSSL and called that adequate. BearSSL treats any
> injected bytes as sufficient, and none of those values carries a
> measurable entropy guarantee, so it is no longer used to satisfy the
> requirement. See README "Entropy" and `include/certainly.h`.

Mac OS 9 has no cryptographic RNG. Connection setup therefore requires a
trusted seed supplied by the application (`MacTLS_SeedTrusted` or a
provider callback). Without one, `MacTLS_Create*` yields a context in
`kMacTLS_Error` with `kMacTLS_ErrEntropy` before a socket is opened or a key
is generated, for both TLS 1.3 and TLS 1.2. The TLS 1.3 handshake
additionally refuses to build a ClientHello unless the engine DRBG was
seeded through that path.

Timer values, tick counts, mouse position, location
settings and `MacTLS_AddEntropy()` input are collected into a pool that is
mixed into the seed derivation as additional input only. They are never
counted as entropy and cannot satisfy the requirement.

The library cannot verify a seed; an application that supplies a
predictable one gets predictable keys.

## Certificate Trust Store

### Bundled Root CAs

Compiled into `ca_roots.c` as C arrays generated by BearSSL's `brssl` tool:

- **ISRG Root X1** — Let's Encrypt
- **DigiCert Global Root G2** — major commercial APIs
- **Google Trust Services R1** — Google/Firebase
- **Baltimore CyberTrust Root** — Azure/Microsoft
- Additional roots as needed (~8-10 total, ~15KB)

### Custom Certificates

Applications can add trust anchors at runtime via `MacTLS_ConfigAddCA()` for self-signed servers or private CAs.

### Limitations

- No certificate revocation checking (no CRL, no OCSP). Acceptable for REST client use case.
- Updating root CAs requires recompilation.

## Project Structure

```
certainly/
├── CMakeLists.txt
├── include/
│   └── certainly.h              # Public API
├── src/
│   ├── certainly.c              # API implementation
│   ├── ot_transport.c           # Open Transport TCP wrapper
│   ├── ot_transport.h           # Internal
│   ├── entropy.c                # Mac OS entropy pool
│   ├── entropy.h                # Internal
│   ├── ca_roots.c               # Compiled-in root certificates
│   └── ca_roots.h               # Internal
├── bearssl/                     # Vendored BearSSL source
│   ├── src/
│   ├── inc/
│   └── CMakeLists.txt
├── tools/
│   └── generate_ca_roots.py     # Root CA → C array generator
├── examples/
│   ├── simple_get/
│   │   ├── simple_get.c
│   │   └── CMakeLists.txt
│   └── chat_client/
│       ├── chat_client.c
│       └── CMakeLists.txt
└── docs/
    └── superpowers/
        └── specs/
```

### Build System

Retro68 CMake toolchain. Three build targets:

1. `libbearssl.a` — BearSSL crypto (built from vendored source)
2. `libcertainly.a` — Certainly library (links BearSSL)
3. Example apps — each produces a runnable Mac OS 9 PPC application

```
cmake -DCMAKE_TOOLCHAIN_FILE=<retro68>/retroppc.toolchain.cmake ..
make
```

### Dependencies

- **Retro68** with Apple Universal Interfaces 3.4 (for OT headers and import libs)
- **No other external dependencies.** BearSSL is vendored. No GUSI. No MPW.

## Explicit Non-Goals

- **No HTTP layer.** Certainly does TLS over TCP. Applications write raw HTTP.
- **No JSON parser.** Use a separate library (cJSON, JSMN).
- **No connection pooling or keep-alive management.** One context = one connection.
- **No proxy support.** No SOCKS, no HTTP CONNECT.
- **No client certificates.** Server authentication only.
- **No TLS session resumption.** Full handshake every connection (optimization target for later).
- **No 68K support.** PowerPC only.

## Future Work (Phase 2+)

- **TLS 1.3 support.** Extend BearSSL's handshake state machine with 1.3 message flow, HKDF key derivation, and 1-RTT handshake. The modular crypto and state machine architecture make BearSSL the best base for this.
- **TLS session resumption.** Cache session keys to skip full handshakes on reconnection.
- **CFM shared library build target.** Retro68 supports this; just a CMakeLists.txt change.
- **HTTP convenience layer.** Optional module on top of Certainly for common REST patterns.
