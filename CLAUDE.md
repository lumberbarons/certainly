# CLAUDE.md

Repository guide for Claude Code (and other coding agents) working on
Certainly.

## What this project is

Certainly is a TLS 1.2 / TLS 1.3 client library for classic Mac OS 9
(PowerPC). It is a thin layer that bridges BearSSL to Open Transport
and exposes a non-blocking pump-loop API. The target environment is
Retro68 (GCC 12 cross-compiler producing PowerPC code for Mac OS 9.2.2).

The repository also contains several example applications, the largest
of which (`examples/postman`) is a full-featured HTTPS request builder
that exercises every part of the library.

## Build environments

There are **two** build environments and they are not interchangeable:

1. **Retro68 cross build** — produces the library and example apps as
   `.dsk` images for Mac OS 9.
   ```sh
   mkdir -p build && cd build
   cmake -DCMAKE_TOOLCHAIN_FILE=$RETRO68/cmake/retro68.toolchain.cmake ..
   make
   ```
   Requires Retro68 on `PATH`. Headers come from Universal Interfaces 3.4.

2. **Host build** — `tests/host/Makefile` compiles unit tests with the
   developer's native `cc`. Used for fast iteration on platform-independent
   code (key schedule, HTTP parser).
   ```sh
   cd tests/host && make test
   ```

If a host LSP / clang reports "Quickdraw.h not found" or "OSStatus
unknown" in source files under `src/` or `examples/`, that is expected
— those files only compile under Retro68.

## Where things live

| Path                  | What it is |
|-----------------------|------------|
| `include/certainly.h` | Public API. Source of truth for what callers see. |
| `src/certainly.c`     | Public-API entry points and the BearSSL ↔ OT pump. |
| `src/ot_transport.c`  | Async Open Transport TCP — connect, send, receive. |
| `src/tls13_*.c`       | TLS 1.3 handshake, key schedule, record layer. |
| `src/ca_roots.c`      | Generated Mozilla trust anchors (do not hand-edit). |
| `tools/`              | CA bundle regeneration script and helpers. |
| `examples/postman/`   | HTTPS request builder. UI is split into `ui.c`, HTTP in `http.c`, glue in `postman.c`. |
| `tests/host/`         | Host-side unit tests. Add new ones to the Makefile. |
| `docs/superpowers/`   | Design specs and implementation plans (historical context). |

## Coding conventions

- **C99**, no compiler extensions. The Retro68 GCC 12 supports the
  language fully; do not rely on C11 features.
- **Static library**, no global mutable state beyond what Open Transport
  itself requires. Per-connection state lives in `MacTLS_Context`.
- **Non-blocking everywhere.** The library must never block the event
  loop. All I/O is pumped from `MacTLS_Pump`, which is called from the
  caller's `WaitNextEvent` loop.
- **Memory.** Use `NewPtrClear` / `DisposePtr` for context allocation;
  these are the Mac OS 9 idiomatic allocators. Never call `malloc` from
  library code.
- **Error reporting.** Return `MacTLS_Error` codes; expose underlying
  BearSSL and Open Transport error codes through `MacTLS_GetBearSSLError`
  and `MacTLS_GetOTError` for diagnostics.
- **Comments.** Explain *why*, not *what*. Do not leave commentary about
  previous attempts, in-progress fixes, or task numbers in the source.

## TLS version strategy

`MacTLS_Create` always begins with a TLS 1.3 ClientHello that also
advertises TLS 1.2 cipher suites. If the server selects TLS 1.3 the
custom handshake in `tls13_handshake.c` runs the connection. If the
server selects TLS 1.2 the connection is reset and BearSSL's T0
engine handles the entire handshake.

The TLS 1.3 path supports X25519 key exchange and the AES-GCM /
ChaCha20-Poly1305 AEAD suites with SHA-256. SHA-384 suites are
explicitly rejected to keep the transcript hash logic simple.

## Testing

- **Host tests** (`tests/host/`) — must pass before any commit that
  touches the key schedule, HTTP parser, or any other portable code.
  Run with `make test` from that directory.
- **Emulator smoke tests** — for changes to the OT transport, handshake
  driver, or example apps, build with Retro68 and exercise the resulting
  `.dsk` in SheepShaver or QEMU. The Postman example is the most
  comprehensive end-to-end test.
- **Real hardware** — the library is intended to run on a physical
  PowerMac running Mac OS 9.2.2. Behaviour can differ from emulators,
  particularly around Open Transport timing.

## Working in this repo

- Prefer editing existing files to creating new ones.
- Do not introduce dependencies on the C standard library beyond what
  Retro68's libc supplies.
- When adding a new public API, add it to `include/certainly.h`,
  document it in the same comment block style as the surrounding API,
  and add a host-side test in `tests/host/` if the behaviour can be
  tested independently of Mac OS.
- Do not commit `build/`, `.dsk` outputs, or generated trust anchor
  files.
