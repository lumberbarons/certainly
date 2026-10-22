# Conformance testing

Native tooling for exercising the real Certainly TLS client against peers
we control. The goal is repeatable evidence about protocol behaviour
without booting a Mac OS 9 emulator. Design background:
[ADR-0001](../../docs/adr/0001-test-shared-tls-code-natively-with-tls-anvil.md)
and [the spec](../../specs/001-tls-1-3-conformance-testing/spec.md).

## What runs

The client is `src/certainly.c`, the TLS 1.3 handshake, key schedule and
record code, the portable `entropy.c`, and vendored BearSSL, compiled with
`cc` against the stub Mac headers in `tests/host/stubs/`. Only the platform
underneath is replaced, by `tests/host/platform/`:

| Mac OS service            | Native stand-in                                   |
|---------------------------|---------------------------------------------------|
| Open Transport (`ot_transport.h`) | nonblocking POSIX sockets, with fault injection |
| `NewPtrClear` / `DisposePtr`      | `calloc` / `free`, with allocation failure injection |
| `TickCount`                       | 60 Hz tick from the monotonic clock           |
| Trusted entropy                   | `/dev/urandom` through `MacTLS_SetEntropyProvider` |

Production trusted-seed rules still apply: with no provider, or a failing
one, the client reports an entropy error and opens no socket.

### Where the adapter differs from Open Transport

- The destination must be an IP literal; there is no DNS.
- An orderly close is noticed once buffered data has been read; Open
  Transport raises its event as soon as the FIN arrives. The pump handles
  either order, but only this one is exercised natively.
- Timing, endianness, word size and compiler differ from the PowerPC build.

`tests/host/test_host_transport.c` pins the adapter's contract: would-block
is `0`, an orderly close is `-1` with `ordRelReceived`, a failed connection
is `-1` with `disconnectReceived` and `lastError`.

## Commands

All from `tests/host/`; nothing here needs Retro68.

```sh
make test                  # existing unit tests plus the adapter contract test
make conformance-client    # builds ../../build/conformance/certainly_client
make conformance-check     # proves the client against controlled peers
```

For the sanitizers, rebuild the client with the same flags the record
tests use:

```sh
make clean-client conformance-check EXTRA_CFLAGS="-fsanitize=address,undefined -g -O1"
```

### Prerequisites

- A C compiler and `make` (as for the other host tests).
- OpenSSL 1.1.1 or later with `s_server -ciphersuites`. macOS's LibreSSL
  does not qualify; set `OPENSSL=/path/to/openssl` if it is not first on
  `PATH`.
- [`uv`](https://docs.astral.sh/uv/), which runs `fault_peer.py`.

`check-client.sh` stops with a diagnostic if one is missing.

## The client

`certainly_client` makes one attempt per process: fresh library state, one
connection, a hard deadline, one JSON `result` line, and an exit status.
Run it without arguments for the options. Typical use:

```sh
certainly_client --attempt demo --connect 127.0.0.1:4433 \
    --server-name conformance.test --ca ca.pem --mode data \
    --send request.txt --expect reply.txt
```

`--connect` is where the socket goes; `--server-name` is what SNI and
certificate checks use. They are independent, so a fixture can be reached at
`127.0.0.1` and still be validated as `conformance.test`.

Fault injection: `--read-chunk`, `--write-chunk` and `--wouldblock-every`
shape what the pump sees from the transport; `--alloc-fail-after` fails
Memory Manager calls; `--entropy none|fail` removes or breaks the trusted
source; `--validation-time` fixes the X.509 clock.

### Outcomes

The exit status equals the outcome code in the result line. Positive tests
pass only on `success`; a TLS 1.2 fallback is its own outcome, not a pass.

| Outcome             | Exit | Meaning |
|---------------------|------|---------|
| `success`           | 0    | Completed over TLS 1.3 (or 1.2 with `--allow-tls12`) |
| `handshake-error`   | 10   | TLS failure not classified below |
| `certificate-error` | 11   | Chain, name, validity or signature check rejected the peer |
| `timeout`           | 12   | Deadline passed |
| `peer-eof`          | 13   | TCP FIN before the exchange completed |
| `peer-reset`        | 14   | Connection reset or other hard failure after connecting |
| `tls12-fallback`    | 15   | Connected, but not over TLS 1.3 |
| `data-mismatch`     | 16   | Application bytes differ from `--expect` |
| `connect-error`     | 17   | TCP never came up |
| `peer-alert`        | 18   | TLS alert closed the connection before completion |
| `usage`             | 20   | Bad command line |
| `entropy-error`     | 21   | No trusted seed; nothing was sent |
| `setup-error`       | 22   | Fixture or file unusable |
| `memory-error`      | 23   | Allocation failed |

Setup and entropy outcomes are never protocol results: a runner must not
count them as a peer being correctly rejected.

The result line also carries the library state and error, the BearSSL error
code and name, the TLS 1.3 handshake state reached (so a rejection can be
tied to the stage it happened at), the negotiated version and cipher suite,
connection and byte counts, and whether a TLS 1.2 reconnect was attempted.

### Known limits of what the client can observe

- The library reports a TLS alert and a bare TCP close after the handshake
  alike as `kMacTLS_Closed`. The client tells them apart only from what the
  transport adapter saw. A response ended by FIN with no `close_notify`
  therefore cannot be told from a complete one by the library itself;
  `--recv-until-close` accepts only a TLS-level close for that reason.
- A plaintext alert at the ServerHello stage makes the library retry over
  TLS 1.2. The result line records the extra connection.

## What `check-client.sh` establishes

Each rejection case runs beside a control that succeeds against the same
fixture, so a rejection cannot be a broken fixture:

- each advertised TLS 1.3 suite handshakes, exchanges an exact known payload,
  and still does so with 1-byte transfers and injected would-block;
- a multi-record download arrives intact, ended by a TLS close;
- wrong server name, untrusted issuer, expired and not-yet-valid
  certificates are each rejected as `certificate-error` with the specific
  BearSSL error, at the Certificate message;
- missing or failing entropy stops before any socket is opened;
- refused connection, silent peer, close and reset before the ServerHello,
  and close, reset or silence after the handshake end in distinct outcomes,
  within the deadline plus a 3 s cleanup allowance;
- a TLS 1.2-only peer fails a TLS 1.3 test;
- missing fixtures and allocation failures are reported as setup problems.

Output and per-attempt JSON logs go to `build/conformance/check-client/`,
which is ignored along with generated keys and certificates. Fixtures are
regenerated on every run by `fixtures/gen.sh`; they never touch
`src/ca_roots.c`.

This is host protocol coverage with a native transport. It says nothing
about Open Transport behaviour or PowerPC code generation; that needs the
guest checks described in the spec.
