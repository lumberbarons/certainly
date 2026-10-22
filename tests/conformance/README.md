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

## External TLS-Anvil smoke

From the repository root, after installing a **JDK 21+**, Python 3.11+,
a C compiler and `make`:

```sh
ANVIL_PYTHON=python3.12 tests/conformance/run-anvil.sh --fetch
```

`--fetch` downloads the exact release in [anvil.lock](anvil.lock), verifies
its SHA-256, and caches the ZIP under `build/conformance/`. Subsequent runs
work offline without `--fetch`. For a separately downloaded release, use
`--archive /path/to/TLS-Anvil-v1.5.3.zip`; the same checksum is mandatory.
Set `JAVA` to select a JDK and `ANVIL_PYTHON` to select Python. macOS's
system Python 3.9 is too old. The JDK must support Java source-file launching
because the fixture exporter uses classes from the pinned distribution.
No Docker, tcpdump, tshark, administrator account, or capture privileges are
needed: this pin supports `-disableTcpDump`.

The runner builds the native client automatically. Equivalent make targets:

```sh
make -C tests/host conformance-anvil ANVIL_PYTHON=python3.12 ANVIL_ARGS=--fetch
make -C tests/host conformance-runner-check ANVIL_PYTHON=python3.12
```

Run one exact upstream test without the rest of the profile:

```sh
ANVIL_PYTHON=python3.12 tests/conformance/run-anvil.sh --test 8446-dZhHUctEjQ
```

Single-test mode still performs client discovery. It supports handshake
tests compatible with this fixed fixture and send-only client lifecycle;
post-handshake and certificate-variation coverage is a later milestone.
The smoke selection is [profiles/smoke.json](profiles/smoke.json):

| Upstream ID | What it establishes |
|---|---|
| `8446-V3SF3rXAAW` | `RecordProtocol.checkMinimumRecordProtocolVersions`: valid TLS 1.3 handshake and client payload; checks received record versions. |
| `8446-dZhHUctEjQ` | `Finished.verifyFinishedMessageCorrect`: sends corrupted Finished verify data and evaluates the client's alert/closure. |

Both run serially with strength 1, one active handshake, and one selected
test template per suite invocation. Each template can generate multiple
cases and connections. A wider inventory or baseline is not included here.

### Verified pinned contract

TLS-Anvil v1.5.3 is pinned at revision
`e9e9ac7160789d66736d36f3bc62430f6a49d497`; both the release identity and
archive SHA-256 are recorded in `anvil.lock`. The unmodified release JAR
accepts `-profileFolder` / `-profiles` with JSON `testIds`, starts
`-triggerScript` asynchronously before each connection, and passes **no
test ID** to the trigger. The local controller starts a fresh owned client
process per trigger and waits for cleanup before launching another.

The fixture exporter freezes the suite's default RSA certificate chain as
explicit DER, valid 2026-01-01 through 2028-01-01. This avoids a pinned
ConfigIO issue: Joda validity times serialize as empty XML elements.
The client validates at 2027-01-01, trusts only that run's exported issuer,
and checks `tls-attacker.com` while connecting to loopback. Chain,
hostname, CertificateVerify and Finished checks remain enabled. Test keys,
DER, anchors and peer configuration stay under ignored build output.
Discovery uses the suite's own probe configuration, and its raw feature
scan is retained separately from test results.

Before integrating Certainly, this contract was exercised with OpenSSL
4.0.3 using `-verify_return_error`, `-verify_hostname` and the same issuer
and validation time. To repeat that control, use OpenSSL 1.1.1+ (not macOS
LibreSSL):

```sh
ANVIL_PYTHON=python3.12 OPENSSL=openssl tests/conformance/run-anvil.sh --backend openssl
```

On 2026-10-22 the reference and Certainly each produced strict upstream
success for two valid-handshake cases and 32 corrupted-Finished cases.
Case counts are determined by live discovery and are checked against the
reports rather than assumed. This observation is integration evidence,
not a frozen protocol baseline.

### Results, correlation and failure handling

Every run prints its unique directory under `build/conformance/anvil-runs/`.
It contains `inputs.json` (suite identity, source revision/dirty state,
binary and fixture hashes), the peer fixture, suite console and diagnostic
logs, and a directory for each selected test. Each test directory keeps:

- `suite/report.json` and `suite/results/ID/_testRun.json`, unchanged;
- one client log per unique attempt plus `attempts.jsonl`;
- `selected.json`, `command.json`, and `evidence.json`.

The upstream reports record the client's TCP port and case timestamps.
The native adapter records its first socket's local port; the reference
client binds a recorded ephemeral port. The controller matches every
reported case to an owned attempt, adds extra connections within the
case's execution window, and explicitly labels the remaining attempts as
discovery. Ambiguous or missing correlation fails the run. When reports
are incomplete, attempts remain unclassified with their invocation ID;
they never contribute passing evidence.

The client sends a fixed payload and allows a 250 ms post-send grace
period before closing. This lets Anvil finish its ReceiveAction before
the client's close_notify arrives. `--single-connection` prevents TLS 1.2
reconnects from consuming a later test's socket; attempted fallback is
still logged and cannot satisfy a TLS 1.3 test. Library protocol code is
shared unchanged with the Mac build.

Exit codes are **0** for strict upstream success with verified stage
evidence, **1** for protocol verdicts or rejected stage evidence, and
**2** for harness/setup failure. `result.json` retains that status. A
conceptual upstream success is preserved but does not make the runner
green. For the negative smoke, Certainly must specifically report
`RecvFinished` and `BR_ERR_BAD_FINISHED`; the reference must report a
Finished digest failure. An unrelated certificate rejection cannot pass.
The pinned suite permits TLS 1.3 connection closure without an alert;
Certainly's negative results explicitly record that no alert was received.
This verifies closure at the corrupted Finished, not transmission of a
particular fatal alert.

Missing prerequisites, failed triggers, crashes, disabled/empty test
selections, incomplete/missing reports and test client timeouts all fail.
Discovery probes can intentionally leave clients waiting: a new trigger
cancels and reaps the old discovery process, and that cancellation is
recorded rather than treated as a successful negative test. Test attempts
require complete client logs and termination. The controller owns process
groups, including trigger descendants, and removes its private control
socket on exit or interruption.

Defaults are an 8 s client limit, a 3 s peer timeout, and a 600 s suite limit
per selected test. Cleanup allows at most one client deadline plus 3 s;
new triggers allow 50 ms for the previous process to exit before reaping
it. Set `--attempt-timeout`, `--suite-timeout` or `--port` explicitly when
needed. Runs never reuse another run's reports, cache, or private socket.

This is native protocol coverage. It does not establish Open Transport,
PowerPC or Mac OS 9 behavior; the guest story remains separate.

Pinned sources for this contract:
[release](https://github.com/tls-attacker/TLS-Anvil/releases/tag/v1.5.3),
[client trigger](https://github.com/tls-attacker/TLS-Anvil/blob/e9e9ac7160789d66736d36f3bc62430f6a49d497/TLS-Test-Framework/src/main/java/de/rub/nds/tlstest/framework/config/delegates/TestClientDelegate.java),
[valid test](https://github.com/tls-attacker/TLS-Anvil/blob/e9e9ac7160789d66736d36f3bc62430f6a49d497/TLS-Testsuite/src/main/java/de/rub/nds/tlstest/suite/tests/both/tls13/rfc8446/RecordProtocol.java),
[negative test](https://github.com/tls-attacker/TLS-Anvil/blob/e9e9ac7160789d66736d36f3bc62430f6a49d497/TLS-Testsuite/src/main/java/de/rub/nds/tlstest/suite/tests/both/tls13/rfc8446/Finished.java).

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
