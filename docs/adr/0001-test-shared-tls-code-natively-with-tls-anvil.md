---
id: ADR-0001
title: Test shared TLS code natively with TLS-Anvil
status: proposed
date: 2026-10-21
deciders: []
supersedes: []
superseded-by: []
related: []
tags: [tls, testing, portability]
---

# ADR-0001: Test shared TLS code natively with TLS-Anvil

## Context and Problem Statement

Certainly is a C99 TLS client for PowerPC Mac OS 9, driven by a nonblocking
`MacTLS_Pump` loop. Its host tests exercise key-schedule vectors, HTTP handling,
trusted entropy, and record boundaries; the application-record tests compile
the real pump against Mac-header stubs and fake transport. Complete connections
still depend on Open Transport, Mac allocation and timers, and a trusted seed
source. Public HTTPS sweeps demonstrate
interoperability but do not establish correct handling of malformed peers. We
need an independent protocol test peer and a fast way to exercise the complete
client without making the emulator the prerequisite for every investigation.

## Decision Drivers

- Exercise the production connection and application-data logic in
  `src/certainly.c`, including partial I/O, handshake completion, fallback,
  post-handshake processing, and closure; testing only the handshake module
  would miss integration defects in that pump.
- Reuse the TLS 1.3 handshake, key schedule, record layer, X.509 validation,
  and vendored BearSSL sources. A parallel test implementation could pass
  while the library used by Mac applications remains wrong.
- Preserve Mac OS 9's cooperative scheduling contract, C99 compatibility,
  `NewPtrClear`/`DisposePtr` allocation, and Open Transport production backend.
  Host sockets, host allocation, and host entropy must stay outside that build.
- Preserve the production trusted-seed requirement in portable `src/entropy.c`.
  Host OS randomness must enter through the existing provider API; supplemental
  platform input and test stubs must never satisfy that requirement.
- Extend the existing native `cc` testing workflow so individual failures can
  be reproduced without booting a PowerPC emulator; keep the separate Retro68
  build and actual target smoke coverage.
- Test a client against invalid but cryptographically coherent server
  exchanges, with validation enabled and evidence of the stage actually
  reached. Rejecting an unrelated test certificate is not evidence of correct
  handling of a later malformed message.
- Distinguish protocol failures from suite setup failures and optional-feature
  exclusions. In particular, current rejection of received KeyUpdate messages
  must remain a visible protocol gap.

## Considered Options

1. **Native shared client with TLS-Anvil, followed by target smoke tests** —
   substitute platform services and drive the complete client against an
   external suite, then check representative cases on Mac OS 9.
2. **Emulator-only conformance testing** — drive every suite case through the
   production Mac OS 9 library and Open Transport from the outset.
3. **A separate host driver around the TLS handshake modules** — reuse crypto
   and handshake code but implement the connection pump and data handling again.
4. **Native shared client with BoGo as the first suite** — use the same platform
   boundary, starting with BoringSSL's command-line shim contract.
5. **Existing unit vectors and public-server sweeps only** — expand current
   tests without integrating an external hostile protocol peer.

## Decision Outcome

Chosen option: **Native shared client with TLS-Anvil, followed by target smoke
tests**.

Build the complete Certainly client natively for testing, substituting a narrow
platform boundary for TCP transport, platform declarations, allocation, timing,
and entropy sources. Retain portable `src/entropy.c` and register a host OS
randomness provider rather than substituting fake entropy success. The native
and Retro68 builds must share the connection pump, TLS
state machines, record handling, certificate verification, and cryptographic
implementation. Host testing is a test facility, not a supported general-purpose
POSIX port.

Use TLS-Anvil as the initial independent conformance peer, pinning its revision
and artifact identity. Its documented client trigger and serial execution model
fit a fresh Certainly connection per attempt. Prefer the locally executed JAR
for host trigger scripts, and prove the pinned suite's trigger, certificate,
selection, and reporting behavior with a reference client before interpreting
Certainly results. This is a selection of the first suite, not a prohibition
on complementary suites later.

The shared implementation and short native feedback loop tip the balance over
emulator-only testing and a duplicate driver. TLS-Anvil's client trigger avoids
adopting BoGo's suite-specific shim flags and error mappings for the first
integration. Retain representative target tests because native sockets and
host CPU behavior cannot establish Open Transport or PowerPC correctness.

## Consequences

### Positive

- Protocol defects can be reproduced against an independent peer using the
  same connection and data-handling code shipped to Mac applications.
- A single protocol fix serves host and target builds rather than requiring
  synchronization with a separate test pump.
- Native transport fault injection can exercise partial reads/writes and
  would-block conditions while retaining the real TLS logic.
- Existing unit tests remain useful, and target tests cover platform behavior
  that native protocol testing cannot observe.

### Negative

- The project must maintain a second platform backend and keep its observable
  transport semantics aligned with the contract used by the pump.
- A pinned external Java suite adds prerequisite, fixture, reporting, and
  upgrade maintenance beyond the existing native C unit tests.
- Source sharing does not make host and target builds identical: compiler,
  endianness, word size, OS timing, and platform-specific BearSSL paths differ.
- Test trust configuration must be supplied internally while the public
  `MacTLS_ConfigAddCA` remains a stub, adding coupling to internal configuration.
- Target smoke coverage still requires a working emulator and user-provided
  Mac OS environment.

### Risks

- An adapter could turn EOF into would-block, hide partial writes, or otherwise
  change what the pump sees. Check adapter semantics explicitly and compare
  representative native and target exchanges.
- Misconfigured certificates could make negative tests fail before their
  intended stage. Establish trusted positive exchanges first, preserve client
  and peer evidence, and treat wrong-stage rejection as inconclusive or failed.
- Suite filters or broad expected-failure rules could overstate conformance.
  Retain raw verdicts, exact case identities, exclusions, and uncovered areas;
  never absorb harness failures into a known-protocol-failure baseline.
- The suite's required fixture or trigger behavior may not fit Certainly as
  expected. Verify it before broad integration and revisit the suite choice if
  meaningful cases require bypassing production validation or protocol logic.

## Pros and Cons of the Options

### Native shared client with TLS-Anvil, followed by target smoke tests

- Good: exercises the actual pump and TLS implementation with fast local
  reproduction and an independent protocol peer.
- Good: TLS-Anvil explicitly documents client triggering and concurrency
  controls; serial attempts simplify correlation and cleanup initially.
- Bad: adds platform adapter and external-suite maintenance, with target
  coverage still needed separately.

### Emulator-only conformance testing

- Good: every case uses the production Open Transport backend, target compiler,
  and PowerPC code generation.
- Bad: automated client launch, guest readiness, NAT addressing, timing, and
  failure extraction become prerequisites for the first protocol result.
- Bad: emulator-dependent reproduction limits the existing native workflow.
- Neutral: remains valuable for representative platform coverage.

### A separate host driver around the TLS handshake modules

- Good: avoids initially adapting the Mac-dependent public client path.
- Bad: duplicates the logic responsible for buffer ownership, partial writes,
  application records, post-handshake traffic, and closure, leaving that
  production integration outside the test.
- Bad: fixes and behavioral changes can drift between the test driver and
  `src/certainly.c`.

### Native shared client with BoGo as the first suite

- Good: supplies a protocol peer with configurable faults and documents
  integration with other TLS implementations.
- Bad: the first adapter must also implement BoGo's shim protocol, configuration
  flags, and expected-error mappings; the upstream portability interface can
  change and must be pinned.
- Neutral: a useful complementary suite once the shared native client exists;
  its rejection here concerns initial integration scope, not test quality.

### Existing unit vectors and public-server sweeps only

- Good: preserves the smallest build and testing dependency footprint.
- Bad: successful public-server exchanges do not exercise deliberate malformed
  messages, illegal state transitions, or expected error responses.
- Bad: vectors do not cover the complete connection and record lifecycle.

## Implementation Notes

- Share `src/certainly.c`, `src/tls13_handshake.c`, `src/tls13_keysched.c`,
  `src/tls13_record.c`, `src/entropy.c`, and vendored BearSSL. Keep backend selection explicit
  in build configuration; do not introduce host-only acceptance behavior into
  protocol code or copy the pump into a harness.
- Isolate the platform dependencies currently exposed through
  `include/certainly.h`, `src/ot_transport.h`, and
  `src/certainly_internal.h`. Reuse `tests/host/stubs/` and the host BearSSL build.
  Native adapters replace Open Transport, Mac allocation and ticks, and the
  supplemental gathering hook from `src/entropy_mac.c`; trusted host randomness
  enters through `MacTLS_SetEntropyProvider`. Preserve the transport contract
  for partial I/O, would-block, orderly EOF, and errors. Keep entropy failure
  behavior intact and do not reuse record tests' fake entropy success stubs.
- Keep socket destination routing separate from the TLS server name used for
  SNI and hostname validation. Test-only trust anchors and validity-time
  configuration must retain chain, hostname, CertificateVerify, Finished, and
  record-authentication checks, and must not alter production roots.
- Start with one active test and handshake at a time. Bound every attempt and
  own its cleanup. A multi-connection test or discovery phase may generate
  several attempts; correlate each one rather than assuming one trigger per
  test or an upstream-provided test ID.
- Record suite identity, source revision and dirty state, fixture identity,
  negotiated version, underlying errors, and raw peer reports. TLS 1.2 fallback
  cannot satisfy a TLS 1.3 positive test. Use host OS randomness and a monotonic
  clock; reproducibility does not require deterministic ephemeral keys.
- Report protocol failures, optional-feature exclusions, inapplicable tests,
  and harness failures separately. A negative test succeeds only when the peer
  verifies the required response at the intended stage. Preserve known mandatory
  failures even if a separate baseline-comparison mode accepts exact recorded
  cases for regression checking.
- Exercise representative valid and invalid exchanges in a Retro68-built guest
  using Open Transport, the cooperative event loop, and the existing provisioned
  trusted seed-file helper. Guest job dispatch must
  not bypass the TLS implementation. Native results do not substitute for
  target smoke checks when platform or pump behavior changes.
- Revisit the platform boundary if it grows into a public portability API or
  requires separate protocol code. Revisit the suite choice if applicable cases
  cannot be driven with validation intact, if pin maintenance prevents useful
  testing, or if another suite supplies materially better missing coverage.

## References

- [TLS-Anvil client testing](https://tls-anvil.com/docs/Quick-Start/Client-Testing/)
  — custom client execution, per-handshake triggering, serial settings, and
  the local JAR arrangement.
- [BoringSSL protocol tests](https://github.com/google/boringssl/blob/main/ssl/test/README.md)
  — independent protocol peer with configurable faults.
- [BoringSSL porting guide](https://github.com/google/boringssl/blob/main/ssl/test/PORTING.md)
  — shim interface, error mapping, and revision-pinning requirements.
