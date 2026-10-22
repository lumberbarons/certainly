# TLS 1.3 conformance testing

**Slug**: `001-tls-1-3-conformance-testing`
**Created**: 2026-10-21
**Status**: Draft

## Description

Certainly maintainers need repeatable evidence that the library accepts valid
TLS 1.3 connections and rejects invalid protocol exchanges. Existing tests cover
key-schedule vectors, HTTP handling, trusted entropy, and record boundaries,
including the real pump with fake transport, but do not exercise complete
connections to an independent hostile peer. This work adds a reproducible conformance-testing workflow,
actionable failure reports, and a small check on the actual Mac OS 9 target.

## Prior Decisions

- None

## Out of Scope

- Fixing every protocol defect discovered by the suite; defects remain visible
  in the baseline and are separate follow-up work.
- BoGo integration, general fuzzing infrastructure, formal verification, or a
  claim of complete TLS conformance or security certification.
- Implementing resumption, 0-RTT, mutual TLS, new cipher suites, or other TLS
  features solely to increase the pass count.
- A general-purpose POSIX port or a redesign of Certainly's public API.
- Completing the public `MacTLS_ConfigAddCA` implementation; the harness can
  supply test trust anchors through the existing internal configuration.
- Automated emulator installation, distribution of ROMs or OS images, unattended
  emulator CI, and tests on physical PowerMac hardware.
- Exhaustive TLS 1.2 testing; detect fallback during TLS 1.3 tests and report it.

## Assumptions

- Build the native macOS runner first, using TLS-Anvil as the initial external
  suite. Use a pinned JAR with Java 21+ to simplify local trigger execution.
  The upstream [client-testing guide](https://tls-anvil.com/docs/Quick-Start/Client-Testing/)
  documents this arrangement. Exact test selectors, certificate configuration,
  capture requirements, and trigger lifecycle must be proved for the pinned
  version before treating the integration as established.
- Share `src/certainly.c`, `src/tls13_handshake.c`, `src/tls13_record.c`,
  `src/tls13_keysched.c`, and vendored BearSSL between host and target builds.
  Substitute only platform services and test configuration. This platform
  boundary is recorded in [proposed ADR-0001](../../docs/adr/0001-test-shared-tls-code-natively-with-tls-anvil.md),
  which awaits review; no accepted ADR exists today.
- Preserve C99, nonblocking library behavior, the Mac allocator conventions,
  and the separate host/Retro68 builds described in `CLAUDE.md`. Host adapters
  can use host OS facilities without introducing those dependencies into the
  Mac library.
- Test certificate and hostname checks stay enabled. Use test-only trust anchors
  with controlled certificate validity and an explicit TLS server name distinct
  from the socket destination. Do not edit generated production CA roots.
- One active test and one handshake at a time is sufficient initially. A suite
  test may trigger multiple fresh connections; each needs its own attempt ID.
- Reuse the existing host Mac-header stubs, BearSSL build, and portable trusted
  entropy implementation. The host harness registers an OS-backed trusted
  entropy provider and uses a monotonic timer; it does not copy the fake entropy
  success stubs from record-boundary tests. The guest uses the existing seed-file
  helper with a provisioned trusted seed. Missing or failed trusted entropy
  remains a setup error before key generation. Record build and fixture inputs;
  reproducibility does not require deterministic TLS keys.
- A user-supplied, booted Mac OS 9 emulator is available for the final milestone.
  The guest polls a host controller for fixed connection jobs, avoiding inbound
  guest networking and assumptions about shared filesystem support.
- Known mandatory-protocol failures, including current `KeyUpdate` rejection,
  are defects in the report, not unsupported optional features. An inventory
  run need not be green for the testing infrastructure to be delivered.
- Delivery order: prove the pinned suite's integration contract (T006), build
  and validate the native client (T001-T005), connect the suite (T007-T009),
  expand coverage and record the baseline (T010-T012), then check the Mac target
  (T013-T015). Documentation and build checks (T016-T017) accompany each step.
  US1 and US2 form the first runnable deliverable; US3 and US4 extend it.

## User Stories

### US1 — Exercise the real TLS client on the development machine (P1)

As a Certainly maintainer, I want to reproduce complete TLS connections on my
development machine so that I can diagnose failures without launching an emulator.

The client drives the same connection, handshake, and application-data code as
the Mac build. A valid trusted peer must succeed before rejection tests count
as evidence; transport errors and certificate setup errors are distinguishable.

### US2 — Run an external conformance check with one command (P1)

As a Certainly maintainer, I want a repeatable external test run so that protocol
changes are checked against an independent peer with deliberately invalid behavior.

The runner checks prerequisites, launches fresh bounded client attempts, and
saves the suite's results alongside client logs. Trigger failures, empty test
selections, timeouts, or missing reports cannot be presented as a passing run.

### US3 — Understand coverage and reproduce individual failures (P2)

As a Certainly maintainer, I want a reviewable baseline and a way to rerun one
failure so that I can prioritize defects and detect regressions.

Show successful tests, protocol defects, unsupported optional features,
inapplicable tests, and harness failures separately. Preserve upstream verdicts
and do not turn a rejection at the wrong stage into a successful negative test.

### US4 — Check representative cases on Mac OS 9 (P2)

As a Certainly maintainer, I want to repeat representative cases on Mac OS 9
so that host results are checked against the actual platform behavior.

An already running guest app accepts fixed connection jobs from a host controller
and reports results while yielding through its event loop. Each attempt is
correlated, bounded, and cleaned up before the next; stale results cannot satisfy
a later run.

## Tasks

### US1

- [x] T001 Reuse the existing host Mac-header stubs and isolate any additional declarations needed for a complete native client build, keeping protocol and pump behavior shared — `tests/host/stubs/`, `include/certainly.h`, `src/certainly_internal.h`, `src/ot_transport.h`, `src/certainly.c`
- [x] T002 Extend the host BearSSL build with adapters for nonblocking sockets, partial reads/writes, would-block, EOF, errors, allocation, and 60 Hz ticks; register OS randomness through the existing trusted provider API while retaining portable entropy.c, and check adapter error semantics — `tests/host/Makefile`, `tests/host/stubs/`, `tests/host/platform/`, `src/entropy.h`, `include/certainly.h`
- [x] T003 Add test-only certificate fixtures and internal configuration for trust anchors, validity time, TLS hostname, and destination routing; retain chain, hostname, and CertificateVerify verification — `tests/conformance/fixtures/`, `src/certainly_internal.h`, `src/certainly.c`
- [x] T004 Build a bounded command-line client with handshake-only and application-data modes, fresh connection state, TLS-version checks, and structured attempt logs; expose detailed TLS 1.3 errors internally where the existing accessor is insufficient — `tests/conformance/certainly_client.c`, `src/certainly.c`, `src/tls13_handshake.h`
- [x] T005 Prove the host client against a controlled reference server with trusted success, wrong-hostname/untrusted rejection, both advertised TLS 1.3 suites, application-data exchange, and injected partial I/O — `tests/conformance/check-client.sh`, `tests/host/platform/`, `tests/host/Makefile`

### US2

- [ ] T006 Pin TLS-Anvil and its artifact checksum, verify the Java/capture prerequisites, and demonstrate the pinned trigger, test-selection, peer-certificate, and report contracts with a reference client before connecting Certainly — `tests/conformance/anvil.lock`, `tests/conformance/README.md`, `tests/conformance/fixtures/`
- [ ] T007 Implement the trigger's fresh-process lifecycle, unique attempt IDs, bounded completion, and child cleanup; establish test-to-attempt correlation for discovery handshakes and multi-connection tests without assuming upstream supplies a test ID — `tests/conformance/trigger-client.sh`, `tests/conformance/controller.py`
- [ ] T008 Add one-command smoke and single-test execution, serial settings, isolated output directories, prerequisite diagnostics, and preservation of raw suite reports and client logs; do not require packet-capture privileges unless the pinned suite actually needs them — `tests/conformance/run-anvil.sh`, `tests/host/Makefile`, `.gitignore`
- [ ] T009 Establish a smoke selection containing a valid exchange and a deliberately invalid handshake, verifying the negative case reaches its intended protocol stage and the suite evaluates the required response — `tests/conformance/profiles/`, `tests/conformance/run-anvil.sh`

### US3

- [ ] T010 Inventory the pinned suite's applicable TLS 1.3 client cases and add a bounded wider profile covering negotiation, extensions/HRR, fragmentation, CertificateVerify/Finished, record authentication, alerts/closure, and post-handshake messages where available; record missing categories rather than implying coverage — `tests/conformance/profiles/`, `tests/conformance/README.md`
- [ ] T011 Summarize upstream results and correlate attempts, retaining exact test identifiers, suite revision, source revision plus dirty state, fixture fingerprints, TLS version, errors, and reproduction commands — `tests/conformance/summarize.py`, `tests/conformance/controller.py`
- [ ] T012 Record a baseline with exact case IDs, evidence, and explanations; distinguish optional-feature exclusions from protocol defects, flag changed outcomes and stale baseline entries, and verify failure/missing-report handling with small report fixtures — `tests/conformance/baseline.json`, `tests/conformance/summarize.py`, `tests/conformance/test_reports.py`

### US4

- [ ] T013 Add a Retro68 test app that reuses the fixture configuration, Certainly library, and existing trusted seed-file helper, polls the controller using Open Transport, performs fixed allowlisted connection jobs, reports TLS/error/data outcomes, and yields through WaitNextEvent — `examples/conformance/`, `examples/common/seed_file.c`, `CMakeLists.txt`
- [ ] T014 Add a guest backend to the controller and trigger, with unique run/attempt IDs, single-job dispatch, guest readiness checks, deadlines, cancellation acknowledgement, and rejection of stale results — `tests/conformance/controller.py`, `tests/conformance/trigger-client.sh`
- [ ] T015 Verify the guest-to-host control and TLS addresses under the existing emulator NAT setup, then rerun the valid and invalid smoke cases on PowerPC and retain comparable reports; document any target-only differences — `tests/conformance/run-anvil.sh`, `docs/EMULATORS.md`, `tests/conformance/README.md`

### Cross-cutting

- [ ] T016 Document build order, commands, prerequisites, result semantics, failure reproduction, and the separate native/target coverage limits — `README.md`, `tests/conformance/README.md`
- [ ] T017 Run existing host tests, the native conformance smoke checks, and a Retro68 build plus emulator smoke after platform-boundary changes; keep generated binaries, keys, anchors, and run artifacts under ignored build output — `tests/host/Makefile`, `CMakeLists.txt`, `.gitignore`, `tests/conformance/run-anvil.sh`

## Done When

- [ ] Following the documented prerequisites, a clean native build uses no Retro68 headers, and existing host tests still pass; a separate Retro68 build still produces the library and example apps.
- [x] The native client negotiates TLS 1.3 and exchanges an exact known payload with a trusted local peer using each currently advertised TLS 1.3 cipher suite; the same fixture fails for a wrong hostname or an untrusted certificate.
- [ ] Both host and guest use the production trusted-entropy requirement; a missing or failed provider/seed produces an entropy setup error before key generation and never counts as successful protocol rejection.
- [x] Limiting transport reads/writes to small chunks and injecting would-block conditions preserves the positive exchange, while orderly EOF, reset, and a stalled peer terminate with distinct logged outcomes within the configured deadline plus a documented cleanup allowance.
- [ ] One documented command runs a pinned TLS-Anvil smoke selection containing a valid exchange and an invalid handshake and saves both raw suite reports and client attempts; a single selected test can be reproduced without running the wider profile.
- [ ] The invalid smoke case demonstrably reaches the intended protocol check and its expected alert/closure is evaluated by TLS-Anvil; a certificate setup failure, crash, or timeout cannot count as that case passing. If Certainly has a protocol defect, the smoke run retains it as a visible failure.
- [ ] Missing prerequisites, a failed trigger, zero executed tests, a missing/incomplete report, or a client that does not terminate cause a nonzero runner exit with a diagnostic, including cleanup of owned processes and sockets.
- [ ] Every native attempt has a unique ID and can be traced to a suite test or an explicitly labeled discovery attempt; artifacts identify suite/build/fixture inputs and whether TLS 1.2 fallback occurred.
- [ ] The wider profile publishes executed and excluded case counts plus uncovered protocol categories, preserves upstream verdicts, and includes a single-case reproduction command for each failure.
- [ ] An inventory run returns nonzero when protocol or harness failures occur. A separately named baseline-comparison mode can accept only exact recorded known protocol failures, always lists them, fails on new failures or harness failures, and flags improvements and stale entries for review.
- [ ] The Mac OS 9 test app performs the same valid and invalid smoke scenarios through Open Transport, returns correlated results, and stays responsive to its event loop. A timed-out/cancelled job is acknowledged and closed before dispatching another; a stale result never completes a new attempt.
- [ ] Documentation distinguishes host protocol coverage from Mac OS 9 platform coverage and records any known defect, including mandatory behavior such as KeyUpdate, without relabeling it as an optional feature.
