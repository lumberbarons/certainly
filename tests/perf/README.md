# Performance harness

Measures what the Certainly pump does for a given workload, natively, against
a TLS 1.3 peer we control. It finds avoidable work and catches regressions in
it. It does not predict speed on a PowerPC Mac running Mac OS 9: the CPU,
caches and BearSSL's code paths differ, so a laptop wall-clock figure says
little about the target. The figures that matter are the ones that mean the
same thing on both.

## What is measured

| Figure | Why it carries over to the target |
|---|---|
| Bytes the library copies itself, per payload byte | Counted in `src/` only (`perf_memtrack.h`), so BearSSL's own copies are excluded. Deterministic. |
| Instructions retired inside library calls | Repeatable to a fraction of a percent. macOS only; elsewhere the figure is absent and time inside calls is shown instead. |
| Longest single `MacTLS_Pump`, in instructions, and by handshake step | A pump that runs long freezes the caller's `WaitNextEvent` loop. |
| Most bytes copied by one pump call | The same stall, from the copying side. |
| Pump calls and productive transport calls per MB | Wasted wakeups and tiny reads or writes. |
| Peak Memory Manager use per connection, and what is left after `MacTLS_Close` | Mac OS 9 apps run in a fixed partition. |

Microsecond and wall-clock figures are reported for context and never flagged,
and so is the longest pump of a transfer: it includes the kernel's time inside
a socket call and moves from run to run with no change to the code. The
longest pump of a handshake is crypto-bound and stable, so that one is flagged.

## Running

From the repository root, with OpenSSL, `uv`, a C compiler and `make`:

```sh
tests/perf/run-perf.sh --label current          # full sizes, three trials
tests/perf/run-perf.sh --label current --quick  # smaller, one trial
uv run --no-project python tests/perf/compare.py \
    build/perf/before/results.jsonl build/perf/current/results.jsonl
```

Results go to `build/perf/<label>/results.jsonl`. `compare.py` takes the
median of the trials, reduces each workload to per-byte or per-handshake
figures, and marks deterministic ones that moved by more than a threshold.

### Measuring another revision

`--tree` points at any checkout. The same client, peer and platform shims
are built against that tree's `src/`, so revisions are compared on identical
workloads:

```sh
git worktree add --detach /some/dir <commit>
tests/perf/run-perf.sh --label before --tree /some/dir
```

Trees that predate the trusted-seed entropy API are supported through
`perf_legacy_entropy.c`. A workload that does not deliver the right bytes is
reported as failed and left out of comparisons, because a broken path is
often a cheap one.

## Workloads

The client names the workload on its first line and `perf_peer.py` carries
it out, so the TLS record size is chosen per connection.

- `handshake`: connect and close, repeated.
- Downloads at several record sizes, application read sizes and sizes of
  transfer, to show whether cost per byte stays flat.
- Transport that delivers records in TCP-sized pieces or intermittently
  reports no data.
- Uploads with large and small application writes.
- A verified download and upload first, so a fast run that corrupts data
  cannot look like an improvement.

## Limits

- The peer follows the client's preferred suite, so runs measure the suite
  the library prefers (ChaCha20-Poly1305 today). The AES-GCM path is not
  measured separately.
- Certificates are ECDSA P-256 with the IP literal as the subject name. RSA
  chains and long chains, which dominate real handshakes, are not covered.
- BearSSL is built for the host. Which AES, GHASH and ChaCha20
  implementations it selects differs on PowerPC, so crypto cost is
  representative of the code path, not of the target.
- Instruction counts include the kernel's work inside socket calls, so
  scenarios that poll heavily are noisier than the rest.
