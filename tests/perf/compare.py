#!/usr/bin/env python3
"""Compare two run-perf.sh result files.

  compare.py BEFORE/results.jsonl AFTER/results.jsonl [--threshold 0.10]

Takes the median of the trials for each scenario, reduces every scenario to
figures that are comparable across payload sizes (per payload byte, or per
connection for handshakes), and prints before, after and the change.

Counters that do not depend on timing (bytes copied, calls into the
transport, instructions retired inside library calls, heap) are marked when
they move by more than the threshold. Wall-clock and microsecond figures are
shown for context but never marked, because they vary with machine load and
say little about a Mac OS 9 target.
"""

import argparse
import json
import statistics
import sys
from collections import defaultdict

HS_STEPS = ["SendClientHello", "SendCCS", "RecvServerHello",
            "RecvEncryptedExtensions", "RecvCertRequestOrCert",
            "RecvCertificate", "RecvCertificateVerify", "RecvFinished",
            "SendFinished", "Complete"]


def load(path):
    runs = defaultdict(list)
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                r = json.loads(line)
                runs[r["scenario"]].append(r)
    return runs


def med(values):
    return statistics.median(values) if values else 0


def figures(runs):
    """Reduce the trials of one scenario to a dict of named figures."""
    r0 = runs[0]
    payload = r0["bytes"]
    conns = r0["repeat"]
    out = {}

    def per(name, key, phase, divisor, det=True):
        out[name] = (med([r[phase][key] for r in runs]) / divisor, det)

    if r0["mode"] == "handshake":
        per("instr/handshake", "lib_instructions", "handshake", conns)
        per("pumps/handshake", "pumps", "handshake", conns)
        per("copied B/handshake", "memcpy_bytes", "handshake", conns)
        out["longest pump (instr)"] = (
            med([r["handshake"]["pump_max_instructions"] for r in runs]), True)
        out["heap peak (B)"] = (
            med([r["heap_peak_per_connection"] for r in runs]), True)
        out["heap leaked (B)"] = (med([r["heap_leaked"] for r in runs]), True)
        out["lib time/handshake (us)"] = (
            med([r["handshake"]["lib_us"] for r in runs]) / conns, False)
        return out

    mb = payload / 1e6
    copied = [r["transfer"]["memcpy_bytes"] + r["transfer"]["memmove_bytes"]
              for r in runs]
    out["copied B/payload B"] = (med(copied) / payload, True)
    per("memmove B/payload B", "memmove_bytes", "transfer", payload)
    per("instr/payload B", "lib_instructions", "transfer", payload)
    per("pumps/MB", "pumps", "transfer", mb)
    per("data recv calls/MB", "recv_data_calls", "transfer", mb)
    per("data send calls/MB", "send_data_calls", "transfer", mb)
    # The longest pump in a transfer is one socket call away from noise: its
    # instruction count includes the kernel's work and varies from run to run
    # with no change to the code. Only the handshake's crypto-bound figure is
    # stable enough to flag.
    out["longest pump (instr)"] = (
        med([r["transfer"]["pump_max_instructions"] for r in runs]), False)
    out["most copied by one pump (B)"] = (
        med([r["transfer"]["pump_max_copy_bytes"] for r in runs]), True)
    out["heap leaked (B)"] = (med([r["heap_leaked"] for r in runs]), True)
    out["lib time/MB (ms)"] = (
        med([r["transfer"]["lib_us"] for r in runs]) / 1000 / mb, False)
    return out


def noise(runs):
    """Spread of the instruction count between trials, as a fraction."""
    if len(runs) < 2:
        return None
    vals = [r["handshake"]["lib_instructions"] + r["transfer"]["lib_instructions"]
            for r in runs]
    m = med(vals)
    return (max(vals) - min(vals)) / m if m else 0


def fmt(v):
    if v == 0:
        return "0"
    if abs(v) >= 1e6:
        return "%.2fM" % (v / 1e6)
    if abs(v) >= 1e4:
        return "%.1fk" % (v / 1e3)
    if abs(v) >= 100:
        return "%.0f" % v
    return "%.3g" % v


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("before")
    ap.add_argument("after")
    ap.add_argument("--threshold", type=float, default=0.10,
                    help="relative change worth marking (default 0.10)")
    ap.add_argument("--only", help="substring filter on scenario name")
    args = ap.parse_args()

    before, after = load(args.before), load(args.after)
    names = [n for n in before if n in after]
    if args.only:
        names = [n for n in names if args.only in n]
    flagged = 0
    failed = []

    for name in names:
        broken = False
        for label, runs in (("before", before[name]), ("after", after[name])):
            bad = [r for r in runs if not r["ok"]]
            if bad:
                broken = True
                failed.append("%s (%s): %s [%s]" % (
                    name, label, bad[0].get("failure", "failed"),
                    bad[0].get("library", "")))
        # A run that did not deliver the right bytes has no cost worth
        # comparing: a broken path is often a cheap one.
        if broken:
            continue
        fb, fa = figures(before[name]), figures(after[name])
        nz = max(filter(None, [noise(before[name]), noise(after[name])]), default=None)
        head = name
        if nz is not None:
            head += "   (instruction noise across trials %.1f%%)" % (nz * 100)
        print(head)
        for key in fb:
            b, det = fb[key]
            a, _ = fa[key]
            if b == 0 and a == 0:
                continue
            change = (a - b) / b if b else float("inf")
            mark = ""
            if det and abs(change) > args.threshold and abs(a - b) >= 1:
                mark = "  <-- %s" % ("worse" if a > b else "better")
                flagged += 1
            chg = "n/a" if change == float("inf") else "%+.0f%%" % (change * 100)
            print("  %-30s %10s -> %-10s %7s%s" % (key, fmt(b), fmt(a), chg, mark))
        print()

    # Where each handshake step's cost sits.
    if "handshake" in before and "handshake" in after:
        print("handshake cost by step (instructions, per handshake; longest single pump)")
        hb = before["handshake"][0]
        ha = after["handshake"][0]
        for i, step in enumerate(HS_STEPS):
            sb, sa = hb["handshake"]["steps"][i], ha["handshake"]["steps"][i]
            if not (sb["pumps"] or sa["pumps"]):
                continue
            cb, ca = hb["repeat"], ha["repeat"]
            print("  %-26s %10s -> %-10s   longest %9s -> %s" % (
                step, fmt(sb["instructions"] / cb), fmt(sa["instructions"] / ca),
                fmt(sb["max_instructions"]), fmt(sa["max_instructions"])))
        print()

    if failed:
        print("not compared, the run did not complete correctly:")
    for f in failed:
        print("  " + f)
    print("%d figure(s) moved more than %.0f%%" % (flagged, args.threshold * 100))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
