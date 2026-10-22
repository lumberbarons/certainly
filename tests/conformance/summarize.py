#!/usr/bin/env python3
"""Summarize a conformance run and compare it with the recorded baseline.

The raw suite reports stay authoritative: this reads them, never rewrites them,
and keeps upstream verdicts verbatim. A harness problem is its own class and can
never be accepted as a known protocol failure.
"""

import argparse
from collections import Counter
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
STRICT = "STRICTLY_SUCCEEDED"
# Least to most severe; anything but STRICT is a deviation the baseline may record.
SEVERITY = [STRICT, "CONCEPTUALLY_SUCCEEDED", "PARTIALLY_FAILED", "FULLY_FAILED"]
DISABLED = "DISABLED"
CLASSES = ["passed", "protocol-failure", "inapplicable", "harness-failure"]
DEFAULT_INVOCATION = {"backend": "certainly", "port": 8443, "attempt_timeout": 8.0,
                      "suite_timeout": 600.0}


class SummaryError(Exception):
    """The run cannot be summarized at all; callers must treat that as a harness failure."""


class BaselineError(Exception):
    pass


def read_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError) as error:
        raise SummaryError(f"cannot read {path}: {error}") from error


def read_report(directory, test_id, discovery_only=False):
    """Return the upstream test record, or raise SummaryError describing why not."""
    test = read_json(directory / "suite/results" / test_id / "_testRun.json")
    if not isinstance(test, dict) or test.get("TestId") != test_id:
        raise SummaryError(f"report does not describe {test_id}")
    cases = test.get("TestCases")
    verdict = test.get("Result")
    if verdict not in SEVERITY and verdict != DISABLED:
        raise SummaryError(f"unknown upstream verdict {verdict!r}")
    if not isinstance(cases, list) or test.get("CaseCount") != len(cases):
        raise SummaryError("case list disagrees with the case count")
    if verdict != DISABLED and not cases and not discovery_only:
        raise SummaryError("executed test has no cases")
    return test


def read_attempts(directory):
    path = directory / "attempts.jsonl"
    if not path.is_file():
        return []
    try:
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    except ValueError as error:
        raise SummaryError(f"cannot read {path}: {error}") from error


def rfc_label(metadata):
    rfc = (metadata or {}).get("rfc") or {}
    return f"RFC {rfc['number']} {rfc.get('section', '')}".strip() if "number" in rfc else None


def failed_cases(test, attempts):
    rows = []
    for case in test["TestCases"]:
        if case.get("Result") == STRICT:
            continue
        rows.append({"uuid": case.get("uuid"), "result": case.get("Result"),
                     "parameters": case.get("ParameterCombination") or {},
                     "information": case.get("AdditionalResultInformation") or [],
                     "attempts": [a["attempt"] for a in attempts
                                  if case.get("uuid") in a.get("case_ids", [])]})
    return rows


def reproduction(invocation, test_id):
    """The command that reruns exactly this upstream test template."""
    options = dict(DEFAULT_INVOCATION, **(invocation or {}))
    parts = ["tests/conformance/run-anvil.sh"]
    if options["backend"] != "certainly":
        parts += ["--backend", options["backend"]]
    if options["port"] != DEFAULT_INVOCATION["port"]:
        parts += ["--port", str(options["port"])]
    for key, flag in (("attempt_timeout", "--attempt-timeout"), ("suite_timeout", "--suite-timeout")):
        if options[key] != DEFAULT_INVOCATION[key]:
            parts += [flag, f"{options[key]:g}"]
    return " ".join(parts + ["--test", test_id])


def entry_for(run, entry, invocation):
    """One test's classified record. Anything unreadable is a harness failure."""
    test_id = entry["test_id"]
    directory = run / test_id
    record = {"test_id": test_id, "class": None, "method": None, "rfc": None, "verdict": None,
              "cases": 0, "classification": "harness-failure", "disabled_reason": None,
              "discovery_only": bool(entry.get("discovery_only")),
              "failed_cases": [], "errors": [], "tls_versions": [], "tls12_fallback": False,
              "signature": [],
              "client_outcomes": {}, "reproduce": reproduction(invocation, test_id)}
    if entry.get("harness_error"):
        record["errors"] = [entry["harness_error"]]
        return record
    try:
        test = read_report(directory, test_id, bool(entry.get("discovery_only")))
        attempts = read_attempts(directory)
    except SummaryError as error:
        record["errors"] = [str(error)]
        return record
    evidence = list(entry.get("evidence_errors", []))
    try:
        for problem in read_json(directory / "evidence.json").get("errors", []):
            if problem not in evidence:
                evidence.append(problem)
    except SummaryError:
        pass
    executed = [a for a in attempts if a.get("phase") == "test"]
    results = [a.get("result") or {} for a in executed]
    versions = sorted({r["tls_version"] for r in results if r.get("tls_version")})
    fallback = any(r.get("tls12_fallback_attempted") or r.get("tls_version") == "1.2" for r in results)
    # What the client did, not how many cases the suite happened to sample.
    signature = sorted({f"{r['outcome']}/{r.get('tls13_state')}/{r.get('bearssl_error_name')}"
                        for r in results if r.get("outcome")})
    record.update(
        {"signature": signature, "class": test.get("TestClass"), "method": test.get("TestMethod"),
         "rfc": rfc_label(test.get("MetaData")), "verdict": test["Result"],
         "cases": len(test["TestCases"]), "disabled_reason": test.get("DisabledReason"),
         "tls_versions": versions, "tls12_fallback": fallback,
         "client_outcomes": dict(Counter(r.get("outcome") for r in results if r.get("outcome")))})
    if test["Result"] == DISABLED:
        record["classification"] = "inapplicable"
        return record
    errors = evidence + (["TLS 1.2 fallback during a TLS 1.3 test"] if fallback else [])
    record["errors"] = errors
    record["failed_cases"] = failed_cases(test, attempts)
    record["classification"] = "protocol-failure" if errors or test["Result"] != STRICT else "passed"
    return record


def coverage(profile, tests, executed_count, excluded):
    covered = {t["test_id"] for t in tests if t["classification"] in ("passed", "protocol-failure")}
    uncovered = [dict(row) for row in (profile or {}).get("uncovered", [])]
    for name, category in ((profile or {}).get("categories") or {}).items():
        if not covered.intersection(category.get("tests", [])):
            uncovered.append({"category": name,
                              "reason": "no executed test produced an upstream verdict"})
    kinds = Counter(row["kind"] for row in excluded)
    return {"executed": executed_count,
            "cases": sum(t["cases"] for t in tests),
            "excluded": dict(kinds), "excluded_tests": len(excluded),
            "uncovered": sorted(uncovered, key=lambda row: row["category"])}


def summarize(run_dir, profile=None):
    run = Path(run_dir)
    index = read_json(run / "result.json")
    inputs = read_json(run / "inputs.json")
    if not isinstance(index, dict) or not isinstance(index.get("tests"), list) or not index["tests"]:
        raise SummaryError("run executed no tests")
    if profile is None and (run / "profile.json").is_file():
        profile = read_json(run / "profile.json")
    invocation = inputs.get("invocation")
    tests = [entry_for(run, entry, invocation) for entry in index["tests"]]
    seen = {t["test_id"] for t in tests}
    for test_id in (profile or {}).get("testIds", []):
        if test_id not in seen:
            record = entry_for(run, {"test_id": test_id, "harness_error": "not run"}, invocation)
            tests.append(record)
    excluded = index.get("excluded", (profile or {}).get("excluded", []))
    counts = Counter(t["classification"] for t in tests)
    counts = {name: counts.get(name, 0) for name in CLASSES}
    counts["excluded"] = len(excluded)
    return {"run": run.name,
            "suite": inputs["suite"], "backend": inputs.get("backend"),
            "source": {"revision": inputs.get("revision"), "dirty": inputs.get("dirty"),
                       "dirty_paths": inputs.get("dirty_paths", [])},
            "fixtures": {key: inputs.get(key) for key in
                         ("client_sha256", "anchors_sha256", "peer_config_sha256")},
            "profile": inputs.get("profile"), "invocation": invocation,
            "counts": counts, "tests": tests, "excluded": excluded,
            "coverage": coverage(profile, tests, len(tests), excluded)}


def load_baseline_data(raw):
    """Validate a baseline; every entry must be an explained, exact protocol defect."""
    if not isinstance(raw, dict) or raw.get("version") != 1 or \
            not isinstance(raw.get("suite_revision"), str) or \
            not isinstance(raw.get("known_failures"), list):
        raise BaselineError("baseline must be a version 1 object with suite_revision and known_failures")
    seen = set()
    for entry in raw["known_failures"]:
        if not isinstance(entry, dict):
            raise BaselineError("baseline entries must be objects")
        test_id = entry.get("test_id")
        if not isinstance(test_id, str) or not test_id:
            raise BaselineError("baseline entry without test_id")
        if test_id in seen:
            raise BaselineError(f"duplicate baseline entry: {test_id}")
        seen.add(test_id)
        if entry.get("kind") != "protocol-defect":
            raise BaselineError(f"{test_id}: only protocol defects can be accepted as known failures")
        if entry.get("verdict") not in SEVERITY[1:]:
            raise BaselineError(f"{test_id}: verdict must be a non-strict upstream verdict")
        if not isinstance(entry.get("signature"), list) or \
                any(not isinstance(item, str) for item in entry["signature"]):
            raise BaselineError(f"{test_id}: signature must list the client outcomes seen")
        for field in ("evidence", "explanation"):
            if not isinstance(entry.get(field), str) or not entry[field].strip():
                raise BaselineError(f"{test_id}: missing {field}")
    inapplicable = raw.get("inapplicable")
    if not isinstance(inapplicable, list) or any(
            not isinstance(row, dict) or not isinstance(row.get("test_id"), str) for row in inapplicable):
        raise BaselineError("baseline must list the tests the suite marks inapplicable")
    ids = [row["test_id"] for row in inapplicable]
    if len(set(ids)) != len(ids) or seen.intersection(ids):
        raise BaselineError("a test is listed twice, or as both a known failure and inapplicable")
    return raw


def load_baseline(path):
    try:
        return load_baseline_data(json.loads(Path(path).read_text()))
    except (OSError, ValueError) as error:
        raise BaselineError(f"cannot read baseline {path}: {error}") from error


def compare(summary, baseline):
    """Accept only exact recorded protocol failures; everything else is surfaced."""
    baseline = load_baseline_data(baseline)
    known = {entry["test_id"]: entry for entry in baseline["known_failures"]}
    by_id = {t["test_id"]: t for t in summary["tests"]}
    recorded_inapplicable = {row["test_id"] for row in baseline["inapplicable"]}
    result = {"accepted": [], "new_failures": [], "changed": [], "improvements": [],
              "stale": [], "harness_failures": [], "newly_inapplicable": [], "problems": []}
    revision = summary["suite"].get("revision")
    if baseline["suite_revision"] != revision:
        result["problems"].append(f"baseline was recorded for suite revision "
                                  f"{baseline['suite_revision']}, this run used {revision}")
    for test in summary["tests"]:
        entry = known.get(test["test_id"])
        if test["classification"] == "harness-failure":
            result["harness_failures"].append(test)
        elif test["classification"] == "protocol-failure":
            if entry is None or test["errors"]:
                result["new_failures"].append(test)
            elif entry["verdict"] == test["verdict"] and entry["signature"] != test["signature"]:
                result["changed"].append(
                    {"test_id": test["test_id"], "recorded": entry["verdict"], "observed": test["verdict"],
                     "reason": f"client behaviour changed: recorded {entry['signature']}, "
                               f"observed {test['signature']}", "test": test})
            elif entry["verdict"] == test["verdict"]:
                result["accepted"].append(test)
            else:
                row = {"test_id": test["test_id"], "recorded": entry["verdict"],
                       "observed": test["verdict"], "test": test}
                worse = SEVERITY.index(test["verdict"]) > SEVERITY.index(entry["verdict"])
                result["changed" if worse else "improvements"].append(row if worse else test)
        elif test["classification"] == "inapplicable":
            # Coverage that silently disappears is a regression too, even for a known failure.
            if test["test_id"] not in recorded_inapplicable:
                result["newly_inapplicable"].append(test)
        elif entry is not None and test["classification"] == "passed":
            result["improvements"].append(test)
    for test_id, entry in known.items():
        if test_id not in by_id:
            result["stale"].append({"test_id": test_id, "recorded": entry["verdict"],
                                    "reason": "not executed"})
    for test_id in sorted(recorded_inapplicable):
        test = by_id.get(test_id)
        if test is None or test["classification"] != "inapplicable":
            result["stale"].append({"test_id": test_id, "recorded": "inapplicable",
                                    "reason": "not executed" if test is None else "now applicable"})
    result["ok"] = not (result["new_failures"] or result["changed"] or result["harness_failures"]
                        or result["newly_inapplicable"] or result["problems"])
    return result


def exit_code(summary, comparison=None):
    """0 green, 1 protocol failure, 2 harness/setup failure."""
    counts = summary["counts"]
    # Inapplicable tests are results, but a run made only of them verified nothing.
    if counts["harness-failure"] or (comparison and comparison["problems"]) or \
            not counts["passed"] + counts["protocol-failure"]:
        return 2
    if comparison is not None:
        return 0 if comparison["ok"] else 1
    return 1 if summary["counts"]["protocol-failure"] else 0


def section(lines, title, rows, brief=False, count=None):
    lines.append(f"{title}: {len(rows) if count is None else count}")
    if not brief:
        lines.extend(f"  {row}" for row in rows)


def describe(test):
    where = f"{test['class'].rsplit('.', 1)[-1]}.{test['method']}" if test.get("class") else "?"
    return f"{test['test_id']}  {where}  {test['verdict'] or '-'}"


def render(summary, comparison=None, brief=False):
    accepted = {t["test_id"] for t in comparison["accepted"]} if comparison else set()
    by_class = {name: [t for t in summary["tests"] if t["classification"] == name] for name in CLASSES}
    source = summary["source"]
    lines = [f"Run {summary['run']}",
             f"Suite TLS-Anvil {summary['suite'].get('version')} revision {summary['suite'].get('revision')}",
             f"Source {source['revision']}{' (dirty)' if source['dirty'] else ''}"
             f"; client {summary['fixtures']['client_sha256']}",
             f"Fixtures: anchors {summary['fixtures']['anchors_sha256']}, "
             f"peer {summary['fixtures']['peer_config_sha256']}", ""]
    section(lines, "passed", [describe(t) for t in by_class["passed"]], brief)
    failures = []
    for test in by_class["protocol-failure"]:
        label = "known protocol failure" if test["test_id"] in accepted else "protocol failure"
        failures.append(f"{describe(test)}  [{label}, {len(test['failed_cases'])} of {test['cases']} cases]")
        failures.extend(f"    {message}" for message in test["errors"])
        failures.append(f"    reproduce: {test['reproduce']}")
    section(lines, "protocol-failure", failures, count=len(by_class["protocol-failure"]))
    section(lines, "inapplicable", [f"{describe(t)}  {t['disabled_reason']}" for t in by_class["inapplicable"]],
            brief)
    harness = []
    for test in by_class["harness-failure"]:
        harness.append(f"{test['test_id']}  {test['errors'][0] if test['errors'] else ''}")
        harness.append(f"    reproduce: {test['reproduce']}")
    section(lines, "harness-failure", harness, count=len(by_class["harness-failure"]))
    section(lines, "excluded", [f"{row['id']}  {row['kind']}: {row['reason']}" for row in summary["excluded"]],
            brief)
    cover = summary["coverage"]
    lines += ["", f"Executed {cover['executed']} tests, {cover['cases']} upstream cases; "
              f"excluded {cover['excluded_tests']} tests ({dict(cover['excluded'])})"]
    section(lines, "uncovered categories", [f"{row['category']}: {row['reason']}" for row in cover["uncovered"]])
    if comparison is not None:
        lines += ["", "Baseline comparison: " + ("accepted" if comparison["ok"] else "FAILED")]
        lines.extend(f"  problem: {problem}" for problem in comparison["problems"])
        section(lines, "  new failures", [describe(t) for t in comparison["new_failures"]])
        section(lines, "  changed outcomes",
                [f"{row['test_id']}: recorded {row['recorded']}, observed {row['observed']}"
                 + (f" ({row['reason']})" if row.get("reason") else "") for row in comparison["changed"]])
        section(lines, "  newly inapplicable",
                [f"{t['test_id']}: {t['disabled_reason']}" for t in comparison["newly_inapplicable"]])
        section(lines, "  improvements to review", [describe(t) if "class" in t else f"{t['test_id']}"
                                                    for t in comparison["improvements"]])
        section(lines, "  stale baseline entries",
                [f"{row['test_id']} ({row['reason']})" for row in comparison["stale"]])
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path, help="run directory printed by run-anvil.sh")
    parser.add_argument("--baseline", nargs="?", const=HERE / "baseline.json", type=Path,
                        help="compare with a recorded baseline (default: baseline.json)")
    args = parser.parse_args(argv)
    try:
        summary = summarize(args.run)
        comparison = compare(summary, load_baseline(args.baseline)) if args.baseline else None
    except (SummaryError, BaselineError, OSError, KeyError) as error:
        print(f"summarize: {error}", file=sys.stderr)
        return 2
    text = render(summary, comparison)
    (args.run / "summary.json").write_text(
        json.dumps({"summary": summary, "comparison": comparison}, indent=2) + "\n")
    (args.run / "summary.txt").write_text(text)
    print(text, end="")
    return exit_code(summary, comparison)


if __name__ == "__main__":
    sys.exit(main())
