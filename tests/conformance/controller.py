#!/usr/bin/env python3
"""Pinned TLS-Anvil runner and authenticated local fresh-process trigger.

Each suite invocation selects exactly one upstream test. Peer-observed TCP ports
and case timestamps distinguish discovery and test connections after execution.
Only upstream reports decide protocol verdicts; client exits validate the harness.
A run executes a profile's tests one at a time and summarizes them with summarize.py.
"""

import argparse
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import zipfile

import summarize

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
OUT = ROOT / "build/conformance"
POSITIVE = "8446-V3SF3rXAAW"
NEGATIVE = "8446-dZhHUctEjQ"
STRICT = "STRICTLY_SUCCEEDED"
TEST_ID = re.compile(r"[A-Za-z0-9-]+")
# Why an applicable template is deliberately not executed; each must be explained.
EXCLUSION_KINDS = {"optional-feature", "harness-limitation", "upstream-disabled", "out-of-scope"}
# Client outcomes a profile may declare expected for a named test; a connect error never is.
TOLERABLE_OUTCOMES = {"timeout", "certificate-error"}
VERDICT_COUNTERS = {"STRICTLY_SUCCEEDED": "StrictlySucceededTests",
                    "CONCEPTUALLY_SUCCEEDED": "ConceptuallySucceededTests",
                    "PARTIALLY_FAILED": "PartiallyFailedTests", "FULLY_FAILED": "FullyFailedTests"}
# A broken environment fails every test alike; stop instead of spending a run on it.
MAX_CONSECUTIVE_FAILURES = 5


class HarnessError(Exception):
    pass


class Interrupted(HarnessError):
    """A signal arrived; unlike a failed test, this ends the whole run."""


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n")


def digest(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def stop_process(process):
    """Reap our entire process group, including a forked trigger/helper."""
    if process is None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=2)


def command(args, **kwargs):
    try:
        result = subprocess.run(args, capture_output=True, text=True,
                                timeout=60, **kwargs)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise HarnessError(f"cannot execute {args[0]}: {error}") from error
    if result.returncode:
        raise HarnessError(f"command failed: {args}\n{result.stderr[-2000:]}")
    return result.stdout + result.stderr


def suite_install(args, lock):
    cache = OUT / f"tls-anvil-{lock['version']}"
    cache.mkdir(parents=True, exist_ok=True)
    archive = Path(args.archive).resolve() if args.archive else cache / "release.zip"
    if args.fetch and not archive.exists():
        # Download is explicit; normal runs are offline and never follow latest.
        temporary = cache / f"download-{secrets.token_hex(8)}.zip"
        try:
            command(["curl", "-fLsS", "--connect-timeout", "15", "--max-time", "55",
                     lock["url"], "-o", str(temporary)])
            if digest(temporary) != lock["sha256"]:
                raise HarnessError("downloaded TLS-Anvil archive checksum mismatch")
            temporary.replace(archive)
        finally:
            temporary.unlink(missing_ok=True)
    if not archive.is_file():
        raise HarnessError("pinned TLS-Anvil archive missing; run with --fetch or --archive ZIP")
    if digest(archive) != lock["sha256"]:
        raise HarnessError(f"TLS-Anvil archive checksum mismatch: {archive}")
    # A fresh extraction prevents changed JARs in a cache from bypassing the pin.
    installation = Path(tempfile.mkdtemp(prefix="installation-", dir=cache))
    try:
        with zipfile.ZipFile(archive) as bundle:
            for entry in bundle.infolist():
                if not (installation / entry.filename).resolve().is_relative_to(installation):
                    raise HarnessError("unsafe path in TLS-Anvil archive")
            bundle.extractall(installation)
        jar = installation / lock["jar"]
        if not jar.is_file():
            raise HarnessError("pinned archive has no expected TLS-Anvil JAR")
        return installation, jar
    except BaseException:
        shutil.rmtree(installation)
        raise


class Attempts:
    """One owner, one live client; all trigger requests are recorded and reaped."""

    def __init__(self, directory, args, lock, anchors, run_id, test_id):
        self.directory = directory
        self.args = args
        self.lock = lock
        self.anchors = anchors
        self.run_id = run_id
        self.test_id = test_id
        self.records = []
        self.errors = []
        self.process = None
        self.current = None
        self.stream = None
        self.closed = False
        self.mutex = threading.Lock()
        self.token = secrets.token_hex(24)

    def finish(self, shutdown=False, next_trigger=False):
        if self.process is None:
            return
        process, record = self.process, self.current
        remaining = max(0, record["deadline_monotonic"] - time.monotonic())
        if next_trigger:
            remaining = min(remaining, 0.05)
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            record["superseded" if next_trigger else "watchdog_timeout"] = True
        finally:
            stop_process(process)
            self.stream.close()
            self.process = None
        record["exit"] = process.returncode
        record["finished_ns"] = time.time_ns()
        record.pop("deadline_monotonic")
        if self.args.backend == "certainly":
            try:
                events = [json.loads(line) for line in Path(record["log"]).read_text().splitlines()]
                results = [event for event in events if event.get("event") == "result"]
                if len(results) != 1 or results[0].get("attempt") != record["attempt"]:
                    raise ValueError("missing/ambiguous client result")
                result = record["result"] = results[0]
                if result["exit"] != process.returncode and not record.get("superseded"):
                    raise ValueError("client exit disagrees with its result")
                record["local_port"] = result.get("local_port")
                if result["exit"] >= 20:
                    self.errors.append(f"{record['attempt']}: {result['outcome']}")
            except (OSError, ValueError, KeyError) as error:
                record["log_error"] = str(error)
                if not (record.get("superseded") or record.get("watchdog_timeout")):
                    self.errors.append(f"{record['attempt']}: invalid client log: {error}")
        if process.returncode < 0 and not (record.get("watchdog_timeout") or record.get("superseded")):
            self.errors.append(f"{record['attempt']}: client killed by signal {process.returncode}")
        if record.get("watchdog_timeout") and not shutdown:
            # Discovery probes may deliberately keep the connection open. This
            # is recorded, never used as evidence of successful rejection.
            record["cleanup"] = "deadline-killed"
        with (self.directory / "attempts.jsonl").open("a") as output:
            output.write(json.dumps(record) + "\n")

    def launch(self):
        with self.mutex:
            if self.closed:
                raise HarnessError("trigger received after shutdown")
            self.finish(next_trigger=True)
            number = len(self.records) + 1
            attempt_id = f"{self.run_id}-{self.test_id}-{number:05d}"
            log = self.directory / f"{number:05d}.jsonl"
            record = {"run": self.run_id, "attempt": attempt_id,
                      "invocation_test": self.test_id,
                      "test_id": None, "phase": "unclassified",
                      "started_ns": time.time_ns(), "log": str(log),
                      "deadline_monotonic": time.monotonic() + self.args.attempt_timeout}
            if self.args.backend == "certainly":
                argv = [str(self.args.client), "--attempt", attempt_id,
                        "--connect", f"127.0.0.1:{self.args.port}", "--server-name",
                        self.lock["server_name"], "--ca", str(self.anchors),
                        "--validation-time", str(self.lock["validation_time"]),
                        "--deadline-ms", str(int(self.args.attempt_timeout * 1000) - 500),
                        "--mode", "data", "--send", str(self.directory / "payload.txt"),
                        "--send-only", "--single-connection"]
            else:
                with socket.socket() as source:
                    source.bind(("127.0.0.1", 0))
                    record["local_port"] = source.getsockname()[1]
                argv = [self.args.openssl, "s_client", "-connect", f"127.0.0.1:{self.args.port}",
                        "-bind", f"127.0.0.1:{record['local_port']}",
                        "-servername", self.lock["server_name"], "-verify_hostname",
                        self.lock["server_name"], "-CAfile", str(self.anchors),
                        "-verify_return_error", "-attime", str(self.lock["validation_time"]),
                        "-tls1_3", "-groups", "X25519", "-ciphersuites",
                        "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256",
                        "-sigalgs", "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256", "-brief",
                        "-ign_eof"]
            record["argv"] = argv
            self.stream = log.open("w")
            try:
                with (self.directory / "payload.txt").open("rb") as payload:
                    self.process = subprocess.Popen(argv, stdin=payload,
                                                    stdout=self.stream, stderr=self.stream,
                                                    start_new_session=True)
            except OSError:
                self.stream.close()
                raise
            record["pid"] = self.process.pid
            self.current = record
            self.records.append(record)
            return {"attempt": attempt_id}

    def serve(self, server):
        server.settimeout(0.2)
        while not self.closed:
            try:
                connection, _ = server.accept()
            except socket.timeout:
                with self.mutex:
                    if self.process and time.monotonic() >= self.current["deadline_monotonic"]:
                        self.finish()
                continue
            with connection:
                connection.settimeout(2)
                try:
                    data = connection.recv(4096)
                    if json.loads(data).get("token") != self.token:
                        raise HarnessError("unauthenticated trigger request")
                    response = self.launch()
                except (OSError, ValueError, HarnessError) as error:
                    self.errors.append(f"trigger failed: {error}")
                    response = {"error": str(error)}
                try:
                    connection.sendall(json.dumps(response).encode())
                except OSError as error:
                    if not self.closed:
                        self.errors.append(f"trigger acknowledgement failed: {error}")

    def close(self):
        with self.mutex:
            self.closed = True
            self.finish(shutdown=True)


def trigger():
    try:
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(float(os.environ["ANVIL_TRIGGER_TIMEOUT"]))
            connection.connect(os.environ["ANVIL_TRIGGER_SOCKET"])
            connection.sendall(json.dumps({"token": os.environ["ANVIL_TRIGGER_TOKEN"]}).encode())
            response = json.loads(connection.recv(4096))
            if "error" in response:
                raise HarnessError(response["error"])
    except (OSError, ValueError, KeyError, HarnessError) as error:
        print(f"anvil trigger failed: {error}", file=sys.stderr)
        return 2
    return 0


def validate_reports(directory, test_id, allow_inapplicable=False, allow_discovery_only=False):
    """Require complete, nonempty reports; Java's process exit is insufficient.

    The suite itself marks a template DISABLED, with a reason, when the client
    under test lacks what it needs. That is only a result where the caller
    accepts inapplicable tests; a smoke test that is disabled proved nothing.

    Some templates judge the ClientHello captured during discovery and open no
    connection, so they have a verdict and no cases. That also needs permission."""
    reports = list(directory.glob("report.json"))
    if len(reports) != 1:
        raise HarnessError("missing or ambiguous suite report")
    report = json.loads(reports[0].read_text())
    test_file = directory / "results" / test_id / "_testRun.json"
    if not test_file.is_file():
        raise HarnessError(f"missing selected test report: {test_id}")
    test = json.loads(test_file.read_text())
    if not isinstance(report, dict) or not isinstance(test, dict):
        raise HarnessError("suite reports must be JSON objects")
    inapplicable = allow_inapplicable and test.get("Result") == "DISABLED"
    if inapplicable:
        if report.get("Running") is not False or report.get("TotalTests") != 1 or \
                report.get("FinishedTests") != 1 or report.get("DisabledTests") != 1 or \
                report.get("TestCaseCount") != 0 or report.get("TestSuiteErrorTests", 0):
            raise HarnessError("incomplete or inconsistent report for an inapplicable test")
        if test.get("TestId") != test_id or test.get("TestCases") != [] or test.get("CaseCount") != 0 \
                or not str(test.get("DisabledReason") or "").strip():
            raise HarnessError("inapplicable test has cases or no reason")
        return report, test
    counter = VERDICT_COUNTERS.get(test.get("Result"))
    if allow_discovery_only and counter and test.get("TestCases") == [] and test.get("CaseCount") == 0:
        if report.get("Running") is not False or report.get("TotalTests") != 1 or \
                report.get("FinishedTests") != 1 or report.get("TestCaseCount") != 0 or \
                report.get(counter) != 1 or report.get("TestSuiteErrorTests", 0) or \
                test.get("TestId") != test_id:
            raise HarnessError("incomplete or inconsistent report for a discovery-evaluated test")
        return report, test
    if report.get("Running") is not False or report.get("TotalTests") != 1 or \
            report.get("FinishedTests") != 1 or report.get("TestCaseCount", 0) < 1:
        raise HarnessError("incomplete or empty suite execution")
    cases = test.get("TestCases", [])
    if not isinstance(cases, list) or test.get("TestId") != test_id or test.get("CaseCount", 0) < 1 or not cases or \
            len(cases) != test["CaseCount"] or len(cases) != report["TestCaseCount"]:
        raise HarnessError("selected test is disabled, empty or incomplete")
    verdicts = {"STRICTLY_SUCCEEDED", "CONCEPTUALLY_SUCCEEDED", "PARTIALLY_FAILED", "FULLY_FAILED"}
    if test.get("Result") not in verdicts or any(not isinstance(case, dict) or
            case.get("Result") not in verdicts for case in cases):
        raise HarnessError("missing or invalid upstream verdict")
    if test["Result"] == "STRICTLY_SUCCEEDED" and any(
            case["Result"] != "STRICTLY_SUCCEEDED" for case in cases):
        raise HarnessError("upstream test and case verdicts disagree")
    if report.get("TestSuiteErrorTests", 0):
        raise HarnessError("upstream reported a test-suite error")
    return report, test


def verify_stage(backend, test_id, attempts):
    """An upstream closure verdict alone cannot prove rejection at Finished."""
    problems = []
    for attempt in attempts:
        if backend == "certainly":
            result = attempt["result"]
            if result.get("tls12_fallback_attempted") or result.get("tls_version") == "1.2":
                problems.append(f"{attempt['attempt']}: TLS 1.2 fallback during a TLS 1.3 test")
            if result.get("outcome") == "certificate-error" and result.get("tls13_state") != "RecvCertificate":
                problems.append(f"{attempt['attempt']}: certificate rejected after the Certificate message")
            if test_id == POSITIVE and (result.get("tls_version") != "1.3" or
                                       result.get("bytes_sent", 0) == 0):
                problems.append(f"{attempt['attempt']}: valid TLS 1.3 data exchange not reached")
            if test_id == NEGATIVE and (result.get("tls13_state") != "RecvFinished" or
                                       result.get("bearssl_error") != 24 or
                                       result.get("outcome") != "handshake-error"):
                problems.append(f"{attempt['attempt']}: corrupted Finished was not the rejection cause")
        elif test_id in (POSITIVE, NEGATIVE):
            log = Path(attempt["log"]).read_text()
            expected = "Verification: OK" if test_id == POSITIVE else "digest check failed"
            if expected not in log:
                problems.append(f"{attempt['attempt']}: reference client lacks {expected!r} evidence")
    return problems


def correlate(test, attempts, tolerate=()):
    """Use peer-observed TCP ports, then case time windows for extra connections.

    Trigger arguments and console log flushing provide no reliable case ID.
    Every peer-reported case must have an unambiguous owned client connection.
    A client that timed out or rejected the certificate is a harness failure unless
    the profile declares that outcome expected for this test, because a broken
    fixture looks exactly like a correct rejection.
    """
    for attempt in attempts:
        attempt.update(phase="discovery", test_id=None, case_ids=[])
    for case in test["TestCases"]:
        matches = [a for a in attempts if a.get("local_port") == case.get("DstPort")
                   and a.get("local_port")]
        if len(matches) != 1:
            raise HarnessError(f"cannot correlate case {case.get('uuid')}: TCP port {case.get('DstPort')}")
        start = datetime.fromisoformat(case["StartTimestamp"].replace("Z", "+00:00")).timestamp()
        end = datetime.fromisoformat(case["EndTimestamp"].replace("Z", "+00:00")).timestamp()
        for attempt in attempts:
            if attempt in matches or start <= attempt["started_ns"] / 1e9 <= end:
                attempt.update(phase="test", test_id=test["TestId"])
                attempt["case_ids"].append(case["uuid"])
    executed = [a for a in attempts if a["phase"] == "test"]
    for attempt in executed:
        if attempt.get("watchdog_timeout") or attempt.get("superseded") or attempt.get("log_error"):
            raise HarnessError(f"{attempt['attempt']}: incomplete or timed-out client")
        result = attempt.get("result", {})
        outcome = result.get("outcome")
        if outcome in ("timeout", "connect-error", "certificate-error") and \
                (outcome == "connect-error" or outcome not in tolerate):
            raise HarnessError(f"{attempt['attempt']}: {outcome}")
    return executed


def run_test(args, lock, jar, anchors, run, test_id, allow_inapplicable=False,
             allow_discovery_only=False, tolerate=()):
    directory = run / test_id
    directory.mkdir()
    (directory / "payload.txt").write_text("certainly conformance payload\n")
    raw = directory / "suite"
    raw.mkdir()
    write_json(directory / "selected.json", {"name": "selected", "profiles": [], "testIds": [test_id]})
    suite_log = directory / "suite.log"
    suite_log.touch()
    attempts = Attempts(directory, args, lock, anchors, run.name, test_id)
    process = None
    with tempfile.TemporaryDirectory(prefix="certainly-anvil-") as control:
        with socket.socket(socket.AF_UNIX) as server:
            socket_path = str(Path(control) / "trigger.sock")
            server.bind(socket_path)
            server.listen(16)
            thread = threading.Thread(target=attempts.serve, args=(server,), daemon=True)
            thread.start()
            env = dict(os.environ, ANVIL_TRIGGER_SOCKET=socket_path,
                       ANVIL_TRIGGER_TOKEN=attempts.token,
                       ANVIL_TRIGGER_TIMEOUT=str(args.attempt_timeout + 5),
                       ANVIL_PYTHON=sys.executable)
            argv = [args.java, "-jar", str(jar), "-disableTcpDump", "-parallelTests", "1",
                    "-config", str(run / "peer-config.xml"),
                    "-parallelHandshakes", "1", "-strength", "1", "-connectionTimeout", "3000",
                    "-outputFolder", str(raw), "-identifier", args.backend,
                    "-profileFolder", str(directory), "-profiles", "selected",
                    "-exportTraces", "client", "-port", str(args.port),
                    "-triggerScript", str(HERE / "trigger-client.sh")]
            write_json(directory / "command.json", argv)
            try:
                with suite_log.open("w") as output:
                    process = subprocess.Popen(argv, cwd=run, env=env, stdout=output,
                                               stderr=subprocess.STDOUT, start_new_session=True)
                    deadline = time.monotonic() + args.suite_timeout
                    while process.poll() is None:
                        if attempts.errors:
                            raise HarnessError("; ".join(attempts.errors[:8]))
                        if time.monotonic() >= deadline:
                            raise HarnessError(f"{test_id}: suite deadline exceeded")
                        try:
                            process.wait(timeout=0.2)
                        except subprocess.TimeoutExpired:
                            pass
                    if process.returncode:
                        raise HarnessError(f"{test_id}: suite exited {process.returncode}; see {suite_log}")
            finally:
                attempts.close()
                thread.join(timeout=3)
                stop_process(process)
            if attempts.errors:
                raise HarnessError("; ".join(attempts.errors[:8]))
    report, test = validate_reports(raw, test_id, allow_inapplicable, allow_discovery_only)
    executed = correlate(test, attempts.records, tolerate)
    (directory / "attempts.jsonl").write_text(
        "".join(json.dumps(attempt) + "\n" for attempt in attempts.records))
    if test["Result"] == "DISABLED":
        write_json(directory / "evidence.json", {"test_id": test_id, "errors": []})
        print(f"{test_id}: inapplicable ({test['DisabledReason']}); {directory}", flush=True)
        return {"test_id": test_id, "verdict": "DISABLED", "cases": 0, "evidence_errors": []}
    discovery_only = not test["TestCases"]
    if not executed and not discovery_only:
        raise HarnessError(f"{test_id}: no correlated test attempts")
    verdict = test["Result"]
    evidence_errors = verify_stage(args.backend, test_id, executed)
    write_json(directory / "evidence.json", {"test_id": test_id, "errors": evidence_errors})
    print(f"{test_id}: {verdict} ({len(executed)} attempts); {directory}", flush=True)
    result = {"test_id": test_id, "verdict": verdict, "cases": report["TestCaseCount"],
              "evidence_errors": evidence_errors}
    if discovery_only:
        result["discovery_only"] = True
    return result


def check_port(port):
    """Fail early and by number if the suite's port is taken.

    The suite listens with SO_REUSEADDR, so a previous run's TIME_WAIT entries
    must not count as busy."""
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError as error:
            raise HarnessError(f"port {port} is not available: {error}") from error


def validate_profile(profile):
    """Reject a profile that could silently drop, duplicate or mislabel a test."""
    ids = profile.get("testIds") if isinstance(profile, dict) else None
    if not isinstance(ids, list) or not ids or len(set(ids)) != len(ids) or \
            any(not isinstance(i, str) or not TEST_ID.fullmatch(i) for i in ids):
        raise HarnessError("profile needs a nonempty list of unique test IDs")
    excluded = profile.get("excluded", [])
    if not isinstance(excluded, list):
        raise HarnessError("profile exclusions must be a list")
    excluded_ids = []
    for row in excluded:
        if not isinstance(row, dict) or row.get("kind") not in EXCLUSION_KINDS or \
                not isinstance(row.get("id"), str) or not TEST_ID.fullmatch(row["id"]) or \
                not str(row.get("reason") or "").strip():
            raise HarnessError(f"profile exclusion needs an ID, a known kind and a reason: {row}")
        excluded_ids.append(row["id"])
    if len(set(excluded_ids)) != len(excluded_ids) or set(excluded_ids) & set(ids):
        raise HarnessError("a test is both executed and excluded, or excluded twice")
    for name, category in (profile.get("categories") or {}).items():
        if not isinstance(category, dict) or not set(category.get("tests", [])) <= set(ids) or \
                not set(category.get("excluded", [])) <= set(excluded_ids):
            raise HarnessError(f"category {name!r} names a test the profile does not list")
    tolerated = profile.get("tolerateOutcomes", {})
    if not isinstance(tolerated, dict) or any(
            test_id not in ids or not isinstance(outcomes, list) or not set(outcomes) <= TOLERABLE_OUTCOMES
            for test_id, outcomes in tolerated.items()):
        raise HarnessError("tolerateOutcomes must map executed test IDs to timeout/certificate-error lists")
    for flag in ("allowInapplicable", "allowDiscoveryOnly"):
        if not isinstance(profile.get(flag, False), bool):
            raise HarnessError(f"{flag} must be true or false")
    for row in profile.get("uncovered", []):
        if not isinstance(row, dict) or not row.get("category") or not str(row.get("reason") or "").strip():
            raise HarnessError("an uncovered category needs a name and a reason")


def load_profile(name):
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name):
        raise HarnessError(f"invalid profile name: {name!r}")
    path = HERE / "profiles" / f"{name}.json"
    if not path.is_file():
        raise HarnessError(f"unknown profile: {name}")
    profile = json.loads(path.read_text())
    validate_profile(profile)
    return dict(profile, name=name), digest(path)


def tls_versions(row):
    """The TLS versions a template declares; a method's list replaces its class's."""
    text = row.get("method_tls_version") or row.get("class_tls_version") or ""
    return set(re.findall(r"\b(D?TLS1[23])\b", text))


def applicable_tls13_client(rows):
    """Compiled templates that can run against a TLS 1.3 client under test."""
    return [row for row in rows
            if any(f".tests.{side}." in row["class"] for side in ("client", "both"))
            and "TLS13" in tls_versions(row)
            and not ("ServerTest" in row["class_annotations"] + row["method_annotations"]
                     and "ClientTest" not in row["class_annotations"] + row["method_annotations"])]


def check_inventory(rows, profile):
    """Every applicable template must be executed or explained; nothing may be implied."""
    applicable = {row["id"] for row in applicable_tls13_client(rows)}
    compiled = {row["id"] for row in rows}
    executed = set(profile["testIds"])
    excluded = {row["id"]: row for row in profile.get("excluded", [])}
    classified = executed | set(excluded)
    kinds = {}
    for row in excluded.values():
        kinds[row["kind"]] = kinds.get(row["kind"], 0) + 1
    report = {"compiled": len(compiled), "applicable": len(applicable),
              "executed": len(executed & applicable), "excluded": len(set(excluded) & applicable),
              "excluded_by_kind": kinds,
              "unclassified": sorted(applicable - classified),
              "unknown": sorted(i for i in classified if i not in compiled),
              "not_applicable": sorted(i for i in classified & compiled if i not in applicable),
              "uncovered": [row["category"] for row in profile.get("uncovered", [])]}
    report["ok"] = not (report["unclassified"] or report["unknown"] or report["not_applicable"])
    return report


def execute(args, lock, jar, anchors, run, test_ids, allow_inapplicable=False,
            allow_discovery_only=False, tolerate=None):
    """Run each test in order. A failed test is recorded and costs only itself."""
    deadline = time.monotonic() + args.total_timeout
    results = []
    consecutive = 0
    stop = None
    for test_id in test_ids:
        if stop is None and time.monotonic() >= deadline:
            stop = "total deadline exceeded"
        if stop is not None:
            results.append({"test_id": test_id, "harness_error": f"not run: {stop}"})
            continue
        try:
            results.append(run_test(args, lock, jar, anchors, run, test_id,
                                    allow_inapplicable=allow_inapplicable,
                                    allow_discovery_only=allow_discovery_only,
                                    tolerate=set((tolerate or {}).get(test_id, ()))))
            consecutive = 0
        except Interrupted as error:
            results.append({"test_id": test_id, "harness_error": str(error)})
            stop = "run interrupted"
        except (HarnessError, OSError, ValueError, KeyError, TypeError) as error:
            print(f"anvil: harness failure: {test_id}: {error}", file=sys.stderr, flush=True)
            results.append({"test_id": test_id, "harness_error": str(error)})
            consecutive += 1
            if consecutive >= MAX_CONSECUTIVE_FAILURES:
                stop = f"aborted after {consecutive} consecutive harness failures"
    return results


def run_inventory(args, lock, jar):
    """Compare the suite's compiled templates with the profile; no client is run."""
    profile, _ = load_profile(args.profile)
    OUT.mkdir(parents=True, exist_ok=True)
    destination = Path(tempfile.mkdtemp(prefix="inventory-", dir=OUT)) / "inventory.json"
    classpath = str(jar) + os.pathsep + str(jar.parent / "lib/*")
    command([args.java, "--class-path", classpath, str(HERE / "fixtures/AnvilInventory.java"),
             str(jar), str(destination)], cwd=destination.parent)  # the suite's loggers write to cwd
    report = check_inventory(json.loads(destination.read_text()), profile)
    print(f"Inventory: {report['compiled']} compiled templates, {report['applicable']} applicable "
          f"to a TLS 1.3 client; {report['executed']} executed, {report['excluded']} excluded "
          f"{report['excluded_by_kind']}; inventory file {destination}")
    for key, title in (("unclassified", "applicable but neither executed nor excluded"),
                       ("unknown", "named by the profile but absent from the suite"),
                       ("not_applicable", "named by the profile but not a TLS 1.3 client template")):
        for test_id in report[key]:
            print(f"  {title}: {test_id}", file=sys.stderr)
    if report["uncovered"]:
        print(f"Uncovered categories: {', '.join(report['uncovered'])}")
    return report


def main():
    if sys.argv[1:] == ["trigger"]:
        return trigger()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true", help="download the pinned release if missing")
    parser.add_argument("--archive", help="use a local release ZIP (checksum still verified)")
    parser.add_argument("--profile", default="smoke",
                        help="profile in tests/conformance/profiles/ to run (default: smoke)")
    parser.add_argument("--test", help="run one exact upstream test ID instead of a profile")
    parser.add_argument("--inventory", action="store_true",
                        help="check that the profile accounts for every applicable suite template; runs no client")
    parser.add_argument("--baseline", nargs="?", const=str(HERE / "baseline.json"), metavar="FILE",
                        help="accept only the exact known protocol failures recorded in FILE "
                             "(default: baseline.json) instead of failing on any")
    parser.add_argument("--backend", choices=["certainly", "openssl"], default="certainly")
    parser.add_argument("--java", default=os.environ.get("JAVA", "java"))
    parser.add_argument("--openssl", default=os.environ.get("OPENSSL", "openssl"))
    parser.add_argument("--client", type=Path, default=OUT / "certainly_client")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--attempt-timeout", type=float, default=8)
    parser.add_argument("--suite-timeout", type=float, default=600,
                        help="limit for each selected test")
    parser.add_argument("--total-timeout", type=float, default=7200,
                        help="limit for the whole run; later tests are recorded as not run")
    args = parser.parse_args()
    installation = None
    run = None
    try:
        if sys.version_info < (3, 11):
            raise HarnessError("Python 3.11+ is required; set ANVIL_PYTHON=python3.12")
        if not all(math.isfinite(n) and n >= 1 for n in (args.attempt_timeout, args.suite_timeout,
                                                          args.total_timeout)) \
                or not 0 < args.port < 65536:
            raise HarnessError("invalid deadline or port")
        if args.inventory and (args.test or args.baseline):
            raise HarnessError("--inventory runs nothing; it cannot be combined with --test or --baseline")
        lock = json.loads((HERE / "anvil.lock").read_text())
        profile = profile_sha = None
        if args.test is None:
            profile, profile_sha = load_profile(args.profile)
        baseline = summarize.load_baseline(args.baseline) if args.baseline else None
        version = command([args.java, "-version"])
        match = re.search(r'version "(\d+)', version)
        if not match or int(match[1]) < lock["java_min"]:
            raise HarnessError(f"Java {lock['java_min']}+ required: {version.strip()}")
        if args.inventory:
            installation, jar = suite_install(args, lock)
            return 0 if run_inventory(args, lock, jar)["ok"] else 1
        if args.backend == "certainly":
            build_log = command(["make", "-C", str(ROOT / "tests/host"), "conformance-client"])
            args.client = args.client.resolve()
            if not args.client.is_file() or not os.access(args.client, os.X_OK):
                raise HarnessError(f"native client missing or not executable: {args.client}")
        else:
            openssl_version = command([args.openssl, "version"])
            help_text = command([args.openssl, "s_client", "-help"])
            if "OpenSSL" not in openssl_version or any(flag not in help_text for flag in
                    ("-tls1_3", "-ciphersuites", "-verify_hostname", "-bind", "-attime")):
                raise HarnessError("reference client requires OpenSSL 1.1.1+ with TLS 1.3 and -bind")
        check_port(args.port)
        installation, jar = suite_install(args, lock)
        runs = OUT / "anvil-runs"
        runs.mkdir(parents=True, exist_ok=True)
        run = Path(tempfile.mkdtemp(prefix=time.strftime("%Y%m%d-%H%M%S-") + args.backend + "-", dir=runs))
        print(f"Artifacts: {run}", flush=True)
        shutil.copy(HERE / "anvil.lock", run / "anvil.lock")
        if args.backend == "certainly":
            (run / "build.log").write_text(build_log)
        status = command(["git", "status", "--porcelain"], cwd=ROOT)
        metadata = {"suite": lock, "backend": args.backend, "java": version,
                    "revision": command(["git", "rev-parse", "HEAD"], cwd=ROOT).strip(),
                    "dirty": bool(status.strip()),
                    "dirty_paths": [line[3:] for line in status.splitlines()],
                    "client_sha256": digest(args.client) if args.backend == "certainly" else None,
                    "profile": {"name": profile["name"] if profile else None, "sha256": profile_sha},
                    "invocation": {"backend": args.backend, "port": args.port,
                                   "attempt_timeout": args.attempt_timeout,
                                   "suite_timeout": args.suite_timeout}}
        if args.backend == "openssl":
            metadata["openssl"] = openssl_version
        anchors = run / "anchors.pem"
        classpath = str(jar) + os.pathsep + str(jar.parent / "lib/*")
        exported = command([args.java, "--class-path", classpath,
                            str(HERE / "fixtures/AnvilAnchors.java"), str(anchors),
                            str(run / "peer-config.xml")], cwd=run)
        (run / "anchors.log").write_text(exported)
        metadata["anchors_sha256"] = digest(anchors)
        metadata["peer_config_sha256"] = digest(run / "peer-config.xml")
        write_json(run / "inputs.json", metadata)
        if profile:
            write_json(run / "profile.json", profile)
        selected = [args.test] if args.test is not None else profile["testIds"]
        if not selected or any(not TEST_ID.fullmatch(test) for test in selected):
            raise HarnessError("empty or invalid test selection")
        # A single ad hoc test, or a profile that says so, may be inapplicable to this client.
        adhoc = args.test is not None
        results = execute(args, lock, jar, anchors, run, selected,
                          allow_inapplicable=adhoc or bool(profile.get("allowInapplicable")),
                          allow_discovery_only=adhoc or bool(profile.get("allowDiscoveryOnly")),
                          tolerate=None if adhoc else profile.get("tolerateOutcomes"))
        index = {"tests": results, "excluded": profile.get("excluded", []) if profile else []}
        write_json(run / "result.json", dict(index, status="summarizing"))
        summary = summarize.summarize(run)
        comparison = summarize.compare(summary, baseline) if baseline else None
        code = summarize.exit_code(summary, comparison)
        write_json(run / "result.json", dict(index, status=("passed", "protocol-failure", "harness-failure")[code],
                                             mode="baseline" if baseline else "inventory"))
        write_json(run / "summary.json", {"summary": summary, "comparison": comparison})
        text = summarize.render(summary, comparison)
        (run / "summary.txt").write_text(text)
        print(summarize.render(summary, comparison, brief=True), end="")
        print(f"anvil: {'PASSED' if code == 0 else 'FAILED'}; {run / 'summary.txt'}", flush=True)
        return code
    except (HarnessError, summarize.SummaryError, summarize.BaselineError, OSError, ValueError,
            KeyError, TypeError) as error:
        print(f"anvil: harness failure: {error}", file=sys.stderr)
        if run:
            write_json(run / "result.json", {"status": "harness-failure", "error": str(error)})
        return 2
    finally:
        if installation:
            shutil.rmtree(installation)


if __name__ == "__main__":
    def interrupted(signum, _frame):
        raise Interrupted(f"interrupted by signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    sys.exit(main())
