"""Harness failures must never become protocol passes. No Java download needed."""

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

import controller as c


class Reports(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.report = {"Running": False, "TotalTests": 1, "FinishedTests": 1,
                       "TestCaseCount": 1, "TestSuiteErrorTests": 0}
        self.test = {"TestId": c.NEGATIVE, "CaseCount": 1, "Result": "STRICTLY_SUCCEEDED",
                     "TestCases": [{"Result": "STRICTLY_SUCCEEDED"}]}
        self.path = self.directory / "results" / c.NEGATIVE / "_testRun.json"
        self.path.parent.mkdir(parents=True)

    def save(self):
        c.write_json(self.directory / "report.json", self.report)
        c.write_json(self.path, self.test)

    def test_complete_report_retains_exact_upstream_verdict(self):
        self.test["Result"] = "FULLY_FAILED"
        self.test["TestCases"][0]["Result"] = "FULLY_FAILED"
        self.save()
        _, actual = c.validate_reports(self.directory, c.NEGATIVE)
        self.assertEqual(actual["Result"], "FULLY_FAILED")

    def test_missing_truncated_and_incomplete_reports_fail(self):
        self.save()
        variants = [("Running", True), ("TotalTests", 0), ("FinishedTests", 0),
                    ("TestCaseCount", 0), ("TestSuiteErrorTests", 1)]
        for field, value in variants:
            with self.subTest(field=field):
                self.save()
                original = self.report[field]
                self.report[field] = value
                c.write_json(self.directory / "report.json", self.report)
                with self.assertRaises(c.HarnessError):
                    c.validate_reports(self.directory, c.NEGATIVE)
                self.report[field] = original
        self.save()
        self.path.write_text('{"TestId":')
        with self.assertRaises(ValueError):
            c.validate_reports(self.directory, c.NEGATIVE)
        self.path.unlink()
        with self.assertRaises(c.HarnessError):
            c.validate_reports(self.directory, c.NEGATIVE)
        (self.directory / "report.json").unlink()
        with self.assertRaises(c.HarnessError):
            c.validate_reports(self.directory, c.NEGATIVE)

    def test_wrong_selection_and_missing_cases_fail(self):
        for replacement in ({"TestId": "other"}, {"CaseCount": 2}, {"TestCases": []},
                            {"Result": "DISABLED"}, {"Result": "UNKNOWN"},
                            {"TestCases": [{"Result": "FULLY_FAILED"}]}):
            with self.subTest(replacement=replacement):
                self.save()
                c.write_json(self.path, dict(self.test, **replacement))
                with self.assertRaises(c.HarnessError):
                    c.validate_reports(self.directory, c.NEGATIVE)

    def test_tampered_distribution_is_rejected_before_extraction(self):
        archive = self.directory / "release.zip"
        archive.write_bytes(b"a changed release")
        args = argparse.Namespace(archive=str(archive), fetch=False)
        lock = {"version": "test", "sha256": "0" * 64}
        with patch.object(c, "OUT", self.directory):
            with self.assertRaisesRegex(c.HarnessError, "checksum mismatch"):
                c.suite_install(args, lock)

    def test_wrong_stage_rejection_cannot_satisfy_negative_smoke(self):
        attempt = {"attempt": "test-1", "result": {"tls13_state": "RecvFinished",
                   "bearssl_error": 24, "outcome": "handshake-error"}}
        self.assertEqual(c.verify_stage("certainly", c.NEGATIVE, [attempt]), [])
        for wrong in ({"tls13_state": "RecvCertificate"}, {"bearssl_error": 62},
                      {"outcome": "timeout"}, {"tls12_fallback_attempted": True}):
            bad = dict(attempt, result=dict(attempt["result"], **wrong))
            self.assertTrue(c.verify_stage("certainly", c.NEGATIVE, [bad]))

    def test_positive_requires_tls13_and_application_data(self):
        attempt = {"attempt": "control", "result": {"tls_version": "1.3", "bytes_sent": 28}}
        self.assertEqual(c.verify_stage("certainly", c.POSITIVE, [attempt]), [])
        attempt["result"]["tls_version"] = "1.2"
        self.assertTrue(c.verify_stage("certainly", c.POSITIVE, [attempt]))
        attempt["result"] = {"tls_version": "1.3", "bytes_sent": 0}
        self.assertTrue(c.verify_stage("certainly", c.POSITIVE, [attempt]))

    def test_case_ports_and_timestamps_correlate_discovery_and_multiple_connections(self):
        attempts = [dict(attempt=f"a{i}", local_port=5000+i, started_ns=i*1_000_000_000)
                    for i in range(1, 5)]
        case = {"DstPort": 5003, "uuid": "case-1", "StartTimestamp": "1970-01-01T00:00:02Z",
                "EndTimestamp": "1970-01-01T00:00:03Z"}
        test = {"TestId": c.NEGATIVE, "TestCases": [case]}
        executed = c.correlate(test, attempts)
        self.assertEqual([a["attempt"] for a in executed], ["a2", "a3"])
        self.assertEqual([a["phase"] for a in attempts], ["discovery", "test", "test", "discovery"])
        self.assertEqual(executed[0]["case_ids"], ["case-1"])
        attempts[0]["local_port"] = 5003
        with self.assertRaises(c.HarnessError):
            c.correlate(test, attempts)
        attempts[0]["local_port"] = 5001
        case["DstPort"] = 9999
        with self.assertRaises(c.HarnessError):
            c.correlate(test, attempts)


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.client = self.directory / "fake-client"
        self.client.write_text(f"#!{sys.executable}\nimport sys, json, os\n"
            "attempt=sys.argv[sys.argv.index('--attempt')+1]\n"
            "print(json.dumps(dict(event='result', attempt=attempt, exit=0, outcome='success', local_port=os.getpid())))\n")
        self.client.chmod(0o755)
        (self.directory / "payload.txt").write_text("payload\n")
        args = argparse.Namespace(backend="certainly", client=self.client, port=8443,
                                  attempt_timeout=1)
        self.owner = c.Attempts(self.directory, args,
            {"server_name": "tls-attacker.com", "validation_time": 1798761600},
            self.directory / "anchors.pem", "run", c.POSITIVE)
        self.addCleanup(self.owner.close)

    def test_discovery_and_multiple_fresh_attempts_are_correlated_and_reaped(self):
        self.owner.launch()
        first = self.owner.process
        self.owner.launch()
        self.assertIsNotNone(first.poll())
        second = self.owner.process
        self.owner.close()
        self.assertIsNotNone(second.poll())
        records = [json.loads(line) for line in (self.directory / "attempts.jsonl").read_text().splitlines()]
        case = {"DstPort": records[1]["local_port"], "uuid": "case-1"}
        for key, value in (("StartTimestamp", records[1]["started_ns"]),
                           ("EndTimestamp", records[1]["finished_ns"])):
            case[key] = datetime.fromtimestamp(value / 1e9, timezone.utc).isoformat()
        c.correlate({"TestId": c.POSITIVE, "TestCases": [case]}, records)
        self.assertEqual([r["phase"] for r in records], ["discovery", "test"])
        self.assertIsNone(records[0]["test_id"])
        self.assertEqual(records[1]["test_id"], c.POSITIVE)
        self.assertEqual(len({r["attempt"] for r in records}), 2)
        self.assertFalse(self.owner.errors)

    def test_stuck_client_is_killed_and_cannot_pass(self):
        self.client.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(60)\n")
        start = time.monotonic()
        self.owner.launch()
        process = self.owner.process
        self.owner.close()
        self.assertLess(time.monotonic() - start, 4)
        self.assertIsNotNone(process.poll())
        self.assertTrue(self.owner.records[0]["watchdog_timeout"])
        record = self.owner.records[0]
        record["local_port"] = 12345
        case = {"DstPort": 12345, "uuid": "case-1", "StartTimestamp": "2026-01-01T00:00:00Z",
                "EndTimestamp": "2026-01-01T00:00:01Z"}
        with self.assertRaisesRegex(c.HarnessError, "timed-out"):
            c.correlate({"TestId": c.POSITIVE, "TestCases": [case]}, [record])

    def test_launch_failure_and_missing_trigger_environment_fail(self):
        self.client.unlink()
        with self.assertRaises(OSError):
            self.owner.launch()
        result = subprocess.run([sys.executable, str(c.HERE / "controller.py"), "trigger"],
                                env={"PATH": os.environ["PATH"]}, capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"trigger failed", result.stderr)

    def test_timeout_cleans_suite_and_its_descendants(self):
        pidfile = self.directory / "pids"
        source = ("import os,signal,time,pathlib\n"
                  "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                  "child=os.fork()\n"
                  "if child: pathlib.Path(os.environ['PIDFILE']).write_text(str(child))\n"
                  "time.sleep(60)\n")
        process = subprocess.Popen([sys.executable, "-c", source], start_new_session=True,
                                   env=dict(os.environ, PIDFILE=str(pidfile)))
        self.addCleanup(c.stop_process, process)
        deadline = time.monotonic() + 3
        while not pidfile.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(pidfile.exists())
        child = int(pidfile.read_text())
        c.stop_process(process)
        self.assertEqual(process.returncode, -signal.SIGKILL)
        # A killed orphan can briefly remain a zombie; it must not be running.
        status = subprocess.run(["ps", "-o", "stat=", "-p", str(child)], capture_output=True, text=True)
        self.assertIn(status.returncode, (0, 1), status.stderr)
        self.assertTrue(not status.stdout.strip() or status.stdout.strip().startswith("Z"))


if __name__ == "__main__":
    unittest.main()
