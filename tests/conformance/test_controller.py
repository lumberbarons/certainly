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


class Profiles(unittest.TestCase):
    def profile(self, **changes):
        base = {"testIds": ["T-a", "T-b"],
                "excluded": [{"id": "T-x", "kind": "optional-feature", "reason": "no resumption"}],
                "categories": {"negotiation": {"tests": ["T-a"]},
                               "resumption": {"tests": [], "excluded": ["T-x"]}},
                "uncovered": [{"category": "client authentication", "reason": "out of scope"}]}
        return dict(base, **changes)

    def test_valid_profile_is_accepted(self):
        c.validate_profile(self.profile(tolerateOutcomes={"T-a": ["timeout", "certificate-error"]},
                                        allowInapplicable=True, allowDiscoveryOnly=True))
        c.validate_profile(self.profile(excluded=[{"id": "T-x", "kind": "out-of-scope", "reason": "r"}],
                                        categories={}))
        c.validate_profile({"testIds": ["T-a"]})

    def test_malformed_profiles_are_rejected(self):
        bad = [{"testIds": []}, {"testIds": ["T-a", "T-a"]}, {"testIds": ["has space"]},
               {"testIds": "T-a"},
               self.profile(excluded=[{"id": "T-a", "kind": "optional-feature", "reason": "r"}]),
               self.profile(excluded=[{"id": "T-x", "kind": "because", "reason": "r"}]),
               self.profile(excluded=[{"id": "T-x", "kind": "optional-feature", "reason": ""}]),
               self.profile(excluded=[{"id": "T-x", "kind": "optional-feature", "reason": "r"},
                                      {"id": "T-x", "kind": "optional-feature", "reason": "r"}]),
               self.profile(categories={"n": {"tests": ["T-unknown"]}}),
               self.profile(categories={"n": {"tests": [], "excluded": ["T-a"]}}),
               self.profile(uncovered=[{"category": "x"}]),
               self.profile(tolerateOutcomes={"T-unknown": ["timeout"]}),
               self.profile(tolerateOutcomes={"T-a": ["connect-error"]}),
               self.profile(tolerateOutcomes={"T-a": "timeout"}),
               self.profile(allowInapplicable="yes"), self.profile(allowDiscoveryOnly=1)]
        for profile in bad:
            with self.subTest(profile=profile), self.assertRaises(c.HarnessError):
                c.validate_profile(profile)

    def test_shipped_profiles_are_valid(self):
        for path in sorted((c.HERE / "profiles").glob("*.json")):
            with self.subTest(profile=path.name):
                c.validate_profile(json.loads(path.read_text()))
                self.assertEqual(c.load_profile(path.stem)[0]["name"], path.stem)

    def test_unknown_or_path_like_profile_names_are_rejected(self):
        for name in ("missing", "../smoke", "smoke/../smoke", ""):
            with self.subTest(name=name), self.assertRaises(c.HarnessError):
                c.load_profile(name)


class Inventory(unittest.TestCase):
    def row(self, test_id, package, version="{TLS13})", disabled=False, method_version=None):
        return {"id": test_id, "class": f"de.rub.nds.tlstest.suite.tests.{package}.Thing",
                "method": "m", "class_annotations": [], "method_annotations": ["Disabled"] if disabled else [],
                "class_tls_version": f"@x.TlsVersion(supported={{{version}", "method_tls_version": method_version,
                "method_condition": None}

    def test_only_tls13_client_and_shared_templates_are_applicable(self):
        rows = [self.row("A", "client.tls13.rfc8446"), self.row("B", "both.tls13.rfc8446"),
                self.row("C", "server.tls13.rfc8446"), self.row("D", "client.tls12.rfc5246", "TLS12, DTLS12})"),
                self.row("E", "both.lengthfield", "TLS12, TLS13})"),
                self.row("F", "client.dtls.rfc6347", "DTLS12})")]
        self.assertEqual([r["id"] for r in c.applicable_tls13_client(rows)], ["A", "B", "E"])

    def test_server_only_templates_are_not_applicable(self):
        server = self.row("S", "both.lengthfield.extensions")
        server["class_annotations"] = ["ServerTest"]
        client = self.row("C", "both.lengthfield")
        client["method_annotations"] = ["ClientTest"]
        both = dict(self.row("B", "both.lengthfield"), class_annotations=["ClientTest", "ServerTest"])
        self.assertEqual([r["id"] for r in c.applicable_tls13_client([server, client, both])], ["C", "B"])

    def test_method_version_overrides_class_version(self):
        rows = [self.row("A", "both.lengthfield", "TLS12, TLS13})", method_version="@x.TlsVersion(supported={TLS12})"),
                self.row("B", "both.lengthfield", "TLS12})", method_version="@x.TlsVersion(supported={TLS13})")]
        self.assertEqual([r["id"] for r in c.applicable_tls13_client(rows)], ["B"])

    def test_every_applicable_template_must_be_executed_or_excluded(self):
        rows = [self.row(i, "client.tls13.rfc8446") for i in ("A", "B", "C")]
        profile = {"testIds": ["A"], "excluded": [{"id": "B", "kind": "optional-feature", "reason": "r"}]}
        report = c.check_inventory(rows, profile)
        self.assertEqual(report["unclassified"], ["C"])
        self.assertEqual((report["executed"], report["excluded"]), (1, 1))
        self.assertFalse(report["ok"])

    def test_profile_entries_unknown_to_the_suite_are_reported(self):
        rows = [self.row("A", "client.tls13.rfc8446")]
        report = c.check_inventory(rows, {"testIds": ["A", "GONE"],
            "excluded": [{"id": "SERVER", "kind": "optional-feature", "reason": "r"}]})
        self.assertEqual(sorted(report["unknown"]), ["GONE", "SERVER"])
        self.assertFalse(report["ok"])

    def test_complete_classification_is_ok_and_counts_uncovered_categories(self):
        rows = [self.row(i, "client.tls13.rfc8446") for i in ("A", "B")]
        profile = {"testIds": ["A"], "excluded": [{"id": "B", "kind": "harness-limitation", "reason": "r"}],
                   "uncovered": [{"category": "x", "reason": "r"}]}
        report = c.check_inventory(rows, profile)
        self.assertTrue(report["ok"])
        self.assertEqual(report["excluded_by_kind"], {"harness-limitation": 1})
        self.assertEqual(report["uncovered"], ["x"])

    def test_statically_disabled_templates_must_still_be_accounted_for(self):
        rows = [self.row("A", "client.tls13.rfc8446", disabled=True)]
        self.assertEqual(c.check_inventory(rows, {"testIds": ["Z"]})["unclassified"], ["A"])


class Profile(unittest.TestCase):
    """A bad test must cost one test, not the run; setup problems must not look like passes."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.run = Path(self.temporary.name)
        self.args = argparse.Namespace(total_timeout=600, backend="certainly")
        self.calls = []

    def execute(self, behaviours, **kwargs):
        def fake(args, lock, jar, anchors, run, test_id, **options):
            self.calls.append(test_id)
            behaviour = behaviours.get(test_id, "ok")
            if isinstance(behaviour, BaseException):
                raise behaviour
            return {"test_id": test_id, "verdict": c.STRICT, "cases": 1, "evidence_errors": []}
        with patch.object(c, "run_test", fake):
            return c.execute(self.args, {}, None, None, self.run, list(behaviours), **kwargs)

    def test_one_harness_failure_does_not_stop_the_remaining_tests(self):
        results = self.execute({"a": "ok", "b": c.HarnessError("cannot correlate"), "c": "ok"})
        self.assertEqual(self.calls, ["a", "b", "c"])
        self.assertEqual([r["test_id"] for r in results], ["a", "b", "c"])
        self.assertEqual(results[1]["harness_error"], "cannot correlate")
        self.assertNotIn("verdict", results[1])
        self.assertEqual(results[2]["verdict"], c.STRICT)

    def test_unreadable_reports_are_recorded_not_raised(self):
        results = self.execute({"a": ValueError("bad json"), "b": OSError("gone")})
        self.assertEqual([bool(r.get("harness_error")) for r in results], [True, True])

    def test_repeated_harness_failures_stop_the_run_and_record_the_rest(self):
        ids = {f"t{i}": c.HarnessError("java is broken") for i in range(c.MAX_CONSECUTIVE_FAILURES + 3)}
        results = self.execute(ids)
        self.assertEqual(len(self.calls), c.MAX_CONSECUTIVE_FAILURES)
        self.assertEqual(len(results), len(ids))
        self.assertIn("not run", results[-1]["harness_error"])

    def test_a_pass_resets_the_consecutive_failure_count(self):
        behaviours = {}
        for i in range(c.MAX_CONSECUTIVE_FAILURES + 2):
            behaviours[f"t{i}"] = c.HarnessError("x") if i % 2 == 0 else "ok"
        self.execute(behaviours)
        self.assertEqual(len(self.calls), len(behaviours))

    def test_total_deadline_records_unstarted_tests_as_not_run(self):
        self.args.total_timeout = 0
        results = self.execute({"a": "ok", "b": "ok"})
        self.assertEqual(self.calls, [])
        self.assertTrue(all("not run" in r["harness_error"] and "deadline" in r["harness_error"]
                            for r in results))

    def test_interruption_stops_the_run_but_keeps_finished_results(self):
        results = self.execute({"a": "ok", "b": c.Interrupted("interrupted by signal 15"), "c": "ok"})
        self.assertEqual(self.calls, ["a", "b"])
        self.assertEqual([r["test_id"] for r in results], ["a", "b", "c"])
        self.assertEqual(results[0]["verdict"], c.STRICT)
        self.assertIn("interrupted", results[1]["harness_error"])
        self.assertIn("not run", results[2]["harness_error"])


class InapplicableTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.report = {"Running": False, "TotalTests": 1, "FinishedTests": 1, "DisabledTests": 1,
                       "TestCaseCount": 0, "TestSuiteErrorTests": 0}
        self.test = {"TestId": "T", "CaseCount": 0, "Result": "DISABLED", "TestCases": [],
                     "DisabledReason": "PSKModeExtension is not supported"}
        self.path = self.directory / "results/T/_testRun.json"
        self.path.parent.mkdir(parents=True)

    def save(self):
        c.write_json(self.directory / "report.json", self.report)
        c.write_json(self.path, self.test)

    def test_disabled_test_is_an_inapplicable_result_only_when_allowed(self):
        self.save()
        _, test = c.validate_reports(self.directory, "T", allow_inapplicable=True)
        self.assertEqual(test["Result"], "DISABLED")
        with self.assertRaises(c.HarnessError):
            c.validate_reports(self.directory, "T")

    def test_disabled_test_without_a_reason_or_with_cases_is_a_harness_failure(self):
        for change in ({"DisabledReason": None}, {"DisabledReason": ""},
                       {"CaseCount": 1, "TestCases": [{"Result": "DISABLED"}]}):
            with self.subTest(change=change):
                self.test = dict(self.test, **change)
                self.save()
                with self.assertRaises(c.HarnessError):
                    c.validate_reports(self.directory, "T", allow_inapplicable=True)


class Correlation(unittest.TestCase):
    def case(self):
        return {"DstPort": 5001, "uuid": "case-1", "StartTimestamp": "1970-01-01T00:00:01Z",
                "EndTimestamp": "1970-01-01T00:00:02Z"}

    def attempt(self, outcome):
        return dict(attempt="a1", local_port=5001, started_ns=1_000_000_000, result={"outcome": outcome})

    def test_unlisted_client_failures_are_harness_failures(self):
        for outcome in ("timeout", "connect-error", "certificate-error"):
            with self.subTest(outcome=outcome), self.assertRaises(c.HarnessError):
                c.correlate({"TestId": "T", "TestCases": [self.case()]}, [self.attempt(outcome)])

    def test_a_listed_outcome_is_tolerated_but_connect_errors_never_are(self):
        test = {"TestId": "T", "TestCases": [self.case()]}
        for outcome in ("timeout", "certificate-error"):
            with self.subTest(outcome=outcome):
                executed = c.correlate(test, [self.attempt(outcome)], tolerate={outcome})
                self.assertEqual(len(executed), 1)
        with self.assertRaises(c.HarnessError):
            c.correlate(test, [self.attempt("connect-error")], tolerate={"connect-error", "timeout"})

    def test_tolerating_one_outcome_does_not_tolerate_another(self):
        with self.assertRaises(c.HarnessError):
            c.correlate({"TestId": "T", "TestCases": [self.case()]}, [self.attempt("timeout")],
                        tolerate={"certificate-error"})

    def test_tolerated_timeout_is_still_a_killed_client_not_a_clean_one(self):
        attempt = dict(self.attempt("timeout"), watchdog_timeout=True)
        with self.assertRaises(c.HarnessError):
            c.correlate({"TestId": "T", "TestCases": [self.case()]}, [attempt], tolerate={"timeout"})

    def test_certificate_rejection_must_be_at_the_certificate_message(self):
        attempt = {"attempt": "a", "result": {"outcome": "certificate-error", "tls13_state": "RecvCertificate"}}
        self.assertEqual(c.verify_stage("certainly", "T", [attempt]), [])
        attempt["result"]["tls13_state"] = "RecvCertificateVerify"
        self.assertTrue(c.verify_stage("certainly", "T", [attempt]))


class DiscoveryEvaluated(unittest.TestCase):
    """Some templates judge the ClientHello seen during discovery and open no connection."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.report = {"Running": False, "TotalTests": 1, "FinishedTests": 1, "TestCaseCount": 0,
                       "TestSuiteErrorTests": 0, "StrictlySucceededTests": 1}
        self.test = {"TestId": "T", "CaseCount": 0, "Result": c.STRICT, "TestCases": []}
        self.path = self.directory / "results/T/_testRun.json"
        self.path.parent.mkdir(parents=True)

    def save(self):
        c.write_json(self.directory / "report.json", self.report)
        c.write_json(self.path, self.test)

    def test_zero_case_verdict_needs_explicit_permission(self):
        self.save()
        _, test = c.validate_reports(self.directory, "T", allow_discovery_only=True)
        self.assertEqual(test["Result"], c.STRICT)
        with self.assertRaises(c.HarnessError):
            c.validate_reports(self.directory, "T")

    def test_failing_zero_case_verdicts_keep_their_verdict(self):
        self.report.update(StrictlySucceededTests=0, FullyFailedTests=1)
        self.test["Result"] = "FULLY_FAILED"
        self.save()
        _, test = c.validate_reports(self.directory, "T", allow_discovery_only=True)
        self.assertEqual(test["Result"], "FULLY_FAILED")

    def test_inconsistent_zero_case_reports_are_rejected(self):
        for change in ({"StrictlySucceededTests": 0}, {"FinishedTests": 0}, {"Running": True},
                       {"TestSuiteErrorTests": 1}, {"TotalTests": 2}):
            with self.subTest(change=change):
                self.report = {"Running": False, "TotalTests": 1, "FinishedTests": 1, "TestCaseCount": 0,
                               "TestSuiteErrorTests": 0, "StrictlySucceededTests": 1}
                self.report.update(change)
                self.save()
                with self.assertRaises(c.HarnessError):
                    c.validate_reports(self.directory, "T", allow_discovery_only=True)

    def test_unknown_verdicts_are_rejected_even_without_cases(self):
        self.test["Result"] = "TEST_SUITE_ERROR"
        self.save()
        with self.assertRaises(c.HarnessError):
            c.validate_reports(self.directory, "T", allow_discovery_only=True)


class PortProbe(unittest.TestCase):
    def test_listener_on_another_address_of_the_machine_is_busy_too(self):
        import socket
        with socket.socket() as busy:
            busy.bind(("0.0.0.0", 0))
            busy.listen(1)
            port = busy.getsockname()[1]
            with self.assertRaisesRegex(c.HarnessError, f"port {port}"):
                c.check_port(port)

    def test_busy_port_is_reported_by_number(self):
        import socket
        with socket.socket() as busy:
            busy.bind(("127.0.0.1", 0))
            busy.listen(1)
            port = busy.getsockname()[1]
            with self.assertRaisesRegex(c.HarnessError, f"port {port}"):
                c.check_port(port)

    def test_port_left_in_time_wait_by_a_previous_run_is_usable(self):
        import socket
        with socket.socket() as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            port = server.getsockname()[1]
            client = socket.create_connection(("127.0.0.1", port))
            connection, _ = server.accept()
            connection.close()  # the side that closes first keeps the TIME_WAIT entry
            client.close()
        c.check_port(port)


class CommandTimeout(unittest.TestCase):
    def test_slow_command_honours_its_own_limit(self):
        with self.assertRaisesRegex(c.HarnessError, "cannot execute"):
            c.command([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.2)

    def test_default_limit_still_allows_ordinary_commands(self):
        self.assertIn("ok", c.command([sys.executable, "-c", "print('ok')"]))


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
