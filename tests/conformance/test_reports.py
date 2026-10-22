"""Summaries and baseline comparison must never turn a harness problem or a
changed outcome into a pass. Small synthetic run directories; no Java needed."""

import json
from pathlib import Path
import tempfile
import unittest

import summarize as s

REVISION = "e9e9ac7160789d66736d36f3bc62430f6a49d497"
STRICT, CONCEPTUAL, PARTIAL, FULL = ("STRICTLY_SUCCEEDED", "CONCEPTUALLY_SUCCEEDED",
                                     "PARTIALLY_FAILED", "FULLY_FAILED")


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


class Run:
    """Builds the on-disk layout controller.py leaves behind."""

    def __init__(self, directory):
        self.directory = Path(directory)
        self.entries = []
        write(self.directory / "inputs.json", {
            "suite": {"version": "1.5.3", "revision": REVISION},
            "backend": "certainly", "revision": "a" * 40, "dirty": True,
            "dirty_paths": ["tests/conformance/controller.py"],
            "client_sha256": "c" * 64, "anchors_sha256": "d" * 64,
            "peer_config_sha256": "e" * 64,
            "profile": {"name": "wide", "sha256": "f" * 64},
            "invocation": {"backend": "certainly", "port": 8443, "attempt_timeout": 8.0}})

    def test(self, test_id, verdict=STRICT, cases=1, failed=None, disabled=None, evidence=(),
             tls="1.3", fallback=False, harness_error=None, report=True, attempts=True,
             cls="de.rub.nds.tlstest.suite.tests.both.tls13.rfc8446.Finished", method="m"):
        directory = self.directory / test_id
        directory.mkdir(parents=True, exist_ok=True)
        entry = {"test_id": test_id, "evidence_errors": list(evidence)}
        if harness_error:
            entry["harness_error"] = harness_error
        else:
            entry.update(verdict=verdict, cases=cases)
        self.entries.append(entry)
        if report:
            # Without an explicit failing set every case carries the test verdict.
            case_rows = [{"Result": verdict if failed is None else FULL if i in failed else STRICT,
                          "uuid": f"U{i}",
                          "ParameterCombination": {"CIPHER_SUITE": f"S{i}"},
                          "AdditionalResultInformation": ["note"]} for i in range(cases)]
            write(directory / "suite/results" / test_id / "_testRun.json", {
                "TestId": test_id, "Result": verdict, "DisabledReason": disabled,
                "TestClass": cls, "TestMethod": method, "CaseCount": cases, "TestCases": case_rows,
                "MetaData": {"rfc": {"number": 8446, "section": "4.4.4. Finished"},
                             "tags": ["both", "tls13"], "description": "d"}})
        if attempts:
            rows = [{"attempt": f"run-{test_id}-{i}", "phase": "test", "test_id": test_id,
                     "case_ids": [f"U{i}"], "exit": 0,
                     "result": {"outcome": "success", "tls_version": tls,
                                "tls12_fallback_attempted": fallback,
                                "bearssl_error_name": "BR_ERR_OK"}} for i in range(cases)]
            rows.append({"attempt": "discovery", "phase": "discovery", "test_id": None,
                         "case_ids": [], "result": {"outcome": "timeout", "tls_version": "1.2"}})
            (directory / "attempts.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
        write(directory / "evidence.json", {"test_id": test_id, "errors": list(evidence)})
        return self

    def finish(self, excluded=()):
        write(self.directory / "result.json", {"status": "x", "tests": self.entries,
                                               "excluded": list(excluded)})
        return self.directory


class Base(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.run_dir = Path(self.temporary.name) / "run"
        self.builder = Run(self.run_dir)

    def summary(self, profile=None, **kwargs):
        self.builder.finish(**kwargs)
        return s.summarize(self.run_dir, profile=profile)

    def by_id(self, summary):
        return {t["test_id"]: t for t in summary["tests"]}


class Classification(Base):
    def test_upstream_verdicts_are_preserved_and_classified_separately(self):
        self.builder.test("T-pass").test("T-concept", CONCEPTUAL).test("T-partial", PARTIAL, cases=3, failed=[1]) \
            .test("T-full", FULL, cases=2, failed=[0, 1])
        summary = self.summary()
        tests = self.by_id(summary)
        self.assertEqual(tests["T-pass"]["classification"], "passed")
        for name, verdict in (("T-concept", CONCEPTUAL), ("T-partial", PARTIAL), ("T-full", FULL)):
            self.assertEqual(tests[name]["classification"], "protocol-failure")
            self.assertEqual(tests[name]["verdict"], verdict)
        self.assertEqual(summary["counts"]["passed"], 1)
        self.assertEqual(summary["counts"]["protocol-failure"], 3)

    def test_failing_cases_keep_their_parameters_and_ids(self):
        self.builder.test("T-partial", PARTIAL, cases=3, failed=[1])
        failed = self.by_id(self.summary())["T-partial"]["failed_cases"]
        self.assertEqual([c["uuid"] for c in failed], ["U1"])
        self.assertEqual(failed[0]["parameters"], {"CIPHER_SUITE": "S1"})
        self.assertEqual(failed[0]["result"], FULL)

    def test_every_executed_test_has_an_exact_reproduction_command(self):
        self.builder.test("8446-abc")
        test = self.by_id(self.summary())["8446-abc"]
        self.assertEqual(test["reproduce"], "tests/conformance/run-anvil.sh --test 8446-abc")

    def test_reproduction_command_keeps_nondefault_invocation_options(self):
        self.builder.test("8446-abc")
        write(self.run_dir / "inputs.json", dict(json.loads((self.run_dir / "inputs.json").read_text()),
              invocation={"backend": "openssl", "port": 9000, "attempt_timeout": 12.0}))
        command = self.by_id(self.summary())["8446-abc"]["reproduce"]
        for part in ("--backend openssl", "--port 9000", "--attempt-timeout 12", "--test 8446-abc"):
            self.assertIn(part, command)

    def test_disabled_tests_are_inapplicable_with_the_suite_reason(self):
        self.builder.test("T-off", "DISABLED", cases=0, disabled="PSKModeExtension is not supported")
        test = self.by_id(self.summary())["T-off"]
        self.assertEqual(test["classification"], "inapplicable")
        self.assertEqual(test["disabled_reason"], "PSKModeExtension is not supported")

    def test_rejected_stage_evidence_is_a_protocol_failure_despite_upstream_success(self):
        self.builder.test("T-wrong-stage", STRICT, evidence=["rejected for the wrong reason"])
        test = self.by_id(self.summary())["T-wrong-stage"]
        self.assertEqual(test["classification"], "protocol-failure")
        self.assertEqual(test["verdict"], STRICT)
        self.assertIn("rejected for the wrong reason", test["errors"])

    def test_tls12_fallback_is_reported_and_cannot_pass(self):
        self.builder.test("T-fallback", STRICT, tls="1.2", fallback=True)
        test = self.by_id(self.summary())["T-fallback"]
        self.assertTrue(test["tls12_fallback"])
        self.assertEqual(test["classification"], "protocol-failure")

    def test_tls_versions_come_from_test_attempts_not_discovery(self):
        self.builder.test("T-pass")
        self.assertEqual(self.by_id(self.summary())["T-pass"]["tls_versions"], ["1.3"])

    def test_report_metadata_is_retained(self):
        self.builder.test("T-pass", cls="x.tests.both.tls13.rfc8446.Finished", method="verify")
        test = self.by_id(self.summary())["T-pass"]
        self.assertEqual((test["class"], test["method"]), ("x.tests.both.tls13.rfc8446.Finished", "verify"))
        self.assertEqual(test["rfc"], "RFC 8446 4.4.4. Finished")


class DiscoveryEvaluated(Base):
    def test_zero_case_verdict_is_reported_as_discovery_only_when_the_controller_says_so(self):
        self.builder.test("T-hello", cases=0)
        self.builder.entries[-1]["discovery_only"] = True
        test = self.by_id(self.summary())["T-hello"]
        self.assertEqual((test["classification"], test["cases"]), ("passed", 0))
        self.assertTrue(test["discovery_only"])

    def test_zero_case_verdict_without_the_flag_is_a_harness_failure(self):
        self.builder.test("T-hello", cases=0)
        self.assertEqual(self.by_id(self.summary())["T-hello"]["classification"], "harness-failure")

    def test_failing_discovery_only_verdict_is_a_protocol_failure(self):
        self.builder.test("T-hello", FULL, cases=0)
        self.builder.entries[-1]["discovery_only"] = True
        test = self.by_id(self.summary())["T-hello"]
        self.assertEqual((test["classification"], test["verdict"]), ("protocol-failure", FULL))
        self.assertEqual(test["failed_cases"], [])


class HarnessProblems(Base):
    def test_recorded_harness_error_is_not_a_protocol_result(self):
        self.builder.test("T-bad", harness_error="cannot correlate case", report=False, attempts=False)
        test = self.by_id(self.summary())["T-bad"]
        self.assertEqual(test["classification"], "harness-failure")
        self.assertIsNone(test["verdict"])
        self.assertIn("cannot correlate", test["errors"][0])

    def test_missing_report_for_an_executed_test_is_a_harness_failure(self):
        self.builder.test("T-gone", report=False)
        self.assertEqual(self.by_id(self.summary())["T-gone"]["classification"], "harness-failure")

    def test_truncated_report_is_a_harness_failure(self):
        self.builder.test("T-cut")
        (self.run_dir / "T-cut/suite/results/T-cut/_testRun.json").write_text('{"TestId":')
        self.assertEqual(self.by_id(self.summary())["T-cut"]["classification"], "harness-failure")

    def test_report_for_a_different_test_is_a_harness_failure(self):
        self.builder.test("T-one")
        path = self.run_dir / "T-one/suite/results/T-one/_testRun.json"
        data = json.loads(path.read_text())
        data["TestId"] = "T-other"
        path.write_text(json.dumps(data))
        self.assertEqual(self.by_id(self.summary())["T-one"]["classification"], "harness-failure")

    def test_unknown_upstream_verdict_is_a_harness_failure(self):
        self.builder.test("T-odd", "SOMETHING_NEW")
        self.assertEqual(self.by_id(self.summary())["T-odd"]["classification"], "harness-failure")

    def test_profile_test_that_never_ran_is_a_harness_failure(self):
        self.builder.test("T-ran")
        summary = self.summary(profile={"testIds": ["T-ran", "T-skipped"]})
        self.assertEqual(self.by_id(summary)["T-skipped"]["classification"], "harness-failure")
        self.assertIn("not run", self.by_id(summary)["T-skipped"]["errors"][0])

    def test_missing_result_index_cannot_be_summarized(self):
        with self.assertRaises(s.SummaryError):
            s.summarize(self.run_dir)

    def test_corrupt_result_index_cannot_be_summarized(self):
        self.run_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir / "result.json").write_text("{")
        with self.assertRaises(s.SummaryError):
            s.summarize(self.run_dir)


class Provenance(Base):
    def test_summary_identifies_suite_source_and_fixtures(self):
        self.builder.test("T-pass")
        summary = self.summary()
        self.assertEqual(summary["suite"]["revision"], REVISION)
        self.assertEqual(summary["source"], {"revision": "a" * 40, "dirty": True,
                                             "dirty_paths": ["tests/conformance/controller.py"]})
        self.assertEqual(summary["fixtures"], {"client_sha256": "c" * 64, "anchors_sha256": "d" * 64,
                                               "peer_config_sha256": "e" * 64})
        self.assertEqual(summary["profile"], {"name": "wide", "sha256": "f" * 64})


PROFILE = {
    "testIds": ["T-a", "T-b"],
    "excluded": [{"id": "T-psk", "kind": "optional-feature", "reason": "no resumption"},
                 {"id": "T-auth", "kind": "harness-limitation", "reason": "fixed fixture"}],
    "categories": {"negotiation": {"tests": ["T-a"]}, "alerts": {"tests": ["T-b"]},
                   "post-handshake": {"tests": [], "excluded": ["T-psk"]}},
    "uncovered": [{"category": "client authentication", "reason": "mutual TLS is out of scope"}],
}


class Coverage(Base):
    def test_executed_and_excluded_counts_are_published_by_kind(self):
        self.builder.test("T-a").test("T-b", "DISABLED", cases=0, disabled="n/a")
        summary = self.summary(profile=PROFILE, excluded=PROFILE["excluded"])
        self.assertEqual(summary["coverage"]["executed"], 2)
        self.assertEqual(summary["coverage"]["excluded"], {"optional-feature": 1, "harness-limitation": 1})
        self.assertEqual(summary["counts"]["inapplicable"], 1)

    def test_categories_without_an_executed_test_are_listed_as_uncovered(self):
        self.builder.test("T-a").test("T-b")
        summary = self.summary(profile=PROFILE, excluded=PROFILE["excluded"])
        names = [row["category"] for row in summary["coverage"]["uncovered"]]
        self.assertEqual(sorted(names), ["client authentication", "post-handshake"])

    def test_inapplicable_only_category_is_not_claimed_as_covered(self):
        self.builder.test("T-a").test("T-b", "DISABLED", cases=0, disabled="n/a")
        summary = self.summary(profile=PROFILE, excluded=PROFILE["excluded"])
        self.assertIn("alerts", [row["category"] for row in summary["coverage"]["uncovered"]])

    def test_harness_failed_category_is_not_claimed_as_covered(self):
        self.builder.test("T-a").test("T-b", harness_error="boom", report=False, attempts=False)
        summary = self.summary(profile=PROFILE, excluded=PROFILE["excluded"])
        self.assertIn("alerts", [row["category"] for row in summary["coverage"]["uncovered"]])


def baseline(*failures, revision=REVISION):
    return {"version": 1, "suite_revision": revision, "known_failures": list(failures)}


def known(test_id, verdict=FULL, kind="protocol-defect"):
    return {"test_id": test_id, "verdict": verdict, "kind": kind,
            "evidence": "observed", "explanation": "because"}


class Comparison(Base):
    def compare(self, base, **kwargs):
        summary = self.summary(**kwargs)
        return s.compare(summary, base)

    def test_exact_known_failure_is_accepted_and_listed(self):
        self.builder.test("T-known", FULL, cases=1, failed=[0])
        result = self.compare(baseline(known("T-known")))
        self.assertTrue(result["ok"])
        self.assertEqual([row["test_id"] for row in result["accepted"]], ["T-known"])

    def test_new_failure_fails_the_comparison(self):
        self.builder.test("T-new", FULL, failed=[0]).test("T-known", FULL, failed=[0])
        result = self.compare(baseline(known("T-known")))
        self.assertFalse(result["ok"])
        self.assertEqual([row["test_id"] for row in result["new_failures"]], ["T-new"])

    def test_harness_failure_fails_even_when_everything_else_is_known(self):
        self.builder.test("T-bad", harness_error="boom", report=False, attempts=False)
        result = self.compare(baseline())
        self.assertFalse(result["ok"])
        self.assertEqual([row["test_id"] for row in result["harness_failures"]], ["T-bad"])

    def test_known_failure_that_is_a_harness_failure_is_not_accepted(self):
        self.builder.test("T-known", harness_error="boom", report=False, attempts=False)
        result = self.compare(baseline(known("T-known")))
        self.assertFalse(result["ok"])
        self.assertEqual(result["accepted"], [])

    def test_known_failure_with_rejected_evidence_is_not_accepted(self):
        self.builder.test("T-known", FULL, failed=[0], tls="1.2", fallback=True)
        result = self.compare(baseline(known("T-known")))
        self.assertFalse(result["ok"])
        self.assertEqual([row["test_id"] for row in result["new_failures"]], ["T-known"])

    def test_worse_verdict_than_recorded_fails(self):
        self.builder.test("T-known", FULL, failed=[0])
        result = self.compare(baseline(known("T-known", PARTIAL)))
        self.assertFalse(result["ok"])
        self.assertEqual(result["changed"][0]["recorded"], PARTIAL)
        self.assertEqual(result["changed"][0]["observed"], FULL)

    def test_better_verdict_is_flagged_for_review_without_failing(self):
        self.builder.test("T-known", PARTIAL, cases=2, failed=[0])
        result = self.compare(baseline(known("T-known", FULL)))
        self.assertTrue(result["ok"])
        self.assertEqual([row["test_id"] for row in result["improvements"]], ["T-known"])
        self.assertEqual(result["accepted"], [])

    def test_known_failure_that_now_passes_is_an_improvement(self):
        self.builder.test("T-known")
        result = self.compare(baseline(known("T-known")))
        self.assertTrue(result["ok"])
        self.assertEqual([row["test_id"] for row in result["improvements"]], ["T-known"])

    def test_entries_for_tests_that_did_not_run_are_stale(self):
        self.builder.test("T-other")
        result = self.compare(baseline(known("T-gone"), known("T-off")))
        self.assertEqual(sorted(row["test_id"] for row in result["stale"]), ["T-gone", "T-off"])
        self.assertTrue(result["ok"])

    def test_entry_for_an_inapplicable_test_is_stale_not_accepted(self):
        self.builder.test("T-off", "DISABLED", cases=0, disabled="n/a")
        result = self.compare(baseline(known("T-off")))
        self.assertEqual([row["test_id"] for row in result["stale"]], ["T-off"])
        self.assertEqual(result["accepted"], [])

    def test_baseline_for_another_suite_revision_fails(self):
        self.builder.test("T-pass")
        result = self.compare(baseline(revision="0" * 40))
        self.assertFalse(result["ok"])
        self.assertIn("suite revision", result["problems"][0])

    def test_only_protocol_defects_can_be_accepted(self):
        for entry in (known("T-x", kind="optional-feature"), dict(known("T-x"), kind=None),
                      dict(known("T-x"), verdict=STRICT), dict(known("T-x"), verdict="NOPE"),
                      {k: v for k, v in known("T-x").items() if k != "explanation"}):
            with self.subTest(entry=entry), self.assertRaises(s.BaselineError):
                s.load_baseline_data(baseline(entry))

    def test_duplicate_entries_are_rejected(self):
        with self.assertRaises(s.BaselineError):
            s.load_baseline_data(baseline(known("T-x"), known("T-x")))

    def test_passing_inapplicable_and_excluded_runs_are_ok_with_an_empty_baseline(self):
        self.builder.test("T-pass").test("T-off", "DISABLED", cases=0, disabled="n/a")
        result = self.compare(baseline(), excluded=PROFILE["excluded"])
        self.assertTrue(result["ok"])


class ExitStatus(Base):
    def test_inventory_run_is_green_only_when_nothing_failed(self):
        self.builder.test("T-pass").test("T-off", "DISABLED", cases=0, disabled="n/a")
        self.assertEqual(s.exit_code(self.summary()), 0)

    def test_inventory_run_fails_on_protocol_failures(self):
        self.builder.test("T-full", FULL, failed=[0])
        self.assertEqual(s.exit_code(self.summary()), 1)

    def test_harness_failures_take_precedence(self):
        self.builder.test("T-full", FULL, failed=[0]).test("T-bad", harness_error="x", report=False, attempts=False)
        self.assertEqual(s.exit_code(self.summary()), 2)

    def test_a_run_where_nothing_produced_a_verdict_is_a_harness_failure(self):
        self.builder.test("T-off", "DISABLED", cases=0, disabled="n/a")
        summary = self.summary()
        self.assertEqual(s.exit_code(summary), 2)
        self.assertEqual(s.exit_code(summary, s.compare(summary, baseline())), 2)

    def test_comparison_accepts_known_failures_but_not_new_or_harness_failures(self):
        self.builder.test("T-known", FULL, failed=[0])
        summary = self.summary()
        self.assertEqual(s.exit_code(summary, s.compare(summary, baseline(known("T-known")))), 0)
        self.assertEqual(s.exit_code(summary, s.compare(summary, baseline())), 1)

    def test_comparison_harness_failure_is_status_two(self):
        self.builder.test("T-bad", harness_error="x", report=False, attempts=False)
        summary = self.summary()
        self.assertEqual(s.exit_code(summary, s.compare(summary, baseline())), 2)


class Rendering(Base):
    def test_brief_text_leaves_out_passing_and_inapplicable_rows_but_keeps_failures(self):
        self.builder.test("T-pass").test("T-full", FULL, failed=[0]) \
            .test("T-off", "DISABLED", cases=0, disabled="n/a")
        text = s.render(self.summary(), brief=True)
        self.assertNotIn("T-pass", text)
        self.assertNotIn("T-off", text)
        self.assertIn("T-full", text)
        self.assertIn("passed: 1", text)


    def test_text_lists_known_failures_and_reproduction_commands(self):
        self.builder.test("T-known", FULL, failed=[0])
        summary = self.summary()
        text = s.render(summary, s.compare(summary, baseline(known("T-known"))))
        self.assertIn("T-known", text)
        self.assertIn("known protocol failure", text)
        self.assertIn("run-anvil.sh --test T-known", text)

    def test_section_counts_are_tests_not_output_lines(self):
        self.builder.test("T-full", FULL, failed=[0]).test("T-bad", harness_error="x", report=False, attempts=False)
        text = s.render(self.summary())
        self.assertIn("protocol-failure: 1\n", text)
        self.assertIn("harness-failure: 1\n", text)

    def test_text_shows_each_classification_separately(self):
        self.builder.test("T-pass").test("T-full", FULL, failed=[0]) \
            .test("T-off", "DISABLED", cases=0, disabled="n/a") \
            .test("T-bad", harness_error="x", report=False, attempts=False)
        text = s.render(self.summary(excluded=PROFILE["excluded"]))
        for heading in ("passed", "protocol-failure", "inapplicable", "harness-failure", "excluded"):
            self.assertIn(heading, text)


if __name__ == "__main__":
    unittest.main()
