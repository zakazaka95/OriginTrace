import ast
import copy
import importlib.util
import json
import pathlib
import sys
import types
import unittest


class UserError(Exception):
    pass


class u64(int):
    pass


class TreeMap(dict):
    pass


class _Public:
    @staticmethod
    def write(function):
        return function

    @staticmethod
    def view(function):
        return function


class _Message:
    sender_address = "0x" + ("1" * 40)


class _Return:
    def __init__(self, calldata):
        self.calldata = calldata


class _Response:
    def __init__(self, payload, status=200):
        self.status_code = status
        self.body = json.dumps(payload).encode("utf-8") if payload is not None else b""


class _Web:
    pages = {}

    def request(self, url, method="GET", body=None, headers=None):
        if method != "GET":
            raise AssertionError("OriginTrace only uses GET in this test")
        status, payload = self.pages.get(url, (404, None))
        return _Response(payload, status)


class _Nondet:
    candidate = None
    validator_candidate = None
    calls = 0
    web = _Web()

    def exec_prompt(self, prompt, response_format=None):
        if self.candidate is None:
            raise AssertionError("Test candidate was not configured")
        self.calls += 1
        if self.calls % 2 == 0 and self.validator_candidate is not None:
            return self.validator_candidate
        return self.candidate


class _VM:
    Return = _Return
    mutator = None

    @staticmethod
    def run_nondet_unsafe(leader_fn, validator_fn):
        candidate = leader_fn()
        if _VM.mutator is not None:
            candidate = _VM.mutator(copy.deepcopy(candidate))
        if not validator_fn(_Return(candidate)):
            raise AssertionError("Validator rejected the configured candidate")
        return candidate


def _load_contract_module():
    fake_genlayer = types.ModuleType("genlayer")
    fake_gl = types.SimpleNamespace(
        Contract=object,
        UserError=UserError,
        public=_Public(),
        message=_Message(),
        nondet=_Nondet(),
        vm=_VM(),
    )
    fake_genlayer.gl = fake_gl
    fake_genlayer.TreeMap = TreeMap
    fake_genlayer.u64 = u64
    sys.modules["genlayer"] = fake_genlayer

    source = pathlib.Path(__file__).with_name("OriginTrace.py")
    spec = importlib.util.spec_from_file_location("origintrace_contract", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ot = _load_contract_module()
PACKAGE = "sampleproject"
VERSION = "4.0.0"
REPOSITORY = "pypa/sampleproject"
RELEASE_URL = f"https://pypi.org/pypi/{PACKAGE}/{VERSION}/json"
FILES = ["sampleproject-4.0.0.tar.gz", "sampleproject-4.0.0-py3-none-any.whl"]


def provenance_url(filename):
    return f"https://pypi.org/integrity/{PACKAGE}/{VERSION}/{filename}/provenance"


def provenance(repository=REPOSITORY):
    return {
        "attestation_bundles": [
            {
                "publisher": {
                    "kind": "GitHub",
                    "repository": repository,
                    "workflow": "release.yml",
                },
                "attestations": [{"version": 1}],
            }
        ]
    }


def release(repository=REPOSITORY):
    return {
        "info": {
            "name": PACKAGE,
            "version": VERSION,
            "project_urls": {"Source": f"https://github.com/{repository}"},
        },
        "urls": [
            {
                "filename": filename,
                "digests": {"sha256": str(index + 1) * 64},
                "packagetype": "sdist" if index == 0 else "bdist_wheel",
                "upload_time_iso_8601": "2024-11-06T22:37:09Z",
                "yanked": False,
            }
            for index, filename in enumerate(FILES)
        ],
    }


class OriginTraceTests(unittest.TestCase):
    def setUp(self):
        ot.gl.nondet.web.pages = {
            RELEASE_URL: (200, release()),
            provenance_url(FILES[0]): (200, provenance()),
            provenance_url(FILES[1]): (200, provenance()),
        }
        ot.gl.nondet.candidate = None
        ot.gl.nondet.validator_candidate = None
        ot.gl.nondet.calls = 0
        _VM.mutator = None
        self.contract = ot.OriginTrace()

    def open(self):
        return self.contract.open_check(PACKAGE, VERSION, REPOSITORY)

    @staticmethod
    def candidate(decision="VERIFIED"):
        return {
            "decision": decision,
            "observed_repository": REPOSITORY,
            "summary": "Every inspected release file has matching publisher provenance.",
            "findings": ["Metadata and attested publisher identify the expected repository."],
        }

    def test_verified_release_persists_complete_receipt(self):
        opened = self.open()
        ot.gl.nondet.candidate = self.candidate()
        result = self.contract.evaluate_release(ot.u64(opened["id"]))

        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(result["receipt"]["facts"]["attested_file_count"], 2)
        self.assertEqual(result["receipt"]["expected_repository"], REPOSITORY)
        self.assertEqual(result["receipt"]["evidence"]["release_status"], 200)
        self.assertEqual(
            result["receipt"]["source_snapshot_hash"],
            ot._hash(ot._canonical(result["receipt"]["evidence"])),
        )
        self.assertEqual(self.contract.get_stats()["verified"], 1)

    def test_missing_file_provenance_becomes_gap(self):
        self.open()
        ot.gl.nondet.web.pages[provenance_url(FILES[1])] = (404, None)
        ot.gl.nondet.candidate = self.candidate("PROVENANCE_GAP")
        result = self.contract.evaluate_release(ot.u64(1))

        self.assertEqual(result["status"], "PROVENANCE_GAP")
        self.assertEqual(result["receipt"]["facts"]["attested_file_count"], 1)

    def test_conflicting_attested_repository_requires_mismatch(self):
        self.open()
        ot.gl.nondet.web.pages[provenance_url(FILES[0])] = (
            200,
            provenance("attacker/lookalike"),
        )
        ot.gl.nondet.candidate = self.candidate("IDENTITY_MISMATCH")
        result = self.contract.evaluate_release(ot.u64(1))
        self.assertEqual(result["status"], "IDENTITY_MISMATCH")

    def test_unreadable_retry_is_bounded(self):
        self.open()
        ot.gl.nondet.web.pages[RELEASE_URL] = (503, None)
        self.assertEqual(self.contract.evaluate_release(ot.u64(1))["status"], "UNREADABLE")
        self.assertEqual(self.contract.evaluate_release(ot.u64(1))["status"], "UNREADABLE")
        self.assertEqual(
            self.contract.evaluate_release(ot.u64(1))["status"],
            "UNREADABLE_FINAL",
        )
        with self.assertRaises(UserError):
            self.contract.evaluate_release(ot.u64(1))

    def test_validator_must_independently_agree(self):
        self.open()
        ot.gl.nondet.candidate = self.candidate("VERIFIED")
        ot.gl.nondet.validator_candidate = self.candidate("PROVENANCE_GAP")
        with self.assertRaises(AssertionError):
            self.contract.evaluate_release(ot.u64(1))

    def test_validator_rejects_tampered_file_digest(self):
        self.open()
        ot.gl.nondet.candidate = self.candidate("VERIFIED")

        def tamper(receipt):
            receipt["evidence"]["files"][0]["sha256"] = "0" * 64
            return receipt

        _VM.mutator = tamper
        with self.assertRaises(AssertionError):
            self.contract.evaluate_release(ot.u64(1))

    def test_validator_rejects_tampered_provenance_url(self):
        self.open()
        ot.gl.nondet.candidate = self.candidate("VERIFIED")

        def tamper(receipt):
            receipt["evidence"]["files"][0]["provenance_url"] = (
                "https://example.invalid/forged-provenance"
            )
            return receipt

        _VM.mutator = tamper
        with self.assertRaises(AssertionError):
            self.contract.evaluate_release(ot.u64(1))

    def test_validator_rejects_tampered_provenance_status(self):
        self.open()
        ot.gl.nondet.candidate = self.candidate("VERIFIED")

        def tamper(receipt):
            receipt["evidence"]["files"][0]["provenance_status"] = 404
            receipt["source_snapshot_hash"] = ot._hash(
                ot._canonical(receipt["evidence"])
            )
            return receipt

        _VM.mutator = tamper
        with self.assertRaises(AssertionError):
            self.contract.evaluate_release(ot.u64(1))

    def test_validator_rejects_tampered_release_and_truncation_fields(self):
        self.open()
        ot.gl.nondet.candidate = self.candidate("VERIFIED")

        def tamper(receipt):
            receipt["evidence"]["release_status"] = 201
            receipt["evidence"]["files_truncated"] = True
            return receipt

        _VM.mutator = tamper
        with self.assertRaises(AssertionError):
            self.contract.evaluate_release(ot.u64(1))

    def test_validator_rejects_tampered_derived_counts(self):
        self.open()
        ot.gl.nondet.candidate = self.candidate("VERIFIED")

        def tamper(receipt):
            receipt["facts"]["attested_file_count"] = 99
            return receipt

        _VM.mutator = tamper
        with self.assertRaises(AssertionError):
            self.contract.evaluate_release(ot.u64(1))

    def test_validator_rejects_tampered_narrative(self):
        self.open()
        ot.gl.nondet.candidate = self.candidate("VERIFIED")

        def tamper(receipt):
            receipt["summary"] = "A leader-authored summary that validators did not produce."
            receipt["findings"] = ["Forged finding"]
            return receipt

        _VM.mutator = tamper
        with self.assertRaises(AssertionError):
            self.contract.evaluate_release(ot.u64(1))

    def test_file_limit_forces_gap_and_is_recorded(self):
        self.open()
        payload = release()
        payload["urls"] = []
        for index in range(9):
            filename = f"sampleproject-4.0.0-{index}.whl"
            payload["urls"].append({
                "filename": filename,
                "digests": {"sha256": str(index) * 64},
                "packagetype": "bdist_wheel",
                "upload_time_iso_8601": "2024-11-06T22:37:09Z",
                "yanked": False,
            })
            ot.gl.nondet.web.pages[provenance_url(filename)] = (
                200,
                provenance(),
            )
        ot.gl.nondet.web.pages[RELEASE_URL] = (200, payload)
        ot.gl.nondet.candidate = self.candidate("PROVENANCE_GAP")

        result = self.contract.evaluate_release(ot.u64(1))
        self.assertEqual(result["status"], "PROVENANCE_GAP")
        self.assertEqual(result["receipt"]["facts"]["file_count"], 8)
        self.assertTrue(result["receipt"]["evidence"]["files_truncated"])

    def test_source_order_does_not_change_canonical_evidence(self):
        first = ot._fetch_evidence(PACKAGE, VERSION)
        reversed_release = release()
        reversed_release["info"]["project_urls"] = {
            "Z source": f"https://github.com/{REPOSITORY}",
            "A docs": "https://example.com/docs",
        }
        ot.gl.nondet.web.pages[RELEASE_URL] = (200, reversed_release)
        second = ot._fetch_evidence(PACKAGE, VERSION)

        reordered = copy.deepcopy(reversed_release)
        reordered["urls"].reverse()
        reordered["info"]["project_urls"] = {
            "A docs": "https://example.com/docs",
            "Z source": f"https://github.com/{REPOSITORY}",
        }
        ot.gl.nondet.web.pages[RELEASE_URL] = (200, reordered)
        third = ot._fetch_evidence(PACKAGE, VERSION)
        self.assertEqual(ot._canonical(second), ot._canonical(third))
        self.assertNotEqual(ot._canonical(first), ot._canonical(second))

    def test_namespaced_json_reader_has_no_legacy_collision_or_headers(self):
        source = pathlib.Path(__file__).with_name("OriginTrace.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_origintrace_read_json"
        ]
        self.assertGreaterEqual(len(calls), 2)
        self.assertTrue(all(len(call.args) == 1 for call in calls))
        self.assertNotIn("def _get_json", source)
        self.assertNotIn("_get_json(", source)
        self.assertNotIn("nondet.web.get", source)
        self.assertIn('nondet.web.request(url, method="GET")', source)
        self.assertNotIn("PYPI_HEADERS", source)
        self.assertNotIn("PROVENANCE_HEADERS", source)


if __name__ == "__main__":
    unittest.main()
