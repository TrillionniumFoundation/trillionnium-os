#!/usr/bin/env python3
"""Differential acceptance, rejection, message, ordering, and output tests."""

from __future__ import annotations

from collections import Counter
import copy
import hashlib
import itertools
import json
import os
from pathlib import Path, PurePosixPath
import platform
import random
import stat
import sys
import time
import unittest

from harness import (BASE, SOURCE_PIN, directory_inventory, encoded, exact_bytes,
                     file_inventory, fixtures, function_ast, implementations, outcome, pin)

sys.path.insert(0, str(BASE))
from candidate.root_topology import candidate_roots_disjoint, original_roots_disjoint
from tools.build_candidate import NEW_BLOCK, OLD_BLOCK


REPORT = {"schema": "hepta.offline.topology-differential-test.v1",
          "inventory_comparisons": 0, "accepted": 0, "rejected": 0,
          "topology_comparisons": 0, "families": Counter(), "rejections": Counter(),
          "failures": [], "mismatches": [], "mutation_detection": True}


class TopologyDifferentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original, cls.candidate = implementations()
        cls.real = fixtures()

    def compare(self, value, case, expected=None, reason=None):
        left = outcome(type(self).original, value)
        right = outcome(type(self).candidate, value)
        REPORT["inventory_comparisons"] += 1
        REPORT["families"][case.split(":", 1)[0]] += 1
        if left != right:
            REPORT["mismatches"].append({"case": case, "original": str(left)[:1000],
                                         "candidate": str(right)[:1000]})
        self.assertEqual(left, right, case)
        REPORT["accepted" if left["accepted"] else "rejected"] += 1
        if not left["accepted"]:
            REPORT["rejections"][left["exception_type"] + ": " + left["message"]] += 1
        if expected is not None:
            self.assertEqual(left["accepted"], expected, case)
        if reason is not None:
            self.assertEqual(left.get("message"), reason, case)
        return left

    def compare_roots(self, names, case):
        paths = [PurePosixPath(name) for name in names]
        left = original_roots_disjoint(paths)
        right = candidate_roots_disjoint(paths)
        REPORT["topology_comparisons"] += 1
        if left != right:
            REPORT["mismatches"].append({"case": case, "roots": names,
                                         "original": left, "candidate": right})
        self.assertEqual(left, right, case)
        return left

    def test_exact_declared_source_change(self):
        raw = exact_bytes(BASE / "originals/late_boundary.r10.original.py", SOURCE_PIN)
        source = raw.decode()
        self.assertEqual(source.count(OLD_BLOCK), 1)
        expected = source.replace(OLD_BLOCK, NEW_BLOCK, 1)
        actual = (BASE / "candidate/inventory_value.py").read_text()
        import ast
        self.assertEqual(ast.dump(function_ast(expected, "inventory_value"), include_attributes=False),
                         ast.dump(function_ast(actual, "inventory_value"), include_attributes=False))
        self.assertEqual(expected.replace(NEW_BLOCK, OLD_BLOCK, 1).encode(), raw)
        manifest = json.loads((BASE / "CANDIDATE-MANIFEST.json").read_text())
        self.assertEqual(pin(expected.encode()), manifest["derived_full_source_if_applied"])
        self.assertFalse(manifest["validation_result_cache"])
        self.assertFalse(manifest["historical_sources_changed"])
        self.assertFalse(manifest["runtime_admission"])

    def test_real_retained_inventory_and_output(self):
        if not self.real:
            self.skipTest("explicit synthetic-only run: private retained fixtures are not loaded")
        outputs = []
        for row, value in self.real:
            result = self.compare(value, "retained:" + row["name"], True)
            self.assertNotIn("elapsed_seconds", result["output"])
            self.assertEqual(set(result["output"]), set(value) - {"elapsed_seconds"})
            outputs.append(result["output"])
        self.assertEqual(outputs[0], outputs[1])
        after = self.real[-1][0]
        self.assertEqual(after["sha256"],
                         "bb8cfb6dd2f108046e8296956e514f7b3eec0ea5aaac5794ad86c70174478609")
        self.assertEqual((after["roots"], after["entries"]), (49, 3991))

    def test_exhaustive_posix_anchor_pairs_and_small_triples(self):
        names = ["/", "//", "/a", "//a", "/a/b", "//a/b", "/ab", "//ab",
                 "/a/bb", "/b", "/b/a", "//b", "/A", "/a/Å", "/a/A\u030a",
                 "/a/中文", "/a/😀", "/\\a", "/a\\b", "/...", "/a/..name",
                 "//?/C:/a", "/a\0b"]
        for index, nameset in enumerate(itertools.product(names, repeat=2)):
            self.compare_roots(nameset, "anchor-pair:%d" % index)
        for index, nameset in enumerate(itertools.product(names[:8], repeat=3)):
            self.compare_roots(nameset, "anchor-triple:%d" % index)
        self.assertTrue(self.compare_roots(["/a", "//a"], "different-anchors"))
        self.assertFalse(self.compare_roots(["/", "/a"], "slash-ancestor"))
        self.assertFalse(self.compare_roots(["//", "//a"], "double-slash-ancestor"))
        self.assertTrue(self.compare_roots(["/", "//a"], "cross-anchor"))
        # The pairwise predicate permits equality; the original schema guard
        # continues to reject duplicate root strings before this predicate.
        self.assertTrue(self.compare_roots(["/same", "/same"], "predicate-equality"))
        self.compare(directory_inventory(["/same", "/same"]), "duplicate:roots", False,
                     "bounded complete inventory required")

    def test_generated_and_deep_disjoint_roots(self):
        rng = random.Random(20261107)
        alphabet = ["a", "b", "a-long", "Å", "A\u030a", "中文", "😀", "..name", "...", "\\x"]
        for index in range(700):
            roots = []
            for _ in range(rng.randrange(1, 13)):
                anchor = rng.choice(["/", "//"])
                roots.append(anchor + "/".join(rng.choice(alphabet)
                                               for _ in range(rng.randrange(1, 7))))
            self.compare_roots(roots, "random:%d" % index)
            self.compare(directory_inventory(roots), "generated:%d" % index)
        for count in (1, 2, 8, 63, 64, 65):
            roots = ["/same/depth/root-%03d" % i for i in range(count)]
            self.compare_roots(roots, "same-depth:%d" % count)
            self.compare(directory_inventory(roots), "root-bound:%d" % count, count <= 64)
        roots = ["/" + "/".join(["deep"] * 128) + "/root-%02d" % i for i in range(4)]
        self.compare_roots(roots, "depth-130")
        self.compare(directory_inventory(roots), "deep:roots", True)
        self.compare_roots(roots + [str(PurePosixPath(roots[0]).parent)], "deep-ancestor")

    def test_canonical_and_type_rejections_and_unchanged_edge_cases(self):
        for root in ("", ".", "a", "a/b", "///a", "////a", "/a/", "/a//b", "/a/./b",
                     "/a/../b", "/..", "//a//b", "//a/", "C:/a", "C:\\a"):
            self.compare(directory_inventory([root]), "noncanonical:" + repr(root), False,
                         "inventory root path differs")
        for roots in ([], ["/a", "/a"], ("/a",), None, [None], [123], [True], [["/a"]]):
            value = directory_inventory(["/a"])
            value["roots"] = roots
            self.compare(value, "root-type:" + repr(roots), False)
        for roots in (["/a", "//a"], ["/Å", "/A\u030a"], ["/a", "/A"], ["/a\0b"]):
            self.compare(directory_inventory(roots), "literal-posix:" + repr(roots), True)
        # Root-only '/' and '//' retain the old later directory-child outcome;
        # this candidate does not change unrelated directory accounting.
        for root in ("/", "//"):
            self.compare(directory_inventory([root]), "anchor-inventory:" + root, False,
                         "inventory omitted or fabricated a directory child")

    def test_rejection_priority_and_exception_messages(self):
        value = directory_inventory(["/a", "/a/b"])
        del value["entries"]["/a"]
        self.compare(value, "priority:overlap-before-root-presence", False, "inventory roots overlap")
        value["roots"].append("relative")
        self.compare(value, "priority:canonical-before-overlap", False, "inventory root path differs")
        value["roots"].append("/a")
        self.compare(value, "priority:duplicate-before-canonical", False,
                     "bounded complete inventory required")
        value["extra"] = 1
        self.compare(value, "priority:schema-before-roots", False,
                     "complete original inventory schema differs")
        value = directory_inventory(["/a"])
        value["entries"]["/a"] = None
        self.compare(value, "priority:root-row-none", False,
                     "'NoneType' object has no attribute 'get'")
        value = directory_inventory(["/a"])
        value["entries"]["/a"]["metadata"] = [False] * 9
        value["entries"]["/outside"] = None
        self.compare(value, "priority:first-invalid-metadata", False, "inventory original metadata differs")
        value["entries"] = dict(reversed(list(value["entries"].items())))
        self.compare(value, "priority:entry-order-outside-before-metadata", False,
                     "inventory entry left its unique complete root")
        value = directory_inventory(["/a"])
        value["entries"][123] = {}
        self.compare(value, "priority:entry-key-type-before-rows", False)

    def test_schema_metadata_names_byte_counts_and_absent_fixture(self):
        base = file_inventory()
        self.compare(base, "synthetic:complete-files", True)
        changes = [
            ("schema", lambda x: x.update(schema="wrong")),
            ("closure-credit", lambda x: x.update(inventory_is_closure_or_retirement=True)),
            ("extra-top-key", lambda x: x.update(extra=True)),
            ("missing-top-key", lambda x: x.pop("elapsed_seconds")),
            ("entries-list", lambda x: x.update(entries=[])),
            ("root-missing", lambda x: x["entries"].pop("/scope")),
            ("missing-child", lambda x: x["entries"].pop("/scope/file-00")),
            ("fake-child", lambda x: x["entries"]["/scope"]["names"].append("fabricated")),
            ("duplicate-child", lambda x: x["entries"]["/scope"]["names"].append("file-00")),
            ("reordered-children", lambda x: x["entries"]["/scope"]["names"].reverse()),
            ("empty-child", lambda x: x["entries"]["/scope"].update(names=[""])),
            ("dot-child", lambda x: x["entries"]["/scope"].update(names=["."])),
            ("dotdot-child", lambda x: x["entries"]["/scope"].update(names=[".."])),
            ("slash-child", lambda x: x["entries"]["/scope"].update(names=["bad/name"])),
            ("nul-child", lambda x: x["entries"]["/scope"].update(names=["bad\0name"])),
            ("metadata-short", lambda x: x["entries"]["/scope"].update(metadata=[1])),
            ("metadata-bool", lambda x: x["entries"]["/scope"]["metadata"].__setitem__(0, True)),
            ("root-file-mode", lambda x: x["entries"]["/scope"]["metadata"].__setitem__(2, stat.S_IFREG)),
            ("file-kind", lambda x: x["entries"]["/scope/file-00"].update(kind="symlink")),
            ("file-mode", lambda x: x["entries"]["/scope/file-00"]["metadata"].__setitem__(2, stat.S_IFLNK)),
            ("hardlink", lambda x: x["entries"]["/scope/file-00"]["metadata"].__setitem__(5, 2)),
            ("size-metadata", lambda x: x["entries"]["/scope/file-00"]["metadata"].__setitem__(6, 99)),
            ("size-bool", lambda x: x["entries"]["/scope/file-00"].update(bytes=True)),
            ("size-negative", lambda x: x["entries"]["/scope/file-00"].update(bytes=-1)),
            ("sha-upper", lambda x: x["entries"]["/scope/file-00"].update(sha256="AB" * 32)),
            ("sha-short", lambda x: x["entries"]["/scope/file-00"].update(sha256="a" * 63)),
            ("sha-newline", lambda x: x["entries"]["/scope/file-00"].update(sha256="a" * 64 + "\n")),
            ("file-extra", lambda x: x["entries"]["/scope/file-00"].update(extra=True)),
            ("counter-bool", lambda x: x.update(file_bytes_hashed=True)),
            ("counter-wrong", lambda x: x.update(file_bytes_hashed=7)),
            ("no-parent", lambda x: x["entries"].update({"/scope/unretained/file":
                                            copy.deepcopy(x["entries"]["/scope/file-00"])})),
            ("outside-root", lambda x: x["entries"].update({"/outside":
                                            copy.deepcopy(x["entries"]["/scope/file-00"])})),
        ]
        for name, mutate in changes:
            value = copy.deepcopy(base)
            mutate(value)
            self.compare(value, "invariant:" + name, False)
        for elapsed in (None, -1, {"unchanged_ignored_field": True}):
            value = copy.deepcopy(base)
            value["elapsed_seconds"] = elapsed
            self.compare(value, "elapsed:ignored-" + repr(elapsed), True)
        fixture = "/proc/1/root/data/local/tmp/hepta-native-guard-" + "a" * 32
        value = directory_inventory([fixture])
        value["entries"][fixture] = {"kind": "absent", "absence": "ENOENT"}
        self.compare(value, "fixture:explicit-ENOENT", True)
        value["entries"][fixture]["absence"] = "EACCES"
        self.compare(value, "fixture:non-ENOENT", False)
        value = directory_inventory(["/scope"])
        value["entries"]["/scope"] = {"kind": "absent", "absence": "ENOENT"}
        self.compare(value, "fixture:not-fixture-root", False)
        self.compare(file_inventory([64 * 1024 * 1024] * 8), "byte-bound:exact512MiB", True)
        self.compare(file_inventory([64 * 1024 * 1024] * 9), "byte-bound:over512MiB", False)
        self.compare(file_inventory([64 * 1024 * 1024 + 1]), "byte-bound:over64MiB-file", False)
        value = directory_inventory(["/scope"])
        value["entries"] = {"/scope/entry-%05d" % i: {} for i in range(30001)}
        self.compare(value, "entry-bound:30001", False, "bounded complete inventory required")

    def test_real_inventory_adversarial_mutations(self):
        if not self.real:
            self.skipTest("explicit synthetic-only run: private retained fixtures are not loaded")
        baseline = self.real[-1][1]
        file_name = next(name for name, row in baseline["entries"].items() if row["kind"] == "file")
        root = baseline["roots"][0]
        changes = [
            ("duplicate", lambda x: x["roots"].append(x["roots"][0])),
            ("ancestor", lambda x: x["roots"].append(str(Path(root).parent))),
            ("noncanonical", lambda x: x["roots"].__setitem__(0, root + "/")),
            ("root-missing", lambda x: x["entries"].pop(root)),
            ("file-missing", lambda x: x["entries"].pop(file_name)),
            ("file-hash", lambda x: x["entries"][file_name].update(sha256="g" * 64)),
            ("file-size", lambda x: x["entries"][file_name].update(bytes=-1)),
            ("hardlink", lambda x: x["entries"][file_name]["metadata"].__setitem__(5, 2)),
            ("metadata-type", lambda x: x["entries"][file_name]["metadata"].__setitem__(8, "0")),
            ("counter", lambda x: x.update(file_bytes_hashed=x["file_bytes_hashed"] + 1)),
            ("closure-credit", lambda x: x.update(inventory_is_closure_or_retirement=True)),
        ]
        for name, mutate in changes:
            value = copy.deepcopy(baseline)
            mutate(value)
            self.compare(value, "retained-mutation:" + name, False)


if __name__ == "__main__":
    began = time.monotonic()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TopologyDifferentialTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    REPORT.update({
        "state": "PASS" if result.wasSuccessful() and not REPORT["mismatches"] else "FAIL",
        "tests_run": result.testsRun, "elapsed_seconds": time.monotonic() - began,
        "python": sys.version, "platform": platform.platform(), "path_flavour": "POSIX",
        "failures": [{"test": str(test), "traceback": tb}
                     for test, tb in result.failures + result.errors],
        "acceptance_and_rejection_equal": not REPORT["mismatches"],
        "exception_type_and_message_equal": not REPORT["mismatches"],
        "normalized_output_equal": not REPORT["mismatches"],
        "runtime_admission": False, "native_case_credit": 0,
        "whole_stage_budget_verified": False,
        "synthetic_only": os.environ.get("HEPTA_TOPOLOGY_SYNTHETIC_ONLY") == "1",
        "skipped_tests": [{"test": str(test), "reason": reason} for test, reason in result.skipped],
    })
    report_path = BASE / ("reports/differential-synthetic-results.json" if REPORT["synthetic_only"]
                          else "reports/differential-results.json")
    report_path.parent.mkdir(exist_ok=True)
    report_path.write_text(json.dumps(REPORT, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    print(json.dumps({key: REPORT[key] for key in ("state", "tests_run", "inventory_comparisons",
                    "topology_comparisons", "accepted", "rejected", "elapsed_seconds")}, sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() and not REPORT["mismatches"] else 1)
