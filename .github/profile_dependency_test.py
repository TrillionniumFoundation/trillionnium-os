"""Source-profile dependency regressions; no runtime or target is contacted."""
from __future__ import annotations

from copy import deepcopy
import json
import unittest

from tools.tests import test_repository_authority as authority

VERIFY = authority.VERIFY


class ProfileDependencyClosureTest(unittest.TestCase):
    # Reuse only setup helpers; unrelated link tests stay in their own suite.
    setUp = authority.RepositoryAuthorityTest.setUp
    tearDown = authority.RepositoryAuthorityTest.tearDown
    profile = authority.RepositoryAuthorityTest.profile
    def assert_profiles_rejected(self, profile=None, modules=None, gaps=None) -> None:
        for relative, value in (
            (VERIFY.PROFILE_PATH, profile),
            ("docs/machine/module-catalog.v1.json", modules),
            ("docs/machine/gap-register.v2.json", gaps),
        ):
            if value is not None:
                (self.root / relative).write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(VERIFY.VerificationError):
            VERIFY.verify_profiles(self.root)

    def module_catalog(self):
        return json.loads((self.root / "docs/machine/module-catalog.v1.json").read_bytes())

    def gap_catalog(self):
        return json.loads((self.root / "docs/machine/gap-register.v2.json").read_bytes())

    def test_selected_graph_has_exact_one_planned_edge(self) -> None:
        profiles = VERIFY.verify_profiles(self.root)
        edges = profiles["profiles"][0]["deferred_dependencies"]
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]["source_module"], "MOD-ROOTLINUX")
        self.assertEqual(edges[0]["dependency_module"], "MOD-GLOBAL-CONTROL")
        self.assertEqual(profiles["profiles"][1]["deferred_dependencies"], [])

    def test_missing_declaration_does_not_default_to_optional(self) -> None:
        _, value = self.profile()
        del value["profiles"][0]["deferred_dependencies"]
        self.assert_profiles_rejected(value)

    def test_missing_edge_cannot_be_silently_omitted(self) -> None:
        _, value = self.profile()
        value["profiles"][0]["deferred_dependencies"] = []
        self.assert_profiles_rejected(value)

    def test_dropping_active_dependency_is_rejected(self) -> None:
        _, value = self.profile()
        value["profiles"][0]["selected_modules"].remove("MOD-PROVIDER")
        self.assert_profiles_rejected(value)

    def test_active_dependency_cannot_be_deferred(self) -> None:
        _, value = self.profile()
        active = value["profiles"][0]
        active["selected_modules"].remove("MOD-PROVIDER")
        entry = deepcopy(active["deferred_dependencies"][0])
        entry["dependency_module"] = "MOD-PROVIDER"
        active["deferred_dependencies"].append(entry)
        self.assert_profiles_rejected(value)

    def test_duplicate_edge_is_rejected(self) -> None:
        _, value = self.profile()
        active = value["profiles"][0]
        active["deferred_dependencies"] *= 2
        self.assert_profiles_rejected(value)

    def test_edge_class_identity_and_extra_authority_fail_closed(self) -> None:
        _, baseline = self.profile()
        for changes in (
            {"classification": "OPTIONAL_RUNTIME"},
            {"source_module": "MOD-BROKER"},
            {"dependency_module": "MOD-TELEMETRY"},
            {"dependency_module": "MOD-MISSING"},
            {"runtime_allowed": True},
        ):
            with self.subTest(changes=changes):
                value = deepcopy(baseline)
                value["profiles"][0]["deferred_dependencies"][0].update(changes)
                self.assert_profiles_rejected(value)

    def test_closed_missing_or_wrong_gap_cannot_hold_edge(self) -> None:
        _, baseline = self.profile()
        for gap_id in ("GAP-MISSING", "GAP-JOB-ADMISSION-001", "GAP-PHYSICAL-ADB-001"):
            with self.subTest(gap=gap_id):
                value = deepcopy(baseline)
                value["profiles"][0]["deferred_dependencies"][0]["blocking_gap"] = gap_id
                self.assert_profiles_rejected(value)

    def test_gap_transition_requires_dependency_reconciliation(self) -> None:
        baseline = self.gap_catalog()
        for changes in ({"status": "CLOSED"}, {"status": "MYSTERY"}, {"exit_level": "L1"}, {"modules": ["MOD-BROKER"]}):
            with self.subTest(changes=changes):
                value = deepcopy(baseline)
                gap = next(item for item in value["gaps"] if item["id"] == "GAP-ROOTLINUX-PLACEMENT-001")
                gap.update(changes)
                self.assert_profiles_rejected(gaps=value)

    def test_planned_maturity_alone_cannot_defer_active_source_paths(self) -> None:
        value = self.module_catalog()
        target = next(item for item in value["modules"] if item["id"] == "MOD-GLOBAL-CONTROL")
        target["paths"].append("packaging/root-linux")
        self.assert_profiles_rejected(modules=value)

    def test_promoting_planned_module_invalidates_stale_exception(self) -> None:
        value = self.module_catalog()
        target = next(item for item in value["modules"] if item["id"] == "MOD-GLOBAL-CONTROL")
        target["maturity"] = "SOURCE_CLOSED_PENDING_EVIDENCE"
        self.assert_profiles_rejected(modules=value)

    def test_selecting_deferred_module_requires_removing_exception(self) -> None:
        _, value = self.profile()
        active = value["profiles"][0]
        active["selected_modules"].extend(["MOD-GLOBAL-CONTROL", "MOD-TELEMETRY"])
        active["selected_implementation_paths"].extend([
            "planned/crates/trillionnium-global-control-plane",
            "planned/crates/trillionnium-telemetry",
        ])
        self.assert_profiles_rejected(value)

    def test_sealed_profile_cannot_inherit_default_deferred_edge(self) -> None:
        _, value = self.profile()
        value["profiles"][1]["deferred_dependencies"] = value["profiles"][0]["deferred_dependencies"]
        self.assert_profiles_rejected(value)

    def test_deferred_reasons_are_bounded_and_single_line(self) -> None:
        _, baseline = self.profile()
        for reason in ("", "x\ny", "x" * 1025, "测" * 342, "x\u0085y", "\ud800"):
            with self.subTest(reason=reason[:20]):
                value = deepcopy(baseline)
                value["profiles"][0]["deferred_dependencies"][0]["reason"] = reason
                self.assert_profiles_rejected(value)

    def test_unknown_self_or_duplicate_dependency_is_rejected(self) -> None:
        baseline = self.module_catalog()
        for dependency in ("MOD-MISSING", "MOD-ROOTLINUX", "MOD-PROVIDER"):
            with self.subTest(dependency=dependency):
                value = deepcopy(baseline)
                source = next(item for item in value["modules"] if item["id"] == "MOD-ROOTLINUX")
                source["dependencies"].append(dependency)
                self.assert_profiles_rejected(modules=value)


if __name__ == "__main__":
    unittest.main()
