from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
RC = ROOT / "android-integration/working-tree/vendor/trillionnium/owner-open/init/trillionnium-owner-open.rc"
PROPERTY_CONTEXTS = (
    ROOT
    / "android-integration/working-tree/vendor/trillionnium/owner-open/sepolicy/private/property_contexts"
)
PROFILE = ROOT / "android-integration/working-tree/vendor/trillionnium/owner-open/config/profile-v3.json"
DATA_READY = "trillionnium.owner_open.data_ready"
ENABLED = "ro.trillionnium.owner_open.enabled"
BOOTSTRAP = "trillionnium_owner_open_bootstrap"


class OwnerOpenInitTimingTest(unittest.TestCase):
    def read(self, path: Path) -> str:
        self.assertTrue(path.is_file(), path)
        return path.read_text(encoding="utf-8")

    @staticmethod
    def action_body(rc: str, trigger: str) -> str:
        lines = rc.splitlines()
        marker = f"on {trigger}"
        try:
            start = next(index for index, line in enumerate(lines) if line.strip() == marker)
        except StopIteration as error:
            raise AssertionError(f"missing init trigger: {marker}") from error
        body: list[str] = []
        for line in lines[start + 1 :]:
            if line.startswith("on "):
                break
            if line and not line[0].isspace() and not line.lstrip().startswith("#"):
                break
            body.append(line)
        return "\n".join(body)

    def test_data_ready_property_is_bound_in_profile_and_selinux(self) -> None:
        profile = json.loads(self.read(PROFILE))
        self.assertEqual(profile.get("data_ready_property"), DATA_READY)
        property_lines = [
            line.split("#", 1)[0].strip()
            for line in self.read(PROPERTY_CONTEXTS).splitlines()
        ]
        matching = [line for line in property_lines if line.startswith(DATA_READY + " ")]
        self.assertEqual(len(matching), 1)
        self.assertEqual(
            matching[0].split(),
            [DATA_READY, "u:object_r:trillionnium_owner_open_prop:s0", "exact", "bool"],
        )

    def test_bootstrap_has_no_enabled_only_start_path(self) -> None:
        rc = self.read(RC)
        combined = f"property:{ENABLED}=true && property:{DATA_READY}=1"
        self.assertIn(f"on {combined}", rc)
        self.assertNotIn(f"on property:{ENABLED}=true\n", rc)
        self.assertEqual(rc.count(f"start {BOOTSTRAP}"), 1)
        self.assertIn(f"start {BOOTSTRAP}", self.action_body(rc, combined))

        # A future edit must not hide a second direct start in comments or an
        # unrelated property action.  Keep the check line-oriented so the
        # combined trigger remains the only owner of this service start.
        start_trigger = re.compile(r"^on\s+(.+)$")
        active_trigger: str | None = None
        starts: list[str] = []
        for raw_line in rc.splitlines():
            line = raw_line.strip()
            match = start_trigger.match(line) if raw_line.startswith("on ") else None
            if match:
                active_trigger = match.group(1)
            elif line == f"start {BOOTSTRAP}":
                starts.append(active_trigger or "")
        self.assertEqual(starts, [combined])

    def test_data_ready_is_published_after_directory_and_restorecon_actions(self) -> None:
        rc = self.read(RC)
        post_fs = self.action_body(rc, "post-fs-data")
        self.assertIn("mkdir /data/trillionnium 0700 root root", post_fs)
        self.assertIn("mkdir /data/trillionnium/owner-open/state/broker 0700 root root", post_fs)
        self.assertIn("restorecon_recursive /data/trillionnium/owner-open", post_fs)
        self.assertIn(f"setprop {DATA_READY} 1", post_fs)
        self.assertLess(
            post_fs.index("mkdir /data/trillionnium/owner-open/state/broker"),
            post_fs.index("restorecon_recursive /data/trillionnium/owner-open"),
        )
        self.assertLess(
            post_fs.index("restorecon_recursive /data/trillionnium/owner-open"),
            post_fs.index(f"setprop {DATA_READY} 1"),
        )

        early_init = self.action_body(rc, "early-init")
        self.assertIn(f"setprop {DATA_READY} 0", early_init)
        self.assertNotIn(f"setprop {DATA_READY} 1", early_init)

    @staticmethod
    def trigger_model(events: list[str]) -> tuple[int, int | None]:
        """Model the init combined-property trigger for both event orders."""
        enabled = False
        data_ready = False
        starts = 0
        first_start: int | None = None
        for index, event in enumerate(events):
            if event == "enabled=true":
                enabled = True
            elif event == "post-fs-data-complete":
                data_ready = True
            else:
                raise AssertionError(f"unknown event {event}")
            if enabled and data_ready and starts == 0:
                starts += 1
                first_start = index
        return starts, first_start

    def test_enabled_before_and_after_post_fs_data_both_start_once_after_barrier(self) -> None:
        rc = self.read(RC)
        self.assertIn(
            f"on property:{ENABLED}=true && property:{DATA_READY}=1",
            rc,
        )
        for events in (
            ["enabled=true", "post-fs-data-complete"],
            ["post-fs-data-complete", "enabled=true"],
        ):
            starts, first_start = self.trigger_model(events)
            self.assertEqual(starts, 1)
            self.assertEqual(first_start, 1)


if __name__ == "__main__":
    unittest.main()
