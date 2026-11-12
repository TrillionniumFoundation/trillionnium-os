#!/usr/bin/env python3
"""Host-only negative checks using original screenshots; no positive case made up."""
from __future__ import annotations

import argparse
from pathlib import Path

from offline_common import checked_read, exact_keys, need, strict_json, write_new_json
from preflight_v56 import validate_candidate
from semantic_scroll_gate import pixel_evidence, validate_identity

BEFORE_SHA = "89ec9ce9e68ea59ecce3ac13dd93c1efe3c1721fb3b1e8f3fa5c97339cc5cded"
AFTER_SHA = "64a9c5c2de0787ca9e8b118b7f5c47373434feb646ab108e5bea76c6955ae50f"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--before", type=Path, required=True)
    p.add_argument("--after", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    before = checked_read(args.before, BEFORE_SHA)
    after = checked_read(args.after, AFTER_SHA)
    pixels, image_a, image_b = pixel_evidence(before, after, [0, 130, 1224, 2920])
    image_a.close()
    image_b.close()
    need(pixels["full_difference_bbox"] == [1212, 2072, 1224, 2920]
         and pixels["changed_pixel_count"] == 10176
         and pixels["side_gutter_only_change"] is True
         and pixels["interior_content_changed"] is False,
         "actual scrollbar-only negative case did not reject")
    controls = [{"name": "actual_historical_scrollbar_only_original_png_pair",
                 "rejected": True, "original_capture_bytes_used": True,
                 "source_commit": "42d3a0f447807659c0f78c8273edee01dd1b734f",
                 "task_id": "9b07550f62414bb5a9ccc16cc2db60e2",
                 "before_sha256": BEFORE_SHA, "after_sha256": AFTER_SHA, "pixels": pixels}]
    rejection_cases = [
        ("duplicate_json_key", lambda: strict_json(b'{"task_id":"first","task_id":"second"}')),
        ("nonfinite_json", lambda: strict_json(b'{"elapsed":NaN}')),
        ("unknown_candidate_not_defaulted", lambda: validate_candidate({})),
        ("candidate_null_not_defaulted", lambda: validate_candidate(None)),
        ("missing_task_and_display_identity", lambda: validate_identity({})),
        ("boolean_identity_not_object", lambda: validate_identity(True)),
        ("unknown_extra_context_field", lambda: exact_keys({"display_id": 21, "legacy": True}, {"display_id"}, "context")),
        ("wrong_original_before_hash", lambda: checked_read(args.before, AFTER_SHA)),
        ("wrong_original_after_hash", lambda: checked_read(args.after, BEFORE_SHA)),
        ("noncanonical_hash", lambda: checked_read(args.before, BEFORE_SHA.upper())),
        ("oversized_or_wrong_image_bound", lambda: checked_read(args.before, BEFORE_SHA, 100)),
        ("invalid_content_rectangle", lambda: pixel_evidence(before, after, [0, 130, 1225, 2920])),
        ("boolean_content_coordinate", lambda: pixel_evidence(before, after, [False, 130, 1224, 2920])),
    ]
    for name, call in rejection_cases:
        try:
            call()
        except ValueError as exc:
            controls.append({"name": name, "rejected": True, "reason": str(exc)})
        else:
            raise AssertionError("negative case accepted: " + name)
    result = {"schema": "hepta.notes-v56-host-preparation-negative-controls.v1",
              "negative_controls_rejected": len(controls), "negative_controls_total": len(controls),
              "controls": controls, "synthetic_positive_cases_created": 0,
              "positive_main_scroll_case_tested": False, "v56_phone_tested": False,
              "phone_actions": 0, "phone_execution_ready": False,
              "full_phone_qualification": False, "old_evidence_modified": False,
              "historical_machine_9_of_9_or_8_of_8_results_rewritten": False}
    print(write_new_json(args.out, result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
