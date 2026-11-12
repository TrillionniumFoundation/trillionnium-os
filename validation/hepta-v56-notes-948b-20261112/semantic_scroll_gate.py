#!/usr/bin/env python3
"""An additional offline content gate; it never replaces the in-flight protocol.

The old RGBA inequality accepts scrollbar fade. This gate requires changed
interior content and independently reviewed semantic rows with reproducible,
consistent image displacement. It deliberately has no inferred or synthetic
positive review. The caller must separately verify the original main-display
protocol, task/native lease and command/readback timing.
"""
from __future__ import annotations

import argparse
from collections import Counter
import io
from pathlib import Path

from PIL import Image, ImageChops

from offline_common import COMMIT, GENERATION, TASK, checked_read, exact_keys, need, require_sha, sha256, strict_json, write_new_json

REVIEW_KEYS = {"schema", "identity", "captures", "content_rect", "reviewer", "reviewed_at_utc",
              "scrollable_start", "anchors"}
IDENTITY_KEYS = {"source_commit", "apk_sha256", "task_id", "generation", "main_display_id",
                 "main_physical_display_id", "background_display_id", "protocol_proof_sha256"}


def validate_identity(identity):
    exact_keys(identity, IDENTITY_KEYS, "scroll identity")
    need(type(identity["source_commit"]) is str and COMMIT.fullmatch(identity["source_commit"]), "source commit required")
    require_sha(identity["apk_sha256"], "APK")
    require_sha(identity["protocol_proof_sha256"], "same-task protocol proof")
    need(type(identity["task_id"]) is str and TASK.fullmatch(identity["task_id"]), "task ID required")
    need(type(identity["generation"]) is str and GENERATION.fullmatch(identity["generation"]), "background generation required")
    need(type(identity["main_display_id"]) is int and identity["main_display_id"] == 0,
         "logical main display must be exact integer zero")
    need(type(identity["background_display_id"]) is int and identity["background_display_id"] > 0,
         "distinct background display required")
    physical = identity["main_physical_display_id"]
    need(type(physical) is str and physical.isascii() and physical.isdigit()
         and str(int(physical)) == physical and 0 < int(physical) < 1 << 64,
         "canonical observed physical display ID required")


def rect(value, bounds, label):
    need(type(value) is list and len(value) == 4 and all(type(n) is int for n in value), label + ": integer rectangle required")
    left, top, right, bottom = value
    need(bounds[0] <= left < right <= bounds[2] and bounds[1] <= top < bottom <= bounds[3],
         label + ": rectangle outside observed content")
    return tuple(value)


def image_rgba(raw):
    with Image.open(io.BytesIO(raw)) as image:
        need(image.format == "PNG" and 200 <= image.width <= 10000 and 400 <= image.height <= 10000
             and image.width * image.height <= 32_000_000, "bounded original full-resolution PNG required")
        image.load()
        return image.convert("RGBA")


def diff_mask(before, after):
    channels = ImageChops.difference(before, after).split()
    mask = channels[0]
    for channel in channels[1:]:
        combined = ImageChops.lighter(mask, channel)
        mask.close()
        channel.close()
        mask = combined
    result = mask.point(lambda n: 255 if n else 0)
    mask.close()
    return result


def pixel_evidence(before_raw, after_raw, content_rect):
    before, after = image_rgba(before_raw), image_rgba(after_raw)
    try:
        need(before.size == after.size, "original full-screen dimensions differ")
        bounds = (0, 0, before.width, before.height)
        area = rect(content_rect, bounds, "content")
        need(area[2] - area[0] >= 200 and area[3] - area[1] >= 400, "content area too small")
        # Fixed, conservative side gutters. They are never accepted as evidence
        # of content motion; scrollbar/caret effects cannot satisfy this gate.
        gutter = max(16, ((area[2] - area[0]) + 49) // 50)
        core = (area[0] + gutter, area[1], area[2] - gutter, area[3])
        with diff_mask(before, after) as mask:
            bbox = mask.getbbox()
            changed = mask.histogram()[255]
            with mask.crop(area) as app_mask, mask.crop(core) as core_mask:
                app_changed = app_mask.histogram()[255]
                core_changed = core_mask.histogram()[255]
                core_bbox = core_mask.getbbox()
        return {"dimensions": list(before.size), "content_rect": list(area), "core_rect": list(core),
                "fixed_side_gutter_px": gutter, "full_difference_bbox": list(bbox) if bbox else None,
                "changed_pixel_count": changed, "app_changed_pixel_count": app_changed,
                "interior_changed_pixel_count": core_changed,
                "interior_difference_bbox": ([core_bbox[0] + core[0], core_bbox[1] + core[1],
                                               core_bbox[2] + core[0], core_bbox[3] + core[1]] if core_bbox else None),
                "interior_content_changed": core_changed > 0,
                "side_gutter_only_change": app_changed > 0 and core_changed == 0}, before, after
    except BaseException:
        before.close()
        after.close()
        raise


def _label(value, name):
    need(type(value) is str and 2 <= len(value.strip()) <= 160 and value == value.strip()
         and any(c.isalnum() for c in value), name + ": observed semantic row label required")


def validate_review(review, identity, before_sha, after_sha, content_rect, before, after, core):
    """Validate a root-authored review against the exact original image bytes.

    Human interpretation of row labels/start position remains an explicit input.
    This function verifies its identity and pixel displacement; it is not OCR.
    """
    exact_keys(review, REVIEW_KEYS, "semantic review")
    need(review["schema"] == "hepta.main-semantic-scroll-review.v1", "review schema unsupported")
    validate_identity(identity)
    validate_identity(review["identity"])
    need(review["identity"] == identity, "review belongs to a different candidate/task/display/protocol")
    exact_keys(review["captures"], {"before_sha256", "after_sha256"}, "review captures")
    need(review["captures"] == {"before_sha256": before_sha, "after_sha256": after_sha},
         "review capture identities differ")
    need(review["content_rect"] == content_rect, "review crop differs from original observed geometry")
    need(review["reviewer"] == "assistant-root", "independent root visual review required")
    need(type(review["reviewed_at_utc"]) is str and review["reviewed_at_utc"].endswith("Z")
         and "T" in review["reviewed_at_utc"], "UTC visual review timestamp required")

    start = review["scrollable_start"]
    exact_keys(start, {"basis", "direction", "clipped_row_label", "clipped_row_rect", "clip_edge", "independently_reviewed"},
               "scrollable starting point")
    need(start["basis"] == "visible_partial_row_in_requested_direction"
         and start["independently_reviewed"] is True, "observed scrollable starting point required")
    need(start["direction"] in ("up", "down"), "bounded vertical swipe direction required")
    _label(start["clipped_row_label"], "clipped row")
    clipped = rect(start["clipped_row_rect"], content_rect, "clipped row")
    if start["direction"] == "up":
        need(start["clip_edge"] == "bottom" and clipped[3] >= content_rect[3] - 2,
             "upward swipe requires reviewed continuation at the bottom")
    else:
        need(start["clip_edge"] == "top" and clipped[1] <= content_rect[1] + 2,
             "downward swipe requires reviewed continuation at the top")

    anchors = review["anchors"]
    need(type(anchors) is list and 3 <= len(anchors) <= 12, "at least three independently reviewed complete list rows required")
    labels, shifts, previous_before, previous_after, proofs = set(), [], None, None, []
    minimum_motion = max(24, (content_rect[3] - content_rect[1] + 99) // 100)
    for anchor in anchors:
        exact_keys(anchor, {"label", "before_rect", "after_rect", "reviewed_same_list_row"}, "anchor")
        _label(anchor["label"], "anchor")
        need(anchor["label"] not in labels and anchor["reviewed_same_list_row"] is True,
             "unique independently reviewed semantic row labels required")
        labels.add(anchor["label"])
        first = rect(anchor["before_rect"], core, "before anchor")
        second = rect(anchor["after_rect"], core, "after anchor")
        need(first[2] - first[0] >= 48 and first[3] - first[1] >= 12,
             "anchor is too small to identify list text")
        need(first[2] - first[0] == second[2] - second[0]
             and first[3] - first[1] == second[3] - second[1], "complete anchor dimensions differ")
        need(abs(second[0] - first[0]) <= 2, "anchor has unexplained horizontal motion")
        dy = second[1] - first[1]
        need((dy <= -minimum_motion if start["direction"] == "up" else dy >= minimum_motion),
             "semantic anchor did not move in the requested direction")
        if previous_before is not None:
            need(first[1] >= previous_before[3] + 8 and second[1] >= previous_after[3] + 8,
                 "anchors must be separate ordered rows")
        with before.crop(first) as a, after.crop(second) as b:
            a_raw, b_raw = a.tobytes(), b.tobytes()
            need(a_raw == b_raw, "same semantic row pixel identity not reproduced; settled review required")
            colors = Counter(a.getdata())
            need(len(colors) >= 8 and a.width * a.height - colors.most_common(1)[0][1] >= 64,
                 "uniform/decoration-only anchor refused")
            proofs.append({"label": anchor["label"], "before_rect": list(first), "after_rect": list(second),
                           "row_rgba_sha256": sha256(a_raw), "vertical_displacement_px": dy})
        shifts.append(dy)
        previous_before, previous_after = first, second
    need(max(shifts) - min(shifts) <= 2, "semantic row motion is inconsistent")
    first_top = anchors[0]["before_rect"][1]
    last_top = anchors[-1]["before_rect"][1]
    need(last_top - first_top >= (content_rect[3] - content_rect[1]) // 10,
         "anchors do not span distinct list content")
    return proofs


def evaluate(before_raw, after_raw, before_sha, after_sha, content_rect, identity, review=None):
    validate_identity(identity)
    require_sha(before_sha, "before capture")
    require_sha(after_sha, "after capture")
    need(sha256(before_raw) == before_sha and sha256(after_raw) == after_sha,
         "original screenshot bytes differ")
    pixels, before, after = pixel_evidence(before_raw, after_raw, content_rect)
    result = {"schema": "hepta.main-semantic-scroll-content-gate.v1", "identity": identity,
              "captures": {"before_sha256": before_sha, "after_sha256": after_sha}, "pixels": pixels,
              "content_gate_passed": False, "full_phone_qualification": False,
              "continuous_interactivity_verified": False, "phone_operations": 0,
              "original_artifacts_modified": False,
              "parent_inflight_protocol_revalidation_required": True,
              "main_scroll_gate_is_necessary_but_not_sufficient": True}
    try:
        need(pixels["interior_content_changed"], "interior unchanged: decorative/scrollbar-only change cannot establish scroll")
        need(review is not None, "independent semantic anchor and scrollable-start review missing")
        proofs = validate_review(review, identity, before_sha, after_sha, content_rect,
                                 before, after, pixels["core_rect"])
        result.update(content_gate_passed=True, semantic_anchor_proofs=proofs,
                      review_semantics_interpreted_by="assistant-root; original screenshots reviewed independently")
    except ValueError as exc:
        result["rejection"] = str(exc)
    finally:
        before.close()
        after.close()
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("before", "after", "identity", "out"):
        p.add_argument("--" + name, type=Path, required=True)
    for name in ("before-sha256", "after-sha256", "identity-sha256"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--content-rect", nargs=4, type=int, required=True)
    p.add_argument("--review", type=Path)
    p.add_argument("--review-sha256")
    args = p.parse_args()
    need((args.review is None) == (args.review_sha256 is None), "review path and exact hash must be supplied together")
    before_raw = checked_read(args.before, args.before_sha256)
    after_raw = checked_read(args.after, args.after_sha256)
    identity = strict_json(checked_read(args.identity, args.identity_sha256, 16384))
    review = strict_json(checked_read(args.review, args.review_sha256, 65536)) if args.review else None
    result = evaluate(before_raw, after_raw, args.before_sha256, args.after_sha256,
                      args.content_rect, identity, review)
    if args.review:
        result["semantic_review_sha256"] = args.review_sha256
    record = write_new_json(args.out, result)
    print(record)
    return 0 if result["content_gate_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
