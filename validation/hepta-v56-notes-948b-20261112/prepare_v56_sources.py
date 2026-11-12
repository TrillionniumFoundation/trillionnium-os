#!/usr/bin/env python3
"""Freeze all original verifier bytes and two identity-independent v56 changes.

This script is host-only. It creates no phone entry point and cannot seal an APK.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

from offline_common import checked_read, need, sha256, strict_json, write_new_json

BASELINE_PIN = "8b582ce9ecf1f64fd6c968570465abf19ea87620d94bf68657b8e32e705df9c8"
MAIN_PIN = "4aa6e0f8db9229e1764d9ee79220ed8fa3eb7ddc3bd5526a857fd179870afe30"
WORKFLOW_PIN = "1188e4ad4666614cfce38d0f74b60819dd2c0e32ebf9cac6cdbd74bcf649791e"
IDLE_PIN = "285f6575f5dc1eaaaff61b591cd8e0171e250ea0799a196ba298bd1cad6478db"

CONTENT_FUNCTION = '''
def nondecorative_content_change(h, before_raw, after_raw, content_rect):
    """Necessary pixel gate only; semantic scroll still requires original-image review."""
    need(type(content_rect) is list and len(content_rect)==4
         and all(type(x) is int for x in content_rect),'integer observed content geometry required')
    with h.png_rgba(before_raw) as left, h.png_rgba(after_raw) as right:
        need(left.size==right.size,'main original image dimensions changed')
        x0,y0,x1,y1=content_rect
        need(0<=x0<x1<=left.width and 0<=y0<y1<=left.height
             and x1-x0>=200 and y1-y0>=400,'observed content geometry outside main image')
        gutter=max(16,(x1-x0+49)//50)
        interior=[x0+gutter,y0,x1-gutter,y1]
        with left.crop(interior) as a,right.crop(interior) as b:
            a_raw,b_raw=a.tobytes(),b.tobytes()
        return {'schema':'hepta.main-interior-content-change.v1',
            'before_png_sha256':h.digest(before_raw),'after_png_sha256':h.digest(after_raw),
            'content_rect':content_rect,'interior_rect':interior,'fixed_side_gutter_px':gutter,
            'before_interior_rgba_sha256':h.digest(a_raw),'after_interior_rgba_sha256':h.digest(b_raw),
            'interior_content_changed':a_raw!=b_raw,
            'semantic_scroll_verified':False,'independent_semantic_review_required':True}

'''


def replace_once(source, old, new, label):
    need(source.count(old) == 1, "exact change cardinality differs: " + label)
    return source.replace(old, new)


def main_source(raw):
    source = raw.decode("utf-8")
    source = replace_once(source, "\ndef verdict(", CONTENT_FUNCTION + "\ndef verdict(", "new necessary pixel gate")
    source = replace_once(source,
        "input_commands_bound=False;pixels_bound=False",
        "input_commands_bound=False;pixels_bound=False;interior_bound=False;interior_proof=None",
        "independent interior state")
    source = replace_once(source,
        "            and record.get('application_pixels_changed') is True)\n",
        "            and record.get('application_pixels_changed') is True)\n"
        "        interior_proof=nondecorative_content_change(h,\n"
        "            h.checked_file(args.out/'main-user'/'settings-before-swipe.png',16<<20),\n"
        "            h.checked_file(args.out/'main-user'/'settings-after-swipe.png',16<<20),\n"
        "            before_surface['geometry']['content_rect'])\n"
        "        need(interior_proof['before_png_sha256']==before_surface['png_sha256']\n"
        "             and interior_proof['after_png_sha256']==after_surface['png_sha256'],\n"
        "             'interior evidence is not bound to the original command-bound images')\n"
        "        interior_bound=pixels_bound and interior_proof['interior_content_changed'] is True\n",
        "raw-bound interior comparison")
    source = replace_once(source,
        "'main_user_actions_completed':record.get('completed') is True,'settings_application_pixels_changed':pixels_bound}",
        "'main_user_actions_completed':record.get('completed') is True,'settings_application_pixels_changed':pixels_bound,\n"
        "        'settings_non_decorative_content_changed':interior_bound}",
        "ninth additional necessary check")
    source = replace_once(source,
        "'machine_checks_passed':all(checks.values()),'qualified':False,'visual_scroll_reviewed':False,",
        "'machine_checks_passed':all(checks.values()),'qualified':False,'visual_scroll_reviewed':False,\n"
        "        'interior_content_proof':interior_proof,'effective_list_scroll_verified':False,\n"
        "        'continuous_interactivity_verified':False,'semantic_anchor_review_required':True,",
        "explicit remaining semantic scope")
    compile(source, "v56-main-user-source-check", "exec")
    return source.encode("utf-8")


def write_bytes(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    need(all(not p.is_symlink() for p in (path, *path.parents)), "output link refused")
    with path.open("xb") as f:
        f.write(raw)
    need(path.read_bytes() == raw, "source readback differs")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    need(args.root.is_absolute() and args.out.is_absolute() and not args.out.exists()
         and args.out.parent.is_dir() and all(not q.is_symlink() for q in args.out.parents), "new isolated output required")
    baseline = strict_json(checked_read(args.root / "BASELINE-CLOSURE.json", BASELINE_PIN))
    originals = {}
    for item in baseline["original_files"]:
        path = args.root / "base" / item["file"]
        if not item["complete_original_bytes_present"]:
            path = args.root / "retrieved-six-r1" / item["file"]
        raw = checked_read(path, item["expected_sha256"])
        need(len(raw) == item["expected_bytes"], "original size differs")
        originals[item["file"]] = raw
    need(len(originals) == 14, "complete original 14-file collector/replay closure required")
    reviewed = {name: checked_read(args.root / "reviewed-v54-replay" / name, pin)
                for name, pin in [
                    ("main_user_inflight.py", MAIN_PIN),
                    ("controller_workflow_evidence.py", WORKFLOW_PIN),
                    ("controller_idle_evidence.py", IDLE_PIN)]}
    plan_before = originals["background_notes_plan.py"]
    plan_after = plan_before.decode("utf-8").replace("v54", "v56").encode("utf-8")
    need(plan_after != plan_before and b"v54" not in plan_after and b"Hepta-v56r1-" in plan_after,
         "version-stamped exact comma plan derivation missing")
    compile(plan_after, "v56-plan-source-check", "exec")
    main_after = main_source(reviewed["main_user_inflight.py"])
    args.out.mkdir(mode=0o700)
    for name, raw in originals.items():
        write_bytes(args.out / "originals" / name, raw)
    for name, raw in reviewed.items():
        write_bytes(args.out / "reviewed-v54-replay" / name, raw)
    write_bytes(args.out / "identity-independent" / "background_notes_plan.py", plan_after)
    write_bytes(args.out / "identity-independent" / "main_user_inflight.py", main_after)
    changes = []
    for name, before, after in [
            ("background_notes_plan.py", plan_before, plan_after),
            ("main_user_inflight.py", reviewed["main_user_inflight.py"], main_after)]:
        delta = "".join(difflib.unified_diff(before.decode().splitlines(True), after.decode().splitlines(True),
                                           fromfile="original/" + name, tofile="v56/" + name))
        write_bytes(args.out / "diffs" / (name + ".diff"), delta.encode())
        changes.append({"file": name, "before_sha256": sha256(before), "after_sha256": sha256(after),
                        "bytes": len(after)})
    result = {"schema": "hepta.notes-v56-identity-independent-source-preparation.v1",
              "original_collector_replay_file_count": 14,
              "ordinary_prepare_external_prerequisites": "unchanged exact UI_SHA/R12_SHA/r7 prerequisites are still mandatory at actual prepare",
              "originals": [{"file": n, "bytes": len(b), "sha256": sha256(b)} for n, b in sorted(originals.items())],
              "reviewed_replay_sources": [{"file": n, "bytes": len(b), "sha256": sha256(b)} for n, b in sorted(reviewed.items())],
              "changes": changes, "phone_actions": 0, "phone_entry_point_generated": False,
              "requires_final_candidate_and_actual_signed_receipt": True}
    print(write_new_json(args.out / "SOURCE-STAGE-RESULT.json", result))


if __name__ == "__main__":
    main()
