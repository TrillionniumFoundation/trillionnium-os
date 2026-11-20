#!/usr/bin/env python3
"""Host-only exact-pixel comparison on a retained PNG; never connects to a phone."""
import argparse
import hashlib
import json
from pathlib import Path
import time

import lifecycle_guards as guards
import phone_lifecycle as lifecycle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.image.expanduser().resolve(strict=True)
    raw = source.read_bytes()
    image = guards.png_extract(raw)
    rectangle = [0, 0, image["width"], min(1100, image["height"])]
    begin = time.perf_counter()
    fast = guards.png_roi(image, rectangle)
    after_fast = time.perf_counter()
    cached = guards.png_roi(image, rectangle)
    after_cached = time.perf_counter()
    portable = guards.png_roi(image, rectangle, portable=True)
    after_portable = time.perf_counter()
    if "_lifecycle_roi_pixels" not in image:
        raise RuntimeError("Pillow acceleration must be present for this qualification")
    if fast != portable or cached != portable:
        raise RuntimeError("fast/cached/portable pixel identity differs")
    out = args.output.expanduser().resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    probe = lifecycle.Probe.__new__(lifecycle.Probe)
    probe.out = out
    fresh = guards.png_extract(raw)
    before_preview = time.perf_counter()
    preview = probe.stop_preview(fresh)
    after_preview = time.perf_counter()
    if preview.get("exact_pixels_verified") is not True:
        raise RuntimeError("lossless preview qualification is unavailable")
    from PIL import Image
    report = {"schema": "hepta.exact-png-roi-benchmark.v1", "phone_contacted": False,
              "source_modified": False, "source_sha256": hashlib.sha256(raw).hexdigest(),
              "source_bytes": len(raw), "width": image["width"], "height": image["height"],
              "channels": image["channels"], "region": rectangle, "pillow_version": Image.__version__,
              "fast_cold_ms": (after_fast - begin) * 1000,
              "fast_cached_ms": (after_cached - after_fast) * 1000,
              "portable_ms": (after_portable - after_cached) * 1000,
              "preview_cold_total_ms": (after_preview - before_preview) * 1000,
              "exact_region_sha256": fast, "all_pixel_hashes_equal": True,
              "preview": preview, "device_cancellation": "not_assessed"}
    lifecycle.write(out / "report.json", report, exclusive=True)
    print(json.dumps(report))


if __name__ == "__main__":
    main()
