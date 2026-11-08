#!/usr/bin/env python3
"""Unprofiled offline microbenchmarks; never an admission or stage-budget test."""

from __future__ import annotations

import json
from pathlib import Path
import platform
import statistics
import sys
import time

from harness import BASE, fixtures, implementations

sys.path.insert(0, str(BASE))
from candidate.root_topology import original_roots_disjoint, candidate_roots_disjoint


def measured(function, argument, iterations):
    wall = time.perf_counter_ns()
    cpu = time.process_time_ns()
    for _ in range(iterations):
        function(argument)
    return {"wall_ns_per_call": (time.perf_counter_ns() - wall) / iterations,
            "cpu_ns_per_call": (time.process_time_ns() - cpu) / iterations}


def summarize(samples):
    return {key: {"median": statistics.median(row[key] for row in samples),
                  "minimum": min(row[key] for row in samples),
                  "maximum": max(row[key] for row in samples)}
            for key in ("wall_ns_per_call", "cpu_ns_per_call")}


def comparison(name, original, candidate, argument, counts, *, rounds=7):
    # Establish equivalence before timing; exclude deepcopy and serialization.
    if original(argument) != candidate(argument):
        raise AssertionError("benchmark input differs: " + name)
    functions = {"original": original, "candidate": candidate}
    samples = {"original": [], "candidate": []}
    for round_index in range(rounds):
        order = ("original", "candidate") if round_index % 2 == 0 else ("candidate", "original")
        for key in order:
            samples[key].append(measured(functions[key], argument, counts[key]))
    summaries = {key: summarize(value) for key, value in samples.items()}
    old = summaries["original"]["wall_ns_per_call"]["median"]
    new = summaries["candidate"]["wall_ns_per_call"]["median"]
    return {"name": name, "rounds": rounds, "iterations_per_sample": counts,
            "samples": samples, "summary": summaries,
            "median_wall_ratio_original_over_candidate": old / new,
            "median_wall_saved_ms_per_call": (old - new) / 1_000_000}


def main():
    if sys.getprofile() is not None or sys.gettrace() is not None:
        raise RuntimeError("benchmarks must run without a Python profiler or trace hook")
    original, candidate = implementations()
    real = fixtures()
    measurements = []
    after = real[-1][1]
    root_cases = [
        ("retained-R9-after-root-overlap-49", after["roots"]),
        ("synthetic-disjoint-64-equal-depth",
         ["/var/lib/owner/state/retained/root-%03d" % i for i in range(64)]),
        ("synthetic-disjoint-64-varied-depth",
         ["/root-%03d" % i + "/part" * i for i in range(64)]),
    ]
    for name, roots in root_cases:
        paths = [Path(name) for name in roots]
        row = comparison(name, original_roots_disjoint, candidate_roots_disjoint, paths,
                         {"original": 3, "candidate": 300})
        row.update({"scope": "pure root non-overlap predicate only", "roots": len(roots),
                    "path_depths": sorted({len(p.parts) for p in paths})})
        measurements.append(row)
    for descriptor, value in real:
        row = comparison(descriptor["name"] + "-complete-inventory_value", original, candidate,
                         value, {"original": 1, "candidate": 1})
        row.update({"scope": "one complete current inventory_value call only",
                    "roots": len(value["roots"]), "entries": len(value["entries"]),
                    "fixture_sha256": descriptor["sha256"]})
        measurements.append(row)
    result = {
        "schema": "hepta.offline.topology-microbenchmark.v1", "state": "MEASURED_OFFLINE",
        "python": sys.version, "platform": platform.platform(), "path_flavour": "POSIX",
        "profiler_enabled": False, "trace_enabled": False,
        "timers": ["time.perf_counter_ns", "time.process_time_ns"],
        "alternating_measurement_order": True, "measurements": measurements,
        "validation_result_cache": False, "historical_readers_executed": False,
        "filesystem_inventory_scanner_executed": False, "phone_calls": 0,
        "runtime_admission": False, "native_case_credit": 0,
        "whole_stage_budget_verified": False,
        "limitation": "Local pure-function timings do not establish total stage runtime, phone performance, or a passed 90-second admission budget.",
    }
    path = BASE / "reports/benchmark-results.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(result, sort_keys=True, ensure_ascii=False, indent=2) + "\n")
    for row in measurements:
        print(json.dumps({"name": row["name"],
              "original_median_ms": row["summary"]["original"]["wall_ns_per_call"]["median"] / 1e6,
              "candidate_median_ms": row["summary"]["candidate"]["wall_ns_per_call"]["median"] / 1e6,
              "ratio": row["median_wall_ratio_original_over_candidate"]}, sort_keys=True))


if __name__ == "__main__":
    main()
