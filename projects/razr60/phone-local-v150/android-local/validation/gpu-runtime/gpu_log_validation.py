"""Independent GPU log predicate. It never changes frozen App source or old receipts."""
from __future__ import annotations

import re

SCHEMA = "hepta.gpuopencl-log-validation.v1"
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def accelerator_log_evidence(log):
    """Require actual GPUOpenCL selection, positive OpenCL model allocation, and offload.

    OpenCL is a *buffer label alias*, not an alternative selected backend. Native
    request/device/output binding must still be validated by the calling driver.
    Enumeration, KV-only allocation, generic GPU strings and zero buffers do not pass.
    """
    if not isinstance(log, str) or len(log.encode("utf-8")) > 2 * 1024 * 1024:
        raise ValueError("bounded UTF-8 native stderr required")
    lines = [ANSI.sub("", line).strip() for line in log.splitlines()]
    selection = [line for line in lines if re.search(r"\bUsing\s+\d+\s+device\(s\):", line)]
    selection_valid = bool(selection) and all(re.search(r"\bUsing\s+1\s+device\(s\):\s*GPUOpenCL\s*$", line) for line in selection)
    prepared = [line for line in lines if re.search(r"\bllama_prepare_model_devices:\s+using device GPUOpenCL\s+\(", line)]
    buffer_rows = []
    for line in lines:
        match = re.search(r"\bload_tensors:\s+(OpenCL|GPUOpenCL)\s+model buffer size\s*=\s*([0-9]+(?:\.[0-9]+)?)\s*(MiB|MB|GiB|bytes)\s*$", line)
        if match:
            buffer_rows.append({"label": match.group(1), "size": float(match.group(2)), "unit": match.group(3), "line": line})
    offload_rows = []
    for line in lines:
        match = re.search(r"\bload_tensors:\s+offloaded\s+(\d+)(?:/(\d+))?\s+layers\s+to GPU\s*$", line)
        if match:
            loaded, total = int(match.group(1)), int(match.group(2)) if match.group(2) else None
            if total is not None and loaded > total:
                continue
            offload_rows.append({"layers": loaded, "total": total, "line": line})
    positive = any(row["size"] > 0 for row in buffer_rows)
    offloaded = max((row["layers"] for row in offload_rows), default=0)
    return {"schema": SCHEMA, "device": "GPUOpenCL", "selected_device_lines": selection,
            "selected_device_verified": selection_valid, "model_device_lines": prepared,
            "model_buffer_lines": [row["line"] for row in buffer_rows], "model_buffer_allocations": buffer_rows,
            "accepted_buffer_labels": ["GPUOpenCL", "OpenCL"], "positive_model_buffer": positive,
            "offloaded_layers_observed": offloaded, "offload_lines": [row["line"] for row in offload_rows],
            "accelerator_offload_observed": bool(selection_valid and prepared and positive and offloaded > 0),
            "fallback_lines": [line for line in lines if "fallback" in line.lower() or "unsupported" in line.lower()],
            "warning_lines": [line for line in lines if re.search(r"\[\s*WARN(?:ING)?\]", line, re.I)],
            "native_identity_binding_required_separately": True,
            "full_operator_coverage_proven": False, "utilization_or_power_measured": False}


def install_for_new_run(acceptance):
    """Explicit in-memory policy for a NEW independently frozen validation run.

    This is not used by offline review and never writes into the pinned driver directory.
    The caller must record this module's SHA and retain the original native/UI/action gates.
    """
    previous = acceptance.accelerator_log_evidence
    if getattr(previous, "hepta_gpu_alias_policy", False):
        raise ValueError("GPU validation override already installed")
    def checked(log, compute):
        return accelerator_log_evidence(log) if compute == "gpu" else previous(log, compute)
    checked.hepta_gpu_alias_policy = True
    acceptance.accelerator_log_evidence = checked
    return {"schema": SCHEMA, "changed_compute": "gpu", "npu_predicate_unchanged": True,
            "native_receipt_gates_unchanged": True, "phone_goal_gates_unchanged": True}
