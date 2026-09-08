#!/usr/bin/env python3
"""Stable CLI facade for bounded Host/Core reproducibility builds.

The build recipe and report implementation remain byte-identical in the private
core. This facade makes every Cargo build use the same retained SID/PGID anchor
and bounded whole-session cleanup already exercised by the product baseline.
A leader exit is therefore never interpreted as proof that descendants released
inherited logs, cache handles or target locks.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time
from typing import Any


HERE = Path(__file__).resolve().parent
CORE_PATH = HERE / "_verify_host_reproducibility_core.py"
CLEANUP_PATH = HERE.parent / "perf/run_product_baseline.py"


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - import machinery
        raise RuntimeError(f"cannot load {name}: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


CORE = _load("_verify_host_reproducibility_core", CORE_PATH)
CLEANUP = _load("_host_reproducibility_process_cleanup", CLEANUP_PATH)
# The report must bind the behavior-bearing public facade, not only its private
# recipe core.
CORE.__file__ = str(Path(__file__).resolve())


def run_build(
    command: list[str],
    env: dict[str, str],
    repo: Path,
    log: Path,
    timeout: int,
) -> dict[str, Any]:
    started = time.monotonic()
    process = CLEANUP.OwnedSessionPopen(
        command,
        cwd=repo,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    count = 0
    digest = hashlib.sha256()
    primary_error: BaseException | None = None
    try:
        assert process.stdout
        with log.open("xb") as output, selectors.DefaultSelector() as selector:
            os.chmod(log, 0o600)
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                CORE.require(
                    time.monotonic() - started < timeout,
                    "Cargo build exceeded timeout",
                )
                for key, _ in selector.select(0.1):
                    block = os.read(key.fileobj.fileno(), 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    count += len(block)
                    CORE.require(
                        count <= CORE.MAX_LOG_BYTES,
                        "Cargo build log exceeded byte bound",
                    )
                    output.write(block)
                    digest.update(block)
            output.flush()
            os.fsync(output.fileno())
        remaining = timeout - (time.monotonic() - started)
        CORE.require(remaining > 0, "Cargo did not finish before deadline")
        code = process.wait(timeout=remaining)
        return {
            "exit_code": code,
            "elapsed_seconds": time.monotonic() - started,
            "log": {
                "path": str(log),
                "bytes": count,
                "sha256": digest.hexdigest(),
            },
        }
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            CLEANUP.stop(process)
        except BaseException as cleanup_error:
            if primary_error is None:
                raise
            raise CORE.VerificationError(
                f"{primary_error}; process-group cleanup failed: {cleanup_error}"
            ) from primary_error


CORE.run_build = run_build

for _name in dir(CORE):
    if not _name.startswith("__") and _name != "run_build":
        globals()[_name] = getattr(CORE, _name)


if __name__ == "__main__":
    raise SystemExit(CORE.main())
