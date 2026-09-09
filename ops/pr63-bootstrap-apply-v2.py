#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: apply-v2.py REPOSITORY ORIGINAL_APPLY_SCRIPT")
    repository, original = sys.argv[1:]
    spec = importlib.util.spec_from_file_location("_pr63_bootstrap_apply_v1", original)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load original PR63 bootstrap transformer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = module.BOOTSTRAP_SOURCE
    if not isinstance(source, str) or not source.endswith("\n"):
        raise SystemExit("original bootstrap source has unexpected framing")
    module.BOOTSTRAP_SOURCE = source.rstrip("\n")
    sys.argv = [str(Path(original)), repository]
    return int(module.main())


if __name__ == "__main__":
    raise SystemExit(main())
