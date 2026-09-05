#!/usr/bin/env python3
"""Preload placeholder module identities used by importlib-based test fixtures.

`dataclasses` resolves postponed annotations through `sys.modules` while a
module is executing. Some tests load source files with `module_from_spec` so the
placeholder must exist before those files are executed. The actual fixture
module object still supplies all tested definitions; this file only makes the
standard-library annotation lookup deterministic under `unittest discover`.
"""

from __future__ import annotations

import sys
import types
import unittest


for name in (
    "owner_open_jsonl_provider_runtime",
):
    sys.modules.setdefault(name, types.ModuleType(name))


class ImportBootstrapTest(unittest.TestCase):
    def test_placeholder_identity_is_registered(self) -> None:
        self.assertIn("owner_open_jsonl_provider_runtime", sys.modules)


if __name__ == "__main__":
    unittest.main()
