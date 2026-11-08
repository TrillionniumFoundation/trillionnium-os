"""UNADOPTED offline constructor binding actual selector bytes to its receipt."""

from __future__ import annotations

import hashlib
import types


SELECTOR_PIN = {"bytes": 11956,
    "sha256": "de7dc784654dec65f0e6d2d7fd81918caf9c3c634d152295c1fb7928cf04a5c2"}


def make_selector(*, selector_source, implementation_source, inventory_function, scope_function):
    if type(selector_source) is not bytes or {
            "bytes": len(selector_source), "sha256": hashlib.sha256(selector_source).hexdigest()} != SELECTOR_PIN:
        raise ValueError("actual selector bytes must match the independently pinned implementation")
    if type(implementation_source) is not bytes or implementation_source != selector_source:
        raise ValueError("declared implementation source must be the exact bytes loaded as selector code")
    module = types.ModuleType("UNADOPTED_bound_reader_selector")
    module.__file__ = "<UNADOPTED_bound_reader_selector:sha256=" + SELECTOR_PIN["sha256"] + ">"
    exec(compile(selector_source, module.__file__, "exec"), module.__dict__)
    result = module.OfflineDerivedSelector(inventory_function=inventory_function,
        scope_function=scope_function, implementation_source=selector_source)
    if result.receipt()["selector_source"] != SELECTOR_PIN:
        raise ValueError("selector construction receipt must identify its actual compiled source bytes")
    return result
