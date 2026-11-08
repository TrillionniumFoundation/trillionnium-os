"""UNADOPTED offline selector for explicitly derived retained pure readers.

Original bytes are verified before derivation.  New modules receive their own
source identity and fresh globals; no original module is monkeypatched.  This
does not implement production adoption or a source-parent boundary reader.
"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import re
import stat
import types


PINS = {
    "r9-reader": {"bytes": 34650, "sha256": "919d508899f405a5942766ad5d9adf0bfa0600aa0bc2e51552a835b5a8c7fbd3"},
    "r9-scope": {"bytes": 37788, "sha256": "f59bae34d9acc80d2c28cd5636b53e13b68d911d2121735883dc7b001e57779f"},
    "r8-reader": {"bytes": 96088, "sha256": "614f44d6eb75f47b02e32b463f18534e2d0bc5a3e8fd928535e7da17909679ae"},
    "r8-scope": {"bytes": 21865, "sha256": "937a34f4ba752e14bb78b1566c672e89b2e26502392d8d2a3561a52ceb88af38"},
    "r7-reader": {"bytes": 37404, "sha256": "5935f4d4b3f00d914c6e0f9aec4429cf424a0601685061fe9277de3df5403b21"},
}
INVENTORY_SOURCES = {
    "r7-readers": {"bytes": 181669, "sha256": "0a9f52cf8fb71177d0816f561cce279811a7182e986c12912d9431bde5997cda"},
    "r8-payload": {"bytes": 218894, "sha256": "9adcd6a865875f209bf56cfadc952b40cf4984889cb3450837446b6b95dcbd54"},
    "r9-scope": {"bytes": 218894, "sha256": "9adcd6a865875f209bf56cfadc952b40cf4984889cb3450837446b6b95dcbd54"},
    "source-parent-inventory-only": {"bytes": 153138, "sha256": "27350db238c5ca31796af91c77b5c2fdb9d02b838d35140f759df907903d4fa4"},
    "current-inventory-only": {"bytes": 259866, "sha256": "f9a19df8a2a1d8b6a09a8c75eec118f4304ad1db5f40fc005fd7d59fb02837b7"},
}
ORIGINAL_INVENTORY_FUNCTION = {"bytes": 3788, "sha256": "086dedcdc7ac8d1627e1c2592ed7a9f130a4395dd4b27e9bc86a512c91af06f1"}
DERIVED_INVENTORY_FUNCTION = {"bytes": 3827, "sha256": "0356d2bd56da36267a72bfb732125eb8807dc6ff32c47789ba8cbc1b523e7f51"}
ORIGINAL_SCOPE_FUNCTION = {"bytes": 8083, "sha256": "798ffcd349da388ba6985b0b5e9a34beb436656aed300d3980280cea100d64a6"}
DERIVED_SCOPE_FUNCTION = {"bytes": 8369, "sha256": "51bd57dffe1a2beca21a3d01288477030f61988daa3d294fdf8d371ade6c9f89"}
DERIVED_SCOPE_SOURCE = {"bytes": 22151, "sha256": "520f0f9a1eab1de60a165908536c03559f3bc49214a3e74b4c5d9036197619ed"}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def pin(raw):
    need(type(raw) is bytes, "selector source must be exact bytes")
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def function_source(raw, name):
    text = raw.decode("utf-8")
    nodes = [n for n in ast.parse(text).body if isinstance(n, ast.FunctionDef) and n.name == name]
    need(len(nodes) == 1, "selector requires one exact function: " + name)
    n = nodes[0]
    return ("\n".join(text.splitlines()[n.lineno - 1:n.end_lineno]) + "\n").encode()


def derive(raw, replacements):
    current = raw
    for label, old, new in replacements:
        old = old.encode() if isinstance(old, str) else old
        new = new.encode() if isinstance(new, str) else new
        need(current.count(old) == 1 and new not in current, "one explicit selector site: " + label)
        current = current.replace(old, new, 1)
    reverse = current
    for label, old, new in reversed(replacements):
        old = old.encode() if isinstance(old, str) else old
        new = new.encode() if isinstance(new, str) else new
        need(reverse.count(new) == 1, "one inverse selector site: " + label)
        reverse = reverse.replace(new, old, 1)
    need(reverse == raw, "whole source inverse must recover every original byte")
    return current


class OfflineDerivedSelector:
    def __init__(self, *, inventory_function, scope_function, implementation_source):
        need(pin(inventory_function) == DERIVED_INVENTORY_FUNCTION,
             "fixed separately identified inventory candidate")
        need(pin(scope_function) == DERIVED_SCOPE_FUNCTION,
             "fixed separately identified scope candidate")
        self.inventory_function_bytes = inventory_function
        self.scope_function_bytes = scope_function
        self.implementation_identity = pin(implementation_source)
        # This is source-construction provenance only, never a PASS/result cache.
        self.constructions = []

    def _module(self, kind, original, derived, sites):
        need(pin(original) == PINS[kind], "exact reference source before module construction: " + kind)
        identity = pin(derived)
        need(identity != pin(original), "derived implementation must have a distinct identity")
        name = "UNADOPTED_derived_" + kind.replace("-", "_")
        result = types.ModuleType(name)
        result.__file__ = "<" + name + ":sha256=" + identity["sha256"] + ">"
        result.__derived_selector__ = self
        result.__reference_source_identity__ = dict(PINS[kind])
        result.__derived_implementation_identity__ = identity
        exec(compile(derived, result.__file__, "exec"), result.__dict__)
        self.constructions.append({"kind": kind, "original_source": pin(original),
            "derived_source": identity, "transformation_sites": list(sites),
            "fresh_module_globals": True, "module_name": result.__name__,
            "module_file": result.__file__, "original_module_mutated": False,
            "reference_source_bytes_changed": False, "whole_byte_inverse_verified": True})
        return result

    def inventory_function(self, source, *, namespace, context):
        need(context in INVENTORY_SOURCES and pin(source) == INVENTORY_SOURCES[context],
             "exact original inventory source for declared selector context")
        original = function_source(source, "inventory_value")
        need(pin(original) == ORIGINAL_INVENTORY_FUNCTION,
             "exact original inventory function before selecting derived code")
        need(set(namespace) == {"C", "Path", "re", "stat"}
             and namespace["Path"] is Path and namespace["re"] is re and namespace["stat"] is stat,
             "same explicit pure inventory binding names and POSIX standard library objects")
        selected = dict(namespace)
        filename = "<UNADOPTED-derived-inventory:" + DERIVED_INVENTORY_FUNCTION["sha256"] + ">"
        exec(compile(self.inventory_function_bytes, filename, "exec"), selected)
        function = selected["inventory_value"]
        need(function.__globals__ is selected and function.__globals__ is not namespace,
             "derived inventory has fresh globals without replacing an original function")
        self.constructions.append({"kind": "inventory-function", "context": context,
            "original_source": pin(source), "original_function": pin(original),
            "derived_function": dict(DERIVED_INVENTORY_FUNCTION),
            "original_module_mutated": False, "fresh_function_globals": True,
            "namespace_bindings": sorted(namespace), "validation_result_cache": False})
        return function

    def r7_reader(self, source):
        need(pin(source) == PINS["r7-reader"], "exact original R7 reader")
        changes = [("inventory-selection",
            "    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<exact R7 inventory reader>','exec'),namespace)\n",
            "    namespace['inventory_value']=__derived_selector__.inventory_function(\n"
            "        raw['source_late'],namespace=namespace,context='r7-readers')\n")]
        return self._module("r7-reader", source, derive(source, changes), [r[0] for r in changes])

    def r8_scope(self, source):
        need(pin(source) == PINS["r8-scope"], "exact embedded original R8 scope")
        old = function_source(source, "verify_complete_scope")
        need(pin(old) == ORIGINAL_SCOPE_FUNCTION, "exact original complete scope function")
        changes = [("old-root-child-membership", old, self.scope_function_bytes)]
        derived = derive(source, changes)
        need(pin(derived) == DERIVED_SCOPE_SOURCE, "fixed complete derived scope identity")
        return self._module("r8-scope", source, derived, [r[0] for r in changes])

    def r8_reader(self, source):
        need(pin(source) == PINS["r8-reader"], "exact original R8 reader")
        changes = [
            ("scope-selection-after-original-pin",
             "    module=types.ModuleType('retained_r8_'+name)\n",
             "    if name=='scope':\n"
             "        return __derived_selector__.r8_scope(source)\n"
             "    module=types.ModuleType('retained_r8_'+name)\n"),
            ("r7-reader-selection-after-original-pin",
             "    r7=types.ModuleType('retained_r8_exact_r7')\n"
             "    exec(compile(raw['r7_reader'],'<same accepted R7 original reader>','exec'),r7.__dict__)\n",
             "    r7=__derived_selector__.r7_reader(raw['r7_reader'])\n"),
            ("inventory-selection-after-original-source-check",
             "    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<unchanged actual R8 inventory reader>','exec'),ns)\n"
             "    inventory_reader=ns['inventory_value']\n",
             "    inventory_reader=__derived_selector__.inventory_function(\n"
             "        late_source,namespace=ns,context='r8-payload')\n"),
        ]
        return self._module("r8-reader", source, derive(source, changes), [r[0] for r in changes])

    def r9_scope(self, source):
        need(pin(source) == PINS["r9-scope"], "exact original R9 scope source")
        changes = [
            ("explicit-validator-provenance-comment",
             "    # Load only original pure inventory/stat validators from exact observed source bytes.\n",
             "    # Verify original pure sources, then select a separately identified derived inventory validator.\n"),
            ("inventory-selection-after-original-source-pins",
             "    exec(compile(function(raw['library_late'],'inventory_value'),'<original-inventory-value>','exec'),invns)\n"
             "    inventory_value=invns['inventory_value']\n",
             "    inventory_value=__derived_selector__.inventory_function(\n"
             "        raw['library_late'],namespace=invns,context='r9-scope')\n"),
        ]
        return self._module("r9-scope", source, derive(source, changes), [r[0] for r in changes])

    def r9_reader(self, source):
        need(pin(source) == PINS["r9-reader"], "exact original R9 reader")
        changes = [
            ("scope-selection-after-archive-member-pins",
             "    def load(name,source):\n"
             "        module=types.ModuleType(name);module.__file__='<retained-r9-'+name+'>'\n",
             "    def load(name,source):\n"
             "        if name=='scope':\n"
             "            return __derived_selector__.r9_scope(source)\n"
             "        module=types.ModuleType(name);module.__file__='<retained-r9-'+name+'>'\n"),
            ("r8-selection-after-read-exact",
             "    prior_reader=load('exact_old_r8_reader',read_exact(R8_READER))\n",
             "    prior_reader=__derived_selector__.r8_reader(read_exact(R8_READER))\n"),
        ]
        return self._module("r9-reader", source, derive(source, changes), [r[0] for r in changes])

    def receipt(self):
        return {"schema": "hepta.UNADOPTED.derived-reader-construction.v1",
            "selector_source": dict(self.implementation_identity),
            "constructions": [dict(row) for row in self.constructions],
            "source_construction_only": True, "validation_result_cache": False,
            "live_observation_cache": False, "original_module_globals_reassigned": False,
            "original_source_bytes_changed": False,
            "new_validator_implementation_identity": True,
            "production_selector_adopted": False, "production_policy_status": "HOLD",
            "source_parent_boundary_reader_status": "HOLD_REQUIRES_NEW_PROVENANCE_POLICY",
            "runtime_admission": False, "native_case_credit": 0,
            "whole_stage_budget_verified": False}
