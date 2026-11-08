#!/usr/bin/env python3
"""Reuse the frozen value corpus, compare Python GBNF with C++ and JSON values.

The C++ executable and the test-only GBNF recognizer are independent oracles.
This suite uses public synthetic schemas. It does not access a phone or model.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CPP = ROOT.parent / "schema-grammar-r1"
sys.path[:0] = [str(ROOT), str(CPP), str(CPP / "tests")]
import python_schema_grammar as candidate
import convert_schema as cpp
import test_converter as corpus
from gbnf_recognizer import Recognizer

SOURCE = Path(candidate.__file__)
SOURCE_SHA = hashlib.sha256(SOURCE.read_bytes()).hexdigest()


def candidate_adapter(raw, **_oracle_interface_arguments):
    # Only adapts the existing test-corpus call sites. Production API is the
    # single compiler_source_sha256 keyword; it has no executable parameters.
    return candidate.convert_schema(raw, compiler_source_sha256=SOURCE_SHA)


corpus.convert_schema = candidate_adapter


class PythonConverterTests(corpus.ConverterTests):
    test_static_elf_has_no_interpreter_or_needed = None
    test_private_cli_preserves_original_and_never_overwrites = None
    test_original_bytes_executable_and_grammar_bound = None

    @classmethod
    def setUpClass(cls):
        cls.exe = Path(os.environ["HEPTA_SCHEMA_CONVERTER"]).resolve()
        cls.exe_sha = cpp.sha(cls.exe.read_bytes())
        cls.schema, cls.no_image = corpus.schema_fixture(True), corpus.schema_fixture(False)
        cls.grammar, cls.proof = candidate_adapter(corpus.encoded(cls.schema))
        cls.recognizer = Recognizer(cls.grammar)
        cls.no_image_recognizer = Recognizer(candidate_adapter(corpus.encoded(cls.no_image))[0])
        cls.by_action, cls.oracles = {}, {}
        for item in cls.schema["oneOf"]:
            action = item["properties"]["arguments"]["properties"]["action"]["const"]
            cls.by_action.setdefault(action, []).append(item)

    def oracle(self, schema):
        key = id(schema)
        if key not in self.oracles:
            grammar, _ = cpp.convert_schema(corpus.encoded(schema), executable=self.exe,
                                            executable_sha256=self.exe_sha)
            self.oracles[key] = (schema, Recognizer(grammar))
        return self.oracles[key][1]

    def differential(self, value, expected, schema=None, recognizer=None):
        schema = self.schema if schema is None else schema
        super().differential(value, expected, schema, recognizer)
        self.assertEqual(self.oracle(schema).accepts(corpus.encoded(value)), expected,
                         "independent C++ grammar disagrees: " + repr(value)[:160])

    def reject_schema(self, schema):
        with self.assertRaises((ValueError, UnicodeError, KeyError, TypeError)):
            candidate_adapter(corpus.encoded(schema))
        # The original executable receives identical complete input bytes.
        result = subprocess.run([str(self.exe)], input=corpus.encoded(schema),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
        self.assertEqual(result.returncode, 65)
        self.assertEqual(result.stdout, b"")
        corpus.STATS["schema_rejections"] += 1

    def test_duplicate_schema_keys_and_size_fail_before_output(self):
        raw = corpus.encoded(self.schema)
        for bad in (b'{"oneOf":[],' + raw[1:], b" " * 65537, b'{"oneOf":', b"\xff",
                    b'NaN', b'Infinity', b'{"oneOf":NaN}', b'{"oneOf":1e999}'):
            with self.assertRaises((ValueError, UnicodeError)):
                candidate_adapter(bad)

    def test_truthful_proof_original_bytes_and_fixed_source(self):
        raw = b"\n " + corpus.encoded(self.no_image) + b"\n"
        grammar, proof = candidate_adapter(raw)
        self.assertEqual(proof["original_schema_bytes"], len(raw))
        self.assertEqual(proof["original_schema_sha256"], cpp.sha(raw))
        self.assertEqual(proof["grammar_sha256"], cpp.sha(grammar))
        self.assertEqual(proof["grammar_bytes"], len(grammar))
        self.assertEqual(proof["compiler_source_sha256"], SOURCE_SHA)
        self.assertEqual(proof["compiler_kind"], "reviewed_python_source")
        self.assertTrue(proof["input_bytes_preserved"] and proof["conversion_completed"])
        self.assertFalse(proof["model_loaded"] or proof["native_action_authorized"] or proof["production_receipt"])
        self.assertFalse(set(proof) & {"returncode", "child_waited", "executable_elf", "converter_sha256"})
        with self.assertRaises(ValueError):
            candidate.convert_schema(raw, compiler_source_sha256="0" * 64)
        with self.assertRaises(TypeError):
            candidate.convert_schema(raw, executable=str(self.exe), executable_sha256=self.exe_sha)

    def test_source_file_mode_link_and_byte_binding(self):
        source_bytes = SOURCE.read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            path = folder / "schema_grammar.py"
            path.write_bytes(source_bytes)
            path.chmod(0o600)
            spec = importlib.util.spec_from_file_location("private_fixture_compiler", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            raw = corpus.encoded(self.no_image)
            self.assertEqual(module.convert_schema(raw, compiler_source_sha256=SOURCE_SHA)[0],
                             candidate_adapter(raw)[0])
            path.chmod(0o622)
            with self.assertRaises(ValueError):
                module.convert_schema(raw, compiler_source_sha256=SOURCE_SHA)
            path.chmod(0o600)
            path.write_bytes(source_bytes + b"\n")
            with self.assertRaises(ValueError):
                module.convert_schema(raw, compiler_source_sha256=SOURCE_SHA)
            path.unlink()
            path.symlink_to(SOURCE)
            with self.assertRaises(OSError):
                module.convert_schema(raw, compiler_source_sha256=SOURCE_SHA)

    def test_all_ascii_and_scalar_boundaries(self):
        schema = {"oneOf": [copy.deepcopy(self.by_action["read_text_anchor"][0])]}
        schema["oneOf"][0]["properties"]["arguments"]["properties"]["anchor_text"]["maxLength"] = 1
        recognizer = Recognizer(candidate_adapter(corpus.encoded(schema))[0])
        value = corpus.sample(schema["oneOf"][0])
        for point in list(range(128)) + [0xD7FF, 0xE000, 0xFFFF, 0x10000, 0x10FFFF]:
            value["arguments"]["anchor_text"] = chr(point)
            self.differential(value, True, schema, recognizer)
        template = corpus.encoded(value).decode().replace(chr(0x10FFFF), "INSERT")
        for point in range(0xD800, 0xE000):
            escaped = template.replace("INSERT", "\\u%04x" % point)
            self.assertFalse(recognizer.accepts(escaped))
            self.assertFalse(self.oracle(schema).accepts(escaped))

    def test_literal_enum_cannot_inject_grammar_and_zero_length(self):
        schema = {"oneOf": [copy.deepcopy(self.by_action["open"][0])]}
        fields = schema["oneOf"][0]["properties"]["arguments"]["properties"]
        aliases = ['quote"', "back\\slash", "line\nbreak", "\0", "🙂", '" | evil ::= "', "[]{}:(),"]
        fields["text"]["enum"] = aliases
        fields["summary"]["maxLength"] = 0
        recognizer = Recognizer(candidate_adapter(corpus.encoded(schema))[0])
        value = corpus.sample(schema["oneOf"][0])
        for alias in aliases:
            value["arguments"]["text"] = alias
            self.differential(value, True, schema, recognizer)
        value["arguments"]["summary"] = "x"
        self.differential(value, False, schema, recognizer)

    def test_conservative_serialization_never_claims_full_json_language(self):
        value = corpus.sample(self.by_action["open"][0])
        raw = corpus.encoded(value).decode()
        self.assertTrue(self.recognizer.accepts(" " + raw + " "))
        self.assertFalse(self.recognizer.accepts("  " + raw))
        alternate = dict(reversed(list(value.items())))
        self.assertTrue(corpus.original_schema_accepts(alternate, self.schema))
        self.assertFalse(self.recognizer.accepts(corpus.encoded(alternate)))

    def test_nested_tuple_whitespace_and_object_order_are_sound(self):
        value = corpus.sample(self.by_action["swipe"][0])
        # json.dumps emits one legal space after each comma and colon, including
        # nested coordinate tuples. Also exercise whitespace before closers.
        ordinary = json.dumps(value, ensure_ascii=False)
        variants = [ordinary, ordinary.replace("]", " ]"), ordinary.replace("}", " }"),
                    ordinary.replace("]", " ]").replace("}", " }")]
        for raw in variants:
            self.assertTrue(self.recognizer.accepts(raw), raw)
            self.assertTrue(corpus.original_schema_accepts(json.loads(raw), self.schema))
            self.assertTrue(self.oracle(self.schema).accepts(raw))
        extra = copy.deepcopy(value)
        extra["arguments"]["start_coordinate"].append(0)
        self.assertFalse(self.recognizer.accepts(json.dumps(extra)))
        reordered = copy.deepcopy(value)
        reordered["arguments"] = dict(reversed(list(reordered["arguments"].items())))
        self.assertTrue(corpus.original_schema_accepts(reordered, self.schema))
        self.assertFalse(self.recognizer.accepts(corpus.encoded(reordered)))


if __name__ == "__main__":
    program = unittest.main(exit=False, verbosity=2)
    result = program.result
    report = {"schema": "hepta.python-schema-converter-host-semantics.v1",
              "status": "PASS" if result.wasSuccessful() else "FAIL", "tests_run": result.testsRun,
              "failures": len(result.failures), "errors": len(result.errors), **corpus.STATS,
              "compiler_source_sha256": SOURCE_SHA,
              "reference_executable_sha256": getattr(PythonConverterTests, "exe_sha", None),
              "grammar_bytes": len(PythonConverterTests.grammar) if hasattr(PythonConverterTests, "grammar") else None,
              "fixture_aliases": 53, "fixture_branches": [13, 18], "private_actual_r9_schemas_tested": False,
              "model_requests": 0, "phone_accessed": False, "proc_grammar_parser_tested": False,
              "comparison": "direct_original_JSON_value_validator_and_independent_Cpp_GBNF_recognizer",
              "serialization_scope": "sound_conservative_fixed_order_Unicode_scalars_no_surrogate_escapes"}
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
