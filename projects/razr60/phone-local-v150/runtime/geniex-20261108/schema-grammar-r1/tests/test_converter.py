#!/usr/bin/env python3
"""Host-only semantic differential tests. No phone, model, SDK or UI calls."""
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from convert_schema import convert_schema, sha, static_elf_contract
from gbnf_recognizer import Recognizer

PACKAGE = r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$"
VIEW = r"^[A-Za-z][A-Za-z0-9_.]*:id/[A-Za-z0-9_]+$"
IMAGE = "r04_0123456789abcdef"
ALIASES = ["计算器", "设置"] + ["Public fixture app %02d" % i for i in range(51)]
PACKAGES = ["org.fixture.app%d" % i for i in range(53)]
STATS = {"accepted_values": 0, "rejected_values": 0, "integer_cases": 0, "schema_rejections": 0}

def encoded(value):
    # Valid Unicode values, canonical order; DEL uses its legal JSON escape.
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).replace("\x7f", r"\u007f").encode()

def tuple_of(values):
    return {"type": "array", "prefixItems": values, "minItems": len(values), "maxItems": len(values)}

def interval(low, high):
    return {"type": "integer", "minimum": low, "maximum": high}

def pattern(value):
    return {"type": "string", "pattern": value}

def text(maximum, minimum=0):
    result = {"type": "string", "maxLength": maximum}
    if minimum:
        result["minLength"] = minimum
    return result

def branch(action, extras):
    args = {"action": {"const": action}, "summary": text(1024), **extras}
    arguments = {"type": "object", "properties": args, "required": list(args), "additionalProperties": False}
    return {"type": "object", "properties": {"name": {"const": "mobile_use"}, "arguments": arguments},
            "required": ["name", "arguments"], "additionalProperties": False}

def schema_fixture(image=True):
    enum = lambda values: {"type": "string", "enum": values}
    parts = [
        branch("terminate", {"status": enum(["success", "partial", "failure", "unknown"])}),
        branch("open", {"text": enum(ALIASES)}),
        branch("observe", {"package": enum(PACKAGES)}),
        branch("screenshot", {"display_id": {"const": 0}}),
        branch("type", {"package": pattern(PACKAGE), "view_id": pattern(VIEW),
                        "old_text": text(4096), "text": text(4096)}),
        branch("focus_type", {"package": enum(PACKAGES), "view_id": pattern(VIEW),
                              "old_text": text(4096), "text": text(4096)}),
        branch("read_text_anchor", {"package": enum(PACKAGES), "title_view_id": pattern(VIEW),
                                    "anchor_text": text(256, 1), "value_view_id": pattern(VIEW)}),
    ]
    parts += [branch("read_text", {"package": pattern(PACKAGE),
              "view_ids": tuple_of([pattern(VIEW) for _ in range(n)])}) for n in range(1, 6)]
    parts += [branch("return_hepta", {})]
    if image:
        coordinate = lambda: tuple_of([interval(0, 1000), interval(0, 1000)])
        image_id = {"const": IMAGE}
        parts += [
            branch("click", {"screenshot_id": image_id, "coordinate": coordinate()}),
            branch("swipe", {"screenshot_id": image_id, "start_coordinate": coordinate(),
                             "end_coordinate": coordinate(), "duration_ms": interval(100, 1500)}),
            branch("long_press", {"screenshot_id": image_id, "coordinate": coordinate(),
                                  "duration_ms": interval(500, 1500)}),
            branch("back", {"screenshot_id": image_id}), branch("home", {"screenshot_id": image_id}),
        ]
    return {"oneOf": parts}

def sample(node):
    if "const" in node:
        return node["const"]
    if "enum" in node:
        return node["enum"][0]
    kind = node["type"]
    if kind == "object":
        return {key: sample(value) for key, value in node["properties"].items()}
    if kind == "array":
        return [sample(value) for value in node["prefixItems"]] if "prefixItems" in node else []
    if kind == "integer":
        return node["minimum"]
    if kind == "string":
        if "pattern" in node:
            return "org.fixture" if node["pattern"] == PACKAGE else "org.fixture:id/value"
        return "x" * node.get("minLength", 0)
    raise ValueError(kind)

def original_schema_accepts(value, schema):
    # Independent direct JSON-value interpretation. It does not use production
    # C++ preflight, generated grammar, or regex translation implementation.
    if "oneOf" in schema:
        return sum(original_schema_accepts(value, item) for item in schema["oneOf"]) == 1
    if "const" in schema and (type(value) is not type(schema["const"]) or value != schema["const"]):
        return False
    if "enum" in schema and not any(type(value) is type(x) and value == x for x in schema["enum"]):
        return False
    kind = schema.get("type")
    if kind is None:
        return True
    types = {"string": str, "integer": int, "object": dict, "array": list}
    if type(value) is not types[kind]:
        return False
    if kind == "object":
        return set(value) == set(schema["properties"]) and set(schema["required"]) <= set(value) \
            and all(original_schema_accepts(value[key], part) for key, part in schema["properties"].items())
    if kind == "array":
        if not schema["minItems"] <= len(value) <= schema["maxItems"]:
            return False
        if "prefixItems" in schema:
            return len(value) == len(schema["prefixItems"]) \
                and all(original_schema_accepts(item, part) for item, part in zip(value, schema["prefixItems"]))
        return all(original_schema_accepts(item, schema["items"]) for item in value)
    if kind == "integer":
        return schema["minimum"] <= value <= schema["maximum"]
    if kind == "string":
        return schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", len(value)) \
            and ("pattern" not in schema or re.fullmatch(schema["pattern"], value) is not None)
    return False

class ConverterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.exe = Path(os.environ["HEPTA_SCHEMA_CONVERTER"]).resolve()
        cls.exe_sha = sha(cls.exe.read_bytes())
        cls.schema = schema_fixture(True)
        cls.no_image = schema_fixture(False)
        cls.grammar, cls.proof = convert_schema(encoded(cls.schema), executable=cls.exe,
                                               executable_sha256=cls.exe_sha)
        cls.recognizer = Recognizer(cls.grammar)
        without, _ = convert_schema(encoded(cls.no_image), executable=cls.exe, executable_sha256=cls.exe_sha)
        cls.no_image_recognizer = Recognizer(without)
        cls.by_action = {}
        for item in cls.schema["oneOf"]:
            action = item["properties"]["arguments"]["properties"]["action"]["const"]
            cls.by_action.setdefault(action, []).append(item)

    def differential(self, value, expected, schema=None, recognizer=None):
        schema = schema or self.schema
        recognizer = recognizer or self.recognizer
        self.assertEqual(original_schema_accepts(value, schema), expected)
        self.assertEqual(recognizer.accepts(encoded(value)), expected, repr(value)[:160])
        STATS["accepted_values" if expected else "rejected_values"] += 1

    def reject_schema(self, schema):
        result = subprocess.run([str(self.exe)], input=encoded(schema), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=3)
        self.assertEqual(result.returncode, 65, result.stderr)
        self.assertEqual(result.stdout, b"")
        STATS["schema_rejections"] += 1

    def test_complete_action_set_and_all_fields(self):
        self.assertEqual(len(self.schema["oneOf"]), 18)
        for node in self.schema["oneOf"]:
            value = sample(node)
            self.differential(value, True)
            for key in list(value["arguments"]):
                bad = copy.deepcopy(value); del bad["arguments"][key]
                self.differential(bad, False)
            bad = copy.deepcopy(value); bad["arguments"]["unexpected"] = "x"
            self.differential(bad, False)
            bad = copy.deepcopy(value); bad["outside"] = True
            self.differential(bad, False)

    def test_complete_53_alias_enum_and_exact_screenshot(self):
        value = sample(self.by_action["open"][0])
        for alias in ALIASES:
            value["arguments"]["text"] = alias
            self.differential(value, True)
        value["arguments"]["text"] = "not a registered alias"
        self.differential(value, False)
        click = sample(self.by_action["click"][0])
        click["arguments"]["screenshot_id"] = "current"
        self.differential(click, False)

    def test_no_image_schema_cannot_gain_visual_actions(self):
        for action in ("click", "swipe", "long_press", "back", "home"):
            self.differential(sample(self.by_action[action][0]), False, self.no_image, self.no_image_recognizer)
        for node in self.no_image["oneOf"]:
            self.differential(sample(node), True, self.no_image, self.no_image_recognizer)

    def test_coordinate_and_duration_exhaustive_boundaries(self):
        for action, field, low in (("click", "coordinate", 0), ("swipe", "duration_ms", 100),
                                   ("long_press", "duration_ms", 500)):
            value = sample(self.by_action[action][0])
            for number in range(-2, 1503):
                value["arguments"][field] = [number, 0] if field == "coordinate" else number
                self.differential(value, low <= number <= (1000 if action == "click" else 1500))
                STATS["integer_cases"] += 1
            for number in (True, False, 0.0, 100.0, 1000.0, "500", None):
                value["arguments"][field] = [number, 0] if field == "coordinate" else number
                self.differential(value, False)

    def test_exact_tuple_lengths_and_types(self):
        click = sample(self.by_action["click"][0])
        for array in ([], [0], [0, 0, 0], "0,0", {"x": 0, "y": 0}):
            click["arguments"]["coordinate"] = array
            self.differential(click, False)
        for index, node in enumerate(self.by_action["read_text"], 1):
            value = sample(node)
            self.assertEqual(len(value["arguments"]["view_ids"]), index)
            self.differential(value, True)
        value = sample(self.by_action["read_text"][0])
        value["arguments"]["view_ids"] = []
        self.differential(value, False)
        value["arguments"]["view_ids"] = ["org.fixture:id/a"] * 6
        self.differential(value, False)
        # Uniqueness is an independent typed-guard obligation, absent from
        # the original schema; never claim this grammar enforces it.
        value["arguments"]["view_ids"] = ["org.fixture:id/a"] * 2
        self.differential(value, True)

    def test_text_length_unicode_and_json_escaping(self):
        for action, field, minimum, maximum in (("terminate", "summary", 0, 1024),
                ("type", "text", 0, 4096), ("read_text_anchor", "anchor_text", 1, 256)):
            value = sample(self.by_action[action][0])
            for size in sorted({0, 1, maximum - 1, maximum, maximum + 1}):
                for character in ("x", "中", "🙂"):
                    value["arguments"][field] = character * size
                    self.differential(value, minimum <= size <= maximum)
            for content in ('quote"slash\\newline\n', "\0\b\f\r\t/", "\x7f", "e\u0301", "🙂", "汉字"):
                value["arguments"][field] = content
                self.differential(value, minimum <= len(content) <= maximum)
        value = sample(self.by_action["read_text_anchor"][0])
        value["arguments"]["anchor_text"] = "🙂"
        raw = encoded(value).decode().replace("🙂", r"\ud83d\ude42")
        self.assertFalse(self.recognizer.accepts(raw))
        self.assertTrue(original_schema_accepts(json.loads(raw), self.schema))

    def test_scalar_length_and_surrogate_representation_boundary(self):
        schema = {"oneOf": [copy.deepcopy(self.by_action["read_text_anchor"][0])]}
        schema["oneOf"][0]["properties"]["arguments"]["properties"]["anchor_text"]["maxLength"] = 1
        grammar, _ = convert_schema(encoded(schema), executable=self.exe, executable_sha256=self.exe_sha)
        recognizer = Recognizer(grammar)
        value = sample(schema["oneOf"][0])
        value["arguments"]["anchor_text"] = "😀"
        self.differential(value, True, schema, recognizer)
        raw = encoded(value).decode()
        pair = raw.replace("😀", r"\ud83d\ude00")
        self.assertEqual(len(json.loads(pair)["arguments"]["anchor_text"]), 1)
        self.assertTrue(original_schema_accepts(json.loads(pair), schema))
        self.assertFalse(recognizer.accepts(pair))  # Conservative serialization subset.
        for surrogate in (r"\ud800", r"\udfff", r"\uD83D"):
            self.assertFalse(recognizer.accepts(raw.replace("😀", surrogate)))
        self.assertTrue(recognizer.accepts(raw.replace("😀", r"\u4e2d")))
        value["arguments"]["anchor_text"] = "😀😀"
        self.differential(value, False, schema, recognizer)

    def test_exact_health_contract_shape_without_nonce_or_tools(self):
        constants = {"kind":"turn.complete", "tool":"none", "call_id":"", "command":"", "task_status":"completed"}
        properties = {key: {"type":"string", "const":value} for key,value in constants.items()}
        properties["argv"] = {"type":"array", "items":{"type":"string"}, "minItems":0, "maxItems":0}
        properties["summary"] = {"type":"string", "maxLength":1024}
        schema = {"type":"object", "properties":properties, "required":list(properties), "additionalProperties":False}
        grammar, proof = convert_schema(encoded(schema), executable=self.exe, executable_sha256=self.exe_sha)
        self.assertEqual(proof["root_schema_kind"], "health_final_only")
        recognizer = Recognizer(grammar)
        value = sample(schema)
        for summary in ("", "fresh_owner_nonce_not_in_grammar", "中文🙂", "x"*1024):
            value["summary"] = summary
            self.differential(value, True, schema, recognizer)
        self.assertNotIn(b"fresh_owner_nonce_not_in_grammar", grammar)
        for key, wrong in (("tool","phone.tap"), ("kind","tool.call"), ("argv",["0"]),
                           ("task_status","in_progress"), ("summary","x"*1025)):
            bad = sample(schema); bad[key] = wrong
            self.differential(bad, False, schema, recognizer)
        changed = copy.deepcopy(schema)
        changed["properties"]["summary"]["const"] = "nonce"
        self.reject_schema(changed)
        changed = copy.deepcopy(schema)
        changed["properties"]["tool"]["const"] = "phone.tap"
        self.reject_schema(changed)

    def test_package_and_view_patterns(self):
        value = sample(self.by_action["type"][0])
        for candidate in ("a.b", "org.example.app_1", "A0.X", "", "a", "a..b", "0a.b", "a._b", "a/b.c",
                          "a.b\n", 'a."b', "org.示例", "a-b.c"):
            value["arguments"]["package"] = candidate
            self.differential(value, re.fullmatch(PACKAGE, candidate) is not None)
        value = sample(self.by_action["type"][0])
        for candidate in ("a.b:id/x_1", "A:id/Z", "", "a:id/", "a.b/x", "0a:id/a", "a:id/x-y",
                          "a:id/é", "a:id/a\n", 'a:id/"'):
            value["arguments"]["view_id"] = candidate
            self.differential(value, re.fullmatch(VIEW, candidate) is not None)

    def test_malformed_json_extra_tokens_and_missing_closers(self):
        raw = encoded(sample(self.by_action["open"][0])).decode()
        fence = chr(96) * 3
        for invalid in (raw[:-1], raw[:-2], raw + "{}", raw + "\nexplanation", fence + "json\n" + raw + "\n" + fence,
                        raw.replace('"name":', '"name":null,"name":'),
                        raw.replace('"summary":""', '"summary":"line\nbreak"'),
                        raw.replace('"summary":""', '"summary":"\\q"')):
            self.assertFalse(self.recognizer.accepts(invalid))

    def test_unknown_keywords_and_unsupported_combinations_fail(self):
        def change(fn):
            value = copy.deepcopy(self.schema)
            fn(value)
            self.reject_schema(value)
        change(lambda s: s.update(description="unknown annotation deliberately rejected"))
        change(lambda s: s.update(anyOf=s.pop("oneOf")))
        change(lambda s: s["oneOf"][0].update(additionalProperties=True))
        change(lambda s: s["oneOf"][1]["properties"]["arguments"]["required"].remove("text"))
        change(lambda s: s["oneOf"].append(copy.deepcopy(s["oneOf"][0])))
        change(lambda s: s["oneOf"][-1]["properties"]["arguments"]["properties"].update(extra={"type":"string"}))
        change(lambda s: s["oneOf"][1]["properties"]["arguments"]["properties"]["text"]["enum"].append(0))
        change(lambda s: s["oneOf"][1]["properties"]["arguments"]["properties"]["text"]["enum"].append(ALIASES[0]))
        change(lambda s: s["oneOf"][4]["properties"]["arguments"]["properties"]["view_id"].update(maxLength=128))
        change(lambda s: s["oneOf"][4]["properties"]["arguments"]["properties"]["view_id"].update(pattern="a+"))
        change(lambda s: s["oneOf"][6]["properties"]["arguments"]["properties"]["anchor_text"].update(minLength=2))
        change(lambda s: s["oneOf"][7]["properties"]["arguments"]["properties"]["view_ids"].update(items={"type":"string"}))
        change(lambda s: s["oneOf"][7]["properties"]["arguments"]["properties"]["view_ids"].update(uniqueItems=True))
        change(lambda s: s["oneOf"][7]["properties"]["arguments"]["properties"]["view_ids"].update(maxItems=2))
        change(lambda s: s["oneOf"][13]["properties"]["arguments"]["properties"]["coordinate"]["prefixItems"][0].update(maximum=1001))

    def test_duplicate_schema_keys_and_size_fail_before_output(self):
        schema_raw = encoded(self.schema)
        raw = b'{"oneOf":[],' + schema_raw[1:]
        for bad in (raw, b" " * 65537, b'{"oneOf":', b"\xff"):
            result = subprocess.run([str(self.exe)], input=bad, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
            self.assertEqual(result.returncode, 65)
            self.assertEqual(result.stdout, b"")

    def test_original_bytes_executable_and_grammar_bound(self):
        raw = b"\n " + encoded(self.no_image) + b"\n"
        grammar, proof = convert_schema(raw, executable=self.exe, executable_sha256=self.exe_sha)
        self.assertEqual(proof["original_schema_sha256"], sha(raw))
        self.assertEqual(proof["original_schema_bytes"], len(raw))
        self.assertEqual(proof["grammar_sha256"], sha(grammar))
        self.assertEqual(proof["grammar_bytes"], len(grammar))
        self.assertTrue(proof["input_sent_unchanged"] and proof["child_waited"])
        self.assertFalse(proof["model_loaded"] or proof["native_action_authorized"] or proof["production_receipt"])
        self.assertLessEqual(len(grammar), 65536)
        with self.assertRaises(ValueError):
            convert_schema(raw, executable=self.exe, executable_sha256="0"*64)
        with self.assertRaises(ValueError):
            convert_schema(raw, executable=self.exe, executable_sha256=self.exe_sha, timeout=4)

    def test_static_elf_has_no_interpreter_or_needed(self):
        contract = static_elf_contract(self.exe.read_bytes())
        self.assertFalse(contract["pt_interp"])
        self.assertEqual(contract["dt_needed"], [])
        with self.assertRaises(ValueError):
            static_elf_contract(b"not ELF")
        dynamic = Path(sys.executable).resolve().read_bytes()
        with self.assertRaises(ValueError):
            static_elf_contract(dynamic)

    def test_private_cli_preserves_original_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            original = folder / "schema.json"; original.write_bytes(encoded(self.schema)); original.chmod(0o600)
            out = folder / "conversion"
            command = [sys.executable, str(ROOT / "convert_schema.py"), "--schema-file", str(original),
                       "--converter", str(self.exe), "--converter-sha256", self.exe_sha, "--out", str(out)]
            done = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual((out / "original-schema.json").read_bytes(), original.read_bytes())
            saved = {p.name: sha(p.read_bytes()) for p in out.iterdir()}
            again = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            self.assertNotEqual(again.returncode, 0)
            self.assertEqual(saved, {p.name: sha(p.read_bytes()) for p in out.iterdir()})
            self.assertEqual(out.stat().st_mode & 0o777, 0o700)
            self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in out.iterdir()))

if __name__ == "__main__":
    program = unittest.main(exit=False, verbosity=2)
    result = program.result
    summary = {"schema": "hepta.schema-converter-host-semantics.v1",
        "status": "PASS" if result.wasSuccessful() else "FAIL", "tests_run": result.testsRun,
        "failures": len(result.failures), "errors": len(result.errors), **STATS,
        "private_actual_r9_schemas_tested": False, "fixture_aliases": 53, "fixture_branches": [13, 18],
        "grammar_bytes": len(ConverterTests.grammar) if hasattr(ConverterTests, "grammar") else None,
        "executable_sha256": ConverterTests.exe_sha if hasattr(ConverterTests, "exe_sha") else None,
        "phone_accessed": False, "model_requests": 0,
        "recognizer_scope": "independent_test_only_acyclic_GBNF_to_Unicode_regex_not_geniex_proc"}
    print(json.dumps(summary, sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
