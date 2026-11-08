"""Reviewed, bounded JSON-Schema subset to GBNF; standard-library Python only.

This module is read by the existing Python interpreter. It launches no process,
loads no model and authorizes no action. The original strict schema/typed parser
remains the result validator. The grammar deliberately chooses a conservative
JSON serialization: declared property order, bounded whitespace, direct Unicode
scalars or non-surrogate escapes. Valid escaped UTF-16 pairs are not generated.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

MAX_BYTES = 65536
SUBSET = "hepta.mobile-schema-gbnf-subset.v1"
REFERENCE_COMMIT = "19cce6919992fdffd92e0ac152caaf1e2b8f254e"
PACKAGE_PATTERN = r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$"
VIEW_PATTERN = r"^[A-Za-z][A-Za-z0-9_.]*:id/[A-Za-z0-9_]+$"


def _need(condition, message):
    if not condition:
        raise ValueError(message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8", "strict")


def _strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            _need(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def nonfinite(_value):
        raise ValueError("nonfinite JSON value")

    value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
                       parse_constant=nonfinite)
    # json.loads accepts escaped isolated surrogates; UTF-8 serialization must
    # never manufacture these as grammar literals or treat them as scalars.
    _canonical(value)
    return value


def _keys(value):
    _need(type(value) is dict, "schema node must be an object")
    return set(value)


def _exact(value, expected):
    _need(_keys(value) == set(expected), "unknown, absent or combined schema keyword")


def _integer(value, low, high):
    _need(type(value) is int and low <= value <= high, "integer bound outside reviewed range")
    return value


def _strings(value):
    _need(type(value) is list and all(type(item) is str for item in value), "string array required")
    _need(len(value) == len(set(value)), "duplicate string value")
    return set(value)


def _validate_node(node, depth, count):
    count[0] += 1
    _need(depth <= 24 and count[0] <= 2048, "schema structure exceeds reviewed bound")
    _keys(node)
    if "const" in node:
        _exact(node, {"const"})
        value = node["const"]
        _need(type(value) is str or (type(value) is int and value == 0),
              "only text constants or display zero are reviewed")
        return
    if "enum" in node:
        _exact(node, {"type", "enum"})
        _need(node["type"] == "string", "enum must explicitly contain strings")
        values = _strings(node["enum"])
        _need(1 <= len(values) <= 64, "enum size outside reviewed catalogue bound")
        return
    _need(type(node.get("type")) is str, "explicit schema type required")
    kind = node["type"]
    if kind == "object":
        _exact(node, {"type", "properties", "required", "additionalProperties"})
        _need(node["additionalProperties"] is False, "every object must be explicitly closed")
        properties = _keys(node["properties"])
        _need(1 <= len(properties) <= 16, "object field count outside reviewed bound")
        _need(_strings(node["required"]) == properties, "every declared property must be required")
        for child in node["properties"].values():
            _validate_node(child, depth + 1, count)
    elif kind == "array":
        _exact(node, {"type", "prefixItems", "minItems", "maxItems"})
        _need(type(node["prefixItems"]) is list, "prefixItems must be an array")
        length = len(node["prefixItems"])
        _need(1 <= length <= 5, "tuple length outside reviewed range")
        _need(_integer(node["minItems"], 1, 5) == length and
              _integer(node["maxItems"], 1, 5) == length, "tuple bounds must equal exact length")
        for child in node["prefixItems"]:
            _validate_node(child, depth + 1, count)
    elif kind == "string":
        if "pattern" in node:
            _exact(node, {"type", "pattern"})
            _need(type(node["pattern"]) is str and
                  node["pattern"] in (PACKAGE_PATTERN, VIEW_PATTERN), "unreviewed pattern")
        else:
            _exact(node, {"type", "maxLength"} | ({"minLength"} if "minLength" in node else set()))
            maximum = _integer(node["maxLength"], 0, 4096)
            minimum = _integer(node.get("minLength", 0), 0, 1)
            _need(minimum <= maximum, "inverted text length")
    elif kind == "integer":
        _exact(node, {"type", "minimum", "maximum"})
        low, high = _integer(node["minimum"], 0, 1500), _integer(node["maximum"], 0, 1500)
        _need((low, high) in ((0, 1000), (100, 1500), (500, 1500)), "unreviewed integer interval")
    else:
        raise ValueError("unreviewed schema type")


_FIELDS = {
    "terminate": {"action", "summary", "status"},
    "open": {"action", "summary", "text"},
    "screenshot": {"action", "summary", "display_id"},
    "click": {"action", "summary", "screenshot_id", "coordinate"},
    "swipe": {"action", "summary", "screenshot_id", "start_coordinate", "end_coordinate", "duration_ms"},
    "long_press": {"action", "summary", "screenshot_id", "coordinate", "duration_ms"},
    "back": {"action", "summary", "screenshot_id"},
    "home": {"action", "summary", "screenshot_id"},
    "type": {"action", "summary", "package", "view_id", "old_text", "text"},
    "focus_type": {"action", "summary", "package", "view_id", "old_text", "text"},
    "observe": {"action", "summary", "package"},
    "read_text": {"action", "summary", "package", "view_ids"},
    "read_text_anchor": {"action", "summary", "package", "title_view_id", "anchor_text", "value_view_id"},
    "return_hepta": {"action", "summary"},
}


def _validate_mobile(schema):
    _exact(schema, {"oneOf"})
    branches = schema["oneOf"]
    _need(type(branches) is list and 1 <= len(branches) <= 32, "invalid action alternatives")
    discriminators, count = set(), [0]
    for branch in branches:
        _validate_node(branch, 0, count)
        _need(branch.get("type") == "object", "alternative must be an object")
        properties = branch["properties"]
        _need(set(properties) == {"name", "arguments"} and properties["name"] == {"const": "mobile_use"},
              "mobile envelope differs")
        arguments = properties["arguments"]
        _need(arguments.get("type") == "object", "arguments must be an object")
        fields = arguments["properties"]
        action_node = fields.get("action", {})
        _need(type(action_node) is dict and set(action_node) == {"const"} and
              type(action_node["const"]) is str, "action discriminator absent")
        action = action_node["const"]
        _need(action in _FIELDS and set(fields) == _FIELDS[action], "unreviewed action fields")
        length = 0
        if action == "read_text":
            _need(fields["view_ids"].get("type") == "array", "read_text discriminator must be a tuple")
            length = len(fields["view_ids"]["prefixItems"])
        discriminator = (action, length)
        _need(discriminator not in discriminators, "overlapping oneOf alternatives")
        discriminators.add(discriminator)


def _validate_health(schema):
    _exact(schema, {"type", "properties", "required", "additionalProperties"})
    _need(schema["type"] == "object" and schema["additionalProperties"] is False, "health root must be closed")
    names = {"kind", "call_id", "tool", "command", "argv", "summary", "task_status"}
    properties = schema["properties"]
    _need(_keys(properties) == names and _strings(schema["required"]) == names, "health fields differ")
    constants = {"kind": "turn.complete", "tool": "none", "call_id": "", "command": "", "task_status": "completed"}
    for key, value in constants.items():
        _need(properties[key] == {"type": "string", "const": value}, "health terminal constant differs")
    arguments = properties["argv"]
    _exact(arguments, {"type", "items", "minItems", "maxItems"})
    _need(arguments["type"] == "array" and arguments["items"] == {"type": "string"} and
          _integer(arguments["minItems"], 0, 0) == 0 and _integer(arguments["maxItems"], 0, 0) == 0,
          "health argv must be empty")
    summary = properties["summary"]
    _exact(summary, {"type", "maxLength"})
    _need(summary["type"] == "string" and _integer(summary["maxLength"], 1024, 1024) == 1024,
          "health summary must not encode a nonce")


def _literal(text):
    # GBNF quoted literals use the same escapes emitted here: slash, quote,
    # newline/control Unicode escapes. A JSON value is serialized first, then
    # quoted a second time to match that serialization literally.
    return json.dumps(text, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


class _Generator:
    def __init__(self):
        self.rules = {}
        self.memo = {}

    def node(self, node):
        # Keep insertion order in this memo key: fixed object order is part of
        # the chosen serialization, while the schema's value constraints stay.
        key = json.dumps(node, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        if key in self.memo:
            return self.memo[key]
        name = "v%d" % len(self.memo)
        self.memo[key] = name
        if "const" in node:
            expression = _literal(json.dumps(node["const"], ensure_ascii=False, separators=(",", ":")))
        elif "enum" in node:
            expression = "( " + " | ".join(_literal(json.dumps(value, ensure_ascii=False))
                                            for value in node["enum"]) + " )"
        elif node["type"] == "object":
            fields = [_literal(json.dumps(key, ensure_ascii=False)) + ' space ":" space ' + self.node(child)
                      for key, child in node["properties"].items()]
            expression = '"{" space ' + ' "," space '.join(fields) + ' "}"'
        elif node["type"] == "array":
            values = [self.node(child) for child in node.get("prefixItems", [])]
            expression = '"[" space ' + ' "," space '.join(values) + ' "]"'
        elif node["type"] == "string":
            if "pattern" in node:
                expression = "package" if node["pattern"] == PACKAGE_PATTERN else "view"
            else:
                minimum, maximum = node.get("minLength", 0), node["maxLength"]
                content = "scalar{%d,%d} " % (minimum, maximum) if maximum else ""
                expression = r'"\"" ' + content + r'"\""'
        else:
            expression = {0: '( "0" | [1-9] [0-9]{0,2} | "1000" )',
                          100: '( [1-9] [0-9]{2} | "1" [0-4] [0-9]{2} | "1500" )',
                          500: '( [5-9] [0-9]{2} | "1" [0-4] [0-9]{2} | "1500" )'}[node["minimum"]]
        self.rules[name] = expression + " space"
        return name

    def generate(self, schema, kind):
        roots = [self.node(branch) for branch in schema["oneOf"]] if kind == "mobile_use" else [self.node(schema)]
        # Each scalar is exactly one decoded Unicode value. Generic strings
        # reject all surrogate escapes, including legal pairs; direct astral
        # UTF-8 remains valid. DEL is available through its non-surrogate escape.
        common = [
            'space ::= " "?',
            r'scalar ::= [^"\\\x00-\x1F\x7F\uD800-\uDFFF] | "\\" (["\\/bfnrt] | "u" ([0-9a-cA-Ce-fE-F] [0-9a-fA-F]{3} | [dD] [0-7] [0-9a-fA-F]{2}))',
            r'package ::= "\"" [A-Za-z] [A-Za-z0-9_]* ("." [A-Za-z] [A-Za-z0-9_]*)+ "\""',
            r'view ::= "\"" [A-Za-z] [A-Za-z0-9_.]* ":id/" [A-Za-z0-9_]+ "\""',
        ]
        lines = ['root ::= space ( ' + ' | '.join(roots) + ' )'] + common
        lines += [name + " ::= " + value for name, value in self.rules.items()]
        grammar = ("\n".join(lines) + "\n").encode("utf-8", "strict")
        _need(0 < len(grammar) <= MAX_BYTES and b"\0" not in grammar, "grammar byte bound")
        return grammar


def _verify_source(expected):
    _need(type(expected) is str and re.fullmatch(r"[0-9a-f]{64}", expected) is not None,
          "compiler source SHA must be fixed")
    path = Path(__file__)
    _need(path.is_absolute() and path.parent.resolve(strict=True) == path.parent,
          "compiler source path must be canonical and absolute")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        _need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and not before.st_mode & 0o022 and
              0 < before.st_size <= 128 * 1024, "compiler source identity/mode differs")
        raw = bytearray()
        while len(raw) < before.st_size:
            block = os.read(fd, min(65536, before.st_size - len(raw)))
            _need(bool(block), "short compiler source read")
            raw.extend(block)
        after, named = os.fstat(fd), path.lstat()
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        _need(all(getattr(before, key) == getattr(after, key) == getattr(named, key) for key in fields),
              "compiler source changed while hashing")
        _need(_sha(raw) == expected, "compiler source SHA differs")
    finally:
        os.close(fd)


def convert_schema(original_bytes, *, compiler_source_sha256):
    """Return bounded GBNF and truthful in-process proof for original bytes.

    The caller must verify/pin this source before importing it, include it in
    its protected source closure, and still validate every generated result
    with the original schema and typed mapper. This function checks the source
    file again; a post-import hash alone is not a loader trust boundary.
    """
    _verify_source(compiler_source_sha256)
    _need(type(original_bytes) is bytes and 0 < len(original_bytes) <= MAX_BYTES, "schema byte bound")
    original = _strict_json(original_bytes)
    _keys(original)
    if "oneOf" in original:
        _validate_mobile(original)
        kind = "mobile_use"
    else:
        _validate_health(original)
        kind = "health_final_only"
    grammar = _Generator().generate(original, kind)
    proof = {"schema": "hepta.schema-gbnf-conversion.v1", "subset": SUBSET,
             "root_schema_kind": kind, "original_schema_bytes": len(original_bytes),
             "original_schema_sha256": _sha(original_bytes), "canonical_schema_sha256": _sha(_canonical(original)),
             "grammar_bytes": len(grammar), "grammar_sha256": _sha(grammar), "grammar_root": "root",
             "compiler_kind": "reviewed_python_source", "compiler_source_sha256": compiler_source_sha256,
             "conversion_completed": True, "input_bytes_preserved": True,
             "reference_converter_commit": REFERENCE_COMMIT,
             "model_loaded": False, "native_action_authorized": False, "production_receipt": False}
    return grammar, proof
