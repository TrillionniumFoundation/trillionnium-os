#!/usr/bin/env python3
"""Derive the reviewed native_streams candidate without importing provider code."""
import argparse
import ast
import difflib
import hashlib
import json
import os
from pathlib import Path

ORIGINAL_OBSERVATION = "2c5ebb75e34fcce4c14638939809dade1f6d129504270930c8f94e2c2ce15b66"
CANDIDATE_OBSERVATION = "22580b8aa22d5c0ab4040888872e642a5176042023dd7bcf50e67efe51248409"
ORIGINAL_DAILY = "ca23c60bbb4114960c6a571492cacd9e0bdc3404191409ac78bcf0c34a06c1d0"
CANDIDATE_DAILY = "689db3908014940a1e39689b966d30ab16ac6f9c0d7892becf1718b9840c824f"

REPLACEMENTS = [
    (
        "    require(isinstance(terminal, dict) and terminal.get('kind') == 'exited'\n",
        "    require(isinstance(terminal, dict) and terminal.get('kind') == 'exited'\n"
        "            and type(terminal.get('exit_code')) is int\n",
    ),
    (
        "        if event.get('kind') != 'output':\n",
        "        require(type(event.get('kind')) is str\n"
        "                and event['kind'] in {'accepted', 'started', 'output', 'terminal'},\n"
        "                'phone result contains an unqualified event kind')\n"
        "        if event['kind'] != 'output':\n",
    ),
    (
        "    require(kinds and kinds[0] == 'accepted' and kinds[-1] == 'terminal'\n"
        "            and all(kinds.count(kind) == 1 for kind in ('accepted', 'started', 'terminal'))\n"
        "            and events[-1]['event'].get('terminal') == terminal,\n"
        "            'phone result does not contain its original accepted/start/terminal events')\n",
        "    require(len(kinds) >= 3 and kinds[:2] == ['accepted', 'started']\n"
        "            and kinds[-1] == 'terminal' and all(kind == 'output' for kind in kinds[2:-1]),\n"
        "            'phone result does not contain its original accepted/start/terminal events')\n"
        "    observed_terminal = events[-1]['event'].get('terminal')\n"
        "    require(isinstance(observed_terminal, dict) and observed_terminal == terminal\n"
        "            and all(type(observed_terminal[key]) is type(value)\n"
        "                    for key, value in terminal.items()),\n"
        "            'phone terminal event differs in value or field type')\n",
    ),
]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def split_function(text):
    start = text.index("def native_streams(")
    end = text.index("\ndef ", start + 1)
    return text[:start], text[start:end], text[end:]


def derive(package):
    original = (package / "reference/phone_observation_tools.original.py").read_bytes()
    daily = (package / "reference/daily_phone_local.original.py").read_bytes()
    assert len(original) == 43445 and sha(original) == ORIGINAL_OBSERVATION
    assert len(daily) == 22059 and sha(daily) == ORIGINAL_DAILY
    before = original.decode("utf-8")
    candidate = before
    for old, new in REPLACEMENTS:
        assert candidate.count(old) == 1
        candidate = candidate.replace(old, new, 1)
    oldparts, newparts = split_function(before), split_function(candidate)
    assert oldparts[0] == newparts[0] and oldparts[2] == newparts[2]
    newraw = candidate.encode("utf-8")
    assert len(newraw) == 43954 and sha(newraw) == CANDIDATE_OBSERVATION
    daily_text = daily.decode("utf-8")
    assert daily_text.count(ORIGINAL_OBSERVATION) == 1
    derived_daily = daily_text.replace(ORIGINAL_OBSERVATION, CANDIDATE_OBSERVATION, 1)
    dailyraw = derived_daily.encode("utf-8")
    assert len(dailyraw) == 22059 and sha(dailyraw) == CANDIDATE_DAILY
    assert derived_daily.replace(CANDIDATE_OBSERVATION, ORIGINAL_OBSERVATION, 1) == daily_text
    ast.parse(candidate)
    ast.parse(derived_daily)
    facts = {
        "schema": "razr60-native-streams-current-source-derivation/v1",
        "state": "HOST_CANDIDATE_NOT_DEPLOYED_OR_PHONE_QUALIFIED",
        "parent_commit": "744fc422a28bd6f505701503bf0d113ab49d4634",
        "current_combination_sha256": "02c2a26af79e367afe48cb1bc378808f3c5a32800548498a0262ea0265c9f708",
        "observation": {
            "original_bytes": len(original), "original_sha256": sha(original),
            "candidate_bytes": len(newraw), "candidate_sha256": sha(newraw),
            "only_function_changed": "native_streams",
            "all_prefix_and_suffix_bytes_identical": True,
            "original_function_sha256": sha(oldparts[1].encode()),
            "candidate_function_sha256": sha(newparts[1].encode()),
        },
        "daily": {
            "original_bytes": len(daily), "original_sha256": sha(daily),
            "candidate_bytes": len(dailyraw), "candidate_sha256": sha(dailyraw),
            "only_change": "PARENTS phone_observation_tools.py SHA256",
            "single_replacement_inverse_exact": True,
        },
        "historical_seals_modified": False,
        "runtime_modified": False,
        "phone_calls": 0,
        "model_requests": 0,
        "qualification_promoted": False,
    }
    outputs = {
        "phone_observation_tools.py": newraw,
        "daily_phone_local.py": dailyraw,
        "phone_observation_tools.py.patch": "".join(difflib.unified_diff(
            before.splitlines(True), candidate.splitlines(True),
            fromfile="reference/phone_observation_tools.original.py",
            tofile="source/phone_observation_tools.py")).encode(),
        "daily_phone_local.py.patch": "".join(difflib.unified_diff(
            daily_text.splitlines(True), derived_daily.splitlines(True),
            fromfile="reference/daily_phone_local.original.py",
            tofile="source/daily_phone_local.py")).encode(),
        "DERIVATION.json": (json.dumps(facts, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(),
    }
    return outputs, facts


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--package-root", type=Path, default=Path(__file__).resolve().parent)
    ap.add_argument("--out", type=Path, help="Fresh directory only; omitted means validate/preview.")
    args = ap.parse_args()
    outputs, facts = derive(args.package_root)
    if args.out is not None:
        os.mkdir(args.out, 0o700)
        for name, raw in outputs.items():
            fd = os.open(args.out / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
            assert (args.out / name).read_bytes() == raw
    print(json.dumps({"derived": facts, "output_files": [
        {"path": name, "bytes": len(raw), "sha256": sha(raw)} for name, raw in outputs.items()
    ]}, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
