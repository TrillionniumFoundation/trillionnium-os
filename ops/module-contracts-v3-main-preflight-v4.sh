#!/usr/bin/env bash
set -euo pipefail

effective="${RUNNER_TEMP:?}/module-contracts-v3-main-preflight-v4-effective.sh"
cp -- ops/module-contracts-v3-main-preflight-v3.sh "$effective"
chmod 0700 "$effective"

python3 - "$effective" <<'PY_PATCHER'
from pathlib import Path
from textwrap import dedent
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")

slash_newline = chr(92) + chr(10)
whitelist_anchor = "  '.github/workflows/tmp-module-contracts-v3-carrier-diagnostic.yml' " + slash_newline
whitelist_replacement = (
    whitelist_anchor
    + "  '.github/workflows/tmp-module-contracts-v3-clippy-inspect.yml' "
    + slash_newline
    + "  '.github/workflows/tmp-module-contracts-v3-main-preflight-v4.yml' "
    + slash_newline
    + "  'ops/module-contracts-v3-main-preflight-v4.sh' "
    + slash_newline
)
if text.count(whitelist_anchor) != 1:
    raise SystemExit("controller whitelist anchor differs")
text = text.replace(whitelist_anchor, whitelist_replacement, 1)

execution_anchor = "PY\n\ncargo fmt --all\n"
clippy_repair = dedent(r'''
PY

python3 - tools/contracts/generate_module_contracts.py <<'PY_CLIPPY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
old = (
    '    let mut limits = MechanicalLimits::default();\n'
    '    limits.max_frame_bytes = MAX_MODULE_CONTRACT_JSON_BYTES;\n'
)
new = (
    '    let limits = MechanicalLimits {\n'
    '        max_frame_bytes: MAX_MODULE_CONTRACT_JSON_BYTES,\n'
    '        ..MechanicalLimits::default()\n'
    '    };\n'
)
if text.count(new) == 1 and text.count(old) == 0:
    pass
elif text.count(old) == 1 and text.count(new) == 0:
    text = text.replace(old, new, 1)
else:
    raise SystemExit("Clippy template repair anchor differs")
path.write_text(text, encoding="utf-8")
print("clippy_template_repairs=1")
PY_CLIPPY

cargo fmt --all
''').removeprefix("\n")
if text.count(execution_anchor) != 1:
    raise SystemExit("controller execution anchor differs")
text = text.replace(execution_anchor, clippy_repair, 1)

docs_anchor = "python3 tools/docs/verify_global_docs.py\n"
docs_stage = dedent(r'''
python3 - <<'PY_STAGE_DOCS'
from pathlib import Path
import subprocess

expected = {
    "android-integration/module-contracts/README.md",
    "docs/MODULE_CONTRACT_STATUS.md",
    "tools/contracts/README.md",
}
completed = subprocess.run(
    ["git", "ls-files", "--others", "--exclude-standard", "-z", "--", "*.md"],
    check=True,
    capture_output=True,
)
observed = {
    item.decode("utf-8")
    for item in completed.stdout.split(b"\0")
    if item
}
if observed != expected:
    raise SystemExit(
        "generated Markdown inventory differs: "
        f"missing={sorted(expected-observed)} extra={sorted(observed-expected)}"
    )
for relative in sorted(expected):
    target = Path(relative)
    if not target.is_file() or target.is_symlink():
        raise SystemExit(f"generated Markdown is not a regular file: {relative}")
subprocess.run(["git", "add", "--", *sorted(expected)], check=True)
tracked = subprocess.run(
    ["git", "ls-files", "-z", "--", *sorted(expected)],
    check=True,
    capture_output=True,
).stdout
tracked_set = {item.decode("utf-8") for item in tracked.split(b"\0") if item}
if tracked_set != expected:
    raise SystemExit("generated Markdown did not enter the exact Git index")
print("generated_markdown_staged=3")
PY_STAGE_DOCS

python3 tools/docs/verify_global_docs.py
''').removeprefix("\n")
if text.count(docs_anchor) != 1:
    raise SystemExit("controller documentation verification anchor differs")
text = text.replace(docs_anchor, docs_stage, 1)

path.write_text(text, encoding="utf-8")
PY_PATCHER

exec bash "$effective"
