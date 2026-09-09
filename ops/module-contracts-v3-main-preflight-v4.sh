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
path.write_text(text, encoding="utf-8")
PY_PATCHER

exec bash "$effective"
