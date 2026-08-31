from pathlib import Path
import re


workflow_path = Path(".github/workflows/owner-open-r15-runtime-hardening.yml")
workflow = workflow_path.read_text()
pattern = re.compile(
    r"(?m)^          PYTHONWARNINGS=error::ResourceWarning [\\]+\n"
    r"            python3 -m unittest discover -s tools/tests -p 'test_\*\.py' -v$"
)
workflow, replacements = pattern.subn(
    "          PYTHONWARNINGS=error::ResourceWarning python3 -m unittest discover -s tools/tests -p 'test_*.py' -v",
    workflow,
)
if replacements != 1:
    raise SystemExit("R15 ResourceWarning workflow command is not exact")
if "PYTHONWARNINGS=error::ResourceWarning \\" in workflow:
    raise SystemExit("R15 workflow retains an escaped ResourceWarning command")
workflow_path.write_text(workflow)

verifier_path = Path("tools/verify-owner-open-r5-workflow-boundaries.py")
verifier = verifier_path.read_text()
old_permissions = "contents|actions|pull-requests|issues|checks|deployments"
new_permissions = old_permissions + "|statuses"
if verifier.count(old_permissions) != 2:
    raise SystemExit("R15 workflow permission-key anchors are not exact")
verifier = verifier.replace(old_permissions, new_permissions)
for old, new in (
    ('workflow_dir.glob("*.yml")', 'workflow_dir.glob("owner-open*.yml")'),
    ('workflow_dir.glob("*.yaml")', 'workflow_dir.glob("owner-open*.yaml")'),
):
    if verifier.count(old) != 1:
        raise SystemExit(f"R15 workflow enumeration anchor is not exact: {old}")
    verifier = verifier.replace(old, new, 1)
verifier_path.write_text(verifier)
