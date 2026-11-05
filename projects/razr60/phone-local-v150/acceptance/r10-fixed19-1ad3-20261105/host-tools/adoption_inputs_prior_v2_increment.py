"""Pure exact source increment for the reviewed nine-source live02 generator.

This file is a generator aid, not a tenth runtime dependency. It never reads
files, invokes a verifier, creates adoption, or changes an existing source.
Apply to the retained adoption-input assembler before or after support-pin
filling. An already changed body is rejected; the increment reverses exactly.
"""
import ast
import hashlib

BASE_SHA256 = '014cff239d95be5996f34920f459ccc3caa7f2bdac48957d2c6242fd84853fce'

BEFORE = "    root=V.strict(add(live['root_plan']))\n"
AFTER = BEFORE + (
    "    H.need(root['schema']=='hepta.root.runtime-properties-live-plan.v2'\n"
    "        and root['prior_failed_transaction']==V.PRIOR_FAILED_TRANSACTION,\n"
    "        'exact live02 plan and failed live01 predecessor required')\n"
    "    prior_raw=add(root['prior_failed_transaction'])\n"
    "    V.verify_prior_failed_transaction(prior_raw,read_pinned=add)\n"
)


def apply(source):
    if type(source) is not str or source.count(BEFORE) != 1 or AFTER in source:
        raise ValueError('one unchanged reviewed adoption root-plan read required')
    if 'verify_prior_failed_transaction' in source:
        raise ValueError('adoption prior-verifier increment already present')
    declarations = [node for node in ast.parse(source).body
        if isinstance(node, ast.Assign) and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'HOST_SUPPORT_SHA256']
    if len(declarations) != 1 or declarations[0].lineno != declarations[0].end_lineno:
        raise ValueError('one reviewed host-support declaration required')
    node = declarations[0]
    value = ast.literal_eval(node.value)
    if value is not None and not (type(value) is str and len(value) == 64
            and all(char in '0123456789abcdef' for char in value)):
        raise ValueError('reviewed support pin or unfilled declaration required')
    lines = source.splitlines(keepends=True)
    line = lines[node.lineno-1]
    lines[node.lineno-1] = line[:node.value.col_offset] + 'None' + line[node.value.end_col_offset:]
    if hashlib.sha256(''.join(lines).encode('utf-8')).hexdigest() != BASE_SHA256:
        raise ValueError('adoption assembler differs beyond its reviewed support pin')
    result = source.replace(BEFORE, AFTER, 1)
    compile(result, '<reviewed-adoption-inputs-with-live02-prior>', 'exec')
    if result.count(AFTER) != 1 or result.replace(AFTER, BEFORE, 1) != source:
        raise ValueError('adoption prior increment is not exactly reversible')
    return result
