#!/usr/bin/env python3
"""Create-only source generation for the reviewed R8 negative/direct operators.

A separately reviewed revision must bind four actual host originals. Default
preview reads no source package, case, private input or final release. Generation
changes only named source literals and corresponding source manifests; it does
not call any product main, create a task/nonce, run a collector, issue a phone
command, build/install/seal a release, or produce READY/physical qualification.
"""
import argparse
import ast
import copy
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
B = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
FINALIZATION = None
FINAL_SCHEMA = 'hepta.r10.property-negative-source-finalization.v1'
FC = B/'r10-boundary-consumers-final-r8'
AC = B/'scoped-acceptance-v150-r10-r1-readiness-r9'
OUT = B/'property-r8-negative-source-generation-final01'
OUTPUTS = {
    'ui': B/'cancel-native-r10-r1-property-r8-operator-r1',
    'fault': B/'fault-signal-r10-r1-property-r8-operator-r1',
    'component': B/'fixed19-comp01-neg03-property-r8-operator-r1',
    'cpu': B/'cpu-cancel-original-verifier-property-r8-operator-r1',
    'p4': B/'cpu-cancel-p4-original-capture-property-r8-operator-r1',
    'phone': B/'cpu-cancel-negative-phone-capture-property-r8-operator-r1'}
PARENT_MANIFESTS = {
    'ui': {'path':str(B/'cancel-native-r10-r1-host-candidate05/MANIFEST.json'),
        'bytes':4262, 'sha256':'65720e417594205b45172fe509f3419d607d3dbf1e579b2a17faa8b40315ca10'},
    'fault': {'path':str(B/'fault-signal-r10-r1-operator-final05/MANIFEST.json'),
        'bytes':2517, 'sha256':'fff728422175cc90a9e818b3b32da873c70c95de269994ebe9c097b770cfc619'},
    'component': {'path':str(B/'fixed19-comp01-neg03-r7-source-candidate01/MANIFEST.json'),
        'bytes':1469, 'sha256':'669b344d40cda3412f0eae806b1db53585342d07eee154fd766913ae889b59ce'}}
DIRECT_PARENTS = {
    'cpu': {'path':str(B/'cpu-cancel-original-verifier-r2-ledger-prefix-candidate01/source/cpu_cancel_originals.py'),
        'bytes':60828, 'sha256':'88fd6ca9ed46e99082d30d25ba5b1aaf9cdc8d071cf0705c62ca933f50a1e531'},
    'p4': {'path':str(B/'cpu-cancel-p4-original-capture-r1-candidate02/source/capture_p4_cancel_originals.py'),
        'bytes':31418, 'sha256':'a66d5e4de27912716748f53a599c513ea46bb81415d64ec184e91e4744c122c2'},
    'phone': {'path':str(B/'cpu-cancel-negative-phone-capture-r1-candidate03/source/capture_negative_originals.py'),
        'bytes':44102, 'sha256':'79ed15ea8b23662c091bd64bcdc63d972b18cd9552f5af9fa2d825ddd75cd082'}}
SOURCE_REFERENCES = {
    'consumer_template': {'path':str(B/'property-r8-lossless-bundle-generators-candidate01/templates/release_boundaries.py'),
        'bytes':77700, 'sha256':'619589ce59c209d491f1994d67008327604ce07894d101a278c3ebc06052a5f1'},
    'readiness_parent': {'path':str(B/'r10-boundary-consumers-final-r7/source/collect_r10_readiness.py'),
        'bytes':16405, 'sha256':'345723406df0c523ab55b167bb52f5ceb9432d387ffe3b4aa5b1e5442465e392'},
    'materializer': {'path':str(B/'scoped-acceptance-v150-r10-r1-readiness-r8/operator/materialize_case_r10.py'),
        'bytes':24834, 'sha256':'b25125bc0e204ea7aefde6f2a17fa2fb8e5edf132a4b62dfbb546964c1c09290'}}
UI_NAMES = {'source/'+name for name in (
    'active_runtime_r10.py','cancel_native_once_r10.py','cancel_phase.py',
    'decode_client_state.py','native_journal_audit.py','observe_cancel_phase_r10.py',
    'production-pins.json','reviewed_page_projection.py')}
FAULT_NAMES = {'source/'+name for name in (
    'active_runtime_r10.py','cancel_phase.py','native_journal_audit.py',
    'observe_cancel_phase_r10.py','observe_carrier_r10.py','production-pins.json',
    'reviewed_page_projection.py','signal_fault_once_r10.py')}
COMPONENT_NAMES = {'source/component_source_context.py','source/prepare_direct_return_component.py',
    'source/verify_unqualified_geometry_fixture.py','reference/original-protocol.json',
    'reference/host_negative_runner.original.py','INTERFACE.json',
    'COMP01-PLAN.template.json','NEG03-PLAN.template.json'}
CONFIG_SHA = '780754928709871d3e70f432acb6a021c6c97ab822aaf7c32c887c132cac8c34'
SERVICE_SHA = '2739a0af53650363e065bb71a448481998c68fc8b8632e61262c319dae6b586a'
MIGRATION_PARENT_SHA = 'bfe7acc92ba8c5b7a3a1c2360d6faf53f804a19c3e25e20aad336e3220fa0e38'
OLD_POLICY_SHA = '50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7'
OLD_ADOPTION_SHA = 'a5f94e24ead8b7b811025197439ddbfa762d05eaf7d1de2a5f61f26d9502ebd5'
OLD_RUNTIME_SHA = '683481bdb653bd7cb97bd6171d6b14f6ecaf4f9948ed2691c7b7c420fea5fe3c'
OLD_COMBINATION_SHA = 'ba5c590860bb7502910617e84d90329a191c5a91e6ace84fb7f8e45b1a556837'
OLD_CONSUMER_SHA = 'a791a7493fe8544aa44b910dd627f405f71678a048f9df94df91529a54fdf703'
PROPERTY_HEAD_SHA = 'eca941303197228ebe03561e612bfe41eb0518c590ff21253444db25a11adc10'
ACTOR_SHA = 'd973891aa125ce2deb2237064fbc101d5d9d915d9e4bd75e25e4da298eecd5f1'
ACTIVE_PARENT_SHA = 'f1a68fcc420799a7221019afdcda046a8d297b23d674e1e2642e888df26635dd'
META = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
MAX_ORIGINAL = 16*1024*1024
MAX_HELPER = 131072
MAX_TOTAL = 64*1024*1024
HASH = re.compile(r'[0-9a-f]{64}\Z')

def need(value, message):
    if not value:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def pin(raw):
    return {'bytes':len(raw), 'sha256':sha(raw)}

def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2,
        allow_nan=False)+'\n').encode('utf-8')

def strict(raw):
    def pairs(rows):
        out = {}
        for name,value in rows:
            need(name not in out, 'duplicate JSON field')
            out[name] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))

def metadata(value):
    return [getattr(value,name) for name in META]

def absolute(path):
    need(type(path) is str and path.startswith('/') and '\0' not in path
         and all(v not in ('','.','..') for v in path[1:].split('/'))
         and str(Path(path)) == path, 'canonical absolute path spelling required')
    return Path(path)

def relative(path):
    need(type(path) is str and path and not path.startswith('/') and '\0' not in path
         and all(v not in ('','.','..') for v in path.split('/'))
         and str(Path(path)) == path, 'canonical relative path spelling required')
    return Path(path)

def descriptor(row, maximum=MAX_ORIGINAL):
    need(type(row) is dict and set(row) == {'path','bytes','sha256'},
         'exact original descriptor required')
    absolute(row['path'])
    need(type(row['bytes']) is int and 0 < row['bytes'] <= maximum
         and type(row['sha256']) is str and HASH.fullmatch(row['sha256']),
         'positive bounded exact original pin required')
    return row

class Originals:
    def __init__(self):
        self.rows = {}
        self.directories = {}
        self.total = 0
    def read(self, row, maximum=MAX_ORIGINAL):
        descriptor(row, maximum)
        path = absolute(row['path'])
        need(path.resolve(strict=True) == path, 'original is not canonical')
        fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and before.st_size == row['bytes'], 'original type or size differs')
            with os.fdopen(fd,'rb',closefd=False) as stream:
                raw = stream.read(row['bytes']+1)
            need(pin(raw) == {k:row[k] for k in ('bytes','sha256')}
                 and metadata(before) == metadata(os.fstat(fd)) == metadata(path.lstat()),
                 'original changed or pinned bytes differ')
        finally:
            os.close(fd)
        record = dict(row, metadata=metadata(before))
        if str(path) in self.rows:
            need(self.rows[str(path)] == record, 'original changed across reads')
        else:
            self.total += len(raw)
            need(self.total <= MAX_TOTAL, 'host source original budget exceeded')
            self.rows[str(path)] = record
        return raw
    def source_directory(self, root, names):
        path = absolute(str(root))
        need(path.resolve(strict=True) == path, 'noncanonical source directory')
        before = path.lstat()
        need(stat.S_ISDIR(before.st_mode), 'source directory required')
        actual = sorted(os.listdir(path))
        need(actual == sorted(names), 'unindexed source tree entry')
        for name in actual:
            value = (path/name).lstat()
            need(stat.S_ISREG(value.st_mode) and value.st_nlink == 1,
                 'source member must be a single regular file')
        need(metadata(before) == metadata(path.lstat()), 'source directory changed')
        record = {'path':str(path),'metadata':metadata(before),'names':actual}
        need(str(path) not in self.directories or self.directories[str(path)] == record,
             'source directory changed across observations')
        self.directories[str(path)] = record
    def recheck(self):
        for row in list(self.rows.values()):
            self.read({k:row[k] for k in ('path','bytes','sha256')}, max(MAX_ORIGINAL,row['bytes']))
        for row in list(self.directories.values()):
            self.source_directory(Path(row['path']),row['names'])

def package_index(raw, expected_schema):
    value = strict(raw)
    need(type(value) is dict and value.get('schema') == expected_schema,
         'source manifest schema differs')
    key = 'runtime_sources' if expected_schema == 'hepta.r10.signal-fault-package.v1' else 'files'
    rows = value.get(key)
    need(type(rows) is list and 1 <= len(rows) <= 512, 'bounded source manifest index required')
    index = {}
    for row in rows:
        need(type(row) is dict and set(row) == {'path','bytes','sha256'}, 'exact relative source row required')
        relative(row['path'])
        need(row['path'] not in index and type(row['bytes']) is int and 0 < row['bytes'] <= MAX_ORIGINAL
             and type(row['sha256']) is str and HASH.fullmatch(row['sha256']), 'source row duplicate or bound')
        index[row['path']] = row
    return value,index

def member(originals, root, index, name, maximum=MAX_ORIGINAL):
    need(name in index, 'missing manifest member: '+name)
    row = index[name]
    return originals.read(dict(row,path=str(root/relative(name))),maximum)

def assignment(raw, name):
    nodes = [n for n in ast.parse(raw).body if isinstance(n,ast.Assign)
        and len(n.targets) == 1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id == name]
    need(len(nodes) == 1, 'one top-level source assignment required: '+name)
    return nodes[0].value

def value(raw, name):
    return ast.literal_eval(assignment(raw,name))

def target(raw, name, key=None):
    node = assignment(raw,name)
    if key is not None:
        need(isinstance(node,ast.Dict), 'literal dictionary required: '+name)
        keys = [ast.literal_eval(k) for k in node.keys]
        need(len(keys) == len(set(keys)) and keys.count(key) == 1, 'one literal dictionary key required')
        node = node.values[keys.index(key)]
    return node

def span(raw,node):
    lines = raw.splitlines(keepends=True)
    start = sum(map(len,lines[:node.lineno-1]))+node.col_offset
    end = sum(map(len,lines[:node.end_lineno-1]))+node.end_col_offset
    need(0 <= start < end <= len(raw), 'source span out of bounds')
    return start,end

def replace_literal(raw, name, expression, key=None):
    node = target(raw,name,key)
    before = span(raw,node)
    new = expression.encode('ascii')
    expression_node = ast.parse(new,mode='eval').body
    need(isinstance(expression_node,(ast.Constant,ast.Dict,ast.Tuple,ast.BinOp,ast.Call)),
         'bounded reviewed source literal expression required')
    result = raw[:before[0]]+new+raw[before[1]:]
    ast.parse(result)
    return result,{'name':name,'key':key,'before':raw[before[0]:before[1]].decode('utf-8'),
        'after':expression}

def inverse(raw, edits, parent):
    result = raw
    for edit in reversed(edits):
        node = target(result,edit['name'],edit['key'])
        a,b = span(result,node)
        need(result[a:b].decode('utf-8') == edit['after'], 'inverse target is not the exact frozen literal')
        result = result[:a]+edit['before'].encode('utf-8')+result[b:]
    need(result == parent, 'whole source literal inverse differs from reviewed parent')
    return True

def functions(raw):
    return {n.name:ast.get_source_segment(raw.decode('utf-8'),n)
        for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))}

def changed_source(parent, changes):
    raw = parent
    edits = []
    for name,key,expression in changes:
        raw,edit = replace_literal(raw,name,expression,key)
        edits.append(edit)
    inverse(raw,edits,parent)
    need(functions(raw) == functions(parent), 'a product function/class body changed')
    compile(raw,'reviewed-literal-derived-source','exec',optimize=0)
    return raw,edits

def finalization():
    value = FINALIZATION
    need(type(value) is dict and set(value) == {'schema','consumer_manifest','acceptance_manifest',
         'policy_adoption','current_policy'} and value['schema'] == FINAL_SCHEMA,
         'actual future source-generation dependencies are not frozen')
    for name in ('consumer_manifest','acceptance_manifest','policy_adoption','current_policy'):
        descriptor(value[name])
    need(value['consumer_manifest']['path'] == str(FC/'MANIFEST.json')
         and value['acceptance_manifest']['path'] == str(AC/'MANIFEST.json'),
         'only the reviewed FC8 and AC9 source namespaces may be finalized')
    need(value['current_policy']['sha256'] not in (OLD_POLICY_SHA,
         '296b09d9c844d2916b0dbdb0765c71cbcb8411790b58f5823798aa872205b659')
         and value['policy_adoption']['sha256'] not in (OLD_ADOPTION_SHA,
         '7899e446ef77d9f05aab7f22298ff9470e04a5253c2397ec6cf292543daac87e'),
         'an old policy/adoption cannot be finalized as current')
    return value

def parent_packages(originals):
    out = {}
    schemas = {'ui':'hepta.r10.native-cancel-operator-package.v1',
        'fault':'hepta.r10.signal-fault-package.v1','component':'hepta.fixed19.comp01-neg03.source-package.v1'}
    expected = {'ui':UI_NAMES,'fault':FAULT_NAMES,'component':COMPONENT_NAMES}
    for kind,row in PARENT_MANIFESTS.items():
        raw = originals.read(row,65536)
        parsed,index = package_index(raw,schemas[kind])
        need(set(index) == expected[kind], 'exact parent member set differs: '+kind)
        root = Path(row['path']).parent
        files = {name:member(originals,root,index,name) for name in index}
        originals.source_directory(root/'source',{Path(n).name for n in files if n.startswith('source/')})
        out[kind] = {'raw':raw,'value':parsed,'files':files}
    for kind,row in DIRECT_PARENTS.items():
        raw = originals.read(row,131072)
        originals.source_directory(Path(row['path']).parent,{Path(row['path']).name})
        out[kind] = {'raw':raw}
    need(sha(out['ui']['files']['source/active_runtime_r10.py']) == ACTIVE_PARENT_SHA
         and out['fault']['files']['source/active_runtime_r10.py'] == out['ui']['files']['source/active_runtime_r10.py'],
         'the two parent packages must contain the same exact shared active source')
    need(sha(out['ui']['files']['source/cancel_native_once_r10.py']) == ACTOR_SHA
         and value(out['cpu']['raw'],'UI_PACKAGE_SHA') == PARENT_MANIFESTS['ui']['sha256'],
         'reviewed Actor or CPU parent UI binding differs')
    need(value(out['cpu']['raw'],'OPERATOR_SOURCES') == {
        Path(n).name:sha(body) for n,body in out['ui']['files'].items()},
         'all eight original CPU operator source bindings differ')
    need(value(out['ui']['files']['source/active_runtime_r10.py'],'PARENT_POLICY_SHA') == MIGRATION_PARENT_SHA,
         'the module migration baseline is not this policy transaction parent')
    return out

def actual_dependencies(originals, frozen):
    fc_raw = originals.read(frozen['consumer_manifest'],65536)
    fc,fc_index = package_index(fc_raw,'hepta.r10.final-boundary-consumers.v8')
    ac_raw = originals.read(frozen['acceptance_manifest'],65536)
    ac,ac_index = package_index(ac_raw,'hepta.r10.scoped-acceptance-package.v1')
    fixed_raw = member(originals,FC,fc_index,'reference/ROOT-REVIEWED-FINALIZATION.json')
    fixed = strict(fixed_raw)
    need(type(fixed) is dict and set(fixed) == {'schema','runtime_manifest','component_combination',
         'policy_adoption','policy_verifier','actual_policy','scope_decision','full_rule'}
         and fixed['schema'] == 'hepta.property-policy.final-pin-freeze.v1',
         'FC8 actual finalization source differs')
    for name in ('runtime_manifest','component_combination','policy_adoption','policy_verifier','scope_decision','full_rule'):
        descriptor(fixed[name],MAX_HELPER if name == 'policy_verifier' else MAX_ORIGINAL)
    policy_raw = originals.read(frozen['current_policy'])
    adoption_raw = originals.read(frozen['policy_adoption'])
    need(fixed['policy_adoption'] == frozen['policy_adoption']
         and fixed['actual_policy'] == pin(policy_raw)
         and fc['actual_policy_adoption_sha256'] == sha(adoption_raw),
         'FC8 actual policy/adoption does not match the explicitly frozen originals')
    need(member(originals,FC,fc_index,'reference/ACTUAL-PROPERTY-POLICY-ADOPTION.original.json') == adoption_raw,
         'FC8 adoption copy is not the same original bytes')
    need(fixed['runtime_manifest']['path'] == str(B/'native-guard-r10-r1-operator-r8/runtime/MANIFEST.json'),
         'only the actual reviewed R8 runtime manifest may supply this source generation')
    runtime_raw = originals.read(fixed['runtime_manifest'],65536)
    runtime = strict(runtime_raw)
    runtime_rows = runtime.get('files')
    need(type(runtime_rows) is list and len(runtime_rows) == 32
         and len({r['path'] for r in runtime_rows}) == 32
         and 'reference/property_parent_late_boundary_r7.py' in {r['path'] for r in runtime_rows}
         and fixed['runtime_manifest']['sha256'] != OLD_RUNTIME_SHA
         and fc['component_package_sha256'] == sha(runtime_raw), 'exact actual R8 source container differs')
    for row in runtime_rows:
        need(type(row) is dict and set(row) == {'path','bytes','sha256'}, 'exact runtime source row required')
        relative(row['path'])
        need(type(row['bytes']) is int and 0 < row['bytes'] <= MAX_ORIGINAL
             and type(row['sha256']) is str and HASH.fullmatch(row['sha256']), 'runtime source row bound')
    combo_raw = originals.read(fixed['component_combination'])
    combo = strict(combo_raw)
    need(member(originals,FC,fc_index,'reference/ACTUAL-CURRENT-COMBINATION.original.json') == combo_raw
         and sha(combo_raw) != OLD_COMBINATION_SHA
         and combo['live_policy_sha256'] == sha(policy_raw)
         and combo['configuration']['sha256'] == CONFIG_SHA
         and combo['service_inputs']['sha256'] == SERVICE_SHA, 'current combination or shared17 changed')
    verifier_raw = originals.read(fixed['policy_verifier'],MAX_HELPER)
    scope_raw = originals.read(fixed['scope_decision'])
    full_rule_raw = originals.read(fixed['full_rule'])
    checks_raw = member(originals,FC,fc_index,'validation/ACTUAL-POLICY-AND-TAIL-RECHECK.json')
    checks = strict(checks_raw)
    summary = checks['actual_policy_adoption']
    need(checks['schema'] == 'hepta.property-policy.final-source-original-checks.v1'
         and pin(checks_raw) == fc['actual_original_checks']
         and summary['runtime_policy'] == pin(policy_raw)
         and summary['current_adoption_sha256'] == sha(adoption_raw)
         and summary['parent_adoption_sha256'] == OLD_ADOPTION_SHA
         and summary['parent_policy'] == {'bytes':2667608,'sha256':OLD_POLICY_SHA}
         and summary['prior_boundary_sha256'] == PROPERTY_HEAD_SHA
         and summary['root_scope_decision_sha256'] == sha(scope_raw)
         and summary['full_rule'] == fixed['full_rule']
         and checks['scope_decision'] == fixed['scope_decision']
         and checks['full_rule'] == fixed['full_rule']
         and checks['runtime_file_count'] == 32
         and checks['runtime_exact_paths'] == sorted(r['path'] for r in runtime_rows)
         and checks['property_parent_boundary_sha256'] == PROPERTY_HEAD_SHA
         and checks['historical_native_failed_case_count'] == 5
         and checks['non_native_case_count'] == 0
         and checks['non_native_roles_in_component_activation'] is True,
         'FC8 pinned original policy/history recheck receipt differs')
    need(fc['component_input_schema'] == 'hepta.r10.component-boundary-inputs.v5'
         and fc['exact_boundary_member_maximum_bytes'] == 32*1024*1024
         and checks['exact_boundary_member_maximum_bytes'] == 32*1024*1024
         and fc['new_component_qualification'] is False
         and checks['current_case_credit'] is False,
         'source-only FC8 state or unchanged whole-bundle bound differs')
    helper = member(originals,FC,fc_index,'source/release_boundaries.py',MAX_HELPER)
    template = originals.read(SOURCE_REFERENCES['consumer_template'],MAX_HELPER)
    expected = {'PACKAGE_SHA':sha(runtime_raw), 'CURRENT_COMBINATION_SHA':sha(combo_raw),
        'POLICY_VERIFIER_SHA':sha(verifier_raw), 'POLICY_VERIFIER_BYTES':len(verifier_raw),
        'CURRENT_POLICY_SHA':sha(policy_raw),'CURRENT_POLICY_ADOPTION_SHA':sha(adoption_raw),
        'CURRENT_SCOPE_DECISION_SHA':sha(scope_raw)}
    rebuilt,helper_edits = changed_source(template,[(name,None,repr(v)) for name,v in expected.items()])
    need(helper == rebuilt and value(helper,'PACKAGE_FILE_COUNT') == 32
         and ast.dump(assignment(helper,'MAX_BUNDLE'),include_attributes=False) ==
             ast.dump(ast.parse('32*1024*1024',mode='eval').body,include_attributes=False),
         'actual helper must be only seven literal bindings of c844')
    readiness = member(originals,FC,fc_index,'source/collect_r10_readiness.py',262144)
    prior_readiness = originals.read(SOURCE_REFERENCES['readiness_parent'],262144)
    rebuilt,readiness_edits = changed_source(prior_readiness,
        [('BOUNDARY_CONSUMER_SHA256',None,repr(sha(helper)))])
    need(readiness == rebuilt, 'readiness differs beyond its one actual helper literal')
    materializer = member(originals,AC,ac_index,'operator/materialize_case_r10.py')
    need(materializer == originals.read(SOURCE_REFERENCES['materializer']),
         'the actual AC9 materializer must remain exact b251')
    ac_note = strict(member(originals,AC,ac_index,'READINESS-R9-FINAL.json'))
    need(ac_note['schema'] == 'hepta.r10.scoped-acceptance-readiness-increment.v9'
         and ac_note['final_consumer_manifest_sha256'] == sha(fc_raw)
         and ac_note['component_package_sha256'] == sha(runtime_raw)
         and ac_note['final_readiness_helper'] == pin(readiness)
         and ac_note['materializer'] == pin(materializer)
         and ac['derivation']['final_consumer_manifest_sha256'] == sha(fc_raw)
         and ac['derivation']['final_readiness_helper_sha256'] == sha(readiness),
         'AC9 source-generation linkage differs; its MANIFEST is package.v1, not increment.v9')
    return {'consumer':pin(helper),'readiness':pin(readiness),'runtime':pin(runtime_raw),
        'combination':pin(combo_raw),'policy':pin(policy_raw),'adoption':pin(adoption_raw),
        'verifier':pin(verifier_raw),'scope':pin(scope_raw),'full_rule':pin(full_rule_raw),
        'consumer_manifest':frozen['consumer_manifest'],'acceptance_manifest':frozen['acceptance_manifest'],
        'actual_policy_source':frozen['current_policy'],'policy_adoption_source':frozen['policy_adoption'],
        'fc_finalization_source':dict(fc_index['reference/ROOT-REVIEWED-FINALIZATION.json'],
            path=str(FC/'reference/ROOT-REVIEWED-FINALIZATION.json')),
        'fc_recheck_source':dict(fc_index['validation/ACTUAL-POLICY-AND-TAIL-RECHECK.json'],
            path=str(FC/'validation/ACTUAL-POLICY-AND-TAIL-RECHECK.json')),
        'helper_literal_reverse':helper_edits,'readiness_literal_reverse':readiness_edits,
        'independent_adoption_or_case_verifier_executed':False}

def rowset(files):
    return [dict(path=name,**pin(body)) for name,body in sorted(files.items())]

def diff(before, after, family):
    chunks = []
    for name in sorted(set(before)|set(after)):
        if before.get(name) != after.get(name):
            chunks.extend(difflib.unified_diff(before.get(name,b'').decode('utf-8').splitlines(True),
                after.get(name,b'').decode('utf-8').splitlines(True),
                fromfile='parent/'+family+'/'+name,tofile='r8/'+family+'/'+name))
    return ''.join(chunks).encode('utf-8')

def derive_packages(parents, binding):
    ui = dict(parents['ui']['files'])
    fault = dict(parents['fault']['files'])
    comp = dict(parents['component']['files'])
    edits = {}
    active,edits['active'] = changed_source(ui['source/active_runtime_r10.py'],[
        ('CONSUMER_SHA',None,repr(binding['consumer']['sha256'])),
        ('READINESS_SHA',None,repr(binding['readiness']['sha256'])),
        ('POLICY_SHA',None,repr(binding['policy']['sha256'])),
        ('ADOPTION_SHA',None,repr(binding['adoption']['sha256']))])
    need(value(active,'PARENT_POLICY_SHA') == MIGRATION_PARENT_SHA,
         'the unchanged module migration parent was not retained')
    ui['source/active_runtime_r10.py'] = active
    fault['source/active_runtime_r10.py'] = active
    need(all(ui[n] == parents['ui']['files'][n] for n in UI_NAMES-{'source/active_runtime_r10.py'})
         and all(fault[n] == parents['fault']['files'][n] for n in FAULT_NAMES-{'source/active_runtime_r10.py'}),
         'UI/fault non-active source bytes changed')
    um = copy.deepcopy(parents['ui']['value'])
    um.update(files=rowset(ui), parent_candidate_manifest_sha256=PARENT_MANIFESTS['ui']['sha256'],
        revision='property-r8-four-explicit-source-literals',
        expected_live_policy_sha256=binding['policy']['sha256'],
        reviewed_policy_adoption_sha256=binding['adoption']['sha256'],
        reviewed_boundary_consumer_sha256=binding['consumer']['sha256'],
        reviewed_readiness_sha256=binding['readiness']['sha256'],
        reviewed_component_runtime_manifest_sha256=binding['runtime']['sha256'],
        reviewed_final_consumer_manifest_sha256=binding['consumer_manifest']['sha256'],
        shared_observer_manifest_relationship='one_actual_active_raw_source_four_literal_inverse_to_f1a68')
    need(um['actual_runtime_ready'] is False and um['physical_qualification'] is False
         and um['real_nonces_generated'] == um['phone_calls'] == um['model_requests'] == 0,
         'source generation cannot supply a READY, task or qualification')
    ui_raw = encoded(um)
    ui['MANIFEST.json'] = ui_raw
    fm = copy.deepcopy(parents['fault']['value'])
    fm.update(runtime_sources=rowset(fault),parent_candidate_manifest_sha256=PARENT_MANIFESTS['fault']['sha256'],
        expected_live_policy_sha256=binding['policy']['sha256'],
        reviewed_policy_adoption_sha256=binding['adoption']['sha256'],
        reviewed_boundary_consumer_sha256=binding['consumer']['sha256'],
        reviewed_readiness_sha256=binding['readiness']['sha256'],
        reviewed_component_runtime_sha256=binding['runtime']['sha256'],
        reviewed_final_consumer_manifest_sha256=binding['consumer_manifest']['sha256'])
    need(fm['actual_task_bound'] is False and fm['actual_r10_ready_bound'] is False
         and fm['physical_case_pass'] is False and fm['phone_calls'] == 0,
         'fault source generation cannot supply an actual task')
    fault['MANIFEST.json'] = encoded(fm)
    context,edits['component'] = changed_source(comp['source/component_source_context.py'],[
        ('MATERIALIZER',None,"B/'scoped-acceptance-v150-r10-r1-readiness-r9/operator/materialize_case_r10.py'"),
        ('CONSUMER',None,"B/'r10-boundary-consumers-final-r8/source/release_boundaries.py'"),
        ('CONSUMER_PIN',None,repr((binding['consumer']['bytes'],binding['consumer']['sha256']))),
        ('READINESS_PIN',None,repr((binding['readiness']['bytes'],binding['readiness']['sha256']))),
        ('RUNTIME_SHA',None,repr(binding['runtime']['sha256'])),
        ('POLICY_SHA',None,repr(binding['policy']['sha256'])),
        ('ADOPTION_SHA',None,repr(binding['adoption']['sha256']))])
    comp['source/component_source_context.py'] = context
    need(all(comp[n] == parents['component']['files'][n]
         for n in COMPONENT_NAMES-{'source/component_source_context.py'}), 'a component fixture/direct helper changed')
    interface_parent = comp['INTERFACE.json']
    interface = interface_parent
    old_root = str(Path(PARENT_MANIFESTS['component']['path']).parent).encode()
    new_root = str(OUTPUTS['component']).encode()
    need(interface.count(old_root) == 3 and interface.count(OLD_RUNTIME_SHA.encode()) == 1,
         'only the three original component interface paths and one runtime identity may change')
    interface = interface.replace(old_root,new_root).replace(OLD_RUNTIME_SHA.encode(),binding['runtime']['sha256'].encode())
    need(interface.replace(new_root,old_root).replace(binding['runtime']['sha256'].encode(),OLD_RUNTIME_SHA.encode())
         == interface_parent, 'complete component interface inverse differs')
    interface_value = strict(interface)
    need(interface_value['package_root'] == str(OUTPUTS['component'])
         and interface_value['sealed_release_required']['component_runtime_sha256'] == binding['runtime']['sha256']
         and all(v is None for v in interface_value['future_inputs'].values()),
         'component interface cannot supply an actual release, identity or result')
    comp['INTERFACE.json'] = interface
    edits['component_interface'] = {'package_path_replacements':3,'runtime_replacements':1,
        'whole_inverse':True,'other_interface_bytes_unchanged':True}
    cm = copy.deepcopy(parents['component']['value'])
    cm['files'] = rowset(comp)
    comp['MANIFEST.json'] = encoded(cm)
    cpu,edits['cpu'] = changed_source(parents['cpu']['raw'],[
        ('UI_PACKAGE_SHA',None,repr(sha(ui_raw))),
        ('OPERATOR_SOURCES','active_runtime_r10.py',repr(sha(active))),
        ('POLICY_SHA',None,repr(binding['policy']['sha256'])),
        ('ADOPTION_SHA',None,repr(binding['adoption']['sha256']))])
    need(value(cpu,'OPERATOR_SOURCES') == {Path(n).name:sha(body)
         for n,body in ui.items() if n.startswith('source/')},
         'new CPU source must bind the same complete eight UI originals')
    p4,edits['p4'] = changed_source(parents['p4']['raw'],[
        ('REVIEWED_OPERATOR_PACKAGE_SHA256',None,repr(sha(ui_raw))),
        ('REVIEWED_ACTIVE_SOURCE_SHA256',None,repr(sha(active))),
        ('REVIEWED_CPU_VERIFIER_SOURCE_SHA256',None,repr(sha(cpu)))])
    old_phone = value(parents['phone']['raw'],'FINAL_DEPENDENCIES')
    need(type(old_phone) is dict and len(old_phone) == 10
         and old_phone['configuration_sha256'] == CONFIG_SHA
         and old_phone['service_inputs_sha256'] == SERVICE_SHA,'phone exact10 dependency parent differs')
    phone_values = {'runtime_package_sha256':binding['runtime']['sha256'],
        'consumer_sha256':binding['consumer']['sha256'],'readiness_sha256':binding['readiness']['sha256'],
        'ui_package_sha256':sha(ui_raw),'active_source_sha256':sha(active),
        'cpu_verifier_sha256':sha(cpu),'policy_adoption_sha256':binding['adoption']['sha256'],
        'live_policy':binding['policy']}
    phone,edits['phone'] = changed_source(parents['phone']['raw'],
        [('FINAL_DEPENDENCIES',name,repr(v)) for name,v in phone_values.items()])
    expected_phone = dict(old_phone,**phone_values)
    need(value(phone,'FINAL_DEPENDENCIES') == expected_phone,
         'only eight of the ten phone dependencies may change')
    packages = {'ui':ui,'fault':fault,'component':comp}
    for kind,body,basename in [('cpu',cpu,'cpu_cancel_originals.py'),
        ('p4',p4,'capture_p4_cancel_originals.py'),('phone',phone,'capture_negative_originals.py')]:
        files = {'source/'+basename:body}
        files['SOURCE-MANIFEST.json'] = encoded({
            'schema':'hepta.r10.property-negative-literal-source-package.v1',
            'state':'SOURCE_PINS_BOUND_ACTUAL_CASE_AND_CAPTURE_NOT_EXECUTED',
            'parent_source':DIRECT_PARENTS[kind],
            'files':rowset(files),'physical_qualification':False,'phone_calls':0,'model_requests':0,
            'new_nonces':0})
        packages[kind] = files
    proof = {'schema':'hepta.r10.property-negative-source-literal-proof.v1',
        'active_one_source_shared_by_ui_and_fault':ui['source/active_runtime_r10.py'] == fault['source/active_runtime_r10.py'],
        'edits':edits,'whole_inverse_to_each_reviewed_parent':True,
        'all_product_functions_and_classes_byte_identical':True,
        'cpu_parent':DIRECT_PARENTS['cpu'],'cpu_three_original_directories_preserved':True,
        'ui_actor_sha256':ACTOR_SHA,'migration_parent_policy_sha256':MIGRATION_PARENT_SHA,
        'consumer_bytes':binding['consumer']['bytes'],'consumer_source_maximum_bytes':MAX_HELPER,
        'active_installed_helper_existing_limit':262144,'component_exact_helper_existing_limit':1048576,
        'operator_manifest_limit_unchanged':65536,'observer_unpack_limit_unchanged':262144,
        'adb_wire_limit_unchanged':65536,'observe_timeout_seconds_unchanged':8,
        'observe_shell_timeout_seconds_unchanged':12,
        'runtime_file_cap_unchanged':32,'native_chain_cap_unchanged':8,
        'component_role_cap_unchanged':24,'whole_bundle_cap_unchanged':33554432,
        'actual_ready_or_scope_supplied':False,'physical_qualification':False}
    need(len(ui_raw) <= 65536, 'the unchanged Actor manifest reader would reject the generated UI manifest')
    patches = {}
    for kind in ('ui','fault','component'):
        before = dict(parents[kind]['files'],**{'MANIFEST.json':parents[kind]['raw']})
        patches[kind] = diff(before,packages[kind],kind)
    for kind in ('cpu','p4','phone'):
        name = next(n for n in packages[kind] if n.startswith('source/'))
        patches[kind] = diff({name:parents[kind]['raw']},{name:packages[kind][name]},kind)
    return packages,proof,patches

def syncdir(path):
    fd = os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def mkdir_new(path):
    need(path.parent.resolve(strict=True) == path.parent,'new output parent is not canonical')
    path.mkdir(mode=0o700)
    syncdir(path.parent)
    need(stat.S_ISDIR(path.lstat().st_mode) and stat.S_IMODE(path.lstat().st_mode) == 0o700,
         'new private directory metadata differs')

def put(path,raw):
    need(path.parent.resolve(strict=True) == path.parent,'new file parent is not canonical')
    fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        with os.fdopen(fd,'wb',closefd=False) as stream:
            stream.write(raw);stream.flush();os.fsync(fd)
        need(os.fstat(fd).st_size == len(raw),'new file short write')
    finally:
        os.close(fd)
    syncdir(path.parent)
    return {'path':str(path),**pin(raw)}

def write_tree(root,files):
    need('MANIFEST.json' in files or 'SOURCE-MANIFEST.json' in files,'output source manifest required')
    mkdir_new(root)
    directories = {str(Path(n).parent) for n in files}
    expanded = set()
    for name in directories:
        p = Path(name)
        while str(p) != '.':
            expanded.add(str(p));p=p.parent
    for name in sorted(expanded,key=lambda v:(len(Path(v).parts),v)):
        mkdir_new(root/relative(name))
    manifests = {'MANIFEST.json','SOURCE-MANIFEST.json'}
    for name in sorted(files,key=lambda n:(n in manifests,n)):
        put(root/relative(name),files[name])
    expected_dirs = {'.'}|expanded
    actual_files = set()
    actual_dirs = {'.'}
    for parent,names,files_on_disk in os.walk(root,followlinks=False):
        base = Path(parent)
        for name in names:
            p = base/name
            need(stat.S_ISDIR(p.lstat().st_mode) and not p.is_symlink(),'output directory changed')
            actual_dirs.add(str(p.relative_to(root)))
        for name in files_on_disk:
            p = base/name
            rel = str(p.relative_to(root));actual_files.add(rel)
            st = p.lstat()
            need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == 0o600
                 and rel in files,'output member metadata differs')
            fd = os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:
                before=os.fstat(fd)
                with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(len(files[rel])+1)
                need(raw == files[rel] and metadata(before) == metadata(os.fstat(fd)) == metadata(p.lstat()),
                     'output source readback differs')
            finally:os.close(fd)
    need(actual_files == set(files) and actual_dirs == expected_dirs,'complete output source tree differs')
    return [dict(path=str(root/name),**pin(body)) for name,body in sorted(files.items())]

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--execute-source-generation-once',action='store_true')
    p.add_argument('--source-sha256')
    args = p.parse_args()
    if not args.execute_source_generation_once:
        print(encoded({'schema':FINAL_SCHEMA,'state':'SOURCE_ONLY_PREVIEW',
            'future_dependencies_bound':FINALIZATION is not None,
            'outputs':{k:str(v) for k,v in OUTPUTS.items()},'originals_read':0,
            'phone_calls':0,'new_nonces':0,'physical_qualification':False}).decode(),end='')
        return 0
    frozen = finalization()
    need(type(args.source_sha256) is str and HASH.fullmatch(args.source_sha256),
         'the reviewed finalized generator source SHA is mandatory')
    originals = Originals()
    source_path = Path(__file__).resolve(strict=True)
    size = source_path.stat().st_size
    self_raw = originals.read({'path':str(source_path),'bytes':size,'sha256':args.source_sha256},131072)
    need(value(self_raw,'FINALIZATION') == frozen,'actual executing generator finalization differs')
    for path in (OUT,*OUTPUTS.values()):
        need(path.parent == B and path.parent.resolve(strict=True) == path.parent,
             'fixed private output namespace changed')
        try:path.lstat()
        except FileNotFoundError:pass
        else:raise ValueError('source generation output already exists: '+str(path))
    parents = parent_packages(originals)
    binding = actual_dependencies(originals,frozen)
    packages,proof,patches = derive_packages(parents,binding)
    originals.recheck()
    mkdir_new(OUT)
    intent = {'schema':'hepta.r10.property-negative-source-generation-intent.v1',
        'source':pin(self_raw),'finalization':frozen,'outputs':{k:str(v) for k,v in OUTPUTS.items()},
        'automatic_retry':False,'maximum_generations':1,'phone_calls':0,'new_nonces':0,
        'physical_qualification':False}
    put(OUT/'INTENT.json',encoded(intent))
    try:
        put(OUT/'FINALIZATION.original.json',encoded(frozen))
        put(OUT/'GENERATOR.original.py',self_raw)
        delivery = {}
        for kind in ('ui','fault','component','cpu','p4','phone'):
            rows = write_tree(OUTPUTS[kind],packages[kind])
            delivery[kind] = {'root':str(OUTPUTS[kind]),'files':rows,
                'manifest':next(r for r in rows if Path(r['path']).name in ('MANIFEST.json','SOURCE-MANIFEST.json'))}
            put(OUT/(kind.upper()+'-LITERAL-INCREMENT.patch'),patches[kind])
        originals.recheck()
        put(OUT/'LITERAL-PROOF.json',encoded(proof))
        put(OUT/'ACTUAL-SOURCE-DEPENDENCIES.json',encoded(binding))
        input_index = put(OUT/'ORIGINAL-INPUTS.json',encoded({
            'schema':'hepta.r10.property-negative-generation-originals.v1',
            'files':list(originals.rows.values()),'source_directories':list(originals.directories.values())}))
        result = {'schema':'hepta.r10.property-negative-source-generation-result.v1',
            'state':'ORIGINAL_SOURCE_GENERATION_COMPLETED_WAITING_ACTUAL_SEAL_READY_AND_CASE',
            'source':pin(self_raw),'finalization':frozen,'packages':delivery,
            'shared_active':next(r for r in delivery['ui']['files'] if r['path'].endswith('/active_runtime_r10.py')),
            'originals':input_index,'all_output_files_read_back':True,
            'actual_ready':False,'task_scope_bound':False,'new_nonces':0,'phone_calls':0,
            'collector_executions':0,'physical_qualification':False,'business19_qualified':False,
            'automatic_retry':False}
        put(OUT/'RESULT.json',encoded(result))
        print(encoded(result).decode(),end='')
        return 0
    except BaseException as error:
        failure={'schema':'hepta.r10.property-negative-source-generation-failure.v1',
            'state':'KNOWN_HOST_SOURCE_GENERATION_FAILED_OUTPUTS_RETAINED',
            'error':type(error).__name__+':'+str(error),'originals':list(originals.rows.values()),
            'automatic_retry':False,'phone_calls':0,'new_nonces':0,'physical_qualification':False}
        put(OUT/'FAILURE.json',encoded(failure))
        raise

if __name__ == '__main__':
    raise SystemExit(main())
