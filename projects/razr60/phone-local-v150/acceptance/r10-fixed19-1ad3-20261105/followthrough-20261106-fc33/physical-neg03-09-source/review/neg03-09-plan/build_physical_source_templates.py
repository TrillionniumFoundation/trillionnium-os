#!/usr/bin/env python3
"""Build narrowly changed UNBOUND physical/closure source templates.

No source/package pin is treated as actual BUILD, READY or case qualification.
Only the already reviewed R5 source graph and current shared material change;
signal/cancel/transport implementations and every actual admission stay intact.
"""
import ast
import difflib
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RUNTIME = ROOT.parent / 'R5-root/runtime/MANIFEST.json'
ROOT_SOURCE = ROOT.parent / 'R5-root/root-chain/source/run_component_root_once.py'
CONFIG_SHA = '5ff00467e8432d7119ba72a700ce07cb20f16555d3dc0c90de7cbfc388103f48'
SERVICE_SHA = '273db17098e5de6c67ded208e120e3910531ab1c7a778faa76824d453ddddd58'
OLD_CONFIG = '780754928709871d3e70f432acb6a021c6c97ab822aaf7c32c887c132cac8c34'
OLD_SERVICE = '2739a0af53650363e065bb71a448481998c68fc8b8632e61262c319dae6b586a'
FIXTURE_SHA = '5ae3f51d89d8e1d36be07846b34b09f652fdf39db0db0eee98ed0f194c720a2d'
SLOTS = ('PKG', 'COMBINATION', 'VERIFIER_SHA', 'VERIFIER_BYTES', 'POLICY_SHA', 'ADOPTION_SHA', 'ROOT_SCOPE_SHA')


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def assignment_span(raw, name):
    nodes = [n for n in ast.parse(raw).body if isinstance(n, ast.Assign) and len(n.targets) == 1
             and isinstance(n.targets[0], ast.Name) and n.targets[0].id == name]
    assert len(nodes) == 1
    value = nodes[0].value
    lines = raw.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    return offsets[value.lineno-1] + value.col_offset, offsets[value.end_lineno-1] + value.end_col_offset


def rhs(raw, name, value):
    start, end = assignment_span(raw, name)
    return raw[:start] + repr(value).encode() + raw[end:]


class Changes:
    def __init__(self, original):
        self.original = self.raw = original
        self.edits = []

    def once(self, old, new):
        before = old.encode() if isinstance(old, str) else old
        after = new.encode() if isinstance(new, str) else new
        assert self.raw.count(before) == 1
        self.raw = self.raw.replace(before, after, 1)
        self.edits.append({'before': before.decode(), 'after': after.decode()})

    def rhs(self, name, value):
        start, end = assignment_span(self.raw, name)
        self.once(self.raw[start:end], repr(value).encode())

    def finish(self):
        restored = self.raw
        for edit in reversed(self.edits):
            before, after = edit['before'].encode(), edit['after'].encode()
            assert restored.count(after) == 1
            restored = restored.replace(after, before, 1)
        assert restored == self.original
        compile(self.raw, '<reviewed-unbound-source-template>', 'exec')
        return self.raw, {'original': pin(self.original), 'candidate': pin(self.raw),
                          'edits': self.edits, 'complete_inverse': True}


def build():
    runtime_raw, root_raw = RUNTIME.read_bytes(), ROOT_SOURCE.read_bytes()
    assert pin(runtime_raw) == {'bytes': 57078, 'sha256': '990c726a1fff139761494cc19cf091deb269201f27ea947dda4a5833e3a72f2a'}
    assert pin(root_raw) == {'bytes': 78566, 'sha256': '2af78597f211b8b7de32d5f40591e46c4ea5ff7caa3c4a2547ac4325666c2032'}
    runtime = json.loads(runtime_raw)
    assert runtime['revision'] == 'r10-r1-fc33-native-bound-v3-r5' and len(runtime['files']) == 38
    normalized = root_raw
    for name in SLOTS:
        normalized = rhs(normalized, name, None)
    results = {}
    ref = ROOT / 'reference'
    path = ref / 'physical-fault-final01/package/source/physical_fault_common.py'
    c = Changes(path.read_bytes())
    c.once("runtime.get('revision')=='r10-r1-operator-r8' and len(runtime['files'])==32",
           "runtime.get('revision')=='r10-r1-fc33-native-bound-v3-r5' and len(runtime['files'])==38")
    c.once("'actual_R8_runtime_manifest_generation'", "'actual_reviewed_R5_runtime_manifest_generation'")
    c.once(OLD_CONFIG, CONFIG_SHA)
    c.once(OLD_SERVICE, SERVICE_SHA)
    results['physical-fault/physical_fault_common.py'] = (path, *c.finish())
    path = ref / 'component-physical-final02/package/source/physical_component_common.py'
    c = Changes(path.read_bytes())
    c.rhs('FIXTURE_SHA', FIXTURE_SHA)
    c.once("                        need(isinstance(value,(str,tuple)),'frozen dependency must remain a literal')",
           """                        if name=='SOURCE_PINS':
                            need(type(value)is dict and set(value)=={'provider_openai_compatible.py',
                                'phone_task_guards.py','phone_observation_tools.py','phone_local_tools.py'}
                                and all(type(v)is tuple and len(v)==2 and type(v[0])is int and 0<v[0]<=1048576
                                    and type(v[1])is str and re.fullmatch('[0-9a-f]{64}',v[1]) for v in value.values()),
                                'exact four geometry source byte pins required')
                        else:
                            need(isinstance(value,(str,tuple)),'frozen dependency must remain a literal')""")
    c.once("{'MATERIALIZER','CONSUMER','CONSUMER_PIN','READINESS_PIN','RUNTIME_SHA','POLICY_SHA','ADOPTION_SHA'},",
           "{'MATERIALIZER','CONSUMER','CONSUMER_PIN','READINESS_PIN','RUNTIME_SHA','POLICY_SHA','ADOPTION_SHA','SOURCE_PINS'},")
    c.once("verify_literal_increment(active_raw,oldactive,{'CONSUMER_SHA','READINESS_SHA','POLICY_SHA','ADOPTION_SHA'})",
           "verify_literal_increment(active_raw,oldactive,{'CONSUMER_SHA','READINESS_SHA','POLICY_SHA','ADOPTION_SHA','CONFIG_SHA','SERVICE_SHA'})")
    c.once("and active.POLICY_SHA==pins['policy_sha256'] and active.ADOPTION_SHA==pins['policy_adoption_inputs_sha256'],",
           "and active.POLICY_SHA==pins['policy_sha256'] and active.ADOPTION_SHA==pins['policy_adoption_inputs_sha256']\n        and active.CONFIG_SHA==pins['configuration_sha256'] and active.SERVICE_SHA==pins['service_inputs_sha256'],")
    results['physical-component/physical_component_common.py'] = (path, *c.finish())
    path = ref / 'cpu-cancel-compat-candidate01/package/source/negative_originals.py'
    c = Changes(path.read_bytes())
    c.rhs('ROOT_CAPTURE_TEMPLATE', (len(normalized), pin(normalized)['sha256']))
    c.once("'configuration': (None,'" + OLD_CONFIG + "'),", "'configuration': (1493,'" + CONFIG_SHA + "'),")
    c.once("'service': (10635,'" + OLD_SERVICE + "')", "'service': (10654,'" + SERVICE_SHA + "')")
    results['closure/negative_originals.py'] = (path, *c.finish())
    return results, {'runtime': pin(runtime_raw), 'root_source': pin(root_raw),
                     'normalized_root': pin(normalized), 'root_slots': list(SLOTS)}


if __name__ == '__main__':
    results, sources = build()
    records = {}
    for name, (path, raw, proof) in results.items():
        output = ROOT / 'candidate/templates' / name
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        patch = ''.join(difflib.unified_diff(path.read_text().splitlines(True), raw.decode().splitlines(True),
                    fromfile='reference/' + str(path.relative_to(ROOT / 'reference')),
                    tofile='candidate/templates/' + name)).encode()
        for dest, body in ((output, raw), (output.with_suffix('.py.patch'), patch)):
            with dest.open('xb') as handle:
                handle.write(body)
        records[name] = proof
    report = {'schema': 'fc33.physical-source-templates.v1', 'state': 'SOURCE_ONLY_NOT_ACTUALLY_BOUND',
              'sources': sources, 'changes': records, 'actual_freeze': None, 'actual_BUILD': None,
              'actual_READY': None, 'phone_calls': 0, 'case_qualification': False,
              'signal_cancel_transport_bodies_changed': False}
    dest = ROOT / 'candidate/templates/DERIVATION.json'
    with dest.open('x') as handle:
        json.dump(report, handle, sort_keys=True, indent=2)
        handle.write('\n')
    print(json.dumps({'templates': {n: p['candidate'] for n, p in records.items()}, 'sources': sources}, sort_keys=True))
