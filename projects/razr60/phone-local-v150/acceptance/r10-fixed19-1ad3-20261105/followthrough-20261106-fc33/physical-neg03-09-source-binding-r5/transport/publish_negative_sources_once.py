"""Root-reviewed, one-use host source publication. No actual task execution.

Prepared transport files are read-only inputs. Existing source originals are
never modified. Any partial new output remains preserved; no automatic cleanup,
overwrite, retry, phone invocation, process signal or native/model call exists.
"""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types
import zlib

SOURCE_PAYLOAD = {'bytes': 711272, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-negative-source-transport-r5-01/SOURCE-PAYLOAD.zlib', 'sha256': '324bf65adb34b22e870ab8d791216ffcc50f360685934ab7696694b866b5a873'}
PAYLOAD_RAW = {'bytes': 2521095, 'sha256': '0d178167de8e3e983b64bc116d8a87d4d04b305d58668a69da5eec670570cf7e'}
EXPECTED_INPUTS = {'bytes': 2537, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-negative-source-binding-r5-01/SOURCE-INPUTS.json', 'sha256': '639a157ab7609bfad53d910216ed5fc8f86b973962b908af463ac876628ee694'}
PUBLISHER_SOURCE = {
    'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/followthrough-20261106-fc33-source-propagation01/derive_reviewed_source_material_v3.py',
    'bytes': 16399, 'sha256': '842f893107dfff481e516419da3fd9b1e2c2445378903012658530d83429ac82',
}
EXISTING_SOURCE_BINDING = {
    'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/followthrough-fc33-release-source-chain-r5-derived01/SOURCE-BINDING.json',
    'bytes': 3608, 'sha256': 'c7b074b529b4bbe258303842b3d0b2f3912d8cdf606f803522775b79ba147003',
}
SOURCE_PARENT = {'bytes': 43142, 'sha256': 'd539cb12c5b3d99f4b6066de148f11db78d3ad4210bc034669ebc1bc99c44903'}
REFERENCE_INDEX = {'bytes': 38100, 'sha256': '1a7f17faf1d6705dac356076ce1d0df0292a35a805bceb117eeea50f52f15e32'}
B = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
META = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns')

def need(value, why):
    if not value:
        raise ValueError(why)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def meta(s):
    return [getattr(s, key) for key in META]


def initial(row):
    # Exact bootstrap reader from the reviewed independent R5 preparer.
    p = Path(row['path'])
    need(p.is_absolute() and p.resolve(strict=True) == p, 'canonical helper original')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        a = os.fstat(fd)
        need(stat.S_ISREG(a.st_mode) and a.st_nlink == 1 and a.st_size == row['bytes'],
             'complete exact helper original')
        with os.fdopen(fd, 'rb', closefd=False) as f:
            raw = f.read(row['bytes'] + 1)
        need(pin(raw) == {k: row[k] for k in ('bytes', 'sha256')}
             and meta(a) == meta(os.fstat(fd)) == meta(p.lstat()), 'helper full9 and SHA bookends')
        return raw
    finally:
        os.close(fd)


def module(raw, name, path):
    value = types.ModuleType(name)
    value.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


def writer(source_raw, material, directories):
    # Reuse the reviewed dirfd algorithm, changing only its closed layout tuple.
    rows = [n for n in ast.parse(source_raw).body
            if isinstance(n, ast.FunctionDef) and n.name == 'publish_material']
    need(len(rows) == 1, 'one reviewed publisher function')
    node = rows[0]
    original = b''.join(source_raw.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])
    before = b"directories=('', 'shared', 'shared/provider', 'shared/provider/source', 'reference')"
    after = ('directories=' + repr(directories)).encode()
    need(original.count(before) == 1 and before != after, 'one closed layout substitution')
    changed = original.replace(before, after, 1)
    need(changed.count(after) == 1 and changed.replace(after, before, 1) == original,
         'full publisher function inverse')
    namespace = dict(material.__dict__)
    exec(compile(changed, '<reviewed-dirfd-publisher-layout-only>', 'exec'), namespace)
    proof = {'parent_function': pin(original), 'candidate_function': pin(changed),
             'before': before.decode(), 'after': after.decode(), 'full_inverse': True}
    return namespace['publish_material'], proof


def located(root, name, raw):
    return {'path': str(root / name), **pin(raw)}



def audit(event, args):
    if event.startswith(('subprocess.', 'socket.', 'pty.', 'ctypes.')) or event in (
        'os.system', 'os.exec', 'os.fork', 'os.forkpty', 'os.posix_spawn',
        'os.kill', 'os.killpg', 'os.remove', 'os.rmdir', 'os.rename',
    ):
        raise RuntimeError('source-only publication forbids external execution, signals or removal: ' + event)


def source_reader(source_raw, material):
    # This caller reads the already selected 2,667,752-byte policy original.
    # Keep the complete reviewed read() body; change only its individual-file
    # envelope to the negative constructor's existing MAX_FILE (16 MiB).
    nodes = [node for node in ast.parse(source_raw).body
             if isinstance(node, ast.FunctionDef) and node.name == 'read']
    need(len(nodes) == 1, 'one reviewed complete source reader')
    node = nodes[0]
    original = b''.join(source_raw.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])
    before, after = b'<=1048576', b'<=16777216'
    need(original.count(before) == 1 and after not in original, 'one source-reader size literal')
    candidate = original.replace(before, after, 1)
    need(candidate.replace(after, before, 1) == original, 'complete source-reader inverse')
    exec(compile(candidate, '<reviewed-source-reader-bound-only>', 'exec'), material.__dict__)
    return {'parent_function': pin(original), 'candidate_function': pin(candidate),
            'before': before.decode(), 'after': after.decode(), 'full_inverse': True,
            'individual_original_max_bytes': 16777216,
            'exact3_full9_single_link_no_follow_and_BOOK_body_unchanged': True}


def directories(files):
    need(0 < len(files) <= 256 and sum(map(len, files.values())) <= 32 * 1024 * 1024,
         'complete bounded source tree')
    parents = {str(parent) for name in files for parent in Path(name).parents if str(parent) != '.'}
    need(len(parents) <= 128, 'bounded closed source directory set')
    # This tuple is passed to the exact reviewed writer() substitution. Its
    # original canonical-path and held-dirfd validation remains unchanged.
    return ('',) + tuple(sorted(parents, key=lambda path: (len(Path(path).parts), path)))


def decode_payload(raw, material):
    value = material.strict(raw)
    need(type(value) is dict and set(value) == {'schema', 'binding_root', 'derived_root', 'files', 'blobs'}
         and value['schema'] == 'hepta.fc33.negative-source-publication-payload.v1',
         'exact prepared source payload contract')
    need(type(value['files']) is list and len(value['files']) == 177
         and type(value['blobs']) is dict and len(value['blobs']) <= 177,
         'complete reviewed input file inventory')
    files = {}
    used = set()
    for row in value['files']:
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}
             and type(row['path']) is str and row['path'] not in files
             and type(row['bytes']) is int and 0 <= row['bytes'] <= 4 * 1024 * 1024,
             'unique bounded complete source member')
        blob = value['blobs'][row['sha256']]
        need(type(blob) is dict and set(blob) == {'encoding', 'content'} and type(blob['content']) is str,
             'complete encoded source original')
        if blob['encoding'] == 'utf-8':
            body = blob['content'].encode('utf-8')
        else:
            need(blob['encoding'] == 'base64', 'declared source encoding only')
            body = base64.b64decode(blob['content'], validate=True)
            need(base64.b64encode(body).decode() == blob['content'], 'canonical binary source original')
        need(pin(body) == {key: row[key] for key in ('bytes', 'sha256')}, 'complete source member byte pin')
        files[row['path']] = body
        used.add(row['sha256'])
    need(used == set(value['blobs']), 'no extra unreferenced source blobs')
    directories(files)
    return value, files


def main():
    need(len(sys.argv) == 3 and sys.argv[1] == '--publish-negative-source-candidate-once'
         and len(sys.argv[2]) == 64 and all(c in '0123456789abcdef' for c in sys.argv[2]),
         'Root must select the exact one-use source-only entry and reviewed source SHA')
    self_path = Path(sys.argv[0])
    need(self_path.is_absolute() and self_path.stat().st_size <= 262144, 'bounded actual publisher source')
    executed_source = initial({'path': str(self_path), 'bytes': self_path.stat().st_size, 'sha256': sys.argv[2]})
    need(SOURCE_PAYLOAD is not None and PAYLOAD_RAW is not None and EXPECTED_INPUTS is not None,
         'unbound publication template cannot read inputs')
    sys.addaudithook(audit)
    producer_raw = initial(PUBLISHER_SOURCE)
    material = module(producer_raw, 'reviewed_negative_source_io', PUBLISHER_SOURCE['path'])
    need(material.read(PUBLISHER_SOURCE) == producer_raw, 'reviewed publisher bootstrap generation unchanged')
    read_proof = source_reader(producer_raw, material)
    compressed = material.read(SOURCE_PAYLOAD)
    need(PAYLOAD_RAW['bytes'] <= 8 * 1024 * 1024, 'bounded complete source payload')
    decoder = zlib.decompressobj()
    payload_raw = decoder.decompress(compressed, PAYLOAD_RAW['bytes'] + 1)
    need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and pin(payload_raw) == PAYLOAD_RAW,
         'complete source payload expansion')
    payload, files = decode_payload(payload_raw, material)
    binding_root, derived_root = Path(payload['binding_root']), Path(payload['derived_root'])
    need(binding_root.parent == derived_root.parent == B and binding_root != derived_root
         and B.resolve(strict=True) == B and binding_root.name == 'followthrough-fc33-negative-source-binding-r5-01'
         and derived_root.name == 'fc33-negative-sources-native-v3-r5-01',
         'two exact independent new source namespaces')
    need(not os.path.lexists(binding_root) and not os.path.lexists(derived_root),
         'both one-use source outputs must be absent; no automatic retry or overwrite')
    inputs_raw = files['SOURCE-INPUTS.json']
    need(located(binding_root, 'SOURCE-INPUTS.json', inputs_raw) == EXPECTED_INPUTS,
         'exact prepared source-only input descriptor')
    inputs = material.strict(inputs_raw)
    need(inputs['output_root'] == str(derived_root) and inputs['reference_root'] == str(binding_root / 'inputs'),
         'same source output and complete copied reference namespace')
    parent_raw = files['reference/derive_negative_sources_UNBOUND.py']
    bound_raw = files['source/derive_negative_sources_BOUND.py']
    need(pin(parent_raw) == SOURCE_PARENT, 'exact reviewed negative source constructor parent')
    parent = module(parent_raw, 'reviewed_negative_source_parent', binding_root / 'reference/derive_negative_sources_UNBOUND.py')
    need(parent.FROZEN_INPUTS is None and parent.literal(bound_raw, 'FROZEN_INPUTS') == EXPECTED_INPUTS,
         'single explicit source-only input binding')
    inverse = parent.Changes(bound_raw)
    inverse.rhs('FROZEN_INPUTS', None)
    restored, inverse_proof = inverse.finish()
    need(restored == parent_raw and len(inverse_proof['edits']) == 1,
         'whole constructor inverse; no body or gate change')
    index_raw = files['inputs/REVIEWED-INPUTS.json']
    need(pin(index_raw) == REFERENCE_INDEX, 'exact complete reviewed reference inventory')
    index = material.strict(index_raw)
    need(len(index['files']) == len({row['path'] for row in index['files']}) == 171,
         'all 171 reviewed sources must be retained')
    expected_names = {'source/derive_negative_sources_BOUND.py', 'reference/derive_negative_sources_UNBOUND.py',
                      'SOURCE-INPUTS.json', 'SOURCE.patch', 'BINDING-PROOF.json', 'inputs/REVIEWED-INPUTS.json'}
    for row in index['files']:
        name = 'inputs/' + row['path']
        need(pin(files[name]) == {key: row[key] for key in ('bytes', 'sha256')}, 'reviewed reference source differs')
        expected_names.add(name)
    need(set(files) == expected_names, 'exact closed prepared source member set')
    proof = material.strict(files['BINDING-PROOF.json'])
    need(proof['constructor'] == located(binding_root, 'source/derive_negative_sources_BOUND.py', bound_raw)
         and proof['source_inputs'] == EXPECTED_INPUTS and proof['complete_constructor_inverse'] is True
         and proof['source_constructor_positive_executed'] is False
         and all(proof[key] is None for key in ('actual_BUILD', 'actual_READY', 'actual_case_plans', 'new_native_scope', 'new_nonce')),
         'prepared source report cannot grant an actual execution')
    # These are existing actual source originals, not candidate-generated
    # receipts. Read all of them before creating either new source namespace.
    source_chain = inputs['release_source_chain']
    chain_raw = material.read(source_chain['constructor'])
    chain_inputs_raw = material.read(source_chain['inputs'])
    need(parent.literal(chain_raw, 'FROZEN_INPUTS') == source_chain['inputs'], 'actual release source-chain input binding')
    inverse_chain = parent.Changes(chain_raw)
    inverse_chain.rhs('FROZEN_INPUTS', None)
    parent.exact_pin(inverse_chain.finish()[0], parent.CHAIN_TEMPLATE)
    material.read(EXISTING_SOURCE_BINDING)
    for name in ('root_manifest', 'actual_policy', 'policy_adoption', 'materializer'):
        material.read(inputs[name])
    need(material.strict(chain_inputs_raw)['output_root'] == str(Path(EXISTING_SOURCE_BINDING['path']).parent),
         'published release source-chain namespace differs')
    files['PUBLISHER-SOURCE.executed.py'] = executed_source
    files['SOURCE-READER-DERIVATION.json'] = material.enc(read_proof)
    publish_binding, writer_proof = writer(producer_raw, material, directories(files))
    files['PUBLISHER-DERIVATION.json'] = material.enc(writer_proof)
    files['DERIVATION.json'] = material.enc({
        'schema': 'hepta.fc33.negative-source-input-publication.v1',
        'state': 'COMPLETE_SOURCE_INPUT_COPIES_ONLY_NO_ACTUAL_TASK',
        'files': [located(binding_root, name, body) for name, body in sorted(files.items())],
        'whole_constructor_inverse': True, 'reference_sources': 171,
        'actual_BUILD': None, 'actual_READY': None, 'actual_case_plans': None,
        'phone_calls': 0, 'model_requests': 0, 'native_dispatches': 0,
    })
    for old in list(material.BOOK.values()):
        material.read({key: old[key] for key in ('path', 'bytes', 'sha256')})
    publish_binding(binding_root, files)
    need(material.read(EXPECTED_INPUTS) == inputs_raw
         and material.read(proof['constructor']) == bound_raw, 'complete published source input readback')
    for row in index['files']:
        material.read(dict(row, path=str(binding_root / 'inputs' / row['path'])))
    bound = module(bound_raw, 'actual_negative_source_constructor', proof['constructor']['path'])
    result = bound.derive_negative_sources(inputs_raw, read_pinned=material.read)
    need(set(result['packages']) == {'ui', 'fault', 'component', 'cpu', 'p4', 'phone', 'closure',
                                     'physical-fault', 'physical-component', 'host-five', 'host-neg06'},
         'complete eleven reviewed source families')
    report = dict(result['report'])
    need(report['state'] == 'SOURCE_ONLY_ACTUAL_PHYSICAL_PLANS_UNBOUND'
         and report['complete_originals_rechecked'] is True and report['all_source_inverses_exact'] is True
         and report['fixed19_credit'] == 0 and report['physical_cases_executed'] == report['host_cases_executed'] == []
         and all(report[name] is None for name in ('actual_freeze_admission', 'actual_BUILD', 'actual_READY')),
         'actual source constructor cannot grant task qualification')
    out = dict(result['files'])
    for number in range(3, 10):
        name = 'NEG-%02d' % number
        plan = material.strict(out['plans/' + name + '.template.json'])
        need(plan['case_id'] == name and plan['automatic_retry'] is False and plan['case_qualified'] is False
             and all(plan[key] is None for key in ('actual_plan', 'actual_freeze_admission', 'actual_sealed_BUILD',
                 'actual_four_role_READY', 'registered_owner_request', 'nonce', 'actual_scope', 'actual_argv', 'fresh_owned_label')),
             'all seven actual execution templates must remain unbound')
    out['SOURCE-CHANGES.json'] = material.enc(result['changes'])
    out['SOURCE-FAMILIES.json'] = material.enc(result['packages'])
    out['SOURCE-INPUTS.original.json'] = inputs_raw
    out['CONSTRUCTOR-SOURCE.original.py'] = bound_raw
    publish_derived, writer_proof = writer(producer_raw, material, directories(out))
    out['PUBLISHER-DERIVATION.json'] = material.enc(writer_proof)
    report.update(
        constructor=proof['constructor'], source_inputs=EXPECTED_INPUTS,
        source_families=located(derived_root, 'SOURCE-FAMILIES.json', out['SOURCE-FAMILIES.json']),
        source_changes=located(derived_root, 'SOURCE-CHANGES.json', out['SOURCE-CHANGES.json']),
        files=[located(derived_root, name, body) for name, body in sorted(out.items())],
        original_files_full9=list(material.BOOK.values()),
        original_files_full9_count=len(material.BOOK),
        original_unique_path_bytes=sum(row['bytes'] for row in material.BOOK.values()),
        source_reader_derivation=read_proof,
        byte_envelopes={'individual_source_original': 16777216, 'negative_constructor_total': parent.MAX_TOTAL,
                        'each_published_tree': 33554432, 'complete_source_payload': 8388608},
    )
    out['DERIVATION.json'] = material.enc(report)
    for old in list(material.BOOK.values()):
        material.read({key: old[key] for key in ('path', 'bytes', 'sha256')})
    publish_derived(derived_root, out)
    need(material.read(located(derived_root, 'DERIVATION.json', out['DERIVATION.json'])) == out['DERIVATION.json'],
         'complete final source-only terminal readback')
    print(json.dumps({
        'state': 'NEG03_09_SOURCE_FAMILIES_PUBLISHED_ALL_ACTUAL_TASKS_UNBOUND',
        'binding_output': str(binding_root), 'source_output': str(derived_root),
        'input_publication': located(binding_root, 'DERIVATION.json', files['DERIVATION.json']),
        'derivation': located(derived_root, 'DERIVATION.json', out['DERIVATION.json']),
        'source_families': located(derived_root, 'SOURCE-FAMILIES.json', out['SOURCE-FAMILIES.json']),
        'source_changes': located(derived_root, 'SOURCE-CHANGES.json', out['SOURCE-CHANGES.json']),
        'family_count': 11, 'unbound_case_count': 7, 'published_file_count': len(out),
        'actual_BUILD': None, 'actual_READY': None, 'actual_case_plans': None,
        'phone_calls': 0, 'model_requests': 0, 'native_dispatches': 0,
    }, sort_keys=True))


if __name__ == '__main__':
    main()
