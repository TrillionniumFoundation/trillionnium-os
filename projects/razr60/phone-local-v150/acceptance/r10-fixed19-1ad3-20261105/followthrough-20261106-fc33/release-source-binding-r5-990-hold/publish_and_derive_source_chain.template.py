"""One host-only publication for the exact prepared 990c source candidate.

Root owns execution. The prepared candidate is on HOLD while new NEG01's
stage rejection is investigated. This file is a template, not an executed run.
There is no phone, installer, BUILD, acceptance nonce, service, or Git action.
"""
import ast
import base64
import hashlib
import json
import os
import stat
import sys
import types
import zlib
from pathlib import Path

PAYLOAD_SHA256 = '__PAYLOAD_SHA256__'
PAYLOAD_BYTES = __PAYLOAD_BYTES__
PAYLOAD_ZLIB_BASE64 = '__PAYLOAD_ZLIB_BASE64__'
PUBLISHER_SOURCE = {
    'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/followthrough-20261106-fc33-source-propagation01/derive_reviewed_source_material_v3.py',
    'bytes': 16399, 'sha256': '842f893107dfff481e516419da3fd9b1e2c2445378903012658530d83429ac82',
}
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

def main():
    need(sys.argv == [sys.argv[0], '--publish-source-candidate-once'],
         'root must select the one-time host source publication entry explicitly')
    payload_raw = zlib.decompress(base64.b64decode(PAYLOAD_ZLIB_BASE64, validate=True))
    need(pin(payload_raw) == {'bytes': PAYLOAD_BYTES, 'sha256': PAYLOAD_SHA256},
         'exact prepared source-only payload')
    producer_raw = initial(PUBLISHER_SOURCE)
    material = module(producer_raw, 'reviewed_material_io', PUBLISHER_SOURCE['path'])
    need(material.read(PUBLISHER_SOURCE) == producer_raw, 'bootstrap source generation unchanged')
    payload = material.strict(payload_raw)
    need(set(payload) == {'files'}, 'only prepared file payload')
    files = {name: base64.b64decode(value, validate=True) for name, value in payload['files'].items()}
    need(set(files) == {'source/release_boundaries.py', 'source/derive_reviewed_release_sources_BOUND.py',
                       'SOURCE-CHAIN-INPUTS.json', 'BINDING-PROOF.json'}, 'closed prepared source member set')
    proof = material.strict(files['BINDING-PROOF.json'])
    binding_root = Path(proof['binding_output'])
    derived_root = Path(proof['derived_output'])
    need(binding_root != derived_root and binding_root.parent == derived_root.parent
         and binding_root.parent.resolve(strict=True) == binding_root.parent,
         'two independent canonical host namespaces')
    need(not os.path.lexists(binding_root) and not os.path.lexists(derived_root),
         'both one-use source outputs must be absent; no overwrite or automatic retry')
    inputs_raw = files['SOURCE-CHAIN-INPUTS.json']
    inputs = material.strict(inputs_raw)
    need(inputs['output_root'] == str(derived_root), 'same source output namespace')
    need(inputs['consumer']['source'] == located(binding_root, 'source/release_boundaries.py',
                                                files['source/release_boundaries.py']),
         'exact prepared bound consumer descriptor')
    for name, key in [('source/release_boundaries.py', 'consumer'),
                      ('source/derive_reviewed_release_sources_BOUND.py', 'constructor'),
                      ('SOURCE-CHAIN-INPUTS.json', 'source_inputs')]:
        need(proof[key] == located(binding_root, name, files[name]), 'exact prepared source record')
    original_constructor = material.read(proof['constructor_parent'])
    original_consumer = material.read(proof['consumer_parent'])
    constructor = module(original_constructor, 'reviewed_source_constructor', proof['constructor_parent']['path'])
    runtime_raw = material.read(inputs['consumer']['runtime_package'])
    need(inputs['consumer']['runtime_package'] == proof['runtime_package'], 'selected actual runtime pin')
    authority = proof['root_supplied_actual_freeze_inputs']
    actual_freeze = material.strict(material.read(authority['freeze']))
    material.read(authority['source'])
    material.read(authority['controller'])
    material.read(proof['root_supplied_independent_preparer_source'])
    need(actual_freeze['runtime_manifest'] == inputs['consumer']['runtime_package']
         and actual_freeze['combination']['sha256'] == inputs['material']['combination']['sha256']
         and actual_freeze['production_ready'] is False and actual_freeze['full19_qualified'] is False,
         'actual frozen source relationship without qualification')
    need(constructor.FROZEN_INPUTS is None and constructor.literal(original_consumer, 'PACKAGE_SHA') is None,
         'exact two unbound source parents')
    change = constructor.Changes(original_consumer)
    change.rhs('PACKAGE_SHA', pin(runtime_raw)['sha256'])
    consumer_raw, consumer_change = change.finish()
    need(consumer_raw == files['source/release_boundaries.py'] and consumer_change == proof['consumer_change']
         and len(consumer_change['changes']) == 1, 'only exact actual package literal binding')
    change = constructor.Changes(original_constructor)
    change.rhs('FROZEN_INPUTS', proof['source_inputs'])
    constructor_raw, constructor_change = change.finish()
    need(constructor_raw == files['source/derive_reviewed_release_sources_BOUND.py']
         and constructor_change == proof['constructor_change'] and len(constructor_change['changes']) == 1,
         'only exact complete source input literal binding')
    publish_binding, writer_proof = writer(producer_raw, material, ('', 'source', 'reference'))
    files['reference/release_boundaries.UNBOUND.py'] = original_consumer
    files['reference/derive_reviewed_release_sources_UNBOUND.py'] = original_constructor
    files['PUBLISHER-DERIVATION.json'] = material.enc(writer_proof)
    files['DERIVATION.json'] = material.enc({
        'schema': 'hepta.fc33.reviewed-source-binding-publication.v1',
        'state': 'SOURCE_BINDING_ONLY_NO_NEW_CASE_QUALIFICATION',
        'files': [located(binding_root, n, raw) for n, raw in sorted(files.items())],
        'full_source_inverse': True, 'phone_calls': 0,
        'actual_BUILD': None, 'actual_install': None, 'actual_READY': None,
        'new_current_case_originals': None,
    })
    for row in list(material.BOOK.values()):
        material.read({key: row[key] for key in ('path', 'bytes', 'sha256')})
    publish_binding(binding_root, files)
    need(material.read(proof['source_inputs']) == inputs_raw, 'published exact input readback')
    need(material.read(proof['constructor']) == constructor_raw, 'published exact bound constructor readback')
    bound = module(constructor_raw, 'actual_input_bound_source_constructor', proof['constructor']['path'])
    result = bound.derive_reviewed_source_chain(inputs_raw, read_pinned=material.read)
    out = dict(result['files'])
    need(len(out) == 14, 'exact reviewed fourteen derived source outputs')
    out['SOURCE-BINDING.json'] = material.enc(result['source_binding'])
    out['SOURCE-CHANGES.json'] = material.enc(result['changes'])
    out['CONSUMER-RUNTIME.json'] = material.enc(result['consumer_runtime'])
    out['SOURCE-CHAIN-INPUTS.original.json'] = inputs_raw
    out['CONSTRUCTOR-SOURCE.original.py'] = constructor_raw
    publish_derived, writer_proof = writer(producer_raw, material, ('', 'source', 'contracts', 'preview-module'))
    out['PUBLISHER-DERIVATION.json'] = material.enc(writer_proof)
    report = dict(result['report'])
    report.update(
        constructor=proof['constructor'], source_inputs=proof['source_inputs'],
        source_binding=located(derived_root, 'SOURCE-BINDING.json', out['SOURCE-BINDING.json']),
        consumer_runtime=located(derived_root, 'CONSUMER-RUNTIME.json', out['CONSUMER-RUNTIME.json']),
        files=[located(derived_root, n, raw) for n, raw in sorted(out.items())],
        original_files_full9=list(material.BOOK.values()),
    )
    out['DERIVATION.json'] = material.enc(report)
    for row in list(material.BOOK.values()):
        material.read({key: row[key] for key in ('path', 'bytes', 'sha256')})
    publish_derived(derived_root, out)
    print(json.dumps({
        'state': 'SOURCE_CANDIDATES_PUBLISHED_ACTUAL_EXECUTION_UNBOUND',
        'binding_output': str(binding_root), 'source_output': str(derived_root),
        'binding_receipt': located(binding_root, 'DERIVATION.json', files['DERIVATION.json']),
        'derivation': located(derived_root, 'DERIVATION.json', out['DERIVATION.json']),
        'consumer': located(derived_root, 'source/release_boundaries.py', out['source/release_boundaries.py']),
        'readiness': result['source_binding']['readiness'],
        'source_binding': located(derived_root, 'SOURCE-BINDING.json', out['SOURCE-BINDING.json']),
        'source_file_count': 14, 'published_file_count': len(out),
        'phone_calls': 0, 'actual_BUILD': None, 'actual_install': None, 'actual_READY': None,
    }, sort_keys=True))

if __name__ == '__main__':
    main()
