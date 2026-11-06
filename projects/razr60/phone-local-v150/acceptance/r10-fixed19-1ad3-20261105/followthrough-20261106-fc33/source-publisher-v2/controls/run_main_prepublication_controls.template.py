"""Actual Mac pinned-source reads through both complete main entry paths.

Only the writer's eventual effect function is intercepted in this test process.
No original source check, JSON parsing, literal inverse or source gate is changed.
No output directory is created; reaching publication is not publication success.
"""
import hashlib
import json
import os
import sys
import types
from pathlib import Path

OLD_RAW = __OLD_SOURCE_LITERAL__.encode('utf-8')
BEFORE = b"change.rhs('FROZEN_INPUTS', proof['source_inputs'])"
AFTER = b"change.rhs('FROZEN_INPUTS', located(binding_root, 'SOURCE-CHAIN-INPUTS.json', inputs_raw))"
NEW_RAW = OLD_RAW.replace(BEFORE, AFTER, 1)
ROOT = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
OUTPUTS = (ROOT + '/followthrough-fc33-release-source-binding-r5-01',
           ROOT + '/followthrough-fc33-release-source-chain-r5-derived01')

def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

assert pin(OLD_RAW) == {'bytes': 141612, 'sha256': 'd6bfac4486ccd444bfe9ee98f1d1536b6453751200677d6bee5c6f5698360a27'}
assert pin(NEW_RAW) == {'bytes': 141651, 'sha256': '477bb8c20d4868428761e403456e9c8b333b72607c8ff51aac404b2429dda342'}
assert OLD_RAW.count(BEFORE) == NEW_RAW.count(AFTER) == 1 and NEW_RAW.replace(AFTER, BEFORE, 1) == OLD_RAW
assert all(not os.path.lexists(path) for path in OUTPUTS)

class ReachedPublicationBoundary(Exception):
    pass

results = []
original_argv = list(sys.argv)
try:
    for version, source in (('v1_actual_failed_source', OLD_RAW), ('v2_canonical_descriptor_source', NEW_RAW)):
        m = types.ModuleType('reviewed_' + version)
        m.__file__ = '<' + version + '>'
        exec(compile(source, m.__file__, 'exec'), m.__dict__)
        writer_factory = m.writer
        observed = []
        factory_calls = []
        def intercept_writer(producer_raw, material, directories):
            # Execute the real reviewed publisher derivation/inverse; do not
            # execute the function that would create the first output directory.
            original_write_function, proof = writer_factory(producer_raw, material, directories)
            factory_calls.append({'directories': directories, 'proof': proof})
            def stop_before_write(out, files):
                assert out == Path(OUTPUTS[0])
                assert set(files) == {'source/release_boundaries.py', 'source/derive_reviewed_release_sources_BOUND.py',
                    'SOURCE-CHAIN-INPUTS.json', 'BINDING-PROOF.json', 'reference/release_boundaries.UNBOUND.py',
                    'reference/derive_reviewed_release_sources_UNBOUND.py', 'PUBLISHER-DERIVATION.json', 'DERIVATION.json'}
                assert pin(files['source/derive_reviewed_release_sources_BOUND.py']) == {
                    'bytes': 34103, 'sha256': '342cf03f11fcb6cc02fd98f68f44a567603389788de45999c6182ad0a4426c5a'}
                assert all(not os.path.lexists(path) for path in OUTPUTS)
                observed.append({'intended_output': str(out),
                    'files': [{'path': name, **pin(raw)} for name, raw in sorted(files.items())],
                    'actual_read_originals': list(material.BOOK.values()),
                    'actual_write_function_invoked': False})
                raise ReachedPublicationBoundary('expected test-only stop before first directory creation')
            return stop_before_write, proof
        m.writer = intercept_writer
        sys.argv = [m.__file__, '--publish-source-candidate-once']
        try:
            m.main()
        except ReachedPublicationBoundary as error:
            assert version == 'v2_canonical_descriptor_source' and len(factory_calls) == len(observed) == 1
            state = 'COMPLETE_MAIN_REACHED_FIRST_PUBLICATION_BOUNDARY_NO_WRITE'
            detail = str(error)
        except ValueError as error:
            assert version == 'v1_actual_failed_source'
            assert str(error) == 'only exact complete source input literal binding'
            assert factory_calls == [] and observed == []
            state = 'ORIGINAL_JSON_ROUNDTRIP_LITERAL_BYTE_REJECTION_REPRODUCED'
            detail = str(error)
        else:
            raise AssertionError('main must stop at the expected failure or test-only effect boundary')
        assert all(not os.path.lexists(path) for path in OUTPUTS)
        results.append({'version': version, 'entry_source': pin(source), 'state': state,
                        'detail': detail, 'writer_factory_calls': factory_calls, 'observed': observed})
finally:
    sys.argv = original_argv
print(json.dumps({'schema': 'hepta.fc33.source-publisher-main-prepublication-controls.v1',
    'state': 'ACTUAL_JSON_MAIN_PATH_BYTE_GATES_VERIFIED_NO_PUBLICATION',
    'results': results, 'both_output_paths_remain_absent': True,
    'controlled_effect_boundary': 'Only writer return value replaced by a test-only sentinel before any directory creation.',
    'scope': 'Actual same main, payload JSON roundtrip and pinned Mac originals through first publish boundary only; no source-chain derive or publisher happy path execution.',
    'actual_source_publication': False, 'source_chain_derive_called': False,
    'new_current_case_inputs': None, 'actual_BUILD': None, 'actual_install': None, 'actual_READY': None,
    'phone_calls': 0, 'acceptance_credit': 0}, sort_keys=True))
