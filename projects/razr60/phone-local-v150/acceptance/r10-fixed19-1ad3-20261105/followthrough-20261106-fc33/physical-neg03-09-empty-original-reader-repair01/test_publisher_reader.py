"""Actual source-reader regression; no source publication, task, or phone."""
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import traceback
import types

PROJECTOR = b'def source_reader(source_raw, material):\n    # This caller reads the already selected 2,667,752-byte policy original.\n    # Match the complete constructor and adoption API\'s 0..MAX_FILE envelope:\n    # empty pinned originals still require the exact empty SHA and full9 checks.\n    nodes = [node for node in ast.parse(source_raw).body\n             if isinstance(node, ast.FunctionDef) and node.name == \'read\']\n    need(len(nodes) == 1, \'one reviewed complete source reader\')\n    node = nodes[0]\n    original = b\'\'.join(source_raw.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])\n    before, after = b"0<desc[\'bytes\']<=1048576", b"0<=desc[\'bytes\']<=16777216"\n    need(original.count(before) == 1 and after not in original, \'one source-reader size literal\')\n    candidate = original.replace(before, after, 1)\n    need(candidate.replace(after, before, 1) == original, \'complete source-reader inverse\')\n    exec(compile(candidate, \'<reviewed-source-reader-bound-only>\', \'exec\'), material.__dict__)\n    return {\'parent_function\': pin(original), \'candidate_function\': pin(candidate),\n            \'before\': before.decode(), \'after\': after.decode(), \'full_inverse\': True,\n            \'individual_original_min_bytes\': 0, \'individual_original_max_bytes\': 16777216,\n            \'exact3_full9_single_link_no_follow_and_BOOK_body_unchanged\': True}\n'
PROJECTOR_PIN = {'bytes': 1345, 'sha256': 'ecd6139f9161bc18d59eee16bd58f3f3de478f39643e3967d12c84167ad753c8'}
READ_PIN = {'bytes': 1053, 'sha256': '529da5df943c53763a07cc232f0bf585250ba76b6b88f76643900224dfb94b03'}
B = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
OUT = B / 'followthrough-fc33-negative-empty-original-host-controls01'
PUBLISHER = {'path': str(B / 'followthrough-fc33-negative-source-transport-r5-02/publish_negative_sources_once.py'),
             'bytes': 19652, 'sha256': 'b1ae10610b16aeb4620ec6f66362d3945e1f2a40717465303b24724e03b4eb81'}
CONSTRUCTOR = {'path': str(B / 'followthrough-fc33-negative-source-binding-r5-02/source/derive_negative_sources_BOUND.py'),
               'bytes': 43397, 'sha256': '1ad08e6375da76631900a1678794127bf69145963c8ac0f04bd798e614e94601'}
INPUTS = {'path': str(B / 'followthrough-fc33-negative-source-binding-r5-02/SOURCE-INPUTS.json'),
          'bytes': 2537, 'sha256': 'b922c80e3e0d212167b164aed3d044d416439510368aa4b02998be2b3dbe9567'}
DERIVED = B / 'fc33-negative-sources-native-v3-r5-02'
META = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
OUTPUT_NAMES = {'RESULT.json', 'ORIGINALS.json', 'CONSTRUCTOR-REPORT.json', 'SOURCE-READER-DERIVATION.json',
                'source_reader.candidate.py'}


def need(value, why):
    if not value:
        raise ValueError(why)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def enc(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode()


def metadata(value):
    return [getattr(value, name) for name in META]


def bootstrap(row):
    path = Path(row['path'])
    need(path.resolve(strict=True) == path and 0 < row['bytes'] <= 16 * 1024 * 1024, 'exact source bootstrap path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        first = os.fstat(fd)
        need(stat.S_ISREG(first.st_mode) and first.st_nlink == 1 and first.st_size == row['bytes'], 'exact regular source bootstrap')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(row['bytes'] + 1)
        need(pin(raw) == {key: row[key] for key in ('bytes', 'sha256')} and
             metadata(first) == metadata(os.fstat(fd)) == metadata(path.lstat()), 'source bootstrap full bytes and full9')
        return raw
    finally:
        os.close(fd)


def module(raw, name, path):
    value = types.ModuleType(name)
    value.__file__ = str(path)
    value.__reviewed_source_sha256__ = pin(raw)['sha256']
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


def audit(event, args):
    if event.startswith(('subprocess.', 'socket.', 'pty.', 'ctypes.')) or event in (
        'os.system', 'os.exec', 'os.fork', 'os.forkpty', 'os.posix_spawn', 'os.kill', 'os.killpg',
        'os.remove', 'os.rmdir', 'os.rename', 'os.mkdir', 'os.chmod', 'os.chown', 'os.link', 'os.symlink',
    ):
        raise RuntimeError('pure source control forbids process, signal, or namespace mutation: ' + event)
    if event == 'open' and len(args) >= 3:
        path, unused, flags = args
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            need(type(path) is str and Path(path).parent == OUT and Path(path).name in OUTPUT_NAMES and
                 flags & os.O_CREAT and flags & os.O_EXCL and not flags & (os.O_TRUNC | os.O_APPEND),
                 'only owned create-once host control artifacts may be written')


def put(name, raw):
    need(name in OUTPUT_NAMES and OUT.resolve(strict=True) == OUT, 'exact own control artifact')
    fd = os.open(OUT / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            need(written > 0, 'complete own artifact write')
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)
    need((OUT / name).read_bytes() == raw, 'whole own artifact readback')
    return {'path': str(OUT / name), **pin(raw)}


def main():
    need(type(PROJECTOR) is bytes and pin(PROJECTOR) == PROJECTOR_PIN and type(READ_PIN) is dict,
         'exact candidate projector source before any action')
    need(OUT.parent.resolve(strict=True) == OUT.parent and not os.path.lexists(OUT), 'new own control output only')
    OUT.mkdir(mode=0o700)
    sys.addaudithook(audit)
    put('source_reader.candidate.py', PROJECTOR)
    publisher_raw = bootstrap(PUBLISHER)
    publisher = module(publisher_raw, 'actual_source02_publisher_for_pure_reader_only', PUBLISHER['path'])
    producer_raw = bootstrap(publisher.PUBLISHER_SOURCE)
    old_material = module(producer_raw, 'old_actual_material_reader', publisher.PUBLISHER_SOURCE['path'])
    publisher.source_reader(producer_raw, old_material)
    constructor_raw = old_material.read(CONSTRUCTOR)
    inputs_raw = old_material.read(INPUTS)
    constructor = module(constructor_raw, 'actual_source02_bound_constructor_pure_only', CONSTRUCTOR['path'])
    need(constructor.FROZEN_INPUTS == INPUTS and not os.path.lexists(DERIVED), 'same actual source02 binding, derived output absent')
    cases = []
    rejected = []
    material = None
    result = None
    error = None

    def trace_old(row):
        try:
            return old_material.read(row)
        except ValueError as exc:
            rejected.append({'descriptor': dict(row), 'error': str(exc)})
            raise

    try:
        try:
            constructor.derive_negative_sources(inputs_raw, read_pinned=trace_old)
        except ValueError as exc:
            need(str(exc) == 'bounded typed source descriptor' and len(rejected) == 1 and
                 type(rejected[0]['descriptor']['bytes']) is int and rejected[0]['descriptor']['bytes'] == 0 and
                 rejected[0]['descriptor']['sha256'] == pin(b'')['sha256'], 'exact actual empty-original failure reproduced')
        else:
            raise AssertionError('old caller reader unexpectedly accepted complete actual adoption')
        cases.append({'id': 'actual_publisher_reader_empty_original_failure', 'passed': True,
                      'kind': 'actual_retained_original_reproduction', 'rejected': rejected[0]})

        namespace = dict(publisher.__dict__)
        exec(compile(PROJECTOR, '<exact-source03-reader-projector>', 'exec'), namespace)
        material = module(producer_raw, 'source03_empty_original_compatible_material_reader', publisher.PUBLISHER_SOURCE['path'])
        proof = namespace['source_reader'](producer_raw, material)
        need(proof['candidate_function'] == READ_PIN and proof['full_inverse'] is True, 'exact selected projected read function')
        put('SOURCE-READER-DERIVATION.json', enc(proof))
        result = constructor.derive_negative_sources(inputs_raw, read_pinned=material.read)
        need(result['report']['state'] == 'SOURCE_ONLY_ACTUAL_PHYSICAL_PLANS_UNBOUND' and
             result['report']['complete_originals_rechecked'] is True and
             result['report']['all_source_inverses_exact'] is True and result['report']['fixed19_credit'] == 0 and
             all(result['report'][key] is None for key in ('actual_freeze_admission', 'actual_BUILD', 'actual_READY')) and
             len(result['packages']) == 11 and not os.path.lexists(DERIVED), 'complete pure source derivation only, no publication')
        for number in range(3, 10):
            plan = material.strict(result['files']['plans/NEG-%02d.template.json' % number])
            need(plan['case_id'] == 'NEG-%02d' % number and plan['automatic_retry'] is False and plan['case_qualified'] is False and
                 all(plan[key] is None for key in ('actual_plan', 'actual_freeze_admission', 'actual_sealed_BUILD',
                    'actual_four_role_READY', 'registered_owner_request', 'nonce', 'actual_scope', 'actual_argv', 'fresh_owned_label')),
                 'all seven actual task templates remain unbound')
        empties = [row for row in material.BOOK.values() if row['bytes'] == 0]
        need(len(empties) == 3 and all(row['sha256'] == pin(b'')['sha256'] for row in empties), 'all actual empty originals fully read')
        cases.append({'id': 'same_actual_constructor_complete_with_candidate_publisher_reader', 'passed': True,
                      'kind': 'actual_complete_source_API_positive_in_memory_only', 'source_family_count': 11,
                      'unbound_case_count': 7, 'planned_file_count': len(result['files']),
                      'planned_file_bytes': sum(map(len, result['files'].values())), 'empty_originals': empties,
                      'planned_files_digest': pin(enc([{'path': name, **pin(raw)} for name, raw in sorted(result['files'].items())]))})

        for label, fields, expected in (
            ('empty_size_boolean_rejected', {'bytes': False}, 'bounded typed source descriptor'),
            ('empty_wrong_hash_rejected', {'sha256': '0' * 64}, 'full source bytes/hash/metadata'),
        ):
            row = {key: empties[0][key] for key in ('path', 'bytes', 'sha256')}
            row.update(fields)
            before = enc(material.BOOK)
            try:
                material.read(row)
            except ValueError as exc:
                need(str(exc) == expected, 'exact malformed descriptor rejection')
            else:
                raise AssertionError('candidate accepted malformed empty-original descriptor')
            need(enc(material.BOOK) == before, 'invalid original must not alter admitted source book')
            cases.append({'id': label, 'passed': True, 'kind': 'explicit_in_memory_descriptor_mutation',
                          'rejection': expected, 'original_book_unchanged': True})
        for record in list(material.BOOK.values()):
            material.read({key: record[key] for key in ('path', 'bytes', 'sha256')})
        need(not os.path.lexists(DERIVED), 'no derived source publication after pure control')
    except BaseException as exc:
        error = {'class': type(exc).__name__, 'detail': str(exc), 'traceback': traceback.format_exc()}

    book = [] if material is None else list(material.BOOK.values())
    book_row = put('ORIGINALS.json', enc(book))
    report_row = None if result is None else put('CONSTRUCTOR-REPORT.json', enc(result['report']))
    value = {'schema': 'hepta.fc33.actual-publisher-empty-original-controls.v1',
             'state': 'COMPLETE_NARROW_HOST_CONTROLS' if error is None else 'CONTROL_FAILED',
             'publisher02': PUBLISHER, 'actual_constructor02': CONSTRUCTOR, 'actual_inputs02': INPUTS,
             'candidate_projector': PROJECTOR_PIN, 'candidate_projected_reader': READ_PIN,
             'cases': cases, 'passed': error is None and len(cases) == 4, 'error': error,
             'originals': book_row, 'unique_original_count': len(book),
             'unique_original_bytes': sum(row['bytes'] for row in book),
             'all_complete_originals_rechecked': error is None, 'constructor_report': report_row,
             'source02_output_published': False, 'source03_output_published': False,
             'phone_calls': 0, 'model_requests': 0, 'native_dispatches': 0,
             'actual_BUILD': None, 'actual_READY': None, 'case_qualification': False}
    row = put('RESULT.json', enc(value))
    print(json.dumps({'state': value['state'], 'result': row, 'originals': book_row, 'constructor_report': report_row,
                      'passed_cases': sum(item['passed'] for item in cases), 'error': error,
                      'source_publications': 0, 'phone_calls': 0}, sort_keys=True))
    if error is not None:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
