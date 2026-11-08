"""Read the already published installation reader; no process or device action.

The returned READY describes its original observation only. Each original case
operator still performs its existing live admission checks before a Send.
"""
import hashlib
import types

B = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
STAGE = {'path': B + '/followthrough-fc33-install-build-controller01/source/derive_release_install_stages_UNBOUND.py',
    'bytes': 64682, 'sha256': '60c6d2e84216798037133199882c5d34101808eb9035a741c64f22d6aa3fbece'}
COMBINATION = '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def pin(raw):
    need(type(raw) is bytes, 'whole original bytes required')
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def load_stage(read_pinned):
    raw = read_pinned(dict(STAGE))
    need(pin(raw) == {k: STAGE[k] for k in ('bytes', 'sha256')}, 'exact published stage source')
    module = types.ModuleType('reviewed_actual_installation_stage')
    module.__file__ = STAGE['path']
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    need(module.FROZEN_INPUTS is None, 'published stage source remains unbound')
    return module


def verify_actual_installation(construction, *, read_pinned):
    """Accept one actual final-install DERIVATION descriptor and complete reader.

    All existing reader originals are reverified. No caller-provided success
    flag, fixture BUILD, or path-only READY can replace these originals.
    The internal read_original callable resolves only the verified original map.
    """
    need(construction is not None, 'UNBOUND_ACTUAL_INSTALLATION_NO_IO')
    need(callable(read_pinned), 'explicit whole-byte original callback')
    S = load_stage(read_pinned)
    S.exact_descriptor(construction)
    need(set(construction) == {'path', 'bytes', 'sha256'}, 'actual final construction descriptor')
    H, unused = S.load_source(S.HELPER, read_pinned, 'reviewed_actual_installation_helper')
    pool = H.Pool(read_pinned)
    pool.read(STAGE); pool.read(S.HELPER)
    consumer, release_api, sources = H.source_context(pool)
    record = H.strict(pool.read(construction, 4 * 1024 * 1024))
    parent = sources['source/verify_install_start_ready_UNBOUND.py']
    need(record['schema'] == 'hepta.fc33.release-install-stage-construction.v1'
         and record['stage'] == 'final_install_reader'
         and record['state'] == 'ACTUAL_INSTALL_START_READY_READER_BOUND_AND_ORIGINALS_VERIFIED'
         and H.same(record['input_source_chain'], H.SOURCE_DERIVATION)
         and H.same(record['immutable_install_helper'], parent)
         and H.same(record['immutable_unbound_install_helper'], parent)
         and record['source_slots_in_immutable_helper_remain_None'] is True,
         'actual final installation construction from this published source chain')
    actual_inputs = record['actual_install_inputs']
    raw = pool.read(actual_inputs, 4 * 1024 * 1024)
    value = H.strict(raw)
    need(H.same(value['execution_plan'], record['execution_plan'])
         and H.same(value['release_inputs'], record['release_inputs']),
         'same exact actual release and original execution plan')
    expected, inverse = S.bind_none(pool.read(parent), {
        'FROZEN_INPUTS': actual_inputs, 'FROZEN_EXECUTION_PLAN': value['execution_plan']})
    actual_reader = record['actual_install_reader']
    reader_raw = pool.read(actual_reader)
    need(reader_raw == expected, 'complete actual installation reader has only the two None bindings')
    reader = H.source_module(reader_raw, actual_reader, 'reviewed_actual_installed_case_reader')
    need(H.same(reader.SOURCES['release'], sources['source/verify_final_release_inputs.py']),
         'same published complete BUILD reader')
    installed = reader.verify_install_start_ready_originals(raw, read_pinned=read_pinned)
    saved = H.strict(pool.read(record['actual_install_verdict'], 4 * 1024 * 1024))
    need(H.same(saved, installed), 'actual saved installation verdict equals the original reader result')
    need(installed['state'] == 'VERIFIED_ACTUAL_INSTALL_START_READY_EXECUTION_ORIGINALS'
         and installed['actual_installer_and_READY_execution_qualified'] is True
         and installed['original_installer_delta_recomputed'] is True
         and installed['three_original_actor_terminals_and_outputs_verified'] is True
         and installed['all_retained_originals_bookended'] is True
         and installed['runtime_combination_sha256'] == COMBINATION
         and installed['READY_qualification_scope'] == 'TRANSPORT_ONLY_AT_ORIGINAL_OBSERVATION'
         and installed['business_qualified'] is False,
         'existing original reader qualified only the selected actual installation transport')
    originals = reader.Originals(value['original_map'], read_pinned)
    def retained(original):
        matches = [row for row in value['original_map'] if H.same(row['original'], original)]
        need(len(matches) == 1, 'one exact verified original-to-retained mapping')
        row = matches[0]['retained']
        reader.descriptor(row, metadata=True)
        body = read_pinned(dict(row))
        need(body == originals.read(original), 'retained alias has the exact complete original bytes')
        return {k: row[k] for k in ('path', 'bytes', 'sha256')}
    release_raw = originals.read(value['release_inputs'], 1024 * 1024)
    release = H.strict(release_raw)
    build_row = release['build_result']
    build_raw = originals.read(build_row, 1024 * 1024)
    need(pool.read(build_row, 1024 * 1024) == build_raw
         and build_row['sha256'] == installed['actual_build_result_sha256'],
         'actual host BUILD directory still contains the original verified BUILD bytes')
    ready_original = installed['actual_ready_original']
    ready_raw = originals.read(ready_original, 1024 * 1024)
    ready_host = retained(ready_original)
    ready = H.strict(ready_raw)
    need(ready['schema'] == 'hepta.r10.actual-readiness.v1'
         and ready['state'] == 'EXACT_COMBINATION_READY_TRANSPORT_ONLY',
         'complete original READY document, not a copied qualification assertion')
    need(originals.read(release['combination']) and release['combination']['sha256'] == COMBINATION,
         'same actual current source combination')
    originals.recheck(); pool.recheck()
    return dict(construction=construction, reader=actual_reader, inputs=actual_inputs,
        verdict=installed, source_inverse=inverse, source_files=sources,
        release_inputs=release, release_inputs_descriptor=value['release_inputs'],
        build_result=build_row, build_raw=build_raw,
        ready_original=ready_original, ready_host=ready_host, ready_raw=ready_raw, ready=ready,
        read_original=originals.read, recheck_originals=originals.recheck,
        source_chain=H.SOURCE_DERIVATION)
