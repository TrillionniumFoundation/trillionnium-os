#!/usr/bin/env python3
"""Rebind reviewed host sources from actual R6 originals, without executing tasks.

The four stages publish source files only. They never run BUILD, an installer,
a READY collector, a materializer, a coordinator, a sender, or a phone command.
FROZEN_INPUTS remains None until Root selects one complete actual input document.
"""
import argparse
import ast
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import types

FROZEN_INPUTS = None
B = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
WORK = str(PurePosixPath(B).parent)
PACKAGE = B + '/followthrough-fc33-r6-source-rebind01'
SCHEMA = 'hepta.fc33.r6.host-source-rebinding-inputs.v1'
STAGES = ('release', 'controllers', 'e2e_sources', 'case_controller')
COMBINATION = '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'
OLD_RUNTIME = '990c726a1fff139761494cc19cf091deb269201f27ea947dda4a5833e3a72f2a'
SHARED = {'bytes': 3519, 'sha256': 'cc7eb624333216e510b540c3af8277e948aa689a108950fa78e8d01c2177e5b1'}
POLICY = {'bytes': 2667752, 'sha256': '69aa6433a11ac4cffb2f1d349cc9f36ec2349a601911c173ebe7d92fff9e0c5b'}
HELPER = {'path': B + '/followthrough-fc33-install-build-controller01/source/derive_component_build_inputs_UNBOUND.py',
    'bytes': 34048, 'sha256': '766f6b933b4982088925669f327e0c7c2d03855b8c3f140052d7fbfd088d1b5f'}
STAGE_PARENT = {'path': B + '/followthrough-fc33-install-build-controller01/source/derive_release_install_stages_UNBOUND.py',
    'bytes': 64682, 'sha256': '60c6d2e84216798037133199882c5d34101808eb9035a741c64f22d6aa3fbece'}
BINDER_PARENT = {'path': B + '/followthrough-fc33-install-build-controller01/source/bind_actual_controller_input.py',
    'bytes': 9085, 'sha256': 'a1bcbebda1ae20af89c859c322c99bbb61c454b6195bb7050224691bbc9598f4'}
CONTROLLER_READER = {'path': B + '/followthrough-fc33-install-build-controller01/source/verify_host_controller_originals.py',
    'bytes': 16570, 'sha256': 'be2b96db92bb456a798c3f8be6c1425a81e3afeadf782940bd695cf4cb3c714a'}
CONSTRUCTOR = {'path': WORK + '/followthrough-20261106-fc33-release-source-chain01/source/derive_reviewed_release_sources_UNBOUND.py',
    'bytes': 33827, 'sha256': '4c8f32d518c4cf17308f561587eeaf12702b8b9addf0bd8e5ad335a33e941835'}
CONSUMER_PARENT = {'path': B + '/followthrough-fc33-release-consumer-r5-source01/source/release_boundaries.py',
    'bytes': 249798, 'sha256': '016d25b5467c96f96f25f7b2d9d606e40ea18a72421e549d0ab630a01f9c2349'}
SOURCE_INPUT_PARENT = {'path': B + '/followthrough-fc33-release-source-chain-r5-derived01/SOURCE-CHAIN-INPUTS.original.json',
    'bytes': 3515, 'sha256': 'e3cc22536e42074ba3fe662101dd4a4c98224de285b0a5c13c32f84d2fac322b'}
LATE_PIN = {'bytes': 181669, 'sha256': '0a9f52cf8fb71177d0816f561cce279811a7182e986c12912d9431bde5997cda'}
GATE_PARENT = {'path': PACKAGE + '/reference/verify_actual_installation_for_cases.original.py',
    'bytes': 6985, 'sha256': '0ce146fa85e665868e47eeb7ea927ebbba08d66ff9bc07c9f09eea42c96eb211'}
CASE_PARENT = {'path': PACKAGE + '/reference/derive_e2e_requests_precompat_UNBOUND.original.py',
    'bytes': 28905, 'sha256': 'd9f40f8c79c0b3059af73b0cf6f189523f7a61dee518c8bb23dd506d417fa15e'}
E2E_PARENT = {'path': B + '/followthrough-fc33-e2e-bound-source-r5-01/BINDING.json',
    'bytes': 60062, 'sha256': '00a6cc4850c40cc710d348480f0d6b2871a145c89ee6801bd195432659a8da15'}
COMPAT_PARENT = {'path': B + '/followthrough-fc33-e2e-coordinator-compat01/SOURCE-COMPAT.json',
    'bytes': 4167, 'sha256': '0ff89af8e719536aa08bba674b9e2dc439afade9d93b7d9aad0dde3536d04dd6'}
BUSINESS_PARENT = {'path': B + '/send_new_native_task_r5.py',
    'bytes': 40788, 'sha256': '5ab04019e94adb989e9909ae3a9aa10db0689de62821ec549db8beb3ec4d0281'}
BUSINESS = {'path': B + '/send_new_native_task_r5_fc33_r6.py',
    'bytes': 41355, 'sha256': 'f90c6ffbf3278b22bf3a48bf055c5ca1cf43c3073c5cc7a852dd09a4cf2eab73'}
OLD_BLOCK = {'path': PACKAGE + '/reference/CLOSE-DETAILS.old.txt',
    'bytes': 251, 'sha256': 'c22be16b96afaa791e75cf8531854bf0064e8cb9b830e87bd85e4c2bbaabbcd5'}
NEW_BLOCK = {'path': PACKAGE + '/reference/CLOSE-DETAILS.new.txt',
    'bytes': 818, 'sha256': '5c88d8b8c4c88fe2605abb55239d21c233e97037ebfdcfb9346f4c4ee2e528f5'}
META = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns')


def need(ok, why):
    if not ok:
        raise ValueError(why)


def pin(raw):
    need(type(raw) is bytes, 'complete original bytes required')
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def enc(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                       allow_nan=False) + '\n').encode()


def same(a, b):
    return enc(a) == enc(b)


def strict(raw):
    need(type(raw) is bytes and len(raw) <= 64 * 1024 * 1024, 'bounded complete input')
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))


def exact(value, names, why):
    need(type(value) is dict and set(value) == set(names), why)
    return value


def no_unknown(value):
    need(value is not None, 'UNBOUND_R6_ACTUAL_SOURCE_INPUT_NO_IO')
    if type(value) is dict:
        for item in value.values():
            no_unknown(item)
    elif type(value) is list:
        for item in value:
            no_unknown(item)


def path(value):
    need(type(value) is str and not any(c in value for c in '\0\r\n\t'), 'plain host path')
    p = PurePosixPath(value)
    need(p.is_absolute() and str(p) == value and '..' not in p.parts, 'canonical host path syntax')
    return p


def output_root(value):
    p = path(value)
    need(p.parent == PurePosixPath(B), 'one explicit fresh source namespace directly under B')
    return p


def descriptor(row):
    exact(row, ('path', 'bytes', 'sha256'), 'exact three-field original descriptor')
    p = path(row['path'])
    need(PurePosixPath(WORK) in p.parents and type(row['bytes']) is int
         and 0 <= row['bytes'] <= 64 * 1024 * 1024 and type(row['sha256']) is str
         and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'typed bounded actual host original')
    return {k: row[k] for k in ('path', 'bytes', 'sha256')}


def located(name, raw):
    return descriptor(dict(path=str(name), **pin(raw)))


class Pool:
    def __init__(self, callback):
        need(callable(callback), 'explicit complete original byte reader')
        self.callback, self.rows, self.total = callback, {}, 0

    def read(self, row):
        row = descriptor(row)
        raw = self.callback(dict(row))
        need(type(raw) is bytes and same(pin(raw), {k: row[k] for k in ('bytes', 'sha256')}),
             'complete original bytes, length and SHA256 must agree')
        old = self.rows.get(row['path'])
        if old is None:
            need(len(self.rows) < 4096 and self.total + len(raw) <= 512 * 1024 * 1024,
                 'bounded complete source original pool')
            self.rows[row['path']] = (row, raw)
            self.total += len(raw)
        else:
            need(same(old[0], row) and old[1] == raw, 'original changed between references')
        return raw

    def recheck(self):
        for row, raw in list(self.rows.values()):
            need(self.callback(dict(row)) == raw, 'all original bytes must survive final bookend')


def module(raw, row, name):
    need(same(pin(raw), {k: row[k] for k in ('bytes', 'sha256')}), 'one complete pinned source')
    value = types.ModuleType(name)
    value.__file__ = row['path']
    exec(compile(raw, row['path'], 'exec'), value.__dict__)
    return value


class Context:
    def __init__(self, value, callback):
        exact(value, ('schema', 'stage', 'output_root', 'actual'), 'closed source construction input')
        need(value['schema'] == SCHEMA and value['stage'] in STAGES, 'one implemented source stage')
        no_unknown(value)
        self.value, self.out, self.pool = value, output_root(value['output_root']), Pool(callback)
        self.r_raw = self.pool.read(CONSTRUCTOR)
        self.R = module(self.r_raw, CONSTRUCTOR, 'reviewed_release_source_constructor')
        need(self.R.FROZEN_INPUTS is None, 'original release source constructor remains unbound')
        self.h_raw = self.pool.read(HELPER)
        self.H = module(self.h_raw, HELPER, 'reviewed_held_dirfd_source_publisher')
        self.publications, self.changes = [], {}

    def change(self, raw, bindings, *, replacements=()):
        c = self.R.Changes(raw)
        for name, value in bindings.items():
            if type(value) is dict and set(value) == {'path', 'bytes', 'sha256'}:
                value = descriptor(value)
            c.rhs(name, value)
        for before, after in replacements:
            c.once(before, after)
        return c.finish()

    def writer(self, files, terminal):
        """Reuse the full held-dirfd writer; only its closed layout/terminal change."""
        need(type(files) is dict and terminal in files, 'one complete source publication map')
        dirs = {''}
        for name, raw in files.items():
            need(type(name) is str and type(raw) is bytes, 'source members are complete bytes')
            rel = PurePosixPath(name)
            need(not rel.is_absolute() and str(rel) == name and '..' not in rel.parts
                 and not any(c in name for c in '\0\r\n\t'), 'safe closed source relative path')
            for parent in rel.parents:
                if str(parent) != '.':
                    dirs.add(str(parent))
        layout = tuple(sorted(dirs, key=lambda n: (n.count('/') + bool(n), n)))
        node = next(n for n in ast.parse(self.h_raw).body
                    if isinstance(n, ast.FunctionDef) and n.name == 'publish_material')
        original = b''.join(self.h_raw.splitlines(keepends=True)[node.lineno - 1:node.end_lineno]).decode()
        anchor = "directories=('', 'originals', 'source', 'requests', 'reference')"
        need(original.count(anchor) == 1, 'exact existing held-dirfd layout anchor')
        changed = original.replace(anchor, 'directories=' + repr(layout), 1)
        need(terminal in ('DERIVATION.json', 'BINDING.json'), 'one reviewed terminal filename')
        if terminal != 'DERIVATION.json':
            changed = changed.replace("'DERIVATION.json'", repr(terminal))
        c = self.R.Changes(self.h_raw)
        if changed != original:
            c.function('publish_material', changed)
            raw, proof = c.finish()
        else:
            raw = self.h_raw
            proof = dict(parent=pin(raw), candidate=pin(raw), changes=[], complete_inverse=True)
        api = module(raw, located(self.out / 'source/host_writer_derivative.py', raw),
                     'reviewed_exact_source_layout_writer')
        return api.publish_material, dict(source=HELPER, closed_directories=layout,
                                         terminal=terminal, full_source_inverse=proof)

    def add_publication(self, out, files, terminal='DERIVATION.json'):
        out = output_root(str(out))
        need(all(str(out) != item['output_root'] for item in self.publications), 'distinct fresh source roots')
        writer, proof = self.writer(files, terminal)
        self.publications.append(dict(output_root=str(out), files=files, terminal=terminal,
                                      publish=writer, publisher_proof=proof))


def freeze_context(ctx, authority):
    """Read the completed host freeze and its original controller; no producer runs."""
    exact(authority, ('freeze', 'source', 'controller'), 'three actual freeze authority originals')
    p = ctx.pool
    raw = p.read(authority['freeze']); freeze = strict(raw)
    root = path(freeze['output'])
    need(root.parent == PurePosixPath(B) and authority['freeze']['path'] == str(root / 'FREEZE-RESULT.json')
         and freeze['schema'] == 'hepta.fc33.native-bound.actual-host-freeze.v1'
         and freeze['state'] == 'FROZEN_FOR_NEW_NEG01_THEN_NEG02_NOT_QUALIFIED'
         and same(freeze['source'], authority['source'])
         and freeze['combination']['sha256'] == COMBINATION
         and freeze['runtime_manifest']['sha256'] != OLD_RUNTIME
         and same(freeze['actual_policy'], POLICY), 'actual new runtime with unchanged reviewed production/policy')
    for name in ('phone_calls', 'native_submissions', 'new_nonces'):
        need(type(freeze[name]) is int and freeze[name] == 0, 'source-only host freeze')
    for name in ('production_ready', 'full19_qualified', 'automatic_retry'):
        need(freeze[name] is False, 'source freeze cannot grant execution qualification')
    need(freeze['all_inputs_bookended_before_publication'] is True
         and freeze['all_output_files_read_back'] is True and freeze['terminal_record_is_last'] is True,
         'original complete host freeze terminal')
    source = p.read(authority['source'])
    need(p.read(located(root / 'DERIVATION.json', raw)) == raw, 'both complete freeze terminal copies')
    controller_raw = p.read(CONTROLLER_READER)
    C = module(controller_raw, CONTROLLER_READER, 'reviewed_freeze_controller_original_reader')
    record = strict(p.read(authority['controller']))
    job, status, streams = C.controller(record, code=0, complete=True)
    request = record['request']
    argv = [authority['source']['path'], '--freeze-reviewed-host-runtime', authority['source']['sha256']]
    need(request['host'] == 'mac' and request['executable'] == '/usr/bin/python3'
         and request['args'] == argv and type(request['idempotency_key']) is str
         and request['idempotency_key'] and not request.get('stdin')
         and all(same(job[k], request[k]) for k in ('host', 'executable', 'args', 'idempotency_key')),
         'actual original request executed precisely the supplied freezer source')
    need(streams['stderr'] == b'' and streams['stdout'].endswith(b'\n'), 'complete successful freeze stdout')
    summary = strict(streams['stdout'])
    need(same(summary['freeze'], authority['freeze']) and summary['state'] == freeze['state']
         and all(same(summary[k], freeze[k]) for k in ('runtime_manifest', 'root_chain_manifest',
                    'combination', 'complete_directory_bytes'))
         and type(summary['phone_calls']) is int and summary['phone_calls'] == 0
         and summary['full19_qualified'] is False, 'controller terminal names these exact frozen artifacts')
    rows = freeze['files']
    need(type(rows) is dict and 1 <= len(rows) <= 256, 'bounded complete frozen source member map')
    files = {}
    for name, row in rows.items():
        rel = PurePosixPath(name)
        need(not rel.is_absolute() and str(rel) == name and '..' not in rel.parts
             and row['path'] == str(root / rel), 'exact frozen output namespace')
        files[name] = p.read(row)
    need(files['FREEZER-SOURCE.original.py'] == source, 'retained freezer source equals actual entry')
    need(type(freeze['result_bytes']) is int and freeze['result_bytes'] == len(raw)
         and type(freeze['terminal_copies']) is int and freeze['terminal_copies'] == 2
         and type(freeze['payload_bytes']) is int and freeze['payload_bytes'] == sum(map(len, files.values()))
         and type(freeze['complete_directory_bytes']) is int
         and freeze['complete_directory_bytes'] == freeze['payload_bytes'] + 2 * len(raw)
         and freeze['complete_directory_bytes'] <= 32 * 1024 * 1024, 'original freeze byte accounting')
    need(same(rows['runtime/MANIFEST.json'], freeze['runtime_manifest'])
         and same(rows['COMBINATION.json'], freeze['combination'])
         and pin(files['COMBINATION.json'])['sha256'] == COMBINATION
         and same(pin(files['shared/SHARED-MATERIALS.json']), SHARED), 'same current source material tuple')
    runtime = strict(files['runtime/MANIFEST.json'])
    members = runtime['files']
    need(type(members) is list and 1 <= len(members) <= 128
         and len({r['path'] for r in members}) == len(members)
         and runtime['current_combination_sha256'] == COMBINATION
         and runtime['current_policy_sha256'] == POLICY['sha256'], 'complete actual runtime manifest')
    for row in members:
        need(same(pin(files['runtime/' + row['path']]), {k: row[k] for k in ('bytes', 'sha256')}),
             'every actual runtime member has its complete frozen bytes')
    late = files['runtime/source/late_boundary.py']
    need(same(pin(late), LATE_PIN), 'this source rebinder preserves the exact reviewed source-parent reader')
    records = ctx.R.literal(late, 'SOURCE_PARENT_RECORDS')
    failed = ctx.R.literal(late, 'HISTORICAL_FAILED_BOUNDARY_COUNT')
    prefix = ctx.R.literal(late, 'MAX_NEW_CURRENT_CASE_PREFIX')
    need(type(records) is tuple and type(failed) is int and type(prefix) is int,
         'actual pinned LATE record and integer declarations')
    chain, budget = failed + len(records) + prefix, 3 * (failed + len(records) + prefix + 2)
    need(same(runtime['source_parent_records'], list(records))
         and type(runtime['native_chain_cap']) is int and runtime['native_chain_cap'] == chain
         and type(runtime['component_role_cap']) is int and runtime['component_role_cap'] == budget
         and type(runtime['runtime_file_count']) is int and runtime['runtime_file_count'] == len(members)
         and runtime['source_parent_qualification_is_current_tuple_credit'] is False,
         'actual records determine chain/role/member budgets without inherited qualification')
    new_block = p.read(NEW_BLOCK)
    sender = files['runtime/source/send_new_native_guard_task_r10_r4.py']
    need(sender.count(new_block) == 1, 'R6 actually contains the final reviewed UI closing block')
    return dict(authority=authority, raw=raw, freeze=freeze, files=files, runtime=runtime,
                runtime_row=freeze['runtime_manifest'], count=len(members), chain=chain, budget=budget,
                controller_job_id=job['id'])


def release_stage(ctx):
    a = exact(ctx.value['actual'], ('freeze_authority', 'binding_output_root'), 'actual release-source inputs')
    f = freeze_context(ctx, a['freeze_authority'])
    binding_root = output_root(a['binding_output_root'])
    need(binding_root != ctx.out, 'separate binding and derived source namespaces')
    parent = ctx.pool.read(CONSUMER_PARENT)
    need(ctx.R.literal(parent, 'PACKAGE_SHA') is None, 'original package identity is explicitly unbound')
    updates = {'PACKAGE_SHA': f['runtime_row']['sha256']}
    for name, value in [('PACKAGE_FILE_COUNT', f['count']), ('CURRENT_COMPONENT_CHAIN_LENGTH', f['chain']),
                        ('COMPONENT_ROLE_BUDGET', f['budget'])]:
        old = ctx.R.literal(parent, name)
        need(type(old) is int, 'reviewed parent budget type')
        if old != value:
            updates[name] = value
    consumer, inverse = ctx.change(parent, updates)
    need(ctx.R.literal(consumer, 'CURRENT_COMBINATION_SHA') == COMBINATION, 'unchanged production combination')
    previous = strict(ctx.pool.read(SOURCE_INPUT_PARENT))
    inputs = dict(schema=ctx.R.INPUT_SCHEMA, material=previous['material'],
                  consumer=dict(source=located(binding_root / 'source/release_boundaries.py', consumer),
                                runtime_package=f['runtime_row']), output_root=str(ctx.out))
    need(ctx.pool.read(inputs['material']['combination']) == f['files']['COMBINATION.json']
         and ctx.pool.read(inputs['material']['shared']) == f['files']['shared/SHARED-MATERIALS.json'],
         'actual R6 retains all previously reviewed production material bytes')
    inputs_raw = enc(inputs)
    input_row = located(binding_root / 'SOURCE-CHAIN-INPUTS.json', inputs_raw)
    bound, constructor_inverse = ctx.change(ctx.r_raw, {'FROZEN_INPUTS': input_row})
    bound_row = located(binding_root / 'source/derive_reviewed_release_sources_BOUND.py', bound)
    virtual = {input_row['path']: (input_row, inputs_raw), inputs['consumer']['source']['path']: (inputs['consumer']['source'], consumer)}
    def read_for_source_derivation(row):
        if row['path'] in virtual:
            selected, raw = virtual[row['path']]
            need(same(row, selected), 'planned source descriptor has exact complete bytes')
            return raw
        return ctx.pool.read(row)
    constructor = module(bound, bound_row, 'reviewed_r6_bound_source_constructor')
    result = constructor.derive_reviewed_source_chain(inputs_raw, read_pinned=read_for_source_derivation)
    need(len(result['files']) == 14, 'same fourteen source products from original constructor')
    binding_files = {'source/release_boundaries.py': consumer,
        'source/derive_reviewed_release_sources_BOUND.py': bound, 'SOURCE-CHAIN-INPUTS.json': inputs_raw,
        'reference/release_boundaries.UNBOUND.py': parent,
        'reference/derive_reviewed_release_sources_UNBOUND.py': ctx.r_raw,
        'BINDING-PROOF.json': enc(dict(schema='hepta.fc33.r6.exact-source-binding-proof.v1',
            actual_freeze_authority=a['freeze_authority'], consumer_parent=CONSUMER_PARENT,
            constructor_parent=CONSTRUCTOR, consumer=inputs['consumer']['source'], constructor=bound_row,
            source_inputs=input_row, consumer_change=inverse, constructor_change=constructor_inverse,
            full_source_inverse=True, planned_inputs_are_source_bytes_only=True,
            actual_BUILD=None, actual_READY=None, actual_cases=None, phone_calls=0))}
    binding_report = dict(schema='hepta.fc33.reviewed-source-binding-publication.v1',
        state='SOURCE_BINDING_ONLY_NO_NEW_CASE_QUALIFICATION',
        files=[located(binding_root / n, b) for n, b in sorted(binding_files.items())],
        actual_freeze_authority=a['freeze_authority'], full_source_inverse=True,
        actual_BUILD=None, actual_READY=None, actual_install=None, new_current_case_originals=None, phone_calls=0)
    binding_files['DERIVATION.json'] = enc(binding_report)
    ctx.add_publication(binding_root, binding_files)
    files = dict(result['files'])
    files.update({'SOURCE-BINDING.json': enc(result['source_binding']),
        'SOURCE-CHANGES.json': enc(result['changes']), 'CONSUMER-RUNTIME.json': enc(result['consumer_runtime']),
        'SOURCE-CHAIN-INPUTS.original.json': inputs_raw, 'CONSTRUCTOR-SOURCE.original.py': bound})
    # Keep the existing 20-member report inventory used by the original component constructor.
    files['PUBLISHER-DERIVATION.json'] = enc(dict(schema='hepta.fc33.r6.held-dirfd-source-publication.v1',
        source_constructor=CONSTRUCTOR, source_input=input_row, binding_terminal=located(binding_root / 'DERIVATION.json', binding_files['DERIVATION.json']),
        actual_freeze_authority=a['freeze_authority'], writer_parent=HELPER, no_actor_execution=True))
    need(len(files) == 20, 'existing source-chain reader receives its exact member family')
    report = dict(result['report'])
    report.update(constructor=bound_row, source_inputs=input_row,
        source_binding=located(ctx.out / 'SOURCE-BINDING.json', files['SOURCE-BINDING.json']),
        consumer_runtime=located(ctx.out / 'CONSUMER-RUNTIME.json', files['CONSUMER-RUNTIME.json']),
        runtime_freeze_authority=a['freeze_authority'], source_rebinding_stage='release',
        files=[located(ctx.out / n, b) for n, b in sorted(files.items())])
    files['DERIVATION.json'] = enc(report)
    ctx.add_publication(ctx.out, files)
    return dict(state='R6_RELEASE_SOURCES_ONLY_ACTUAL_EXECUTION_UNBOUND',
                release_derivation=located(ctx.out / 'DERIVATION.json', files['DERIVATION.json']),
                binding_derivation=located(binding_root / 'DERIVATION.json', binding_files['DERIVATION.json']),
                consumer=located(ctx.out / 'source/release_boundaries.py', consumer),
                readiness=result['source_binding']['readiness'], runtime=f['runtime_row'])


def release_context(ctx, row):
    raw = ctx.pool.read(row); report = strict(raw)
    need(report['state'] == 'SOURCE_CANDIDATES_ONLY_ACTUAL_EXECUTION_UNBOUND'
         and report['actual_execution_slots_unbound'] is True
         and all(report[k] is False for k in ('BUILD', 'install', 'READY'))
         and report['source_rebinding_stage'] == 'release', 'actual R6 source-only release derivation')
    root = path(row['path']).parent
    need(path(row['path']).name == 'DERIVATION.json', 'actual release source terminal')
    rows = report['files']
    need(type(rows) is list and len(rows) == 20 and len({r['path'] for r in rows}) == 20,
         'complete actual release source member list')
    selected, bodies = {}, {}
    for item in rows:
        name = str(path(item['path']).relative_to(root))
        selected[name], bodies[name] = descriptor(item), ctx.pool.read(item)
    f = freeze_context(ctx, report['runtime_freeze_authority'])
    input_row = report['source_inputs']; inputs_raw = ctx.pool.read(input_row); inputs = strict(inputs_raw)
    need(same(inputs['consumer']['runtime_package'], f['runtime_row']) and inputs['output_root'] == str(root),
         'actual source constructor selected this R6 runtime and namespace')
    consumer = ctx.pool.read(inputs['consumer']['source'])
    parent = ctx.pool.read(CONSUMER_PARENT)
    updates = {'PACKAGE_SHA': f['runtime_row']['sha256']}
    for name, v in [('PACKAGE_FILE_COUNT', f['count']), ('CURRENT_COMPONENT_CHAIN_LENGTH', f['chain']),
                    ('COMPONENT_ROLE_BUDGET', f['budget'])]:
        if ctx.R.literal(parent, name) != v:
            updates[name] = v
    expected, unused = ctx.change(parent, updates)
    need(consumer == expected == bodies['source/release_boundaries.py'], 'entire actual consumer inverse')
    bound, unused = ctx.change(ctx.r_raw, {'FROZEN_INPUTS': input_row})
    need(ctx.pool.read(report['constructor']) == bound == bodies['CONSTRUCTOR-SOURCE.original.py'],
         'entire actual source constructor has only the one None binding')
    ctor = module(bound, report['constructor'], 'reviewed_actual_r6_release_source_constructor')
    recomputed = ctor.derive_reviewed_source_chain(inputs_raw, read_pinned=ctx.pool.read)
    need(all(bodies[n] == body for n, body in recomputed['files'].items())
         and bodies['SOURCE-BINDING.json'] == enc(recomputed['source_binding'])
         and bodies['SOURCE-CHANGES.json'] == enc(recomputed['changes'])
         and bodies['CONSUMER-RUNTIME.json'] == enc(recomputed['consumer_runtime']),
         'all actual published release source bytes recompute through original public constructor')
    return dict(row=row, raw=raw, report=report, root=root, selected=selected, bodies=bodies,
                inputs=inputs, freeze=f, source_binding=recomputed['source_binding'])


def controllers_stage(ctx):
    a = exact(ctx.value['actual'], ('release_derivation',), 'one actual R6 release source terminal')
    release = release_context(ctx, a['release_derivation'])
    helper, hp = ctx.change(ctx.h_raw, {'SOURCE_ROOT': str(release['root']),
        'SOURCE_DERIVATION': a['release_derivation'], 'RUNTIME': release['freeze']['runtime_row']})
    helper_row = located(ctx.out / 'source/derive_component_build_inputs_UNBOUND.py', helper)
    stage_parent = ctx.pool.read(STAGE_PARENT)
    stage, sp = ctx.change(stage_parent, {'HELPER': helper_row})
    stage_row = located(ctx.out / 'source/derive_release_install_stages_UNBOUND.py', stage)
    binder, bp = ctx.change(ctx.pool.read(BINDER_PARENT), {'PACKAGE_ROOT': str(ctx.out),
        'SOURCES': {'component_build': helper_row, 'release_install_stage': stage_row}})
    gate, gp = ctx.change(ctx.pool.read(GATE_PARENT), {'STAGE': stage_row})
    gate_row = located(ctx.out / 'source/verify_actual_installation_for_cases.py', gate)
    need(all(ctx.R.literal(b, 'FROZEN_INPUTS') is None for b in (helper, stage)),
         'both actual case/BUILD/install stage inputs remain None')
    files = {'source/derive_component_build_inputs_UNBOUND.py': helper,
        'source/derive_release_install_stages_UNBOUND.py': stage,
        'source/bind_actual_controller_input.py': binder,
        'source/verify_actual_installation_for_cases.py': gate,
        'SOURCE-INVERSES.json': enc(dict(component_helper=hp, stage=sp, binder=bp, case_install_gate=gp)),
        'reference/RELEASE-DERIVATION.original.json': release['raw']}
    report = dict(schema='hepta.fc33.r6.controller-source-rebinding.v1',
        state='HOST_SOURCE_CONTROLLERS_BOUND_ACTUAL_CASE_BUILD_INSTALL_INPUTS_UNBOUND',
        release_derivation=a['release_derivation'], runtime=release['freeze']['runtime_row'],
        helper=helper_row, stage=stage_row, case_install_gate=gate_row,
        binder=located(ctx.out / 'source/bind_actual_controller_input.py', binder),
        unchanged_P4_observer_and_controller_reader_reused=True, all_source_inverses_complete=True,
        actual_NEG01=None, actual_NEG02=None, actual_LEASE_originals=None, actual_BUILD=None, actual_READY=None,
        phone_calls=0, actor_dispatches=0,
        files=[located(ctx.out / n, b) for n, b in sorted(files.items())])
    files['DERIVATION.json'] = enc(report)
    ctx.add_publication(ctx.out, files)
    return dict(state=report['state'], controller_derivation=located(ctx.out / 'DERIVATION.json', files['DERIVATION.json']),
                binder=report['binder'], case_install_gate=gate_row)


def actual_e2e_parent(ctx):
    raw = ctx.pool.read(E2E_PARENT); parent = strict(raw)
    need(parent['state'] == 'SOURCE_BOUND_TASK_EXECUTION_UNBOUND'
         and parent['source_combination_sha256'] == COMBINATION, 'same actual E2E source parent')
    root = path(E2E_PARENT['path']).parent
    rows = parent['files']
    need(type(rows) is list and len(rows) == 48 and len({r['path'] for r in rows}) == 48,
         'all 48 exact parent members')
    selected, files = {}, {}
    for row in rows:
        name = str(path(row['path']).relative_to(root))
        selected[name], files[name] = descriptor(row), ctx.pool.read(row)
    compat_raw = ctx.pool.read(COMPAT_PARENT); compat = strict(compat_raw)
    name = 'source/run_fixed19_e2e_root_once.py'
    need(same(compat['parent_binding'], E2E_PARENT)
         and same(compat['parent_coordinator'], selected[name]), 'actual coordinator compatibility parent')
    fixed = ctx.pool.read(compat['coordinator'])
    before = b'   receipts.append(dict(phase=phase,**result))\n'
    after = b"   receipts.append({**result,'phase':phase})\n"
    need(files[name].count(before) == 1 and fixed == files[name].replace(before, after)
         and fixed.count(after) == 1 and fixed.replace(after, before) == files[name],
         'retain the actually published one-line receipt compatibility fix')
    return parent, selected, files, compat, fixed


def e2e_sources_stage(ctx):
    a = exact(ctx.value['actual'], ('release_derivation', 'business_sender'), 'actual R6 E2E source inputs')
    release = release_context(ctx, a['release_derivation'])
    need(same(a['business_sender'], BUSINESS), 'exact reviewed business sender directly under original B')
    business = ctx.pool.read(a['business_sender']); parent_sender = ctx.pool.read(BUSINESS_PARENT)
    before, after = ctx.pool.read(OLD_BLOCK), ctx.pool.read(NEW_BLOCK)
    need(parent_sender.count(before) == 1 and business == parent_sender.replace(before, after)
         and business.replace(after, before) == parent_sender, 'only the reviewed business UI block changed')
    parent, selected, files, compat, coordinator_parent = actual_e2e_parent(ctx)
    files = dict(files)
    ready_row = release['selected']['source/collect_r10_readiness.py']
    core_name = 'operator-chain/root_acceptance_r10.py'
    replacements = (
        ("    read(b/'send_new_native_task_r5.py',65536,SENDER_SHA)",
         "    read(b/'send_new_native_task_r5_fc33_r6.py',65536,SENDER_SHA)"),
        ("    path=b/'send_new_native_task_r5.py';read(path,65536,SENDER_SHA)",
         "    path=b/'send_new_native_task_r5_fc33_r6.py';read(path,65536,SENDER_SHA)"))
    core, core_inverse = ctx.change(files[core_name], {'SENDER_SHA': BUSINESS['sha256'],
        'READINESS_SHA': ready_row['sha256']}, replacements=replacements)
    files[core_name] = core
    om_name = 'operator-chain/SOURCE-MANIFEST.json'
    old_manifest_raw = files[om_name]; om = strict(old_manifest_raw)
    operators = {PurePosixPath(name).name: raw for name, raw in files.items()
                 if name.startswith('operator-chain/') and name.endswith('.py')}
    need(len(operators) == 6, 'the original six operator source bodies')
    om.update(files=[dict(path=name, **pin(raw)) for name, raw in sorted(operators.items())],
        parent_operator_manifest_sha256=pin(old_manifest_raw)['sha256'],
        current_collector_manifest=located(ctx.out / 'collector-package/MANIFEST.json', files['collector-package/MANIFEST.json']),
        current_shared_materials=located(ctx.out / 'shared/SHARED-MATERIALS.json', files['shared/SHARED-MATERIALS.json']),
        actual_component_runtime_manifest=release['freeze']['runtime_row'],
        actual_runtime_host_freeze=release['freeze']['authority']['freeze'],
        current_formal_source_binding=release['selected']['SOURCE-BINDING.json'],
        reviewed_readiness_helper_sha256=ready_row['sha256'], sender_sha256=BUSINESS['sha256'])
    files[om_name] = enc(om)
    coordinator, coordinator_inverse = ctx.change(coordinator_parent, {'OPERATOR_MANIFEST_PIN': pin(files[om_name])})
    files['source/run_fixed19_e2e_root_once.py'] = coordinator
    files['reference/RUNTIME-FREEZE.original.json'] = release['freeze']['raw']
    files['reference/RUNTIME-MANIFEST.original.json'] = release['freeze']['files']['runtime/MANIFEST.json']
    files['reference/FORMAL-SOURCE-BINDING.original.json'] = release['bodies']['SOURCE-BINDING.json']
    files['reference/readiness.source.original.py'] = release['bodies']['source/collect_r10_readiness.py']
    files['reference/release_boundaries.source.original.py'] = release['bodies']['source/release_boundaries.py']
    inputs = dict(parent_binding=E2E_PARENT, coordinator_compatibility=COMPAT_PARENT,
        release_derivation=a['release_derivation'], business_sender=a['business_sender'],
        runtime_freeze=release['freeze']['authority']['freeze'], runtime_manifest=release['freeze']['runtime_row'],
        formal_source_binding=release['selected']['SOURCE-BINDING.json'],
        boundary_consumer=release['selected']['source/release_boundaries.py'], readiness_source=ready_row,
        owned_capture_source=parent['owned_capture_source'], output=str(ctx.out))
    files['BINDING-INPUTS.json'] = enc(inputs)
    need(set(files) == set(selected) and len(files) == 48, 'same complete E2E source member family')
    for name, raw in files.items():
        if name.endswith('.py'):
            compile(raw, name, 'exec')
    binding = dict(schema='hepta.fc33.e2e.actual-source-binding.v1', state='SOURCE_BOUND_TASK_EXECUTION_UNBOUND',
        inputs=inputs, source_combination_sha256=COMBINATION,
        operator_manifest=located(ctx.out / om_name, files[om_name]),
        collector_manifest=located(ctx.out / 'collector-package/MANIFEST.json', files['collector-package/MANIFEST.json']),
        coordinator=located(ctx.out / 'source/run_fixed19_e2e_root_once.py', coordinator),
        shared_materials=located(ctx.out / 'shared/SHARED-MATERIALS.json', files['shared/SHARED-MATERIALS.json']),
        owned_capture_source=parent['owned_capture_source'], actual_business_sender=a['business_sender'],
        actual_release_derivation=a['release_derivation'], reviewed_coordinator_compatibility=COMPAT_PARENT,
        operator_source_inverse=core_inverse, coordinator_source_inverse=coordinator_inverse,
        unchanged_materializer_and_seven_collectors=True, unchanged_production15_and_shared17=True,
        actual_BUILD=None, actual_READY=None, actual_context=None, actual_native_scope=None, actual_request=None,
        phone_calls=0, model_requests=0, native_dispatches=0, new_nonces=0, fixed19_credit=0,
        automatic_retry=False, historical_pass_inherited=False,
        files=[located(ctx.out / n, raw) for n, raw in sorted(files.items())])
    files['BINDING.json'] = enc(binding)
    ctx.add_publication(ctx.out, files, 'BINDING.json')
    return dict(state='R6_E2E_SOURCES_ONLY_ACTUAL_CASE_INPUTS_UNBOUND',
                e2e_binding=located(ctx.out / 'BINDING.json', files['BINDING.json']),
                coordinator=binding['coordinator'], operator_manifest=binding['operator_manifest'])


def controller_context(ctx, row):
    raw = ctx.pool.read(row); report = strict(raw)
    need(report['schema'] == 'hepta.fc33.r6.controller-source-rebinding.v1'
         and report['state'] == 'HOST_SOURCE_CONTROLLERS_BOUND_ACTUAL_CASE_BUILD_INSTALL_INPUTS_UNBOUND',
         'actual newly published R6 controller source terminal')
    release = release_context(ctx, report['release_derivation'])
    root = path(row['path']).parent
    helper, unused = ctx.change(ctx.h_raw, {'SOURCE_ROOT': str(release['root']),
        'SOURCE_DERIVATION': report['release_derivation'], 'RUNTIME': release['freeze']['runtime_row']})
    need(ctx.pool.read(report['helper']) == helper, 'actual helper whole source inverse')
    stage, unused = ctx.change(ctx.pool.read(STAGE_PARENT), {'HELPER': report['helper']})
    need(ctx.pool.read(report['stage']) == stage, 'actual stage whole source inverse')
    gate, unused = ctx.change(ctx.pool.read(GATE_PARENT), {'STAGE': report['stage']})
    need(ctx.pool.read(report['case_install_gate']) == gate, 'actual installation gate whole source inverse')
    binder, unused = ctx.change(ctx.pool.read(BINDER_PARENT), {'PACKAGE_ROOT': str(root),
        'SOURCES': {'component_build': report['helper'], 'release_install_stage': report['stage']}})
    need(ctx.pool.read(report['binder']) == binder, 'actual binding helper whole source inverse')
    for item in report['files']:
        need(path(item['path']).is_relative_to(root), 'controller file under its exact published root')
        ctx.pool.read(item)
    return report, release


def case_controller_stage(ctx):
    a = exact(ctx.value['actual'], ('controller_derivation', 'e2e_binding'), 'actual final case-source inputs')
    controllers, release = controller_context(ctx, a['controller_derivation'])
    binding = strict(ctx.pool.read(a['e2e_binding']))
    need(binding['schema'] == 'hepta.fc33.e2e.actual-source-binding.v1'
         and binding['state'] == 'SOURCE_BOUND_TASK_EXECUTION_UNBOUND'
         and same(binding['actual_release_derivation'], controllers['release_derivation'])
         and same(binding['actual_business_sender'], BUSINESS)
         and same(binding['reviewed_coordinator_compatibility'], COMPAT_PARENT),
         'E2E and installed reader source graph share the same actual R6 release derivation')
    original_value = ctx.value
    check_value = dict(schema=SCHEMA, stage='e2e_sources', output_root=str(path(a['e2e_binding']['path']).parent),
                       actual=dict(release_derivation=controllers['release_derivation'], business_sender=BUSINESS))
    check = Context(check_value, ctx.pool.read)
    e2e_sources_stage(check)
    expected_files = check.publications[0]['files']
    need(ctx.pool.read(a['e2e_binding']) == expected_files['BINDING.json'],
         'actual E2E binding must recompute byte-for-byte through the source-only derivation')
    root = path(a['e2e_binding']['path']).parent
    for item in binding['files']:
        name = str(path(item['path']).relative_to(root))
        need(ctx.pool.read(item) == expected_files[name], 'every actual E2E source byte recomputes')
    parent = ctx.pool.read(CASE_PARENT)
    need(ctx.R.literal(parent, 'FROZEN_INPUTS') is None, 'case inputs are still explicitly unbound')
    source, inverse = ctx.change(parent, {'PACKAGE': str(ctx.out), 'GATE': controllers['case_install_gate'],
        'E2E': str(root), 'BINDING': descriptor(a['e2e_binding'])})
    files = {'source/derive_e2e_requests_UNBOUND.py': source, 'SOURCE-INVERSE.json': enc(inverse),
             'reference/PARENT-CASE-CONSTRUCTOR.original.py': parent}
    source_row = located(ctx.out / 'source/derive_e2e_requests_UNBOUND.py', source)
    report = dict(schema='hepta.fc33.r6.case-request-source-rebinding.v1',
        state='FOUR_ORIGINAL_E2E_REQUEST_ENTRIES_BOUND_ACTUAL_CASE_INPUTS_UNBOUND',
        controller_derivation=a['controller_derivation'], e2e_binding=a['e2e_binding'],
        case_install_gate=controllers['case_install_gate'], constructor=source_row,
        actual_case_inputs=None, actual_materialization=None, actual_context=None, actual_dispatch=None,
        COMP01='INDEPENDENT_JUDGMENT_OF_SAME_ACTUAL_E2E_NATIVE_RETURN_NO_FIFTH_SEND',
        original_four_cases=['E2E-01', 'E2E-02', 'E2E-03', 'E2E-04'], settings_return_required=False,
        phone_calls=0, native_dispatches=0, new_nonces=0, fixed19_credit=0,
        files=[located(ctx.out / n, b) for n, b in sorted(files.items())])
    files['DERIVATION.json'] = enc(report)
    ctx.add_publication(ctx.out, files)
    return dict(state=report['state'], case_controller_derivation=located(ctx.out / 'DERIVATION.json', files['DERIVATION.json']),
                constructor=source_row)


def derive_rebindings(raw, *, read_pinned):
    need(FROZEN_INPUTS is not None, 'UNBOUND_R6_SOURCE_REBINDING_NO_IO')
    selected = descriptor(FROZEN_INPUTS)
    need(type(raw) is bytes and same(pin(raw), {k: selected[k] for k in ('bytes', 'sha256')}),
         'exact selected source-only construction input')
    value = strict(raw)
    no_unknown(value)
    ctx = Context(value, read_pinned)
    need(ctx.pool.read(selected) == raw, 'selected input is one actual original')
    functions = dict(release=release_stage, controllers=controllers_stage,
                     e2e_sources=e2e_sources_stage, case_controller=case_controller_stage)
    result = functions[value['stage']](ctx)
    ctx.pool.recheck()
    result.update(phone_calls=0, BUILD_executed=False, actual_install=None, actual_READY=None,
                  new_acceptance_nonces=0, fixed19_credit=0, automatic_retry=False,
                  original_source_count=len(ctx.pool.rows), original_source_bytes=ctx.pool.total,
                  all_complete_originals_bookended=True)
    return dict(summary=result, publications=ctx.publications)


class HostReader:
    def __init__(self):
        self.observed = {}

    def __call__(self, row):
        row = descriptor(row)
        p = Path(row['path'])
        need(p.resolve(strict=True) == p, 'canonical actual original without symlink ancestors')
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            first = os.fstat(fd)
            meta = lambda s: [getattr(s, n) for n in META]
            need(stat.S_ISREG(first.st_mode) and first.st_nlink == 1 and first.st_size == row['bytes'],
                 'actual complete single-link regular original')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(row['bytes'] + 1)
                need(stream.read(1) == b'', 'complete original EOF')
            need(meta(first) == meta(os.fstat(fd)) == meta(p.lstat())
                 and same(pin(raw), {k: row[k] for k in ('bytes', 'sha256')}), 'actual full9 and byte bookends')
            old = self.observed.get(row['path'])
            observed = dict(row, metadata=meta(first))
            need(old is None or same(old, observed), 'actual original full9 changed between reads')
            self.observed[row['path']] = observed
            return raw
        finally:
            os.close(fd)


def main():
    need(FROZEN_INPUTS is not None, 'UNBOUND_R6_SOURCE_REBINDING_NO_IO')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--publish-host-sources-once', action='store_true', required=True)
    parser.parse_args()
    reader = HostReader()
    raw = reader(FROZEN_INPUTS)
    result = derive_rebindings(raw, read_pinned=reader)
    for item in result['publications']:
        out = Path(item['output_root'])
        need(out.parent.resolve(strict=True) == out.parent and not os.path.lexists(out),
             'every source output must be absent before first publication; no automatic retry')
    for row in list(reader.observed.values()):
        reader({k: row[k] for k in ('path', 'bytes', 'sha256')})
    outputs = []
    for item in result['publications']:
        out = Path(item['output_root'])
        item['publish'](out, item['files'])
        for name, body in item['files'].items():
            need(reader(located(out / name, body)) == body, 'all published source bytes read back')
        outputs.append(located(out / item['terminal'], item['files'][item['terminal']]))
    print(json.dumps(dict(result['summary'], published_source_terminals=outputs), sort_keys=True))


if __name__ == '__main__':
    main()
