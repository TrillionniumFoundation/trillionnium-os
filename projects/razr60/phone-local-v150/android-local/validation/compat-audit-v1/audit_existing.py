#!/usr/bin/env python3
"""Read existing host evidence and write a separate grammar compatibility audit.

No ADB, subprocess, phone interaction, old-evidence edit or replacement verdict.
"""
import argparse
import hashlib
import importlib
import json
from pathlib import Path
import re
import sys


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--drivers', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    drivers = args.drivers.resolve(strict=True)
    base = args.evidence.resolve(strict=True)
    candidates = [base / 'acceptance.json'] if (base / 'acceptance.json').is_file() else list(base.glob('cases/*/acceptance.json'))
    if len(candidates) != 1:
        raise ValueError('supply an existing evidence directory with exactly one acceptance case')
    case = candidates[0].parent
    output = args.output.resolve()
    if output == base or base in output.parents or case in output.parents or output.exists():
        raise ValueError('audit output must be new and outside original evidence')
    sys.path.insert(0, str(drivers))
    acceptance = importlib.import_module('phone_acceptance')
    if Path(acceptance.__file__).resolve() != drivers / 'phone_acceptance.py':
        raise ValueError('wrong compatibility module imported')
    if sha((drivers / 'phone_acceptance.py').read_bytes()) != '8ace4acac2309653e7159dfd62d7bc479a1b0f0b6956ebedb5673cb51a788268':
        raise ValueError('compatibility driver does not match reviewed r1')
    manifest = acceptance.strict_json((case / 'file-manifest.json').read_bytes())
    pins = {entry['path']: entry for entry in manifest['files']}
    consumed = {}

    def read(relative):
        path = case / relative
        if path.is_symlink() or not path.is_file() or case not in path.resolve().parents:
            raise ValueError('unsafe or missing evidence: ' + relative)
        raw = path.read_bytes()
        if len(raw) > 32 * 1024 * 1024:
            raise ValueError('evidence exceeds audit bound')
        pin = pins.get(relative)
        if not pin or len(raw) != pin['bytes'] or sha(raw) != pin['sha256']:
            raise ValueError('evidence differs from original file manifest: ' + relative)
        consumed[relative] = {'path': relative, 'bytes': len(raw), 'sha256': sha(raw)}
        return raw

    old = acceptance.strict_json(read('acceptance.json'))
    collection = acceptance.strict_json(read('collection.json'))
    if old['collection'] != collection:
        raise ValueError('recorded collections disagree')
    packages = {}
    for path in sorted((case / 'task').glob('step-*.json')):
        if not re.fullmatch(r'step-[0-9]{2,}-(?:before|after)\.json', path.name):
            continue
        obs = acceptance.strict_json(read('task/' + path.name))
        identity = obs.get('observation_id')
        if isinstance(identity, str) and acceptance.HEX32.fullmatch(identity):
            package = obs.get('package')
            packages.setdefault(identity, set()).add(package if isinstance(package, str) else None)
    boolean_gates = ('app_receipt_available', 'run_id_binding_valid', 'process_exit_observed',
        'inference_completed', 'native_output_binding_valid', 'accelerator_runtime_valid',
        'accelerator_offload_observed', 'app_identity_and_runtime_valid')
    rows = []
    for old_row in collection['associated_runs']:
        run = old_row['run_id']
        if not isinstance(run, str) or not acceptance.HEX32.fullmatch(run):
            raise ValueError('invalid retained run ID')
        prefix = 'runs/' + run + '/'
        app = acceptance.strict_json(read(prefix + 'app-receipt.json'))
        native = acceptance.strict_json(read(prefix + 'native-result.json'))
        grammar = read(prefix + 'grammar.gbnf')
        rows.append({'run_id': run, 'grammar_schema': app.get('grammar_schema'),
            'grammar_observation_id': app.get('grammar_observation_id'),
            'grammar_current_package': app.get('grammar_current_package'),
            'grammar_sha256': sha(grammar),
            'original_controller_grammar_binding_valid': old_row.get('controller_grammar_binding_valid'),
            'compat_controller_grammar_binding_valid': acceptance.controller_grammar_binding_valid(app, native, grammar, packages),
            'original_recorded_non_grammar_gates_passed': all(old_row.get(k) is True for k in boolean_gates) and old_row.get('exit_code') == 0,
            'original_recorded_other_failed_gates': [k for k in boolean_gates if old_row.get(k) is not True] + ([] if old_row.get('exit_code') == 0 else ['exit_code'])})
    window_raw = read('ui-final-window.txt')
    text = window_raw.decode('utf-8', 'replace')
    lines = text.splitlines()
    focus_lines = [x.strip() for x in lines if 'mCurrentFocus=' in x]
    hints = [x.strip() for x in lines if any(k in x for k in ('WINDOW MANAGER', 'mFocusedApp', 'mObscuringWindow', 'topFocusedDisplayId', 'mCurrentFocus', 'com.android.settings'))]
    report = {'schema': 'hepta.existing-evidence-grammar-compat-audit.v1',
        'original_evidence_directory': str(case), 'original_verdict_preserved': old.get('verdict'),
        'replacement_acceptance_verdict': None, 'phone_contacted': False, 'original_evidence_modified': False,
        'compat_driver_sha256': sha((drivers / 'phone_acceptance.py').read_bytes()),
        'original_file_manifest_sha256': sha((case / 'file-manifest.json').read_bytes()),
        'original_task_result_status': (old.get('task_result') or {}).get('status'),
        'original_independent_ui': old.get('independent_ui'), 'original_errors': old.get('errors'),
        'original_collection_errors': collection.get('errors'), 'runs': rows,
        'only_recorded_native_gate_mismatch_is_known_schema_compatibility': bool(rows) and all(
            row['original_controller_grammar_binding_valid'] is False
            and row['compat_controller_grammar_binding_valid'] is True
            and row['original_recorded_non_grammar_gates_passed'] is True for row in rows),
        'focus_text_audit': {'bytes': len(window_raw), 'sha256': sha(window_raw),
            'mCurrentFocus_field_present': bool(focus_lines), 'mCurrentFocus_lines': focus_lines,
            'first_lines': lines[:5], 'relevant_lines': hints[:80],
            'scope': 'This describes the retained dumpsys window windows output only; no fresh focus query or foreground assertion is added.'},
        'consumed_original_files': sorted(consumed.values(), key=lambda x: x['path'])}
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    output.chmod(0o600)
    print(json.dumps({'audit': str(output), 'sha256': sha(output.read_bytes()),
        'original_verdict': old.get('verdict'), 'runs': rows,
        'only_recorded_native_gate_mismatch_is_known_schema_compatibility': report['only_recorded_native_gate_mismatch_is_known_schema_compatibility'],
        'focus_text_audit': report['focus_text_audit']}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
