#!/usr/bin/env python3
"""Reproduce this unadopted current-consumer construction without original I/O."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import types

PACKAGE = Path(__file__).resolve().parents[1]


def build(base, v3):
    source = (PACKAGE / 'candidate/source_parent_consumer.py').read_bytes()
    loader_raw = (PACKAGE / 'candidate/bound_loader.py').read_bytes()
    loader = types.ModuleType('manifest_bound_consumer_loader')
    exec(compile(loader_raw, '<manifest-bound-consumer-loader>', 'exec'), loader.__dict__)
    candidate = loader.load_bound(source, source)
    original = (base / 'originals/late_boundary.r10.original.py').read_bytes()
    inventory = candidate.function_source((base / 'candidate/derived/source_parent_inventory_value.py').read_bytes(), 'inventory_value')
    v3_source = (v3 / 'candidate/source_parent_reader.py').read_bytes()
    v3_loader = (v3 / 'candidate/bound_loader.py').read_bytes()
    candidate.need(candidate.pin(v3_source) == candidate.V3_CONSTRUCTOR
                   and candidate.pin(v3_loader) == candidate.V3_LOADER, 'unchanged sealed v3 constructor/loader')
    derived, transformation = candidate.derive_source(original, inventory)
    return {'schema': 'hepta.UNADOPTED.current-consumer-construction.v4',
            'constructor_source': candidate.pin(source), 'bound_loader_source': candidate.pin(loader_raw),
            'frozen_current_source': candidate.pin(original), 'actual_derived_current_source': candidate.pin(derived),
            'v3_constructor_source': candidate.pin(v3_source), 'v3_bound_loader_source': candidate.pin(v3_loader),
            'inventory_function': candidate.pin(inventory), 'methods': list(candidate.METHODS),
            'transformation': transformation, 'v1_current_inventory_selected': True,
            'v3_complete_reader_selected_by_real_current_consumers': True,
            'v2_retained_r9_adapter_selected': False, 'frozen_source_bytes_changed': False,
            'old_execution_receipts_reused': False, 'validation_result_cache': False,
            'production_adopted': False, 'runtime_admission': False, 'current_native_case_credit': 0,
            'complete_production_IO_metering_verified': False, 'whole_stage_budget_verified': False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--v3', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.check and args.output:
        parser.error('--check and --output are exclusive')
    base = args.base.resolve(); v3 = args.v3.resolve() if args.v3 else base / 'source-parent-v3'
    value = build(base, v3)
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    if args.check:
        expected = (PACKAGE / 'CONSUMER-CANDIDATE-MANIFEST-v4.json').read_bytes()
        if raw != expected:
            raise ValueError('saved consumer construction manifest differs from current exact bytes')
        print(json.dumps({'state': 'PASS', 'whole_byte_inverse_verified': True,
                          'actual_derived_current_source': value['actual_derived_current_source'],
                          'production_adopted': False, 'runtime_admission': False}, sort_keys=True))
    elif args.output:
        with args.output.open('xb') as stream:
            stream.write(raw)
    else:
        print(raw.decode(), end='')


if __name__ == '__main__':
    main()
